package unban

import (
	"context"
	"errors"
	"log"
	"strings"

	"gorm.io/gorm"
	"sealos-complik-admin/internal/infra/k8s"
	"sealos-complik-admin/internal/modules/pagequery"
)

var (
	ErrUnbanInvalidInput = errors.New("namespace and operator name are required")
	ErrUnbanNotFound     = errors.New("unban not found")
)

type Service struct {
	repository *Repository
	locker     k8s.NamespaceLocker
}

func NewService(repository *Repository, locker k8s.NamespaceLocker) *Service {
	return &Service{repository: repository, locker: locker}
}

// CreateUnban creates a new unban record.
func (s *Service) CreateUnban(ctx context.Context, req CreateUnbanRequest) error {
	input, err := normalizeUnbanInput(req.Namespace, req.OperatorName)
	if err != nil {
		return err
	}

	record := &Unban{
		Namespace:    input.Namespace,
		OperatorName: input.OperatorName,
	}

	if err := s.repository.CreateUnban(ctx, record); err != nil {
		return translateRepositoryError(err)
	}

	if s.locker != nil {
		if _, err := s.locker.EnsureUnlocked(ctx, input.Namespace); err != nil {
			log.Printf("unban unlock failed for namespace %s: %v", input.Namespace, err)

			if rollbackErr := s.repository.DeleteUnbanByID(ctx, record.ID); rollbackErr != nil {
				log.Printf(
					"unban rollback failed for namespace %s: %v",
					input.Namespace,
					rollbackErr,
				)
			}

			return err
		}
	}

	return nil
}

// DeleteUnbanByID deletes a single unban record by id.
func (s *Service) DeleteUnbanByID(ctx context.Context, id uint64) error {
	if id == 0 {
		return ErrUnbanInvalidInput
	}

	if err := s.repository.DeleteUnbanByID(ctx, id); err != nil {
		return translateRepositoryError(err)
	}

	return nil
}

// GetUnbans returns all unban records for the given namespace.
func (s *Service) GetUnbans(ctx context.Context, namespace string) ([]UnbanResponse, error) {
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}

	unbans, err := s.repository.GetUnbansByNamespace(ctx, namespace)
	if err != nil {
		return nil, translateRepositoryError(err)
	}

	responses := make([]UnbanResponse, 0, len(unbans))
	for i := range unbans {
		responses = append(responses, *toUnbanResponse(&unbans[i]))
	}

	return responses, nil
}

// ListUnbans returns all unban records.
func (s *Service) ListUnbans(ctx context.Context) ([]UnbanResponse, error) {
	unbans, err := s.repository.ListUnbans(ctx)
	if err != nil {
		return nil, err
	}

	responses := make([]UnbanResponse, 0, len(unbans))
	for i := range unbans {
		responses = append(responses, *toUnbanResponse(&unbans[i]))
	}

	return responses, nil
}

func (s *Service) ListUnbansPage(
	ctx context.Context,
	options pagequery.Options,
	keyword string,
	operatorName string,
) (*PaginatedUnbanResponse, error) {
	unbans, total, err := s.repository.ListUnbansPage(ctx, options, keyword, operatorName)
	if err != nil {
		return nil, err
	}

	responses := make([]UnbanResponse, 0, len(unbans))
	for i := range unbans {
		responses = append(responses, *toUnbanResponse(&unbans[i]))
	}

	response := pagequery.NewPaginatedResponse(responses, total, options)

	return &response, nil
}

type normalizedUnbanInput struct {
	Namespace    string
	OperatorName string
}

// normalizeUnbanInput keeps create validation consistent.
func normalizeUnbanInput(namespace, operatorName string) (*normalizedUnbanInput, error) {
	trimmedNamespace := strings.TrimSpace(namespace)
	trimmedOperatorName := strings.TrimSpace(operatorName)

	if trimmedNamespace == "" || trimmedOperatorName == "" {
		return nil, ErrUnbanInvalidInput
	}

	return &normalizedUnbanInput{
		Namespace:    trimmedNamespace,
		OperatorName: trimmedOperatorName,
	}, nil
}

func validateNamespace(namespace string) error {
	if strings.TrimSpace(namespace) == "" {
		return ErrUnbanInvalidInput
	}

	return nil
}

// translateRepositoryError hides storage details from the handler layer.
func translateRepositoryError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrUnbanNotFound
	}

	return err
}

func toUnbanResponse(record *Unban) *UnbanResponse {
	return &UnbanResponse{
		ID:           record.ID,
		Namespace:    record.Namespace,
		OperatorName: record.OperatorName,
		CreatedAt:    record.CreatedAt,
		UpdatedAt:    record.UpdatedAt,
	}
}
