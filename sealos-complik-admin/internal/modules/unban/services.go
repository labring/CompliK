package unban

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"
)

var (
	ErrUnbanInvalidInput = errors.New("namespace and operator name are required")
	ErrUnbanNotFound     = errors.New("unban not found")
)

type Service struct {
	repository *Repository
}

func NewService(repository *Repository) *Service {
	return &Service{repository: repository}
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
