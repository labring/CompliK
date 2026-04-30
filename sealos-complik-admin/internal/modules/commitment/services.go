package commitment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"
)

var (
	ErrCommitmentAlreadyExists  = errors.New("commitment already exists")
	ErrCommitmentInvalidInput   = errors.New("namespace, file name, and file url are required")
	ErrCommitmentNotFound       = errors.New("commitment not found")
	ErrCommitmentInvalidFile    = errors.New("only pdf file is allowed")
	ErrCommitmentUploadDisabled = errors.New("commitment upload is disabled: oss is not configured")
)

const (
	defaultCommitmentObjectPrefix = "commitments"
	maxCommitmentFileSizeBytes    = 10 << 20 // 10MB
	pdfContentType                = "application/pdf"
)

type fileUploader interface {
	Upload(ctx context.Context, objectKey string, reader io.Reader, contentType string) (string, error)
	DownloadByURL(ctx context.Context, fileURL string) (io.ReadCloser, string, error)
}

type Service struct {
	repository *Repository
	uploader   fileUploader
	ossPrefix  string
}

type DownloadedCommitmentFile struct {
	FileName    string
	ContentType string
	Reader      io.ReadCloser
}

func NewService(repository *Repository, uploader fileUploader, ossPrefix string) *Service {
	normalizedPrefix := normalizeObjectPrefix(ossPrefix)
	if normalizedPrefix == "" {
		normalizedPrefix = defaultCommitmentObjectPrefix
	}

	return &Service{
		repository: repository,
		uploader:   uploader,
		ossPrefix:  normalizedPrefix,
	}
}

// CreateCommitment creates a new commitment for the given namespace.
func (s *Service) CreateCommitment(ctx context.Context, req CreateCommitmentRequest) error {
	input, err := normalizeCreateCommitmentInput(req.Namespace, req.FileName, req.FileURL)
	if err != nil {
		return err
	}

	if _, err := s.repository.GetCommitmentByNamespace(ctx, input.Namespace); err == nil {
		return ErrCommitmentAlreadyExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	commitment := &Commitment{
		Namespace: input.Namespace,
		FileName:  input.FileName,
		FileURL:   input.FileURL,
	}

	if err := s.repository.CreateCommitment(ctx, commitment); err != nil {
		return translateRepositoryError(err)
	}

	return nil
}

// UpdateCommitment updates the commitment record for the given namespace.
func (s *Service) UpdateCommitment(ctx context.Context, namespace string, req UpdateCommitmentRequest) error {
	commitment, err := s.repository.GetCommitmentByNamespace(ctx, namespace)
	if err != nil {
		return translateRepositoryError(err)
	}

	input, err := normalizeUpdateCommitmentInput(namespace, req.FileName, req.FileURL)
	if err != nil {
		return err
	}

	commitment.FileName = input.FileName
	commitment.FileURL = input.FileURL

	if err := s.repository.UpdateCommitment(ctx, commitment); err != nil {
		return translateRepositoryError(err)
	}

	return nil
}

// DeleteCommitment deletes the commitment record for the given namespace.
func (s *Service) DeleteCommitment(ctx context.Context, namespace string) error {
	if err := s.repository.DeleteCommitmentByNamespace(ctx, namespace); err != nil {
		return translateRepositoryError(err)
	}

	return nil
}

// GetCommitment returns the commitment record for the given namespace.
func (s *Service) GetCommitment(ctx context.Context, namespace string) (*CommitmentResponse, error) {
	commitment, err := s.repository.GetCommitmentByNamespace(ctx, namespace)
	if err != nil {
		return nil, translateRepositoryError(err)
	}

	return toCommitmentResponse(commitment), nil
}

// ListCommitments returns all commitment records.
func (s *Service) ListCommitments(ctx context.Context) ([]CommitmentResponse, error) {
	commitments, err := s.repository.ListCommitments(ctx)
	if err != nil {
		return nil, err
	}

	responses := make([]CommitmentResponse, 0, len(commitments))
	for i := range commitments {
		responses = append(responses, *toCommitmentResponse(&commitments[i]))
	}

	return responses, nil
}

// UploadCommitment uploads commitment PDF and upserts commitment metadata by namespace.
func (s *Service) UploadCommitment(ctx context.Context, namespace string, fileHeader *multipart.FileHeader) (*CommitmentResponse, error) {
	trimmedNamespace := strings.TrimSpace(namespace)
	if trimmedNamespace == "" || fileHeader == nil {
		return nil, ErrCommitmentInvalidInput
	}
	if s.uploader == nil {
		return nil, ErrCommitmentUploadDisabled
	}
	if !isPDFFile(fileHeader) {
		return nil, ErrCommitmentInvalidFile
	}
	if fileHeader.Size <= 0 || fileHeader.Size > maxCommitmentFileSizeBytes {
		return nil, fmt.Errorf("pdf size must be between 1 byte and %d bytes", maxCommitmentFileSizeBytes)
	}

	file, err := fileHeader.Open()
	if err != nil {
		return nil, fmt.Errorf("open uploaded file: %w", err)
	}
	defer file.Close()

	objectKey := s.buildObjectKey(trimmedNamespace, fileHeader.Filename)
	fileURL, err := s.uploader.Upload(ctx, objectKey, file, pdfContentType)
	if err != nil {
		return nil, err
	}

	fileName := strings.TrimSpace(fileHeader.Filename)
	existing, err := s.repository.GetCommitmentByNamespace(ctx, trimmedNamespace)
	if err == nil {
		existing.FileName = fileName
		existing.FileURL = fileURL
		if saveErr := s.repository.UpdateCommitment(ctx, existing); saveErr != nil {
			return nil, translateRepositoryError(saveErr)
		}

		return toCommitmentResponse(existing), nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, translateRepositoryError(err)
	}

	commitment := &Commitment{
		Namespace: trimmedNamespace,
		FileName:  fileName,
		FileURL:   fileURL,
	}
	if err := s.repository.CreateCommitment(ctx, commitment); err != nil {
		return nil, translateRepositoryError(err)
	}

	return toCommitmentResponse(commitment), nil
}

// DownloadCommitment streams the commitment file for browser download.
func (s *Service) DownloadCommitment(ctx context.Context, namespace string) (*DownloadedCommitmentFile, error) {
	trimmedNamespace := strings.TrimSpace(namespace)
	if trimmedNamespace == "" {
		return nil, ErrCommitmentInvalidInput
	}
	if s.uploader == nil {
		return nil, ErrCommitmentUploadDisabled
	}

	commitment, err := s.repository.GetCommitmentByNamespace(ctx, trimmedNamespace)
	if err != nil {
		return nil, translateRepositoryError(err)
	}

	reader, contentType, err := s.uploader.DownloadByURL(ctx, commitment.FileURL)
	if err != nil {
		return nil, err
	}

	fileName := strings.TrimSpace(commitment.FileName)
	if fileName == "" {
		fileName = filepath.Base(strings.TrimSpace(commitment.FileURL))
	}
	if strings.TrimSpace(contentType) == "" {
		contentType = pdfContentType
	}

	return &DownloadedCommitmentFile{
		FileName:    fileName,
		ContentType: contentType,
		Reader:      reader,
	}, nil
}

type normalizedCommitmentInput struct {
	Namespace string
	FileName  string
	FileURL   string
}

// normalizeCreateCommitmentInput keeps create validation consistent.
func normalizeCreateCommitmentInput(namespace, fileName, fileURL string) (*normalizedCommitmentInput, error) {
	return normalizeCommitmentInput(namespace, fileName, fileURL)
}

// normalizeUpdateCommitmentInput keeps update validation consistent.
func normalizeUpdateCommitmentInput(namespace, fileName, fileURL string) (*normalizedCommitmentInput, error) {
	return normalizeCommitmentInput(namespace, fileName, fileURL)
}

func normalizeCommitmentInput(namespace, fileName, fileURL string) (*normalizedCommitmentInput, error) {
	trimmedNamespace := strings.TrimSpace(namespace)
	trimmedFileName := strings.TrimSpace(fileName)
	trimmedFileURL := strings.TrimSpace(fileURL)

	if trimmedNamespace == "" || trimmedFileName == "" || trimmedFileURL == "" {
		return nil, ErrCommitmentInvalidInput
	}

	return &normalizedCommitmentInput{
		Namespace: trimmedNamespace,
		FileName:  trimmedFileName,
		FileURL:   trimmedFileURL,
	}, nil
}

func normalizeObjectPrefix(prefix string) string {
	trimmed := strings.TrimSpace(prefix)
	trimmed = strings.Trim(trimmed, "/")
	return trimmed
}

func isPDFFile(fileHeader *multipart.FileHeader) bool {
	if fileHeader == nil {
		return false
	}

	filename := strings.TrimSpace(fileHeader.Filename)
	if !strings.EqualFold(filepath.Ext(filename), ".pdf") {
		return false
	}

	contentType := strings.TrimSpace(fileHeader.Header.Get("Content-Type"))
	return contentType == "" || contentType == pdfContentType || contentType == "application/octet-stream"
}

func (s *Service) buildObjectKey(namespace, filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		ext = ".pdf"
	}

	ts := time.Now().UTC().Format("20060102T150405")
	safeNamespace := sanitizePathSegment(namespace)

	return fmt.Sprintf("%s/%s/%s%s", s.ossPrefix, safeNamespace, ts, ext)
}

func sanitizePathSegment(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "unknown"
	}

	var b strings.Builder
	b.Grow(len(trimmed))
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}

	return b.String()
}

// translateRepositoryError hides storage details from the handler layer.
func translateRepositoryError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrCommitmentNotFound
	}
	if errors.Is(err, http.ErrMissingFile) {
		return ErrCommitmentInvalidInput
	}

	return err
}

func toCommitmentResponse(commitment *Commitment) *CommitmentResponse {
	return &CommitmentResponse{
		Namespace: commitment.Namespace,
		FileName:  commitment.FileName,
		FileURL:   commitment.FileURL,
		CreatedAt: commitment.CreatedAt,
		UpdatedAt: commitment.UpdatedAt,
	}
}
