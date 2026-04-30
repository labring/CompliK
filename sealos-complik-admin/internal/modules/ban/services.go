package ban

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"
)

var (
	ErrBanInvalidInput   = errors.New("namespace, ban start time, and operator name are required")
	ErrBanNotFound       = errors.New("ban not found")
	ErrBanInvalidFile    = errors.New("only png, jpg, jpeg, webp, and gif screenshots are supported")
	ErrBanUploadDisabled = errors.New("ban screenshot upload is disabled: oss is not configured")
)

const (
	defaultBanObjectPrefix        = "bans"
	maxBanScreenshotCount         = 6
	maxBanScreenshotFileSizeBytes = 10 << 20 // 10MB
)

type Service struct {
	repository *Repository
	uploader   fileUploader
	ossPrefix  string
	now        func() time.Time
}

func NewService(repository *Repository, uploader fileUploader, ossPrefix string) *Service {
	normalizedPrefix := normalizeObjectPrefix(ossPrefix)
	if normalizedPrefix == "" {
		normalizedPrefix = defaultBanObjectPrefix
	}

	return &Service{
		repository: repository,
		uploader:   uploader,
		ossPrefix:  normalizedPrefix,
		now:        time.Now,
	}
}

// CreateBan creates a new ban record.
func (s *Service) CreateBan(ctx context.Context, req CreateBanRequest) error {
	return s.createBan(ctx, req, nil)
}

// UploadBan creates a new ban record and uploads screenshots to OSS.
func (s *Service) UploadBan(ctx context.Context, req CreateBanRequest, screenshots []*multipart.FileHeader) error {
	return s.createBan(ctx, req, screenshots)
}

func (s *Service) createBan(ctx context.Context, req CreateBanRequest, screenshots []*multipart.FileHeader) error {
	input, err := normalizeBanInput(
		req.Namespace,
		req.Reason,
		req.BanStartTime,
		req.BanEndTime,
		req.OperatorName,
		req.ScreenshotURLs,
	)
	if err != nil {
		return err
	}

	screenshotURLs := append(StringList(nil), input.ScreenshotURLs...)
	if len(screenshots) > 0 {
		uploadedURLs, err := s.uploadScreenshots(ctx, input.Namespace, screenshots)
		if err != nil {
			return err
		}
		screenshotURLs = append(screenshotURLs, uploadedURLs...)
	}

	ban := &Ban{
		Namespace:      input.Namespace,
		Reason:         input.Reason,
		ScreenshotURLs: screenshotURLs,
		BanStartTime:   input.BanStartTime,
		BanEndTime:     input.BanEndTime,
		OperatorName:   input.OperatorName,
	}

	if err := s.repository.CreateBan(ctx, ban); err != nil {
		return translateRepositoryError(err)
	}

	return nil
}

// DeleteBanByID deletes a single ban record by id.
func (s *Service) DeleteBanByID(ctx context.Context, id uint64) error {
	if id == 0 {
		return ErrBanInvalidInput
	}

	if err := s.repository.DeleteBanByID(ctx, id); err != nil {
		return translateRepositoryError(err)
	}

	return nil
}

// GetBans returns all ban records for the given namespace.
func (s *Service) GetBans(ctx context.Context, namespace string) ([]BanResponse, error) {
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}

	bans, err := s.repository.GetBansByNamespace(ctx, namespace)
	if err != nil {
		return nil, translateRepositoryError(err)
	}

	responses := make([]BanResponse, 0, len(bans))
	for i := range bans {
		responses = append(responses, *toBanResponse(&bans[i]))
	}

	return responses, nil
}

// ListBans returns all ban records.
func (s *Service) ListBans(ctx context.Context) ([]BanResponse, error) {
	bans, err := s.repository.ListBans(ctx)
	if err != nil {
		return nil, err
	}

	responses := make([]BanResponse, 0, len(bans))
	for i := range bans {
		responses = append(responses, *toBanResponse(&bans[i]))
	}

	return responses, nil
}

// GetBanStatus returns whether the given namespace is currently banned.
func (s *Service) GetBanStatus(ctx context.Context, namespace string) (*BanStatusResponse, error) {
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}

	banned, err := s.repository.HasActiveBan(ctx, namespace, s.now())
	if err != nil {
		return nil, err
	}

	return &BanStatusResponse{Banned: banned}, nil
}

type DownloadedBanScreenshot struct {
	FileName    string
	ContentType string
	Reader      io.ReadCloser
}

// DownloadScreenshotByURL streams a ban screenshot through admin.
func (s *Service) DownloadScreenshotByURL(ctx context.Context, fileURL string) (*DownloadedBanScreenshot, error) {
	trimmedURL := strings.TrimSpace(fileURL)
	if trimmedURL == "" {
		return nil, ErrBanInvalidInput
	}
	if s.uploader == nil {
		return nil, ErrBanUploadDisabled
	}

	reader, contentType, err := s.uploader.DownloadByURL(ctx, trimmedURL)
	if err != nil {
		return nil, err
	}

	fileName := filepath.Base(trimmedURL)
	if strings.TrimSpace(fileName) == "" || fileName == "." || fileName == "/" {
		fileName = "screenshot"
	}
	if strings.TrimSpace(contentType) == "" {
		contentType = "application/octet-stream"
	}

	return &DownloadedBanScreenshot{
		FileName:    fileName,
		ContentType: contentType,
		Reader:      reader,
	}, nil
}

type normalizedBanInput struct {
	Namespace      string
	Reason         string
	ScreenshotURLs []string
	BanStartTime   time.Time
	BanEndTime     *time.Time
	OperatorName   string
}

// normalizeBanInput keeps create validation consistent.
func normalizeBanInput(namespace, reason string, banStartTime time.Time, banEndTime *time.Time, operatorName string, screenshotURLs []string) (*normalizedBanInput, error) {
	trimmedNamespace := strings.TrimSpace(namespace)
	trimmedReason := strings.TrimSpace(reason)
	trimmedOperatorName := strings.TrimSpace(operatorName)
	normalizedScreenshotURLs := normalizeScreenshotURLs(screenshotURLs)

	if trimmedNamespace == "" || banStartTime.IsZero() || trimmedOperatorName == "" {
		return nil, ErrBanInvalidInput
	}
	// Permanent ban only: reject any non-nil end time.
	if banEndTime != nil {
		return nil, ErrBanInvalidInput
	}
	if len(normalizedScreenshotURLs) > maxBanScreenshotCount {
		return nil, fmt.Errorf("%w: screenshot count must be at most %d", ErrBanInvalidInput, maxBanScreenshotCount)
	}

	return &normalizedBanInput{
		Namespace:      trimmedNamespace,
		Reason:         trimmedReason,
		ScreenshotURLs: normalizedScreenshotURLs,
		BanStartTime:   banStartTime,
		BanEndTime:     nil,
		OperatorName:   trimmedOperatorName,
	}, nil
}

func (s *Service) uploadScreenshots(ctx context.Context, namespace string, screenshots []*multipart.FileHeader) ([]string, error) {
	if len(screenshots) == 0 {
		return nil, nil
	}
	if len(screenshots) > maxBanScreenshotCount {
		return nil, fmt.Errorf("%w: screenshot count must be at most %d", ErrBanInvalidInput, maxBanScreenshotCount)
	}
	if s.uploader == nil {
		return nil, ErrBanUploadDisabled
	}

	uploaded := make([]string, 0, len(screenshots))
	for index, screenshot := range screenshots {
		contentType, ok := screenshotContentType(screenshot)
		if !ok {
			return nil, ErrBanInvalidFile
		}
		if screenshot.Size <= 0 || screenshot.Size > maxBanScreenshotFileSizeBytes {
			return nil, fmt.Errorf("%w: screenshot size must be between 1 byte and %d bytes", ErrBanInvalidFile, maxBanScreenshotFileSizeBytes)
		}

		file, err := screenshot.Open()
		if err != nil {
			return nil, fmt.Errorf("open uploaded screenshot: %w", err)
		}

		objectKey := s.buildScreenshotObjectKey(namespace, index, screenshot.Filename)
		fileURL, uploadErr := s.uploader.Upload(ctx, objectKey, file, contentType)
		closeErr := file.Close()
		if uploadErr != nil {
			return nil, uploadErr
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close uploaded screenshot: %w", closeErr)
		}

		uploaded = append(uploaded, fileURL)
	}

	return uploaded, nil
}

func normalizeScreenshotURLs(urls []string) []string {
	if len(urls) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(urls))
	for _, url := range urls {
		trimmed := strings.TrimSpace(url)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}

	if len(normalized) == 0 {
		return nil
	}

	return normalized
}

func normalizeObjectPrefix(prefix string) string {
	trimmed := strings.TrimSpace(prefix)
	return strings.Trim(trimmed, "/")
}

func screenshotContentType(fileHeader *multipart.FileHeader) (string, bool) {
	if fileHeader == nil {
		return "", false
	}

	filename := strings.ToLower(strings.TrimSpace(fileHeader.Filename))
	contentType := strings.ToLower(strings.TrimSpace(fileHeader.Header.Get("Content-Type")))

	switch filepath.Ext(filename) {
	case ".png":
		if contentType == "" || contentType == "image/png" || contentType == "application/octet-stream" {
			return "image/png", true
		}
	case ".jpg", ".jpeg":
		if contentType == "" || contentType == "image/jpeg" || contentType == "application/octet-stream" {
			return "image/jpeg", true
		}
	case ".webp":
		if contentType == "" || contentType == "image/webp" || contentType == "application/octet-stream" {
			return "image/webp", true
		}
	case ".gif":
		if contentType == "" || contentType == "image/gif" || contentType == "application/octet-stream" {
			return "image/gif", true
		}
	}

	return "", false
}

func (s *Service) buildScreenshotObjectKey(namespace string, index int, filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		ext = ".png"
	}

	timestamp := time.Now().UTC().Format("20060102T150405")
	safeNamespace := sanitizePathSegment(namespace)

	return fmt.Sprintf("%s/%s/%s-%02d%s", s.ossPrefix, safeNamespace, timestamp, index+1, ext)
}

func sanitizePathSegment(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "unknown"
	}

	var builder strings.Builder
	builder.Grow(len(trimmed))
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			builder.WriteRune(r)
			continue
		}
		builder.WriteByte('_')
	}

	return builder.String()
}

func validateNamespace(namespace string) error {
	if strings.TrimSpace(namespace) == "" {
		return ErrBanInvalidInput
	}

	return nil
}

// translateRepositoryError hides storage details from the handler layer.
func translateRepositoryError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrBanNotFound
	}

	return err
}

func toBanResponse(ban *Ban) *BanResponse {
	return &BanResponse{
		ID:             ban.ID,
		Namespace:      ban.Namespace,
		Reason:         ban.Reason,
		ScreenshotURLs: []string(ban.ScreenshotURLs),
		BanStartTime:   ban.BanStartTime,
		BanEndTime:     ban.BanEndTime,
		OperatorName:   ban.OperatorName,
		CreatedAt:      ban.CreatedAt,
		UpdatedAt:      ban.UpdatedAt,
	}
}
