package ban

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// CreateOrUploadBan routes POST /api/bans based on content type.
func (h *Handler) CreateOrUploadBan(c *gin.Context) {
	contentType := strings.ToLower(c.GetHeader("Content-Type"))
	if strings.HasPrefix(contentType, "multipart/form-data") {
		h.UploadBan(c)
		return
	}

	h.CreateBan(c)
}

// CreateBan handles the creation of a new ban record.
func (h *Handler) CreateBan(c *gin.Context) {
	var req CreateBanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
			"error":   err.Error(),
		})
		return
	}

	if err := h.service.CreateBan(c.Request.Context(), req); err != nil {
		h.respondWithServiceError(c, err, "failed to create ban")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "ban created successfully",
	})
}

// UploadBan handles creating a ban record with screenshot uploads.
func (h *Handler) UploadBan(c *gin.Context) {
	var req UploadBanRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid form data",
			"error":   err.Error(),
		})
		return
	}

	banStartTime, err := parseBanTime(req.BanStartTime)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid ban start time",
			"error":   err.Error(),
		})
		return
	}

	screenshots, err := bindBanScreenshots(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid screenshot files",
			"error":   err.Error(),
		})
		return
	}

	createReq := CreateBanRequest{
		Namespace:    req.Namespace,
		Reason:       req.Reason,
		BanStartTime: banStartTime,
		OperatorName: req.OperatorName,
	}
	if err := h.service.UploadBan(c.Request.Context(), createReq, screenshots); err != nil {
		h.respondWithServiceError(c, err, "failed to upload ban")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "ban created successfully",
	})
}

// DeleteBanByID handles deleting a single ban record by id.
func (h *Handler) DeleteBanByID(c *gin.Context) {
	var req BanIDRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request path",
			"error":   err.Error(),
		})
		return
	}

	if err := h.service.DeleteBanByID(c.Request.Context(), req.ID); err != nil {
		h.respondWithServiceError(c, err, "failed to delete ban")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "ban deleted successfully",
	})
}

// GetBans handles retrieving all ban records for a namespace.
func (h *Handler) GetBans(c *gin.Context) {
	namespace, ok := bindBanNamespace(c)
	if !ok {
		return
	}

	resp, err := h.service.GetBans(c.Request.Context(), namespace)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to get bans")
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ListBans handles listing all ban records.
func (h *Handler) ListBans(c *gin.Context) {
	resp, err := h.service.ListBans(c.Request.Context())
	if err != nil {
		h.respondWithServiceError(c, err, "failed to list bans")
		return
	}

	c.JSON(http.StatusOK, resp)
}

// PreviewScreenshot streams a ban screenshot for inline browser preview.
func (h *Handler) PreviewScreenshot(c *gin.Context) {
	var req BanScreenshotQueryRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request query",
			"error":   err.Error(),
		})
		return
	}

	file, err := h.service.DownloadScreenshotByURL(c.Request.Context(), req.URL)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to preview ban screenshot")
		return
	}
	defer file.Reader.Close()

	c.Header("Content-Type", file.ContentType)
	c.Header("Content-Disposition", fmt.Sprintf("inline; filename*=UTF-8''%s", url.QueryEscape(file.FileName)))
	c.Status(http.StatusOK)
	if _, err := io.Copy(c.Writer, file.Reader); err != nil {
		_ = c.Error(err)
	}
}

// GetBanStatus handles checking whether a namespace is currently banned.
func (h *Handler) GetBanStatus(c *gin.Context) {
	namespace, ok := bindBanNamespace(c)
	if !ok {
		return
	}

	resp, err := h.service.GetBanStatus(c.Request.Context(), namespace)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to get ban status")
		return
	}

	c.JSON(http.StatusOK, resp)
}

// bindBanNamespace extracts the namespace from the URI and validates it.
func bindBanNamespace(c *gin.Context) (string, bool) {
	var req BanNamespaceRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request path",
			"error":   err.Error(),
		})
		return "", false
	}

	return req.Namespace, true
}

// respondWithServiceError handles responding with appropriate error messages based on the service error.
func (h *Handler) respondWithServiceError(c *gin.Context, err error, fallbackMessage string) {
	switch {
	case errors.Is(err, ErrBanInvalidInput):
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
	case errors.Is(err, ErrBanInvalidFile):
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
	case errors.Is(err, ErrBanUploadDisabled):
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"message": err.Error(),
		})
	case errors.Is(err, ErrBanNotFound):
		c.JSON(http.StatusNotFound, gin.H{
			"message": err.Error(),
		})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": fallbackMessage,
			"error":   err.Error(),
		})
	}
}

func bindBanScreenshots(c *gin.Context) ([]*multipart.FileHeader, error) {
	form, err := c.MultipartForm()
	if err != nil {
		if errors.Is(err, http.ErrNotMultipart) {
			return nil, nil
		}
		return nil, err
	}
	if form == nil || form.File == nil {
		return nil, nil
	}

	screenshots := append([]*multipart.FileHeader{}, form.File["screenshots"]...)
	screenshots = append(screenshots, form.File["screenshots[]"]...)
	if len(screenshots) == 0 {
		return nil, nil
	}

	return screenshots, nil
}

func parseBanTime(value string) (time.Time, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, ErrBanInvalidInput
	}

	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04",
		"2006-01-02 15:04:05",
	}

	for _, layout := range layouts {
		parsed, err := time.Parse(layout, trimmed)
		if err == nil {
			return parsed, nil
		}
		parsed, err = time.ParseInLocation(layout, trimmed, time.Local)
		if err == nil {
			return parsed, nil
		}
	}

	return time.Time{}, ErrBanInvalidInput
}
