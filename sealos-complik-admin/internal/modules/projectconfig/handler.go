package projectconfig

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// CreateProjectConfig handles the creation of a new project configuration.
func (h *Handler) CreateProjectConfig(c *gin.Context) {
	// Parse and validate the request body.
	var req CreateProjectConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
			"error":   err.Error(),
		})
		return
	}

	// Call the service layer to create the project configuration.
	err := h.service.CreateProjectConfig(c.Request.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, ErrProjectConfigInvalidInput):
			c.JSON(http.StatusBadRequest, gin.H{
				"message": err.Error(),
			})
		case errors.Is(err, ErrProjectConfigInvalidJSON):
			c.JSON(http.StatusBadRequest, gin.H{
				"message": err.Error(),
			})
		case errors.Is(err, ErrProjectConfigAlreadyExists):
			c.JSON(http.StatusConflict, gin.H{
				"message": err.Error(),
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "failed to create project config",
				"error":   err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "project config created successfully",
	})
}

// UpdateProjectConfig handles updating a project configuration.
func (h *Handler) UpdateProjectConfig(c *gin.Context) {
	configName, ok := bindProjectConfigName(c)
	if !ok {
		return
	}

	var req UpdateProjectConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
			"error":   err.Error(),
		})
		return
	}

	if err := h.service.UpdateProjectConfig(c.Request.Context(), configName, req); err != nil {
		h.respondWithServiceError(c, err, "failed to update project config")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "project config updated successfully",
	})
}

// DeleteProjectConfig handles deleting a project configuration.
func (h *Handler) DeleteProjectConfig(c *gin.Context) {
	configName, ok := bindProjectConfigName(c)
	if !ok {
		return
	}

	if err := h.service.DeleteProjectConfig(c.Request.Context(), configName); err != nil {
		h.respondWithServiceError(c, err, "failed to delete project config")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "project config deleted successfully",
	})
}

// GetProjectConfig handles retrieving a project configuration by config name.
func (h *Handler) GetProjectConfig(c *gin.Context) {
	configName, ok := bindProjectConfigName(c)
	if !ok {
		return
	}

	resp, err := h.service.GetProjectConfig(c.Request.Context(), configName)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to get project config")
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ListProjectConfigs handles listing all project configurations.
func (h *Handler) ListProjectConfigs(c *gin.Context) {
	resp, err := h.service.ListProjectConfigs(c.Request.Context())
	if err != nil {
		h.respondWithServiceError(c, err, "failed to list project configs")
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ListProjectConfigsByType handles listing project configurations filtered by config type.
func (h *Handler) ListProjectConfigsByType(c *gin.Context) {
	configType, ok := bindProjectConfigType(c)
	if !ok {
		return
	}

	resp, err := h.service.ListProjectConfigsByType(c.Request.Context(), configType)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to list project configs by type")
		return
	}

	c.JSON(http.StatusOK, resp)
}

// bindProjectConfigName extracts the config name from the URI and validates it.
func bindProjectConfigName(c *gin.Context) (string, bool) {
	var req ProjectConfigNameRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request path",
			"error":   err.Error(),
		})
		return "", false
	}

	return req.ConfigName, true
}

// bindProjectConfigType extracts the config type from the URI and validates it.
func bindProjectConfigType(c *gin.Context) (string, bool) {
	var req ProjectConfigTypeRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request path",
			"error":   err.Error(),
		})
		return "", false
	}

	return req.ConfigType, true
}

// respondWithServiceError handles responding with appropriate error messages based on the service error.
func (h *Handler) respondWithServiceError(c *gin.Context, err error, fallbackMessage string) {
	switch {
	case errors.Is(err, ErrProjectConfigInvalidInput):
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
	case errors.Is(err, ErrProjectConfigInvalidJSON):
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
	case errors.Is(err, ErrProjectConfigAlreadyExists):
		c.JSON(http.StatusConflict, gin.H{
			"message": err.Error(),
		})
	case errors.Is(err, ErrProjectConfigNotFound):
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
