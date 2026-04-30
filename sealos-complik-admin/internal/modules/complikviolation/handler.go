package complikviolation

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) CreateViolation(c *gin.Context) {
	var req CreateViolationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
			"error":   err.Error(),
		})
		return
	}

	if err := h.service.CreateViolation(c.Request.Context(), req); err != nil {
		h.respondWithServiceError(c, err, "failed to create complik violation")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "complik violation created successfully",
	})
}

func (h *Handler) DeleteViolations(c *gin.Context) {
	namespace, ok := bindNamespace(c)
	if !ok {
		return
	}

	if err := h.service.DeleteViolations(c.Request.Context(), namespace); err != nil {
		h.respondWithServiceError(c, err, "failed to delete complik violations")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "complik violations deleted successfully",
	})
}

func (h *Handler) DeleteViolationByID(c *gin.Context) {
	var req ViolationIDRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request path",
			"error":   err.Error(),
		})
		return
	}

	if err := h.service.DeleteViolationByID(c.Request.Context(), req.ID); err != nil {
		h.respondWithServiceError(c, err, "failed to delete complik violation")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "complik violation deleted successfully",
	})
}

func (h *Handler) GetViolations(c *gin.Context) {
	namespace, ok := bindNamespace(c)
	if !ok {
		return
	}

	includeAll, ok := bindIncludeAllQuery(c)
	if !ok {
		return
	}

	resp, err := h.service.GetViolations(c.Request.Context(), namespace, includeAll)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to get complik violations")
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *Handler) ListViolations(c *gin.Context) {
	includeAll, ok := bindIncludeAllQuery(c)
	if !ok {
		return
	}

	resp, err := h.service.ListViolations(c.Request.Context(), includeAll)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to list complik violations")
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *Handler) GetViolationStatus(c *gin.Context) {
	namespace, ok := bindNamespace(c)
	if !ok {
		return
	}

	resp, err := h.service.GetViolationStatus(c.Request.Context(), namespace)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to get complik violation status")
		return
	}

	c.JSON(http.StatusOK, resp)
}

func bindNamespace(c *gin.Context) (string, bool) {
	var req NamespaceRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request path",
			"error":   err.Error(),
		})
		return "", false
	}

	return req.Namespace, true
}

func bindIncludeAllQuery(c *gin.Context) (bool, bool) {
	raw := strings.TrimSpace(c.Query("include_all"))
	if raw == "" {
		return false, true
	}

	includeAll, err := strconv.ParseBool(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid include_all query",
			"error":   err.Error(),
		})
		return false, false
	}

	return includeAll, true
}

func (h *Handler) respondWithServiceError(c *gin.Context, err error, fallbackMessage string) {
	switch {
	case errors.Is(err, ErrViolationInvalidInput):
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
	case errors.Is(err, ErrViolationNotFound):
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
