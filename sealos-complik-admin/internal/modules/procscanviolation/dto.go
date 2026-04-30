package procscanviolation

import (
	"encoding/json"
	"time"
)

type NamespaceRequest struct {
	Namespace string `uri:"namespace" binding:"required,max=255"`
}

type ViolationIDRequest struct {
	ID uint64 `uri:"id" binding:"required,min=1"`
}

type CreateViolationRequest struct {
	Namespace         string          `json:"namespace" binding:"required,max=255"`
	PodName           string          `json:"pod_name" binding:"omitempty,max=255"`
	ContainerID       string          `json:"container_id" binding:"omitempty,max=128"`
	NodeName          string          `json:"node_name" binding:"omitempty,max=128"`
	PID               int             `json:"pid" binding:"required,min=1"`
	ProcessName       string          `json:"process_name" binding:"required,max=255"`
	ProcessCommand    string          `json:"process_command" binding:"required"`
	MatchType         string          `json:"match_type" binding:"omitempty,max=32"`
	MatchRule         string          `json:"match_rule" binding:"omitempty,max=255"`
	Message           string          `json:"message" binding:"required"`
	IsIllegal         *bool           `json:"is_illegal"`
	LabelActionStatus string          `json:"label_action_status" binding:"omitempty,max=32"`
	LabelActionResult string          `json:"label_action_result" binding:"omitempty"`
	DetectedAt        time.Time       `json:"detected_at" binding:"required"`
	RawPayload        json.RawMessage `json:"raw_payload"`
}

type ViolationResponse struct {
	ID                uint64          `json:"id"`
	Namespace         string          `json:"namespace"`
	PodName           string          `json:"pod_name,omitempty"`
	ContainerID       string          `json:"container_id,omitempty"`
	NodeName          string          `json:"node_name,omitempty"`
	PID               int             `json:"pid"`
	ProcessName       string          `json:"process_name"`
	ProcessCommand    string          `json:"process_command"`
	MatchType         string          `json:"match_type,omitempty"`
	MatchRule         string          `json:"match_rule,omitempty"`
	Message           string          `json:"message"`
	IsIllegal         bool            `json:"is_illegal"`
	LabelActionStatus string          `json:"label_action_status,omitempty"`
	LabelActionResult string          `json:"label_action_result,omitempty"`
	DetectedAt        time.Time       `json:"detected_at"`
	RawPayload        json.RawMessage `json:"raw_payload,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type ViolationStatusResponse struct {
	Violated bool `json:"violated"`
}
