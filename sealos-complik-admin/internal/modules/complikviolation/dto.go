package complikviolation

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
	Namespace     string          `json:"namespace" binding:"required,max=255"`
	Region        string          `json:"region" binding:"omitempty,max=64"`
	DiscoveryName string          `json:"discovery_name" binding:"omitempty,max=255"`
	CollectorName string          `json:"collector_name" binding:"omitempty,max=255"`
	DetectorName  string          `json:"detector_name" binding:"required,max=64"`
	ResourceName  string          `json:"resource_name" binding:"omitempty,max=255"`
	Host          string          `json:"host" binding:"omitempty,max=255"`
	URL           string          `json:"url" binding:"omitempty,max=1024"`
	Path          []string        `json:"path"`
	Keywords      []string        `json:"keywords"`
	Description   string          `json:"description" binding:"omitempty"`
	Explanation   string          `json:"explanation" binding:"omitempty"`
	IsIllegal     *bool           `json:"is_illegal"`
	IsTest        bool            `json:"is_test"`
	DetectedAt    time.Time       `json:"detected_at" binding:"required"`
	RawPayload    json.RawMessage `json:"raw_payload"`
}

type ViolationResponse struct {
	ID            uint64          `json:"id"`
	Namespace     string          `json:"namespace"`
	Region        string          `json:"region,omitempty"`
	DiscoveryName string          `json:"discovery_name,omitempty"`
	CollectorName string          `json:"collector_name,omitempty"`
	DetectorName  string          `json:"detector_name"`
	ResourceName  string          `json:"resource_name,omitempty"`
	Host          string          `json:"host,omitempty"`
	URL           string          `json:"url,omitempty"`
	Path          []string        `json:"path,omitempty"`
	Keywords      []string        `json:"keywords,omitempty"`
	Description   string          `json:"description,omitempty"`
	Explanation   string          `json:"explanation,omitempty"`
	IsIllegal     bool            `json:"is_illegal"`
	IsTest        bool            `json:"is_test"`
	DetectedAt    time.Time       `json:"detected_at"`
	RawPayload    json.RawMessage `json:"raw_payload,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

type ViolationStatusResponse struct {
	Violated bool `json:"violated"`
}
