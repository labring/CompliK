package projectconfig

import (
	"encoding/json"
	"time"
)

type ProjectConfigNameRequest struct {
	ConfigName string `uri:"config_name" binding:"required,max=255"`
}

type ProjectConfigTypeRequest struct {
	ConfigType string `uri:"config_type" binding:"required,max=50"`
}

type CreateProjectConfigRequest struct {
	ConfigName  string          `json:"config_name" binding:"required,max=255"`
	ConfigType  string          `json:"config_type" binding:"required,max=50"`
	ConfigValue json.RawMessage `json:"config_value" binding:"required"`
	Description string          `json:"description" binding:"omitempty,max=500"`
}

type UpdateProjectConfigRequest struct {
	ConfigName  string          `json:"config_name" binding:"required,max=255"`
	ConfigType  string          `json:"config_type" binding:"required,max=50"`
	ConfigValue json.RawMessage `json:"config_value" binding:"required"`
	Description string          `json:"description" binding:"omitempty,max=500"`
}

type ProjectConfigResponse struct {
	ConfigName  string          `json:"config_name"`
	ConfigType  string          `json:"config_type"`
	ConfigValue json.RawMessage `json:"config_value"`
	Description string          `json:"description,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}
