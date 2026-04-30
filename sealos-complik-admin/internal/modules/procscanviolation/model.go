package procscanviolation

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

type ProcscanViolationEvent struct {
	ID                uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Namespace         string    `gorm:"size:255;not null;index:idx_procscan_namespace_time,priority:1" json:"namespace"`
	PodName           string    `gorm:"size:255;index:idx_procscan_pod_time,priority:1" json:"pod_name,omitempty"`
	ContainerID       string    `gorm:"size:128;index:idx_procscan_container_time,priority:1" json:"container_id,omitempty"`
	NodeName          string    `gorm:"size:128;index:idx_procscan_node_time,priority:1" json:"node_name,omitempty"`
	PID               int       `gorm:"not null" json:"pid"`
	ProcessName       string    `gorm:"size:255;not null;index:idx_procscan_process_time,priority:1" json:"process_name"`
	ProcessCommand    string    `gorm:"type:text;not null" json:"process_command"`
	MatchType         string    `gorm:"size:32" json:"match_type,omitempty"`
	MatchRule         string    `gorm:"size:255" json:"match_rule,omitempty"`
	Message           string    `gorm:"type:text;not null" json:"message"`
	IsIllegal         bool      `gorm:"not null" json:"is_illegal"`
	LabelActionStatus string    `gorm:"size:32" json:"label_action_status,omitempty"`
	LabelActionResult string    `gorm:"type:text" json:"label_action_result,omitempty"`
	DetectedAt        time.Time `gorm:"not null;index:idx_procscan_namespace_time,priority:2;index:idx_procscan_pod_time,priority:2;index:idx_procscan_process_time,priority:2;index:idx_procscan_container_time,priority:2;index:idx_procscan_node_time,priority:2" json:"detected_at"`
	RawPayload        *string   `gorm:"type:json" json:"raw_payload,omitempty"`
	CreatedAt         time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt         time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (ProcscanViolationEvent) TableName() string {
	return "procscan_violation_events"
}

func AutoMigrate(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("procscan violation automigrate: database is nil")
	}

	if err := db.AutoMigrate(&ProcscanViolationEvent{}); err != nil {
		return fmt.Errorf("procscan violation automigrate: %w", err)
	}

	return nil
}
