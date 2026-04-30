package complikviolation

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

type ComplikViolationEvent struct {
	ID            uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Namespace     string    `gorm:"size:255;not null;index:idx_complik_namespace_time,priority:1;index:idx_complik_namespace_status_time,priority:1" json:"namespace"`
	Region        string    `gorm:"size:64" json:"region,omitempty"`
	DiscoveryName string    `gorm:"size:255" json:"discovery_name,omitempty"`
	CollectorName string    `gorm:"size:255" json:"collector_name,omitempty"`
	DetectorName  string    `gorm:"size:64;not null;index:idx_complik_detector_time,priority:1" json:"detector_name"`
	ResourceName  string    `gorm:"size:255" json:"resource_name,omitempty"`
	Host          string    `gorm:"size:255;index:idx_complik_host_time,priority:1" json:"host,omitempty"`
	URL           string    `gorm:"size:1024" json:"url,omitempty"`
	Path          *string   `gorm:"type:json" json:"path,omitempty"`
	Keywords      *string   `gorm:"type:json" json:"keywords,omitempty"`
	Description   string    `gorm:"type:text" json:"description,omitempty"`
	Explanation   string    `gorm:"type:text" json:"explanation,omitempty"`
	IsIllegal     bool      `gorm:"not null" json:"is_illegal"`
	IsTest        bool      `gorm:"not null;default:false" json:"is_test"`
	Status        string    `gorm:"size:32;not null;default:open;index:idx_complik_namespace_status_time,priority:2" json:"status"`
	DetectedAt    time.Time `gorm:"not null;index:idx_complik_namespace_time,priority:2;index:idx_complik_namespace_status_time,priority:3;index:idx_complik_detector_time,priority:2;index:idx_complik_host_time,priority:2" json:"detected_at"`
	RawPayload    *string   `gorm:"type:json" json:"raw_payload,omitempty"`
	CreatedAt     time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt     time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (ComplikViolationEvent) TableName() string {
	return "complik_violation_events"
}

func AutoMigrate(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("complik violation automigrate: database is nil")
	}

	if err := db.AutoMigrate(&ComplikViolationEvent{}); err != nil {
		return fmt.Errorf("complik violation automigrate: %w", err)
	}

	return nil
}
