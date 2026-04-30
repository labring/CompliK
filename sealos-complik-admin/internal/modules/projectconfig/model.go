package projectconfig

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type ProjectConfig struct {
	// ID remains the internal primary key for joins and stable references.
	ID          uint64          `gorm:"primaryKey;autoIncrement" json:"id"`
	ConfigName  string          `gorm:"size:255;not null;uniqueIndex" json:"config_name"`
	ConfigType  string          `gorm:"size:50;not null" json:"config_type"`
	ConfigValue json.RawMessage `gorm:"type:json;not null" json:"config_value"`
	Description string          `gorm:"size:500" json:"description,omitempty"`
	CreatedAt   time.Time       `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time       `gorm:"autoUpdateTime" json:"updated_at"`
}

// AutoMigrate creates or updates the project_configs table schema.
func AutoMigrate(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("projectconfig automigrate: database is nil")
	}

	if err := db.AutoMigrate(&ProjectConfig{}); err != nil {
		return fmt.Errorf("projectconfig automigrate: %w", err)
	}

	return nil
}
