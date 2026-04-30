package unban

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

const legacyNamespaceColumn = "user" + "_id"

type Unban struct {
	// ID remains the internal primary key for joins and stable references.
	ID           uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Namespace    string    `gorm:"size:255;not null;index" json:"namespace"`
	OperatorName string    `gorm:"size:100;not null" json:"operator_name"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// AutoMigrate creates or updates the unbans table schema.
func AutoMigrate(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("unban automigrate: database is nil")
	}

	if db.Migrator().HasColumn(&Unban{}, legacyNamespaceColumn) && !db.Migrator().HasColumn(&Unban{}, "namespace") {
		if err := db.Migrator().RenameColumn(&Unban{}, legacyNamespaceColumn, "namespace"); err != nil {
			return fmt.Errorf("unban rename legacy namespace column: %w", err)
		}
	}

	if err := db.AutoMigrate(&Unban{}); err != nil {
		return fmt.Errorf("unban automigrate: %w", err)
	}

	return nil
}
