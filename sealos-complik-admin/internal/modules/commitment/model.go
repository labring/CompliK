package commitment

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

const legacyNamespaceColumn = "user" + "_id"

type Commitment struct {
	// ID remains the internal primary key for joins and stable references.
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Namespace string    `gorm:"size:255;not null;index" json:"namespace"`
	FileName  string    `gorm:"size:255;not null" json:"file_name"`
	FileURL   string    `gorm:"size:512;not null" json:"file_url"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// AutoMigrate creates or updates the commitments table schema.
func AutoMigrate(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("commitment automigrate: database is nil")
	}

	if db.Migrator().HasColumn(&Commitment{}, legacyNamespaceColumn) && !db.Migrator().HasColumn(&Commitment{}, "namespace") {
		if err := db.Migrator().RenameColumn(&Commitment{}, legacyNamespaceColumn, "namespace"); err != nil {
			return fmt.Errorf("commitment rename legacy namespace column: %w", err)
		}
	}

	if err := db.AutoMigrate(&Commitment{}); err != nil {
		return fmt.Errorf("commitment automigrate: %w", err)
	}

	return nil
}
