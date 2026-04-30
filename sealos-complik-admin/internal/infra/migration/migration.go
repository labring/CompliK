package migration

import (
	"fmt"

	"sealos-complik-admin/internal/modules/ban"
	"sealos-complik-admin/internal/modules/commitment"
	"sealos-complik-admin/internal/modules/complikviolation"
	"sealos-complik-admin/internal/modules/procscanviolation"
	"sealos-complik-admin/internal/modules/projectconfig"
	"sealos-complik-admin/internal/modules/unban"

	"gorm.io/gorm"
)

// AutoMigrate runs all module migrations in one place.
func AutoMigrate(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migration automigrate: database is nil")
	}

	migrations := []struct {
		name string
		run  func(*gorm.DB) error
	}{
		{name: "project config", run: projectconfig.AutoMigrate},
		{name: "commitment", run: commitment.AutoMigrate},
		{name: "complik violation", run: complikviolation.AutoMigrate},
		{name: "procscan violation", run: procscanviolation.AutoMigrate},
		{name: "ban", run: ban.AutoMigrate},
		{name: "unban", run: unban.AutoMigrate},
	}

	for _, migration := range migrations {
		if err := migration.run(db); err != nil {
			return fmt.Errorf("auto migrate %s: %w", migration.name, err)
		}
	}

	return nil
}
