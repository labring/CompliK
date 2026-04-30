package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"sealos-complik-admin/internal/infra/config"
)

const (
	pingTimeout = 5 * time.Second
)

var client *gorm.DB

// Init initializes the shared MySQL connection and verifies it is reachable.
func Init(cfg config.DatabaseConfig) (*gorm.DB, error) {
	if client != nil {
		return client, nil
	}
	// varify config before trying to connect to avoid unnecessary connection attempts with invalid config
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	// Create database if it does not exist
	if err := createDatabase(cfg); err != nil {
		return nil, err
	}

	// Open connection to the newly created database and verify it is reachable
	db, err := open(DSN(cfg))
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}

	client = db
	return client, nil
}

// createDatabase creates the configured database if it does not already exist.
func createDatabase(cfg config.DatabaseConfig) error {
	db, err := open(serverDSN(cfg))
	if err != nil {
		return fmt.Errorf("connect mysql server: %w", err)
	}
	defer closeDB(db)

	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	query := fmt.Sprintf(
		"CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
		quoteIdentifier(cfg.Name),
	)
	if err := db.WithContext(ctx).Exec(query).Error; err != nil {
		return fmt.Errorf("create database %q: %w", cfg.Name, err)
	}

	return nil
}

// Get returns the initialized shared database connection.
func Get() *gorm.DB {
	return client
}

// Close closes the shared database connection if it has been initialized.
func Close() error {
	if client == nil {
		return nil
	}

	db := client
	client = nil

	if err := closeDB(db); err != nil {
		return fmt.Errorf("close database: %w", err)
	}

	return nil
}

// CloseWithReport closes the shared connection and reports any error through logf.
func CloseWithReport(logf func(string, ...any)) {
	if err := Close(); err != nil && logf != nil {
		logf("%v", err)
	}
}

// DSN builds the MySQL data source name from application config.
func DSN(cfg config.DatabaseConfig) string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Name,
	)
}

// serverDSN builds a MySQL data source name without selecting a database first.
func serverDSN(cfg config.DatabaseConfig) string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
	)
}

// validateConfig checks the minimum fields required to build a valid MySQL DSN.
func validateConfig(cfg config.DatabaseConfig) error {
	if cfg.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("database port %d is invalid", cfg.Port)
	}
	if cfg.Username == "" {
		return fmt.Errorf("database username is required")
	}
	if cfg.Name == "" {
		return fmt.Errorf("database name is required")
	}

	return nil
}

func open(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open gorm connection: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql db: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ping mysql: %w", err)
	}

	return db, nil
}

func closeDB(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("get sql db: %w", err)
	}

	return sqlDB.Close()
}

func quoteIdentifier(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}
