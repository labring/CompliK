// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package postages implements a database handle plugin for storing detection results.
// It supports MySQL/PostgreSQL databases and provides automatic schema migration
// and event-driven result persistence.
package postages

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

const (
	pluginName = constants.HandleDatabasePostgres
	pluginType = constants.HandleDatabasePluginType
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &DatabasePlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type DatabasePlugin struct {
	log            logger.Logger
	db             *gorm.DB
	databaseConfig DatabaseConfig
}
type DatabaseConfig struct {
	Region             string `json:"region"`
	Host               string `json:"host"`
	Port               string `json:"port"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	DatabaseName       string `json:"databaseName"`
	TableName          string `json:"tableName"`
	Charset            string `json:"charset"`
	AdminBaseURL       string `json:"adminBaseURL"`
	AdminTimeoutSecond int    `json:"adminTimeoutSecond"`
}

func (p *DatabasePlugin) getDefaultConfig() DatabaseConfig {
	return DatabaseConfig{
		DatabaseName:       "complik",
		Charset:            "utf8mb4",
		TableName:          "detectorRecord",
		Region:             "UNKNOWN",
		AdminBaseURL:       defaultAdminBaseURL,
		AdminTimeoutSecond: int(defaultAdminTimeout / time.Second),
	}
}

func (p *DatabasePlugin) loadConfig(setting string) error {
	p.databaseConfig = p.getDefaultConfig()
	p.log.Debug("Loading database plugin configuration")

	if setting == "" {
		p.log.Error("Configuration cannot be empty")
		return errors.New("configuration cannot be empty")
	}

	var configFromJSON DatabaseConfig
	err := json.Unmarshal([]byte(setting), &configFromJSON)
	if err != nil {
		p.log.Error("Failed to parse configuration", logger.Fields{
			"error": err.Error(),
		})
		return err
	}
	if configFromJSON.Host == "" {
		return errors.New("host configuration cannot be empty")
	}
	if configFromJSON.Port == "" {
		return errors.New("port configuration cannot be empty")
	}
	if configFromJSON.Username == "" {
		return errors.New("username configuration cannot be empty")
	}
	if configFromJSON.Password == "" {
		return errors.New("password configuration cannot be empty")
	}

	p.databaseConfig.Host = configFromJSON.Host
	p.databaseConfig.Port = configFromJSON.Port
	p.databaseConfig.Username = configFromJSON.Username

	// Support secure password from environment variable or encryption
	if pwd, err := config.GetSecureValue(configFromJSON.Password); err == nil {
		p.databaseConfig.Password = pwd
		p.log.Debug("Using secure password from environment/encryption")
	} else {
		p.databaseConfig.Password = configFromJSON.Password
		p.log.Warn("Using plain text password - consider using environment variables")
	}

	p.databaseConfig.Region = configFromJSON.Region
	if configFromJSON.Region != "" {
		p.databaseConfig.Region = configFromJSON.Region
	}
	if configFromJSON.DatabaseName != "" {
		p.databaseConfig.DatabaseName = configFromJSON.DatabaseName
	}
	if configFromJSON.Charset != "" {
		p.databaseConfig.Charset = configFromJSON.Charset
	}
	if configFromJSON.TableName != "" {
		p.databaseConfig.TableName = configFromJSON.TableName
	}
	if configFromJSON.AdminBaseURL != "" {
		if adminBaseURL, err := config.GetSecureValue(configFromJSON.AdminBaseURL); err == nil {
			p.databaseConfig.AdminBaseURL = adminBaseURL
		} else {
			p.databaseConfig.AdminBaseURL = configFromJSON.AdminBaseURL
		}
	}
	if configFromJSON.AdminTimeoutSecond > 0 {
		p.databaseConfig.AdminTimeoutSecond = configFromJSON.AdminTimeoutSecond
	}

	p.log.Info("Database configuration loaded", logger.Fields{
		"host":      p.databaseConfig.Host,
		"port":      p.databaseConfig.Port,
		"database":  p.databaseConfig.DatabaseName,
		"table":     p.databaseConfig.TableName,
		"region":    p.databaseConfig.Region,
		"admin_url": p.databaseConfig.AdminBaseURL,
	})

	return nil
}

type DetectorRecord struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	DiscoveryName string    `gorm:"size:255"   json:"discovery_name"`
	CollectorName string    `gorm:"size:255"   json:"collector_name"`
	DetectorName  string    `gorm:"size:255"   json:"detector_name"`
	Name          string    `gorm:"size:255"   json:"name"`
	Namespace     string    `gorm:"size:255"   json:"namespace"`
	Host          string    `gorm:"size:255"   json:"host"`
	Path          *string   `gorm:"type:json"  json:"path"`
	URL           string    `gorm:"size:500"   json:"url"`
	IsIllegal     bool      `                  json:"is_illegal"`
	Description   string    `gorm:"type:text"  json:"description,omitempty"`
	Keywords      *string   `gorm:"type:json"  json:"keywords,omitempty"`
	CreatedAt     time.Time `                  json:"created_at"`
	UpdatedAt     time.Time `                  json:"updated_at"`
}

func (p *DatabasePlugin) Name() string { return pluginName }
func (p *DatabasePlugin) Type() string { return pluginType }

func (p *DatabasePlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	p.log.Info("Starting database plugin")

	err := p.loadConfig(config.Settings)
	if err != nil {
		p.log.Error("Failed to load configuration", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	p.log.Debug("Initializing database connection")
	if err := p.initDB(); err != nil {
		p.log.Error("Failed to initialize database", logger.Fields{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	p.log.Debug("Running database migration")
	if err := p.db.AutoMigrate(&DetectorRecord{}); err != nil {
		p.log.Error("Database migration failed", logger.Fields{
			"error": err.Error(),
			"table": p.databaseConfig.TableName,
		})
		return fmt.Errorf("database migration failed: %w", err)
	}

	p.log.Info("Database migration completed successfully")
	subscribe := eventBus.Subscribe(constants.DetectorTopic)
	p.log.Debug("Subscribed to detector topic", logger.Fields{
		"topic": constants.DetectorTopic,
	})

	p.log.Info("Database plugin started successfully")

	go func() {
		defer func() {
			if r := recover(); r != nil {
				p.log.Error("Database plugin panic", logger.Fields{
					"panic": fmt.Sprintf("%v", r),
				})
			}
		}()

		for {
			select {
			case event, ok := <-subscribe:
				if !ok {
					p.log.Info("Event subscription channel closed")
					return
				}

				result, ok := event.Payload.(*models.DetectorInfo)
				if !ok {
					p.log.Error("Invalid event payload type", logger.Fields{
						"expected": "*models.DetectorInfo",
						"actual":   fmt.Sprintf("%T", event.Payload),
					})
					continue
				}

				result.Region = p.databaseConfig.Region

				p.log.Debug("Saving detection result to database", logger.Fields{
					"host":       result.Host,
					"namespace":  result.Namespace,
					"is_illegal": result.IsIllegal,
				})

				if err := p.saveResults(result); err != nil {
					p.log.Error("Failed to save result to database", logger.Fields{
						"error":     err.Error(),
						"host":      result.Host,
						"namespace": result.Namespace,
					})
				} else {
					p.log.Debug("Result saved successfully", logger.Fields{
						"host": result.Host,
					})
					if result.IsIllegal {
						if err := p.reportViolation(result); err != nil {
							p.log.Error("Failed to report violation to admin", logger.Fields{
								"error":     err.Error(),
								"host":      result.Host,
								"namespace": result.Namespace,
							})
						} else {
							p.log.Debug("Violation reported to admin successfully", logger.Fields{
								"host":      result.Host,
								"namespace": result.Namespace,
							})
						}
					}
				}
			case <-ctx.Done():
				p.log.Info("Database plugin stopping")
				return
			}
		}
	}()

	return nil
}

func (p *DatabasePlugin) Stop(ctx context.Context) error {
	p.log.Info("Stopping database plugin")

	if p.db != nil {
		sqlDB, err := p.db.DB()
		if err != nil {
			p.log.Error("Failed to get database connection", logger.Fields{
				"error": err.Error(),
			})
			return fmt.Errorf("failed to get database connection: %w", err)
		}

		if err := sqlDB.Close(); err != nil {
			p.log.Error("Failed to close database connection", logger.Fields{
				"error": err.Error(),
			})
			return err
		}

		p.log.Debug("Database connection closed")
	}

	return nil
}

func (p *DatabasePlugin) initDB() error {
	p.log.Debug("Initializing database", logger.Fields{
		"host":     p.databaseConfig.Host,
		"port":     p.databaseConfig.Port,
		"database": p.databaseConfig.DatabaseName,
	})
	serverDSN := p.buildDSN(false)
	dbConfig := &gorm.Config{
		Logger: gormLogger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			gormLogger.Config{
				SlowThreshold: 3 * time.Second,
				LogLevel:      gormLogger.Error,
				Colorful:      false,
			},
		),
	}
	db, err := gorm.Open(mysql.Open(serverDSN), dbConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to MySQL server: %w", err)
	}
	err = db.Exec(
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s CHARACTER SET %s COLLATE %s_unicode_ci",
			p.databaseConfig.DatabaseName,
			p.databaseConfig.Charset,
			p.databaseConfig.Charset),
	).Error
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	dbDSN := p.buildDSN(true)
	db, err = gorm.Open(mysql.Open(dbDSN), dbConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	p.db = db

	p.log.Info("Database initialized successfully", logger.Fields{
		"database": p.databaseConfig.DatabaseName,
	})

	return nil
}

func (p *DatabasePlugin) buildDSN(includeDB bool) string {
	dbPart := "/"
	if includeDB {
		dbPart = "/" + p.databaseConfig.DatabaseName
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%s)%s?charset=%s&parseTime=True&loc=Local",
		p.databaseConfig.Username,
		p.databaseConfig.Password,
		p.databaseConfig.Host,
		p.databaseConfig.Port,
		dbPart,
		p.databaseConfig.Charset,
	)
}

func (p *DatabasePlugin) saveResults(result *models.DetectorInfo) error {
	if p == nil {
		p.log.Error("DatabasePlugin instance is nil")
		return errors.New("DatabasePlugin instance is nil")
	}
	if p.db == nil {
		p.log.Error("Database connection not initialized")
		return errors.New("database connection not initialized")
	}
	if result == nil {
		p.log.Error("Detection result is nil")
		return errors.New("detection result is nil")
	}
	record := DetectorRecord{
		DiscoveryName: result.DiscoveryName,
		CollectorName: result.CollectorName,
		DetectorName:  result.DetectorName,
		Name:          result.Name,
		Namespace:     result.Namespace,
		Host:          result.Host,
		URL:           result.URL,
		IsIllegal:     result.IsIllegal,
		Description:   result.Description,
	}
	if len(result.Path) > 0 {
		if pathJSON, err := json.Marshal(result.Path); err == nil {
			pathStr := string(pathJSON)
			record.Path = &pathStr
		}
	}
	if len(result.Keywords) > 0 {
		if keywordsJSON, err := json.Marshal(result.Keywords); err == nil {
			keywordsStr := string(keywordsJSON)
			record.Keywords = &keywordsStr
		}
	}
	if err := p.db.Create(&record).Error; err != nil {
		p.log.Error("Failed to insert record", logger.Fields{
			"error":     err.Error(),
			"host":      record.Host,
			"namespace": record.Namespace,
		})
		return err
	}

	p.log.Debug("Record saved successfully", logger.Fields{
		"host":       record.Host,
		"namespace":  record.Namespace,
		"is_illegal": record.IsIllegal,
	})

	return nil
}
