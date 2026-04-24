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

// Package custom provides a compliance detector plugin that uses custom keyword rules
// stored in a MySQL database to detect potentially illegal or non-compliant content.
// The plugin periodically refreshes keyword rules from the database and uses an AI-powered
// content reviewer to analyze collected website content against these rules.
package custom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
	"github.com/bearslyricattack/CompliK/complik/plugins/compliance/detector/utils"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

const (
	pluginName = constants.ComplianceDetectorCustom
	pluginType = constants.ComplianceDetectorPluginType
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &CustomPlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type CustomPlugin struct {
	log          logger.Logger
	reviewer     *utils.ContentReviewer
	db           *gorm.DB
	keywords     []utils.CustomKeywordRule
	customConfig CustomConfig
}

func (p *CustomPlugin) Name() string {
	return pluginName
}

func (p *CustomPlugin) Type() string {
	return pluginType
}

type CustomConfig struct {
	Dsn          string `json:"dsn"`
	DatabaseName string `json:"databaseName"`
	TickerMinute int    `json:"tickerMinute"`
	MaxWorkers   int    `json:"maxWorkers"`
	Host         string `json:"host"`
	Port         string `json:"port"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Charset      string `json:"charset"`
	TableName    string `json:"tableName"`
	APIKey       string `json:"apiKey"`
	APIBase      string `json:"apiBase"`
	APIPath      string `json:"apiPath"`
	Model        string `json:"model"`
}

func (p *CustomPlugin) getDefaultConfig() CustomConfig {
	return CustomConfig{
		DatabaseName: "custom",
		Charset:      "utf8mb4",
		TickerMinute: 600,
		MaxWorkers:   20,
		TableName:    "CustomKeywordRule",
		Model:        "gpt-5",
		APIBase:      "https://aiproxy.usw.sealos.io/v1",
		APIPath:      "/chat/completions",
	}
}

func (p *CustomPlugin) loadConfig(setting string) error {
	p.customConfig = p.getDefaultConfig()
	p.log.Debug("Loading custom detector configuration")

	if setting == "" {
		p.log.Error("Configuration cannot be empty")
		return errors.New("configuration cannot be empty")
	}

	var configFromJSON CustomConfig

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

	if configFromJSON.APIKey == "" {
		return errors.New("APIKey configuration cannot be empty")
	}

	p.customConfig.Host = configFromJSON.Host
	p.customConfig.Port = configFromJSON.Port
	p.customConfig.Username = configFromJSON.Username

	// Support secure password from environment variable or encryption
	if pwd, err := config.GetSecureValue(configFromJSON.Password); err == nil {
		p.customConfig.Password = pwd
		p.log.Debug("Using secure password from environment/encryption")
	} else {
		p.customConfig.Password = configFromJSON.Password
		p.log.Warn("Using plain text password - consider using environment variables")
	}

	// Support secure API key from environment variable or encryption
	if apiKey, err := config.GetSecureValue(configFromJSON.APIKey); err == nil {
		p.customConfig.APIKey = apiKey
		p.log.Debug("Using secure API key from environment/encryption")
	} else {
		p.customConfig.APIKey = configFromJSON.APIKey
		p.log.Warn("Using plain text API key - consider using environment variables")
	}

	if configFromJSON.APIPath != "" {
		p.customConfig.APIPath = configFromJSON.APIPath
	}

	if configFromJSON.APIBase != "" {
		p.customConfig.APIBase = configFromJSON.APIBase
	}

	if configFromJSON.Dsn != "" {
		p.customConfig.Dsn = configFromJSON.Dsn
	}

	if configFromJSON.DatabaseName != "" {
		p.customConfig.DatabaseName = configFromJSON.DatabaseName
	}

	if configFromJSON.TickerMinute > 0 {
		p.customConfig.TickerMinute = configFromJSON.TickerMinute
	}

	if configFromJSON.MaxWorkers > 0 {
		p.customConfig.MaxWorkers = configFromJSON.MaxWorkers
	}

	if configFromJSON.Charset != "" {
		p.customConfig.Charset = configFromJSON.Charset
	}

	if configFromJSON.TableName != "" {
		p.customConfig.TableName = configFromJSON.TableName
	}

	if configFromJSON.Model != "" {
		p.customConfig.Model = configFromJSON.Model
	}

	p.log.Info("Custom detector configuration loaded", logger.Fields{
		"database":       p.customConfig.DatabaseName,
		"table":          p.customConfig.TableName,
		"api_base":       p.customConfig.APIBase,
		"model":          p.customConfig.Model,
		"max_workers":    p.customConfig.MaxWorkers,
		"ticker_minutes": p.customConfig.TickerMinute,
	})

	return nil
}

func (p *CustomPlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	p.log.Info("Starting custom detector plugin")

	err := p.loadConfig(config.Settings)
	if err != nil {
		p.log.Error("Failed to load configuration", logger.Fields{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	p.log.Debug("Initializing database connection")

	if err := p.initDB(); err != nil {
		p.log.Error("Failed to initialize database", logger.Fields{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	p.reviewer = utils.NewContentReviewer(
		p.log,
		p.customConfig.APIKey,
		p.customConfig.APIBase,
		p.customConfig.APIPath,
		p.customConfig.Model,
	)
	p.log.Debug("Content reviewer initialized")

	err = p.readFromDatabase(ctx)
	if err != nil {
		p.log.Error("Failed to read keywords from database", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	p.log.Info("Keywords loaded from database", logger.Fields{
		"keyword_count": len(p.keywords),
	})

	subscribe := eventBus.Subscribe(constants.CollectorTopic)
	p.log.Debug("Subscribed to collector topic", logger.Fields{
		"topic": constants.CollectorTopic,
	})
	semaphore := make(chan struct{}, p.customConfig.MaxWorkers)

	ticker := time.NewTicker(time.Duration(p.customConfig.TickerMinute) * time.Minute)
	defer ticker.Stop()

	p.log.Info("Custom detector started", logger.Fields{
		"worker_pool_size":         p.customConfig.MaxWorkers,
		"refresh_interval_minutes": p.customConfig.TickerMinute,
	})

	for {
		select {
		case event, ok := <-subscribe:
			if !ok {
				p.log.Info("Event subscription channel closed")
				return nil
			}

			semaphore <- struct{}{}

			go func(e eventbus.Event) {
				defer func() { <-semaphore }()
				defer func() {
					if r := recover(); r != nil {
						p.log.Error("Goroutine panic in custom detector", logger.Fields{
							"panic":       r,
							"stack_trace": string(debug.Stack()),
						})
					}
				}()

				res, ok := e.Payload.(*models.CollectorInfo)
				if !ok {
					p.log.Error("Invalid event payload type", logger.Fields{
						"expected": "*models.CollectorInfo",
						"actual":   fmt.Sprintf("%T", e.Payload),
					})

					return
				}

				p.log.Debug("Processing custom detection", logger.Fields{
					"namespace":     res.Namespace,
					"name":          res.Name,
					"host":          res.Host,
					"keyword_rules": len(p.keywords),
				})

				startTime := time.Now()
				result, err := p.customJudge(ctx, res)
				duration := time.Since(startTime)

				if err != nil {
					p.log.Error("Custom judgement failed", logger.Fields{
						"host":        result.Host,
						"namespace":   result.Namespace,
						"error":       err.Error(),
						"duration_ms": duration.Milliseconds(),
					})
				} else {
					p.log.Debug("Custom detection completed", logger.Fields{
						"host":        result.Host,
						"is_illegal":  result.IsIllegal,
						"duration_ms": duration.Milliseconds(),
					})
				}

				eventBus.Publish(constants.DetectorTopic, eventbus.Event{
					Payload: result,
				})
			}(event)
		case <-ticker.C:
			go func() {
				defer func() {
					if r := recover(); r != nil {
						p.log.Error("Panic in scheduled database read", logger.Fields{
							"panic": r,
						})
					}
				}()

				p.log.Debug("Scheduled database read triggered")

				err := p.readFromDatabase(ctx)
				if err != nil {
					p.log.Error("Failed to read keywords from database", logger.Fields{
						"error": err.Error(),
					})
					return
				}

				p.log.Info("Keywords refreshed from database", logger.Fields{
					"keyword_count": len(p.keywords),
				})
			}()
		case <-ctx.Done():
			p.log.Info("Shutting down custom detector plugin")
			// Wait for all workers to finish
			for range p.customConfig.MaxWorkers {
				semaphore <- struct{}{}
			}

			p.log.Debug("All workers finished")

			return nil
		}
	}
}

func (p *CustomPlugin) Stop(ctx context.Context) error {
	p.log.Info("Stopping custom detector plugin")

	if p.db != nil {
		sqlDB, err := p.db.DB()
		if err == nil {
			sqlDB.Close()
			p.log.Debug("Database connection closed")
		}
	}

	return nil
}

func (p *CustomPlugin) initDB() error {
	p.log.Debug("Initializing database", logger.Fields{
		"host":     p.customConfig.Host,
		"port":     p.customConfig.Port,
		"database": p.customConfig.DatabaseName,
	})
	serverDSN := p.buildDSN(false)
	dbConfig := &gorm.Config{
		Logger: gormLogger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			gormLogger.Config{
				SlowThreshold: 3 * time.Second,  // Slow query threshold set to 3 seconds
				LogLevel:      gormLogger.Error, // Show error logs only
				Colorful:      false,            // Disable color output
			},
		),
	}

	db, err := gorm.Open(mysql.Open(serverDSN), dbConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to MySQL server: %w", err)
	}

	err = db.Exec(
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s CHARACTER SET %s COLLATE %s_unicode_ci",
			p.customConfig.DatabaseName,
			p.customConfig.Charset,
			p.customConfig.Charset),
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
	tableName := db.NamingStrategy.TableName("CustomKeywordRule")

	err = db.AutoMigrate(&utils.CustomKeywordRule{})
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	var tableExists bool

	err = db.Raw("SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = ? AND table_name = ?",
		p.customConfig.TableName, tableName).
		Scan(&tableExists).
		Error
	if err != nil {
		p.log.Warn("Failed to check table existence", logger.Fields{
			"error": err.Error(),
			"table": tableName,
		})
	}

	var count int64

	err = db.Model(&utils.CustomKeywordRule{}).Count(&count).Error
	if err != nil {
		return fmt.Errorf("failed to query data count: %w", err)
	}

	if count == 0 {
		sampleRule := utils.CustomKeywordRule{
			Type:        "malware",
			Keywords:    strings.Join([]string{"virus", "trojan", "malware", "backdoor"}, ","),
			Description: "Malware detection rule",
		}

		err = db.Create(&sampleRule).Error
		if err != nil {
			return fmt.Errorf("failed to insert sample data: %w", err)
		}

		var newCount int64
		db.Model(&utils.CustomKeywordRule{}).Count(&newCount)

		p.log.Info("Sample rule inserted", logger.Fields{
			"rule_type":   "malware",
			"total_rules": newCount,
		})
	}

	p.log.Info("Database initialized successfully", logger.Fields{
		"database":   p.customConfig.DatabaseName,
		"table":      tableName,
		"rule_count": count,
	})

	return nil
}

func (p *CustomPlugin) buildDSN(includeDB bool) string {
	if p.customConfig.Dsn != "" {
		return p.customConfig.Dsn
	}

	dbPart := "/"
	if includeDB {
		dbPart = "/" + p.customConfig.DatabaseName
	}

	return fmt.Sprintf("%s:%s@tcp(%s:%s)%s?charset=%s&parseTime=True&loc=Local",
		p.customConfig.Username,
		p.customConfig.Password,
		p.customConfig.Host,
		p.customConfig.Port,
		dbPart,
		p.customConfig.Charset,
	)
}

func (p *CustomPlugin) readFromDatabase(ctx context.Context) error {
	var models []utils.CustomKeywordRule

	p.log.Debug("Reading keyword rules from database")

	err := p.db.WithContext(ctx).Find(&models).Error
	if err != nil {
		p.log.Error("Failed to read keyword rules", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	oldCount := len(p.keywords)
	p.keywords = models

	p.log.Debug("Keyword rules updated", logger.Fields{
		"old_count": oldCount,
		"new_count": len(models),
	})

	return nil
}

func (p *CustomPlugin) customJudge(
	ctx context.Context,
	collector *models.CollectorInfo,
) (res *models.DetectorInfo, err error) {
	taskCtx, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()

	p.log.Debug("Starting custom judgement", logger.Fields{
		"url":           collector.URL,
		"is_empty":      collector.IsEmpty,
		"keyword_rules": len(p.keywords),
	})

	if collector.IsEmpty {
		p.log.Debug("Skipping empty content", logger.Fields{
			"host": collector.Host,
		})

		return &models.DetectorInfo{
			DiscoveryName: collector.DiscoveryName,
			CollectorName: collector.CollectorName,
			DetectorName:  p.Name(),
			Name:          collector.Name,
			Namespace:     collector.Namespace,
			Host:          collector.Host,
			Path:          collector.Path,
			URL:           collector.URL,
			IsIllegal:     false,
			Description:   collector.CollectorMessage,
			Keywords:      []string{},
		}, nil
	}

	result, err := p.reviewer.ReviewSiteContent(taskCtx, collector, p.Name(), p.keywords)
	if err != nil {
		return &models.DetectorInfo{
			DiscoveryName: collector.DiscoveryName,
			CollectorName: collector.CollectorName,
			DetectorName:  p.Name(),
			Name:          collector.Name,
			Namespace:     collector.Namespace,
			Host:          collector.Host,
			Path:          collector.Path,
			URL:           collector.URL,
			IsIllegal:     false,
			Description:   "",
			Keywords:      []string{},
		}, err
	} else {
		return result, nil
	}
}
