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

// Package lark implements a notification plugin for Lark (Feishu) messaging platform.
// It provides webhook-based notifications for detection results with optional
// whitelist support to filter notifications based on namespace or host.
package lark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
	"github.com/bearslyricattack/CompliK/complik/plugins/handle/lark/whitelist"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

const (
	pluginName = constants.HandleLark
	pluginType = constants.HandleLarkPluginType
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &LarkPlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type LarkPlugin struct {
	log        logger.Logger
	notifier   *Notifier
	larkConfig LarkConfig
}

func (p *LarkPlugin) Name() string {
	return pluginName
}

func (p *LarkPlugin) Type() string {
	return pluginType
}

type LarkConfig struct {
	Region             string `json:"region"`
	Webhook            string `json:"webhook"`
	EnabledWhitelist   *bool  `json:"enabled_whitelist"`
	Host               string `json:"host"`
	Port               string `json:"port"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	DatabaseName       string `json:"databaseName"`
	TableName          string `json:"tableName"`
	Charset            string `json:"charset"`
	HostTimeoutHour    int    `json:"host_timeout_hour"`
	AdminBaseURL       string `json:"adminBaseURL"`
	AdminTimeoutSecond int    `json:"adminTimeoutSecond"`
}

func (p *LarkPlugin) getDefaultConfig() LarkConfig {
	b := false

	return LarkConfig{
		Region:             "UNKNOWN",
		EnabledWhitelist:   &b,
		DatabaseName:       "complik",
		TableName:          "whitelist",
		Charset:            "utf8mb4",
		AdminBaseURL:       config.DefaultAdminBaseURL,
		AdminTimeoutSecond: config.DefaultAdminTimeoutSecond,
	}
}

func (p *LarkPlugin) loadConfig(setting string) error {
	p.larkConfig = p.getDefaultConfig()

	if strings.TrimSpace(setting) == "" {
		return errors.New("configuration cannot be empty")
	}

	var configFromJSON LarkConfig

	err := json.Unmarshal([]byte(setting), &configFromJSON)
	if err != nil {
		p.log.Error("Failed to parse config", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if configFromJSON.EnabledWhitelist != nil && *configFromJSON.EnabledWhitelist {
		p.larkConfig.EnabledWhitelist = configFromJSON.EnabledWhitelist
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

		p.larkConfig.Host = configFromJSON.Host
		p.larkConfig.Port = configFromJSON.Port
		p.larkConfig.Username = configFromJSON.Username
		// Support retrieving password from environment variable or encrypted value
		if pwd, err := config.GetSecureValue(configFromJSON.Password); err == nil {
			p.larkConfig.Password = pwd
		} else {
			p.larkConfig.Password = configFromJSON.Password
		}
	}

	if configFromJSON.HostTimeoutHour > 0 {
		p.larkConfig.HostTimeoutHour = configFromJSON.HostTimeoutHour
	}

	if configFromJSON.DatabaseName != "" {
		p.larkConfig.DatabaseName = configFromJSON.DatabaseName
	}

	if configFromJSON.TableName != "" {
		p.larkConfig.TableName = configFromJSON.TableName
	}

	if configFromJSON.Charset != "" {
		p.larkConfig.Charset = configFromJSON.Charset
	}

	p.larkConfig.Webhook = configFromJSON.Webhook
	if configFromJSON.Region != "" {
		p.larkConfig.Region = configFromJSON.Region
	}
	if strings.TrimSpace(configFromJSON.AdminBaseURL) != "" {
		if secureValue, err := config.GetSecureValue(configFromJSON.AdminBaseURL); err == nil {
			p.larkConfig.AdminBaseURL = secureValue
		} else {
			p.larkConfig.AdminBaseURL = configFromJSON.AdminBaseURL
		}
	}
	if configFromJSON.AdminTimeoutSecond > 0 {
		p.larkConfig.AdminTimeoutSecond = configFromJSON.AdminTimeoutSecond
	}
	if err := p.applyNotificationsRuntimeConfig(context.Background()); err != nil {
		return fmt.Errorf("failed to apply notifications runtime config from admin: %w", err)
	}
	if strings.TrimSpace(p.larkConfig.Webhook) == "" {
		return errors.New("complik_notifications_runtime config missing webhook")
	}

	return nil
}

func (p *LarkPlugin) applyNotificationsRuntimeConfig(ctx context.Context) error {
	runtimeCfg, err := config.LoadNotificationsRuntimeConfig(
		ctx,
		p.larkConfig.AdminBaseURL,
		p.larkConfig.AdminTimeoutSecond,
	)
	if err != nil {
		return err
	}
	if runtimeCfg == nil {
		return errors.New("complik_notifications_runtime config not found in admin")
	}
	webhook := strings.TrimSpace(runtimeCfg.Webhook)
	if webhook == "" {
		return errors.New("complik_notifications_runtime config missing webhook")
	}
	p.larkConfig.Webhook = webhook
	return nil
}

func (p *LarkPlugin) initDB() (db *gorm.DB, err error) {
	serverDSN := p.buildDSN(false)
	dbConfig := &gorm.Config{
		Logger: gormLogger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			gormLogger.Config{
				SlowThreshold: 3 * time.Second,  // Slow query threshold set to 3 seconds
				LogLevel:      gormLogger.Error, // Show only error logs
				Colorful:      false,            // Disable color output
			},
		),
	}

	db, err = gorm.Open(mysql.Open(serverDSN), dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MySQL server: %w", err)
	}

	createDBSQL := fmt.Sprintf(
		"CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET %s COLLATE %s_unicode_ci",
		p.larkConfig.DatabaseName,
		p.larkConfig.Charset,
		p.larkConfig.Charset,
	)

	err = db.Exec(createDBSQL).Error
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	dbDSN := p.buildDSN(true)

	db, err = gorm.Open(mysql.Open(dbDSN), dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}

func (p *LarkPlugin) buildDSN(includeDB bool) string {
	dbPart := "/"
	if includeDB {
		dbPart = "/" + p.larkConfig.DatabaseName
	}

	return fmt.Sprintf("%s:%s@tcp(%s:%s)%s?charset=%s&parseTime=True&loc=Local",
		p.larkConfig.Username,
		p.larkConfig.Password,
		p.larkConfig.Host,
		p.larkConfig.Port,
		dbPart,
		p.larkConfig.Charset,
	)
}

func (p *LarkPlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	err := p.loadConfig(config.Settings)
	if err != nil {
		return err
	}

	if *p.larkConfig.EnabledWhitelist {
		var db *gorm.DB
		if db, err = p.initDB(); err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}

		if err := db.AutoMigrate(&whitelist.Whitelist{}); err != nil {
			return fmt.Errorf("database migration failed: %w", err)
		}

		p.notifier = NewNotifier(
			p.larkConfig.Webhook,
			db,
			time.Duration(p.larkConfig.HostTimeoutHour)*time.Hour,
			p.larkConfig.Region,
		)

		var count int64
		db.Model(&whitelist.Whitelist{}).Count(&count)

		if count == 0 {
			testData := &whitelist.Whitelist{
				Region:    "cn-beijing",
				Name:      "Test Whitelist Item",
				Namespace: "default",
				Hostname:  "test.example.com",
				Type:      "namespace",
				Remark:    "This is a test data entry initialized to verify whitelist functionality",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			if err := db.Create(testData).Error; err != nil {
				p.log.Error("Failed to insert test data", logger.Fields{
					"error": err.Error(),
				})
			} else {
				p.log.Info("Test data inserted successfully")
			}
		}
	} else {
		p.notifier = NewNotifier(p.larkConfig.Webhook, nil, 0, p.larkConfig.Region)
	}

	subscribe := eventBus.Subscribe(constants.DetectorTopic)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				p.log.Error("Plugin goroutine panic", logger.Fields{
					"panic": r,
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

				result.Region = p.larkConfig.Region

				err := p.notifier.SendAnalysisNotification(result)
				if err != nil {
					p.log.Error("Failed to send notification", logger.Fields{
						"error": err.Error(),
					})
				}
			case <-ctx.Done():
				p.log.Info("Plugin received stop signal")
				return
			}
		}
	}()

	return nil
}

func (p *LarkPlugin) Stop(ctx context.Context) error {
	return nil
}
