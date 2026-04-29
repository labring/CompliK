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
package lark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
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
	Region                 string `json:"region"`
	Webhook                string `json:"webhook"`
	AdminBaseURL           string `json:"adminBaseURL"`
	AdminTimeoutSecond     int    `json:"adminTimeoutSecond"`
	AdminBasicAuthUsername string `json:"adminBasicAuthUsername"`
	AdminBasicAuthPassword string `json:"adminBasicAuthPassword"`
}

func (p *LarkPlugin) getDefaultConfig() LarkConfig {
	return LarkConfig{
		Region:             "UNKNOWN",
		AdminBaseURL:       config.DefaultAdminBaseURL,
		AdminTimeoutSecond: config.DefaultAdminTimeoutSecond,
	}
}

func (p *LarkPlugin) loadConfig(ctx context.Context, setting string) error {
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
	p.applyAdminBasicAuthConfig(configFromJSON)
	if err := p.applyNotificationsRuntimeConfig(ctx); err != nil {
		return fmt.Errorf("failed to apply notifications runtime config from admin: %w", err)
	}
	if strings.TrimSpace(p.larkConfig.Webhook) == "" {
		return errors.New("complik_notifications_runtime config missing webhook")
	}

	return nil
}

func (p *LarkPlugin) applyAdminBasicAuthConfig(configFromJSON LarkConfig) {
	auth := config.ResolveAdminBasicAuth(
		configFromJSON.AdminBasicAuthUsername,
		configFromJSON.AdminBasicAuthPassword,
	)
	p.larkConfig.AdminBasicAuthUsername = auth.Username
	p.larkConfig.AdminBasicAuthPassword = auth.Password
}

func (p *LarkPlugin) adminBasicAuth() config.AdminBasicAuth {
	return config.AdminBasicAuth{
		Username: p.larkConfig.AdminBasicAuthUsername,
		Password: p.larkConfig.AdminBasicAuthPassword,
	}
}

func (p *LarkPlugin) applyNotificationsRuntimeConfig(ctx context.Context) error {
	runtimeCfg, err := config.LoadNotificationsRuntimeConfigWithAuth(
		ctx,
		p.larkConfig.AdminBaseURL,
		p.larkConfig.AdminTimeoutSecond,
		p.adminBasicAuth(),
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

func (p *LarkPlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	err := p.loadConfig(ctx, config.Settings)
	if err != nil {
		return err
	}

	p.notifier = NewNotifier(p.larkConfig.Webhook, p.larkConfig.Region)

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
