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

// Package safety provides a compliance detector plugin that performs safety and compliance
// checks on collected website content using AI-powered analysis. The plugin subscribes to
// collector events, analyzes content for potential violations, and publishes detection results.
package safety

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
	"github.com/bearslyricattack/CompliK/complik/plugins/compliance/detector/utils"
)

const (
	pluginName = constants.ComplianceDetectorSafety
	pluginType = constants.ComplianceDetectorPluginType
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &SafetyPlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type SafetyPlugin struct {
	log          logger.Logger
	reviewer     *utils.ContentReviewer
	safetyConfig SafetyConfig
	safetyPrompt string
}

func (p *SafetyPlugin) Name() string {
	return pluginName
}

func (p *SafetyPlugin) Type() string {
	return pluginType
}

type SafetyConfig struct {
	MaxWorkers             int    `json:"maxWorkers"`
	APIKey                 string `json:"apiKey"`
	APIBase                string `json:"apiBase"`
	APIPath                string `json:"apiPath"`
	Model                  string `json:"model"`
	AdminBaseURL           string `json:"adminBaseURL"`
	AdminTimeoutSecond     int    `json:"adminTimeoutSecond"`
	AdminBasicAuthUsername string `json:"adminBasicAuthUsername"`
	AdminBasicAuthPassword string `json:"adminBasicAuthPassword"`
}

func (p *SafetyPlugin) getDefaultConfig() SafetyConfig {
	return SafetyConfig{
		MaxWorkers:         20,
		AdminBaseURL:       config.DefaultAdminBaseURL,
		AdminTimeoutSecond: config.DefaultAdminTimeoutSecond,
	}
}

func (p *SafetyPlugin) loadConfig(ctx context.Context, setting string) error {
	p.safetyConfig = p.getDefaultConfig()
	p.log.Debug("Loading safety detector configuration")

	if setting == "" {
		p.log.Error("Configuration cannot be empty")
		return errors.New("configuration cannot be empty")
	}

	var safetyConfig SafetyConfig

	err := json.Unmarshal([]byte(setting), &safetyConfig)
	if err != nil {
		p.log.Error("Failed to parse configuration", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if safetyConfig.MaxWorkers > 0 {
		p.safetyConfig.MaxWorkers = safetyConfig.MaxWorkers
	}
	if strings.TrimSpace(safetyConfig.AdminBaseURL) != "" {
		if secureValue, err := config.GetSecureValue(safetyConfig.AdminBaseURL); err == nil {
			p.safetyConfig.AdminBaseURL = secureValue
		} else {
			p.safetyConfig.AdminBaseURL = safetyConfig.AdminBaseURL
		}
	}
	if safetyConfig.AdminTimeoutSecond > 0 {
		p.safetyConfig.AdminTimeoutSecond = safetyConfig.AdminTimeoutSecond
	}
	p.applyAdminBasicAuthConfig(safetyConfig)
	if err := p.applyModelRuntimeConfig(ctx); err != nil {
		return fmt.Errorf("failed to apply model runtime config from admin: %w", err)
	}
	if err := p.applySafetyPromptRules(ctx); err != nil {
		return fmt.Errorf("failed to apply safety prompt rules from admin: %w", err)
	}
	if strings.TrimSpace(p.safetyConfig.APIKey) == "" ||
		strings.TrimSpace(p.safetyConfig.APIBase) == "" ||
		strings.TrimSpace(p.safetyConfig.APIPath) == "" ||
		strings.TrimSpace(p.safetyConfig.Model) == "" {
		return errors.New("model_runtime config from admin is incomplete")
	}

	p.log.Info("Safety detector configuration loaded", logger.Fields{
		"api_base":    p.safetyConfig.APIBase,
		"api_path":    p.safetyConfig.APIPath,
		"model":       p.safetyConfig.Model,
		"max_workers": p.safetyConfig.MaxWorkers,
	})

	return nil
}

func (p *SafetyPlugin) applyAdminBasicAuthConfig(safetyConfig SafetyConfig) {
	auth := config.ResolveAdminBasicAuth(
		safetyConfig.AdminBasicAuthUsername,
		safetyConfig.AdminBasicAuthPassword,
	)
	p.safetyConfig.AdminBasicAuthUsername = auth.Username
	p.safetyConfig.AdminBasicAuthPassword = auth.Password
}

func (p *SafetyPlugin) adminBasicAuth() config.AdminBasicAuth {
	return config.AdminBasicAuth{
		Username: p.safetyConfig.AdminBasicAuthUsername,
		Password: p.safetyConfig.AdminBasicAuthPassword,
	}
}

func (p *SafetyPlugin) applyModelRuntimeConfig(ctx context.Context) error {
	modelCfg, err := config.LoadModelRuntimeConfigWithAuth(
		ctx,
		p.safetyConfig.AdminBaseURL,
		p.safetyConfig.AdminTimeoutSecond,
		p.adminBasicAuth(),
	)
	if err != nil {
		return err
	}
	if modelCfg == nil {
		return errors.New("model_runtime config not found in admin")
	}
	if strings.TrimSpace(modelCfg.APIKey) != "" {
		if secureValue, err := config.GetSecureValue(modelCfg.APIKey); err == nil {
			p.safetyConfig.APIKey = secureValue
		} else {
			p.safetyConfig.APIKey = modelCfg.APIKey
		}
	}
	if strings.TrimSpace(modelCfg.APIBase) != "" {
		p.safetyConfig.APIBase = strings.TrimSpace(modelCfg.APIBase)
	}
	if strings.TrimSpace(modelCfg.APIPath) != "" {
		p.safetyConfig.APIPath = strings.TrimSpace(modelCfg.APIPath)
	}
	if strings.TrimSpace(modelCfg.Model) != "" {
		p.safetyConfig.Model = strings.TrimSpace(modelCfg.Model)
	}
	return nil
}

func (p *SafetyPlugin) applySafetyPromptRules(ctx context.Context) error {
	cfgs, err := config.ListAdminProjectConfigsByTypeWithAuth(
		ctx,
		p.safetyConfig.AdminBaseURL,
		p.safetyConfig.AdminTimeoutSecond,
		"safety",
		p.adminBasicAuth(),
	)
	if err != nil {
		return err
	}
	if len(cfgs) == 0 {
		return errors.New("no safety rules found in admin configs")
	}

	type ruleItem struct {
		name    string
		content string
	}
	rules := make([]ruleItem, 0, len(cfgs))
	for _, cfg := range cfgs {
		var payload struct {
			Content string `json:"content"`
		}
		if err := cfg.DecodeValue(&payload); err != nil {
			p.log.Warn("Failed to decode safety rule config_value", logger.Fields{
				"config_name": cfg.ConfigName,
				"error":       err.Error(),
			})
			continue
		}
		content := strings.TrimSpace(payload.Content)
		if content == "" {
			p.log.Warn("Skip empty safety rule content", logger.Fields{
				"config_name": cfg.ConfigName,
			})
			continue
		}
		rules = append(rules, ruleItem{name: strings.TrimSpace(cfg.ConfigName), content: content})
	}
	if len(rules) == 0 {
		return errors.New("no valid safety rules found in admin configs")
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].name < rules[j].name
	})
	parts := make([]string, 0, len(rules))
	for _, rule := range rules {
		parts = append(parts, rule.content)
	}
	p.safetyPrompt = strings.Join(parts, "\n\n")
	p.log.Info("Applied safety rules from admin", logger.Fields{"rule_count": len(rules)})
	return nil
}

func (p *SafetyPlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	p.log.Info("Starting safety detector plugin")

	err := p.loadConfig(ctx, config.Settings)
	if err != nil {
		p.log.Error("Failed to load configuration", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	p.reviewer = utils.NewContentReviewer(
		p.log,
		p.safetyConfig.APIKey,
		p.safetyConfig.APIBase,
		p.safetyConfig.APIPath,
		p.safetyConfig.Model,
	)
	p.log.Debug("Content reviewer initialized")

	subscribe := eventBus.Subscribe(constants.CollectorTopic)
	p.log.Debug("Subscribed to collector topic", logger.Fields{
		"topic": constants.CollectorTopic,
	})

	semaphore := make(chan struct{}, p.safetyConfig.MaxWorkers)
	p.log.Info("Safety detector started", logger.Fields{
		"worker_pool_size": p.safetyConfig.MaxWorkers,
	})
	time.Sleep(30 * time.Second)
	eventBus.Publish(constants.DetectorTopic, eventbus.Event{
		Payload: &models.DetectorInfo{
			DiscoveryName: "程序启动，飞书通知测试",
			CollectorName: "程序启动，飞书通知测试",
			DetectorName:  p.Name(),
			Name:          "程序启动，飞书通知测试",
			Namespace:     "程序启动，飞书通知测试",
			Host:          "",
			Path:          nil,
			URL:           "程序启动，飞书通知测试",
			IsIllegal:     true,
			Description:   "飞书消息测试 - 程序已成功启动",
			Keywords:      []string{"程序启动", "飞书测试", "系统初始化"},
		},
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
						p.log.Error("Goroutine panic in safety detector", logger.Fields{
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

				p.log.Debug("Processing safety check", logger.Fields{
					"namespace": res.Namespace,
					"name":      res.Name,
					"host":      res.Host,
					"is_empty":  res.IsEmpty,
				})

				startTime := time.Now()
				result, err := p.safetyJudge(ctx, res)
				duration := time.Since(startTime)

				if err != nil {
					p.log.Error("Safety judgement failed", logger.Fields{
						"host":        result.Host,
						"namespace":   result.Namespace,
						"name":        result.Name,
						"error":       err.Error(),
						"duration_ms": duration.Milliseconds(),
					})
				} else {
					logLevel := "info"
					if result.IsIllegal {
						logLevel = "warn"
					}

					fields := logger.Fields{
						"host":        result.Host,
						"namespace":   result.Namespace,
						"name":        result.Name,
						"is_illegal":  result.IsIllegal,
						"duration_ms": duration.Milliseconds(),
					}

					if len(result.Keywords) > 0 {
						fields["keywords"] = result.Keywords
					}

					if logLevel == "warn" {
						p.log.Warn("Illegal content detected", fields)
					} else {
						p.log.Debug("Safety check completed", fields)
					}
				}

				eventBus.Publish(constants.DetectorTopic, eventbus.Event{
					Payload: result,
				})
			}(event)
		case <-ctx.Done():
			p.log.Info("Shutting down safety detector plugin")
			// Wait for all workers to finish
			for range p.safetyConfig.MaxWorkers {
				semaphore <- struct{}{}
			}

			p.log.Debug("All workers finished")

			return nil
		}
	}
}

func (p *SafetyPlugin) Stop(ctx context.Context) error {
	p.log.Info("Stopping safety detector plugin")
	// Cleanup resources if needed
	if p.reviewer != nil {
		p.log.Debug("Cleaning up content reviewer resources")
	}

	return nil
}

func (p *SafetyPlugin) safetyJudge(
	ctx context.Context,
	collector *models.CollectorInfo,
) (res *models.DetectorInfo, err error) {
	taskCtx, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()

	p.log.Debug("Starting safety judgement", logger.Fields{
		"url":             collector.URL,
		"is_empty":        collector.IsEmpty,
		"timeout_seconds": 80,
	})

	if collector.IsEmpty {
		p.log.Debug("Skipping empty content", logger.Fields{
			"host":   collector.Host,
			"reason": collector.CollectorMessage,
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

	p.log.Debug("Calling content reviewer", logger.Fields{
		"host":           collector.Host,
		"content_length": len(collector.HTML),
	})

	result, err := p.reviewer.ReviewSiteContent(taskCtx, collector, p.Name(), nil, p.safetyPrompt)
	if err != nil {
		p.log.Error("Content review failed", logger.Fields{
			"host":  collector.Host,
			"error": err.Error(),
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
			Description:   "",
			Keywords:      []string{},
		}, err
	} else {
		return result, nil
	}
}
