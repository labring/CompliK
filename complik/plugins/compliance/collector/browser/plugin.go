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

package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
	"github.com/bearslyricattack/CompliK/complik/plugins/compliance/collector/browser/utils"
)

const (
	pluginName = constants.ComplianceCollectorBrowserName
	pluginType = constants.ComplianceCollectorPluginType
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &BrowserPlugin{
			log:       logger.GetLogger().WithField("plugin", pluginName),
			collector: NewCollector(),
		}
	}
}

type BrowserPlugin struct {
	log           logger.Logger
	browserConfig BrowserConfig
	browserPool   *utils.BrowserPool
	collector     *Collector
}

func (p *BrowserPlugin) Name() string {
	return pluginName
}

func (p *BrowserPlugin) Type() string {
	return pluginType
}

type BrowserConfig struct {
	CollectorTimeoutSecond int `json:"timeout"`
	MaxWorkers             int `json:"maxWorkers"`
	BrowserNumber          int `json:"browserNumber"`
	BrowserTimeoutMinute   int `json:"browserTimeout"`
}

func (p *BrowserPlugin) getDefaultBrowserConfig() BrowserConfig {
	return BrowserConfig{
		CollectorTimeoutSecond: 200,
		MaxWorkers:             20,
		BrowserNumber:          20,
		BrowserTimeoutMinute:   300,
	}
}

func (p *BrowserPlugin) loadConfig(setting string) error {
	p.browserConfig = p.getDefaultBrowserConfig()
	if setting == "" {
		p.log.Info("Using default browser configuration")
		return nil
	}

	var configFromJSON BrowserConfig

	err := json.Unmarshal([]byte(setting), &configFromJSON)
	if err != nil {
		p.log.Error("Failed to parse config, using defaults", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if configFromJSON.CollectorTimeoutSecond > 0 {
		p.browserConfig.CollectorTimeoutSecond = configFromJSON.CollectorTimeoutSecond
	}

	if configFromJSON.MaxWorkers > 0 {
		p.browserConfig.MaxWorkers = configFromJSON.MaxWorkers
	}

	if configFromJSON.BrowserNumber > 0 {
		p.browserConfig.BrowserNumber = configFromJSON.BrowserNumber
	}

	if configFromJSON.BrowserTimeoutMinute > 0 {
		p.browserConfig.BrowserTimeoutMinute = configFromJSON.BrowserTimeoutMinute
	}

	return nil
}

func (p *BrowserPlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	err := p.loadConfig(config.Settings)
	if err != nil {
		return err
	}

	p.log.Info("Starting browser plugin", logger.Fields{
		"timeout_seconds":   p.browserConfig.CollectorTimeoutSecond,
		"max_workers":       p.browserConfig.MaxWorkers,
		"browser_pool_size": p.browserConfig.BrowserNumber,
	})

	p.browserPool = utils.NewBrowserPool(
		p.browserConfig.BrowserNumber,
		time.Duration(p.browserConfig.BrowserTimeoutMinute)*time.Minute,
	)
	subscribe := eventBus.Subscribe(constants.DiscoveryTopic)

	semaphore := make(chan struct{}, p.browserConfig.MaxWorkers)
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
						p.log.Error("Goroutine panic recovered", logger.Fields{
							"panic": r,
							"stack": string(debug.Stack()),
						})
					}
				}()

				ingress, ok := e.Payload.(models.DiscoveryInfo)
				if !ok {
					p.log.Error("Invalid event payload type", logger.Fields{
						"expected": "models.DiscoveryInfo",
						"actual":   fmt.Sprintf("%T", e.Payload),
					})

					return
				}

				var result *models.CollectorInfo

				taskCtx, cancel := context.WithTimeout(
					ctx,
					time.Duration(p.browserConfig.CollectorTimeoutSecond)*time.Second,
				)
				taskCtx = context.WithValue(taskCtx, startTimeContextKey, time.Now())

				defer cancel()

				p.log.Debug("Processing discovery", logger.Fields{
					"namespace": ingress.Namespace,
					"name":      ingress.Name,
					"host":      ingress.Host,
				})

				result, err := p.collector.CollectorAndScreenshot(
					taskCtx,
					ingress,
					p.browserPool,
					p.Name(),
					time.Duration(p.browserConfig.CollectorTimeoutSecond)*time.Second,
				)
				if err != nil {
					if p.shouldSkipError(err) {
						result = &models.CollectorInfo{
							DiscoveryName:    ingress.DiscoveryName,
							CollectorName:    p.Name(),
							Name:             ingress.Name,
							Namespace:        ingress.Namespace,
							Host:             ingress.Host,
							Path:             ingress.Path,
							URL:              "",
							HTML:             "",
							Screenshot:       nil,
							IsEmpty:          true,
							CollectorMessage: err.Error(),
						}
						eventBus.Publish(constants.CollectorTopic, eventbus.Event{
							Payload: result,
						})
						p.log.Debug("Skipped known error", logger.Fields{
							"host":  ingress.Host,
							"error": err.Error(),
						})
					} else {
						p.log.Error("Collection failed", logger.Fields{
							"host":      ingress.Host,
							"namespace": ingress.Namespace,
							"name":      ingress.Name,
							"error":     err.Error(),
						})
					}
				} else {
					eventBus.Publish(constants.CollectorTopic, eventbus.Event{
						Payload: result,
					})
					p.log.Debug("Collection successful", logger.Fields{
						"host":      ingress.Host,
						"namespace": ingress.Namespace,
						"name":      ingress.Name,
					})
				}
			}(event)
		case <-ctx.Done():
			for range p.browserConfig.MaxWorkers {
				semaphore <- struct{}{}
			}
			return nil
		}
	}
}

func (p *BrowserPlugin) Stop(ctx context.Context) error {
	p.log.Info("Stopping browser plugin")

	if p.browserPool != nil {
		p.browserPool.Close()
	}

	return nil
}

func (p *BrowserPlugin) shouldSkipError(err error) bool {
	if err == nil {
		return false
	}

	skipPatterns := []string{
		"ERR_HTTP_RESPONSE_CODE_FAILURE",
		"ERR_INVALID_AUTH_CREDENTIALS",
		"ERR_INVALID_RESPONSE",
		"ERR_EMPTY_RESPONSE",
		"navigation failed",
		"net::ERR_EMPTY_RESPONSE",
		"net::ERR_CONNECTION_RESET",
		"net::ERR_EMPTY_RESPONSE",
		"net::ERR_NAME_NOT_RESOLVED",
		"net::ERR_HTTP_RESPONSE_CODE_FAILURE",
		"navigation failed: net::ERR_HTTP_RESPONSE_CODE_FAILURE",
		"navigation failed: net::ERR_EMPTY_RESPONSE",
	}

	errStr := err.Error()
	for _, pattern := range skipPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}
