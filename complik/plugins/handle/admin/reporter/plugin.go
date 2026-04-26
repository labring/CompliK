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

package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
)

const (
	pluginName             = constants.HandleAdminReporter
	pluginType             = constants.HandleAdminPluginType
	defaultAdminBaseURL    = "http://sealos-complik-admin:8080"
	defaultAdminTimeoutSec = 10
	complikViolationsPath  = "/api/complik-violations"
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &AdminReporterPlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type AdminReporterPlugin struct {
	log            logger.Logger
	reporterConfig ReporterConfig
}

type ReporterConfig struct {
	Region             string `json:"region"`
	AdminBaseURL       string `json:"adminBaseURL"`
	AdminTimeoutSecond int    `json:"adminTimeoutSecond"`
}

type complikViolationRequest struct {
	Namespace     string    `json:"namespace"`
	Region        string    `json:"region,omitempty"`
	DiscoveryName string    `json:"discovery_name,omitempty"`
	CollectorName string    `json:"collector_name,omitempty"`
	DetectorName  string    `json:"detector_name"`
	ResourceName  string    `json:"resource_name,omitempty"`
	Host          string    `json:"host,omitempty"`
	URL           string    `json:"url,omitempty"`
	Path          []string  `json:"path,omitempty"`
	Keywords      []string  `json:"keywords,omitempty"`
	Description   string    `json:"description,omitempty"`
	Explanation   string    `json:"explanation,omitempty"`
	IsIllegal     bool      `json:"is_illegal"`
	IsTest        bool      `json:"is_test"`
	Status        string    `json:"status"`
	DetectedAt    time.Time `json:"detected_at"`
	RawPayload    any       `json:"raw_payload,omitempty"`
}

func (p *AdminReporterPlugin) Name() string {
	return pluginName
}

func (p *AdminReporterPlugin) Type() string {
	return pluginType
}

func (p *AdminReporterPlugin) getDefaultConfig() ReporterConfig {
	return ReporterConfig{
		Region:             "UNKNOWN",
		AdminBaseURL:       defaultAdminBaseURL,
		AdminTimeoutSecond: defaultAdminTimeoutSec,
	}
}

func (p *AdminReporterPlugin) loadConfig(setting string) error {
	p.reporterConfig = p.getDefaultConfig()
	if strings.TrimSpace(setting) == "" {
		return errors.New("configuration cannot be empty")
	}

	var configFromJSON ReporterConfig
	if err := json.Unmarshal([]byte(setting), &configFromJSON); err != nil {
		return err
	}
	if strings.TrimSpace(configFromJSON.Region) != "" {
		p.reporterConfig.Region = strings.TrimSpace(configFromJSON.Region)
	}
	if strings.TrimSpace(configFromJSON.AdminBaseURL) != "" {
		if secureValue, err := config.GetSecureValue(configFromJSON.AdminBaseURL); err == nil {
			p.reporterConfig.AdminBaseURL = secureValue
		} else {
			p.reporterConfig.AdminBaseURL = configFromJSON.AdminBaseURL
		}
	}
	if configFromJSON.AdminTimeoutSecond > 0 {
		p.reporterConfig.AdminTimeoutSecond = configFromJSON.AdminTimeoutSecond
	}

	p.log.Info("Admin reporter configuration loaded", logger.Fields{
		"region":         p.reporterConfig.Region,
		"admin_base_url": p.reporterConfig.AdminBaseURL,
		"admin_timeout":  p.reporterConfig.AdminTimeoutSecond,
	})
	return nil
}

func (p *AdminReporterPlugin) Start(
	ctx context.Context,
	cfg config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	if err := p.loadConfig(cfg.Settings); err != nil {
		return err
	}

	subscribe := eventBus.Subscribe(constants.DetectorTopic)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				p.log.Error("Plugin goroutine panic", logger.Fields{"panic": r})
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
				if strings.TrimSpace(result.Region) == "" {
					result.Region = p.reporterConfig.Region
				}
				if err := p.reportViolation(result); err != nil {
					p.log.Error("Failed to report detector event to admin", logger.Fields{
						"error":     err.Error(),
						"host":      result.Host,
						"namespace": result.Namespace,
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

func (p *AdminReporterPlugin) Stop(ctx context.Context) error {
	return nil
}

func (p *AdminReporterPlugin) reportViolation(result *models.DetectorInfo) error {
	if result == nil {
		return fmt.Errorf("detector result is nil")
	}
	if strings.TrimSpace(result.Namespace) == "" {
		return fmt.Errorf("namespace is required for admin reporting")
	}

	requestBody := complikViolationRequest{
		Namespace:     result.Namespace,
		Region:        result.Region,
		DiscoveryName: result.DiscoveryName,
		CollectorName: result.CollectorName,
		DetectorName:  result.DetectorName,
		ResourceName:  result.Name,
		Host:          result.Host,
		URL:           result.URL,
		Path:          result.Path,
		Keywords:      result.Keywords,
		Description:   result.Description,
		Explanation:   result.Explanation,
		IsIllegal:     result.IsIllegal,
		IsTest:        isComplikTestEvent(result),
		Status:        "open",
		DetectedAt:    time.Now().UTC(),
		RawPayload:    result,
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.adminTimeout())
	defer cancel()

	return postJSON(ctx, p.adminEndpoint(), requestBody)
}

func (p *AdminReporterPlugin) adminEndpoint() string {
	return strings.TrimRight(p.reporterConfig.AdminBaseURL, "/") + complikViolationsPath
}

func (p *AdminReporterPlugin) adminTimeout() time.Duration {
	timeoutSecond := p.reporterConfig.AdminTimeoutSecond
	if timeoutSecond <= 0 {
		timeoutSecond = defaultAdminTimeoutSec
	}
	return time.Duration(timeoutSecond) * time.Second
}

func isComplikTestEvent(result *models.DetectorInfo) bool {
	if result == nil {
		return false
	}
	if strings.EqualFold(result.Name, "程序启动，飞书通知测试") {
		return true
	}
	for _, keyword := range result.Keywords {
		if keyword == "程序启动" {
			return true
		}
	}
	return false
}

func postJSON(ctx context.Context, endpoint string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	return nil
}
