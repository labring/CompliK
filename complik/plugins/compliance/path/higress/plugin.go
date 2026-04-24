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

// Package higress provides a compliance plugin that queries Higress gateway logs
// to collect information about discovered services and their access patterns.
// The plugin subscribes to discovery events and queries log data for analysis.
package higress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	pluginName = constants.ComplianceCollectorHigressName
	pluginType = constants.ComplianceHigressPluginType
)

const (
	maxWorkers = 20
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &HigressPlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type HigressPlugin struct {
	log    logger.Logger
	config HigressConfig
	client *http.Client
}

type HigressConfig struct {
	LogServerPath string `json:"log_server_path"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	TimeRange     string `json:"time_range"` // Default time range, e.g. "5m"
	App           string `json:"app"`        // Application name
}

type LogEntry struct {
	Timestamp string `json:"_time"`
	Message   string `json:"_msg"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
	Path      string `json:"path"`
}

func (p *HigressPlugin) Name() string {
	return pluginName
}

func (p *HigressPlugin) Type() string {
	return pluginType
}

func (p *HigressPlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	p.log.Debug("Starting Higress plugin", logger.Fields{
		"plugin":     pluginName,
		"maxWorkers": maxWorkers,
	})

	// Parse configuration
	if err := p.parseConfig(config); err != nil {
		p.log.Error("Failed to parse plugin config", logger.Fields{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to parse configuration: %w", err)
	}

	p.log.Debug("Plugin config parsed successfully", logger.Fields{
		"timeRange": p.config.TimeRange,
		"app":       p.config.App,
		"hasAuth":   p.config.Username != "",
	})

	// Initialize HTTP client
	p.client = &http.Client{
		Timeout: 30 * time.Second,
	}

	subscribe := eventBus.Subscribe(constants.DiscoveryTopic)
	semaphore := make(chan struct{}, maxWorkers)

	p.log.Info("Higress plugin started successfully", logger.Fields{
		"timeout": "30s",
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
						p.log.Error("Goroutine panic recovered", logger.Fields{
							"error": fmt.Sprintf("%v", r),
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

				p.log.Debug("Processing discovery event", logger.Fields{
					"host":      ingress.Host,
					"namespace": ingress.Namespace,
					"name":      ingress.Name,
				})

				// Query logs
				result, err := p.queryLogs(ingress)
				if err != nil {
					p.log.Error("Failed to query Higress logs", logger.Fields{
						"host":      ingress.Host,
						"namespace": ingress.Namespace,
						"name":      ingress.Name,
						"error":     err.Error(),
					})
				} else {
					// Publish query result to collector topic
					eventBus.Publish(constants.CollectorTopic, eventbus.Event{
						Payload: result,
					})
					p.log.Info("Successfully queried Higress logs", logger.Fields{
						"host":      ingress.Host,
						"namespace": ingress.Namespace,
						"logCount":  len(result),
					})
				}
			}(event)
		case <-ctx.Done():
			p.log.Info("Context cancelled, stopping Higress plugin")
			// Wait for all worker goroutines to finish
			for range maxWorkers {
				semaphore <- struct{}{}
			}

			p.log.Info("Higress plugin stopped successfully")

			return nil
		}
	}
}

func (p *HigressPlugin) Stop(ctx context.Context) error {
	p.log.Info("Stopping Higress plugin")

	if p.client != nil {
		p.client.CloseIdleConnections()
		p.log.Debug("HTTP client idle connections closed")
	}

	p.log.Info("Higress plugin stopped")

	return nil
}

func (p *HigressPlugin) parseConfig(config config.PluginConfig) error {
	p.log.Debug("Parsing plugin configuration")

	configData, err := json.Marshal(config)
	if err != nil {
		p.log.Error("Failed to marshal config", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	err = json.Unmarshal(configData, &p.config)
	if err != nil {
		p.log.Error("Failed to unmarshal config to HigressConfig", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	// Set default values
	if p.config.TimeRange == "" {
		p.config.TimeRange = "5m"
		p.log.Debug("Set default time range", logger.Fields{"timeRange": "5m"})
	}

	if p.config.App == "" {
		p.config.App = "higress"
		p.log.Debug("Set default app name", logger.Fields{"app": "higress"})
	}

	p.log.Debug("Configuration parsed successfully", logger.Fields{
		"logServerPath":  p.config.LogServerPath,
		"timeRange":      p.config.TimeRange,
		"app":            p.config.App,
		"hasCredentials": p.config.Username != "",
	})

	return nil
}

func (p *HigressPlugin) queryLogs(
	ingress models.DiscoveryInfo,
) ([]LogEntry, error) {
	p.log.Debug("Starting log query", logger.Fields{
		"host":      ingress.Host,
		"namespace": ingress.Namespace,
	})

	// Build query parameters
	query := p.buildQuery(ingress)
	p.log.Debug("Built log query", logger.Fields{
		"query": query,
	})

	// Send request
	resp, err := p.sendLogQuery(query)
	if err != nil {
		p.log.Error("Failed to send log query request", logger.Fields{
			"query": query,
			"error": err.Error(),
		})

		return nil, fmt.Errorf("failed to send log query request: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	logs, err := p.parseLogResponse(resp.Body)
	if err != nil {
		p.log.Error("Failed to parse log response", logger.Fields{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to parse log response: %w", err)
	}

	p.log.Debug("Log query completed successfully", logger.Fields{
		"logCount": len(logs),
	})

	return logs, nil
}

func (p *HigressPlugin) buildQuery(ingress models.DiscoveryInfo) string {
	var builder strings.Builder

	// Base query: filter by namespace and keywords
	builder.WriteString(fmt.Sprintf(`{namespace="%s"} `, ingress.Namespace))

	// Add path keyword search
	if ingress.Host != "" {
		builder.WriteString(fmt.Sprintf(`"%s" `, ingress.Host))
	}

	// Add time range
	builder.WriteString(fmt.Sprintf(`_time:%s `, p.config.TimeRange))

	// Add application filter
	builder.WriteString(fmt.Sprintf(`app:="%s" `, p.config.App))

	// Add JSON parsing and field extraction
	builder.WriteString(`| unpack_json `)

	// Remove unnecessary fields
	builder.WriteString(`| Drop _stream_id,_stream,job,node `)

	// Limit return quantity
	builder.WriteString(`| limit 1000`)

	return builder.String()
}

func (p *HigressPlugin) sendLogQuery(query string) (*http.Response, error) {
	p.log.Debug("Sending HTTP request for log query")

	// Use request method similar to VLogs
	req, err := p.generateRequest(query)
	if err != nil {
		p.log.Error("Failed to generate HTTP request", logger.Fields{
			"error": err.Error(),
		})
		return nil, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		p.log.Error("HTTP request failed", logger.Fields{
			"url":   req.URL.String(),
			"error": err.Error(),
		})

		return nil, fmt.Errorf("HTTP request error: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		p.log.Error("HTTP request returned error status", logger.Fields{
			"statusCode": resp.StatusCode,
			"status":     resp.Status,
		})
		resp.Body.Close()

		return nil, fmt.Errorf("response error, status code: %d", resp.StatusCode)
	}

	p.log.Debug("HTTP request successful", logger.Fields{
		"statusCode": resp.StatusCode,
	})

	return resp, nil
}

func (p *HigressPlugin) generateRequest(query string) (*http.Request, error) {
	// Build request URL
	baseURL := fmt.Sprintf("%s/select/logsql/query?query=%s",
		p.config.LogServerPath,
		strings.ReplaceAll(query, " ", "%20"))

	p.log.Debug("Generating HTTP request", logger.Fields{
		"url": baseURL,
	})

	req, err := http.NewRequest(http.MethodGet, baseURL, nil)
	if err != nil {
		p.log.Error("Failed to create HTTP request", logger.Fields{
			"url":   baseURL,
			"error": err.Error(),
		})

		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set basic authentication
	req.SetBasicAuth(p.config.Username, p.config.Password)
	p.log.Debug("Set basic authentication", logger.Fields{
		"username": p.config.Username,
	})

	return req, nil
}

func (p *HigressPlugin) parseLogResponse(body io.Reader) ([]LogEntry, error) {
	p.log.Debug("Parsing log response body")

	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		p.log.Error("Failed to read response body", logger.Fields{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	p.log.Debug("Read response body", logger.Fields{
		"bodySize": len(bodyBytes),
	})

	if len(bodyBytes) == 0 {
		p.log.Debug("Empty response body")
		return []LogEntry{}, nil
	}

	lines := strings.Split(string(bodyBytes), "\n")
	validLines := 0
	parseErrors := 0

	logs := make([]LogEntry, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			parseErrors++

			p.log.Debug("Failed to parse log line as JSON, using raw text", logger.Fields{
				"line":  line,
				"error": err.Error(),
			})
			// If JSON parsing fails, create a simple log entry
			entry = LogEntry{
				Timestamp: time.Now().Format(time.RFC3339),
				Message:   line,
			}
		} else {
			validLines++
		}

		logs = append(logs, entry)
	}

	p.log.Debug("Log response parsing completed", logger.Fields{
		"totalLines":  len(lines),
		"validLines":  validLines,
		"parseErrors": parseErrors,
		"logEntries":  len(logs),
	})

	return logs, nil
}
