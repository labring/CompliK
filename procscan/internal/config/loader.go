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

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
	"gopkg.in/yaml.v3"
)

const (
	procscanNotificationsConfigType = "procscan_notifications_runtime"
	procscanRulesConfigType         = "procscan_rules"
	defaultAdminConfigTimeout       = 5 * time.Second
)

var defaultAdminClient = &http.Client{Timeout: defaultAdminConfigTimeout}

// Loader handles configuration file loading and parsing
type Loader struct {
	configPath string
	lastHash   string
}

type adminProjectConfigResponse struct {
	ConfigName  string          `json:"config_name"`
	ConfigValue json.RawMessage `json:"config_value"`
}

type remoteNotificationsConfig struct {
	Region  *string `json:"region"`
	Webhook *string `json:"webhook"`
}

// NewLoader creates a new configuration loader
func NewLoader(configPath string) *Loader {
	return &Loader{
		configPath: configPath,
	}
}

// Load reads and parses the configuration file
func (l *Loader) Load() (*models.Config, error) {
	if _, err := os.Stat(l.configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file does not exist: %s", l.configPath)
	}

	data, err := os.ReadFile(l.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file is empty: %s", l.configPath)
	}

	var config models.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration file: %w", err)
	}

	// Update last hash
	hash, _ := l.calculateHash()
	l.lastHash = hash

	if err := l.loadAdminConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func (l *Loader) loadAdminConfig(config *models.Config) error {
	adminBaseURL := strings.TrimSpace(config.Notifications.Admin.BaseURL)
	if adminBaseURL == "" {
		return fmt.Errorf("notifications.admin.base_url is required")
	}

	notifications, err := l.loadRemoteNotificationsConfig(adminBaseURL, config.Notifications.Admin.Timeout)
	if err != nil {
		return fmt.Errorf("load notifications config from admin: %w", err)
	}
	if notifications.Region == nil || strings.TrimSpace(*notifications.Region) == "" {
		return fmt.Errorf("admin config %q missing region", procscanNotificationsConfigType)
	}
	if notifications.Webhook == nil || strings.TrimSpace(*notifications.Webhook) == "" {
		return fmt.Errorf("admin config %q missing webhook", procscanNotificationsConfigType)
	}
	config.Notifications.Region = strings.TrimSpace(*notifications.Region)
	config.Notifications.Lark.Webhook = strings.TrimSpace(*notifications.Webhook)

	rules, err := l.loadRemoteRulesConfig(adminBaseURL, config.Notifications.Admin.Timeout)
	if err != nil {
		return fmt.Errorf("load detection rules config from admin: %w", err)
	}
	config.DetectionRules = *rules

	return nil
}

func (l *Loader) loadRemoteNotificationsConfig(adminBaseURL string, timeout time.Duration) (*remoteNotificationsConfig, error) {
	var config remoteNotificationsConfig
	if err := l.loadRemoteConfigValue(adminBaseURL, timeout, procscanNotificationsConfigType, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (l *Loader) loadRemoteRulesConfig(adminBaseURL string, timeout time.Duration) (*models.DetectionRules, error) {
	var rules models.DetectionRules
	if err := l.loadRemoteConfigValue(adminBaseURL, timeout, procscanRulesConfigType, &rules); err != nil {
		return nil, err
	}
	return &rules, nil
}

func (l *Loader) loadRemoteConfigValue(adminBaseURL string, timeout time.Duration, configType string, target any) error {
	endpoint := strings.TrimRight(adminBaseURL, "/") + "/api/configs/type/" + url.PathEscape(configType)
	resp, err := adminClient(timeout).Get(endpoint)
	if err != nil {
		return fmt.Errorf("request %s: %w", configType, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request %s: status %d, body %s", configType, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payloads []adminProjectConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&payloads); err != nil {
		return fmt.Errorf("decode %s response: %w", configType, err)
	}
	if len(payloads) == 0 {
		return fmt.Errorf("%s response is empty", configType)
	}

	sort.Slice(payloads, func(i, j int) bool {
		return payloads[i].ConfigName < payloads[j].ConfigName
	})

	if len(payloads[0].ConfigValue) == 0 {
		return fmt.Errorf("%s config value is empty", configType)
	}
	if err := json.Unmarshal(payloads[0].ConfigValue, target); err != nil {
		return fmt.Errorf("decode %s config value: %w", configType, err)
	}

	return nil
}

func adminClient(timeout time.Duration) *http.Client {
	if timeout <= 0 || timeout == defaultAdminConfigTimeout {
		return defaultAdminClient
	}
	return &http.Client{Timeout: timeout}
}

// HasChanged checks if the configuration file has changed since last load
func (l *Loader) HasChanged() (bool, error) {
	currentHash, err := l.calculateHash()
	if err != nil {
		return false, err
	}

	if l.lastHash == "" {
		l.lastHash = currentHash
		return false, nil
	}

	changed := currentHash != l.lastHash
	if changed {
		l.lastHash = currentHash
	}

	return changed, nil
}

// GetConfigPath returns the configuration file path
func (l *Loader) GetConfigPath() string {
	return l.configPath
}

// GetConfigDir returns the directory containing the configuration file
func (l *Loader) GetConfigDir() string {
	return filepath.Dir(l.configPath)
}

// calculateHash computes SHA256 hash of the configuration file
func (l *Loader) calculateHash() (string, error) {
	file, err := os.Open(l.configPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
