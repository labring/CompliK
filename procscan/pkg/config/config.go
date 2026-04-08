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

// Package config provides configuration structures and utilities for loading
// and managing ProcScan scanner settings, detection rules, and notification configurations.
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ScannerConfig defines scanner configuration
type ScannerConfig struct {
	ProcPath     string        `yaml:"proc_path"`
	ScanInterval time.Duration `yaml:"scan_interval"`
	LogLevel     string        `yaml:"log_level"`
}

// LabelActionConfig defines label action configuration
type LabelActionConfig struct {
	Enabled bool              `yaml:"enabled"`
	Data    map[string]string `yaml:"data"`
}

// ActionsConfig defines action configuration
type ActionsConfig struct {
	Label LabelActionConfig `yaml:"label"`
}

// LarkNotificationConfig defines Lark (Feishu) notification configuration
type LarkNotificationConfig struct {
	Webhook string `yaml:"webhook"`
}

// AdminNotificationConfig defines admin API notification configuration
type AdminNotificationConfig struct {
	BaseURL string        `yaml:"base_url"`
	Timeout time.Duration `yaml:"timeout"`
}

// NotificationsConfig defines notification configuration
type NotificationsConfig struct {
	Lark   LarkNotificationConfig  `yaml:"lark"`
	Admin  AdminNotificationConfig `yaml:"admin"`
	Region string                  `yaml:"region"`
}

// RuleSet defines a set of detection rules
type RuleSet struct {
	Processes  []string `yaml:"processes"`
	Keywords   []string `yaml:"keywords"`
	Commands   []string `yaml:"commands"`
	Namespaces []string `yaml:"namespaces"`
	PodNames   []string `yaml:"podNames"`
}

// DetectionRules defines detection rules with blacklist and whitelist
type DetectionRules struct {
	Blacklist RuleSet `yaml:"blacklist"`
	Whitelist RuleSet `yaml:"whitelist"`
}

// Config defines the main configuration structure
type Config struct {
	Scanner        ScannerConfig       `yaml:"scanner"`
	Actions        ActionsConfig       `yaml:"actions"`
	Notifications  NotificationsConfig `yaml:"notifications"`
	DetectionRules DetectionRules      `yaml:"detectionRules"`
}

// LoadConfig loads configuration from the specified path
func LoadConfig(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Set default values
	if config.Scanner.ProcPath == "" {
		config.Scanner.ProcPath = "/host/proc"
	}
	if config.Scanner.ScanInterval == 0 {
		config.Scanner.ScanInterval = 100 * time.Second
	}
	if config.Scanner.LogLevel == "" {
		config.Scanner.LogLevel = "info"
	}

	return &config, nil
}
