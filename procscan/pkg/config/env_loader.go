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

// Package config provides environment variable loading functionality for configuration.
package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

// EnvLoader is an environment variable loader
type EnvLoader struct {
	prefix     string                   // Environment variable prefix
	separator  string                   // Separator, default is "_"
	mapping    map[string]string        // Field mapping
	converters map[string]TypeConverter // Type converters
}

// TypeConverter is the interface for type converters
type TypeConverter interface {
	Convert(value string) (interface{}, error)
}

// NewEnvLoader creates a new environment variable loader
func NewEnvLoader(prefix string) *EnvLoader {
	if prefix == "" {
		prefix = "PROCSCAN"
	}

	return &EnvLoader{
		prefix:     strings.ToUpper(prefix),
		separator:  "_",
		mapping:    make(map[string]string),
		converters: make(map[string]TypeConverter),
	}
}

// SetSeparator sets the separator
func (e *EnvLoader) SetSeparator(separator string) *EnvLoader {
	e.separator = separator
	return e
}

// AddMapping adds a field mapping
func (e *EnvLoader) AddMapping(field, envKey string) *EnvLoader {
	e.mapping[field] = envKey
	return e
}

// AddConverter adds a type converter
func (e *EnvLoader) AddConverter(field string, converter TypeConverter) *EnvLoader {
	e.converters[field] = converter
	return e
}

// LoadFromEnv loads configuration from environment variables
func (e *EnvLoader) LoadFromEnv(config *models.Config) error {
	legacy.L.WithField("prefix", e.prefix).Info("Starting to load configuration from environment variables")

	// Load scanner configuration
	if err := e.loadScannerConfig(&config.Scanner); err != nil {
		return fmt.Errorf("failed to load scanner configuration: %w", err)
	}

	// Load actions configuration
	if err := e.loadActionsConfig(&config.Actions); err != nil {
		return fmt.Errorf("failed to load actions configuration: %w", err)
	}

	// Load notifications configuration
	if err := e.loadNotificationsConfig(&config.Notifications); err != nil {
		return fmt.Errorf("failed to load notifications configuration: %w", err)
	}

	// Load detection rules
	if err := e.loadDetectionRules(&config.DetectionRules); err != nil {
		return fmt.Errorf("failed to load detection rules: %w", err)
	}

	legacy.L.Info("Environment variable configuration loading completed")
	return nil
}

// loadScannerConfig loads scanner configuration
func (e *EnvLoader) loadScannerConfig(scanner *models.ScannerConfig) error {
	configMap := map[string]interface{}{
		"scanner.proc_path":     &scanner.ProcPath,
		"scanner.scan_interval": &scanner.ScanInterval,
		"scanner.log_level":     &scanner.LogLevel,
	}

	return e.loadConfigMap(configMap)
}

// loadActionsConfig loads actions configuration
func (e *EnvLoader) loadActionsConfig(actions *models.ActionsConfig) error {
	configMap := map[string]interface{}{
		"actions.label.enabled": &actions.Label.Enabled,
		"actions.label.data":    &actions.Label.Data,
	}

	return e.loadConfigMap(configMap)
}

// loadNotificationsConfig loads notifications configuration
func (e *EnvLoader) loadNotificationsConfig(notifications *models.NotificationsConfig) error {
	configMap := map[string]interface{}{
		"notifications.lark.webhook":   &notifications.Lark.Webhook,
		"notifications.admin.base_url": &notifications.Admin.BaseURL,
	}

	return e.loadConfigMap(configMap)
}

// loadDetectionRules loads detection rules
func (e *EnvLoader) loadDetectionRules(rules *models.DetectionRules) error {
	// Blacklist rules
	blacklistMap := map[string]interface{}{
		"detectionRules.blacklist.processes":  &rules.Blacklist.Processes,
		"detectionRules.blacklist.keywords":   &rules.Blacklist.Keywords,
		"detectionRules.blacklist.commands":   &rules.Blacklist.Commands,
		"detectionRules.blacklist.namespaces": &rules.Blacklist.Namespaces,
		"detectionRules.blacklist.podNames":   &rules.Blacklist.PodNames,
	}

	if err := e.loadConfigMap(blacklistMap); err != nil {
		return err
	}

	// Whitelist rules
	whitelistMap := map[string]interface{}{
		"detectionRules.whitelist.processes":  &rules.Whitelist.Processes,
		"detectionRules.whitelist.keywords":   &rules.Whitelist.Keywords,
		"detectionRules.whitelist.commands":   &rules.Whitelist.Commands,
		"detectionRules.whitelist.namespaces": &rules.Whitelist.Namespaces,
		"detectionRules.whitelist.podNames":   &rules.Whitelist.PodNames,
	}

	return e.loadConfigMap(whitelistMap)
}

// loadConfigMap loads a configuration map
func (e *EnvLoader) loadConfigMap(configMap map[string]interface{}) error {
	for field, target := range configMap {
		envValue := e.getEnvValue(field)
		if envValue == "" {
			continue
		}

		// Type conversion
		convertedValue, err := e.convertValue(field, envValue)
		if err != nil {
			legacy.L.WithFields(map[string]interface{}{
				"field": field,
				"value": envValue,
				"error": err.Error(),
			}).Error("Environment variable type conversion failed")
			return fmt.Errorf("field '%s' type conversion failed: %w", field, err)
		}

		// Set value
		if err := e.setFieldValue(target, convertedValue); err != nil {
			return fmt.Errorf("failed to set field '%s' value: %w", field, err)
		}

		legacy.L.WithFields(map[string]interface{}{
			"field":   field,
			"env_key": e.getEnvKey(field),
			"value":   convertedValue,
		}).Debug("Loaded configuration from environment variable")
	}

	return nil
}

// getEnvValue gets the environment variable value
func (e *EnvLoader) getEnvValue(field string) string {
	envKey := e.getEnvKey(field)
	return os.Getenv(envKey)
}

// getEnvKey gets the environment variable key name
func (e *EnvLoader) getEnvKey(field string) string {
	// Check if there is a custom mapping
	if customKey, exists := e.mapping[field]; exists {
		return customKey
	}

	// Default mapping: convert dot-separated field names to underscore-separated
	key := strings.ReplaceAll(field, ".", e.separator)
	key = strings.ReplaceAll(key, "-", "_")
	key = strings.ToUpper(key)
	return e.prefix + e.separator + key
}

// convertValue converts value type
func (e *EnvLoader) convertValue(field, value string) (interface{}, error) {
	// Check if there is a custom converter
	if converter, exists := e.converters[field]; exists {
		return converter.Convert(value)
	}

	// Automatic type inference
	return e.autoConvert(field, value)
}

// autoConvert performs automatic type conversion
func (e *EnvLoader) autoConvert(field, value string) (interface{}, error) {
	// Infer type based on field name
	if strings.Contains(field, "interval") || strings.Contains(field, "timeout") {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return nil, fmt.Errorf("invalid duration format: %w", err)
		}
		return duration, nil
	}

	if strings.Contains(field, "enabled") {
		if strings.ToLower(value) == "true" || value == "1" {
			return true, nil
		} else if strings.ToLower(value) == "false" || value == "0" {
			return false, nil
		}
		return nil, fmt.Errorf("invalid boolean value: %s", value)
	}

	if strings.Contains(field, "processes") ||
		strings.Contains(field, "keywords") ||
		strings.Contains(field, "commands") ||
		strings.Contains(field, "namespaces") ||
		strings.Contains(field, "podNames") {
		// Slice type, comma-separated
		if value == "" {
			return []string{}, nil
		}
		return strings.Split(value, ","), nil
	}

	if strings.Contains(field, "data") {
		// Map type, simplified handling: key1=value1,key2=value2
		return e.parseMap(value)
	}

	// Default to string
	return value, nil
}

// parseMap parses map type
func (e *EnvLoader) parseMap(value string) (map[string]string, error) {
	if value == "" {
		return make(map[string]string), nil
	}

	result := make(map[string]string)
	pairs := strings.Split(value, ",")

	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid map format: %s", pair)
		}
		result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}

	return result, nil
}

// setFieldValue sets the field value
func (e *EnvLoader) setFieldValue(target interface{}, value interface{}) error {
	targetValue := reflect.ValueOf(target)
	if targetValue.Kind() != reflect.Ptr {
		return fmt.Errorf("target must be a pointer")
	}

	targetValue = targetValue.Elem()
	if !targetValue.CanSet() {
		return fmt.Errorf("cannot set field value")
	}

	valueType := reflect.ValueOf(value)
	if !valueType.Type().ConvertibleTo(targetValue.Type()) {
		return fmt.Errorf("cannot convert %v to %v", valueType.Type(), targetValue.Type())
	}

	targetValue.Set(valueType.Convert(targetValue.Type()))
	return nil
}

// ListEnvVars lists all related environment variables
func (e *EnvLoader) ListEnvVars() []string {
	var envVars []string

	// Collect all environment variables
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, e.prefix+"_") {
			envVars = append(envVars, env)
		}
	}

	return envVars
}

// GetEnvSummary gets the environment variable summary
func (e *EnvLoader) GetEnvSummary() map[string]interface{} {
	summary := make(map[string]interface{})

	envVars := e.ListEnvVars()
	summary["total_env_vars"] = len(envVars)
	summary["env_vars"] = envVars
	summary["prefix"] = e.prefix
	summary["separator"] = e.separator

	return summary
}

// Specific type converter implementations

// StringConverter converts string values
type StringConverter struct{}

func (c *StringConverter) Convert(value string) (interface{}, error) {
	return value, nil
}

// BoolConverter converts boolean values
type BoolConverter struct{}

func (c *BoolConverter) Convert(value string) (interface{}, error) {
	switch strings.ToLower(value) {
	case "true", "1", "yes", "on", "enabled":
		return true, nil
	case "false", "0", "no", "off", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %s", value)
	}
}

// DurationConverter converts duration values
type DurationConverter struct{}

func (c *DurationConverter) Convert(value string) (interface{}, error) {
	return time.ParseDuration(value)
}

// IntConverter converts integer values
type IntConverter struct{}

func (c *IntConverter) Convert(value string) (interface{}, error) {
	return strconv.Atoi(value)
}

// StringSliceConverter converts string slice values
type StringSliceConverter struct {
	Separator string
}

func (c *StringSliceConverter) Convert(value string) (interface{}, error) {
	separator := c.Separator
	if separator == "" {
		separator = ","
	}

	if value == "" {
		return []string{}, nil
	}

	return strings.Split(value, separator), nil
}
