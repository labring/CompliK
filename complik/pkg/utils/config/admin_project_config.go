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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	DefaultAdminBaseURL       = "http://sealos-complik-admin:8080"
	DefaultAdminTimeoutSecond = 10
)

type AdminProjectConfig struct {
	ConfigName  string          `json:"config_name"`
	ConfigType  string          `json:"config_type"`
	ConfigValue json.RawMessage `json:"config_value"`
	Description string          `json:"description"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type ModelRuntimeConfig struct {
	APIKey  string `json:"apiKey"`
	APIBase string `json:"apiBase"`
	APIPath string `json:"apiPath"`
	Model   string `json:"model"`
}

type NotificationsRuntimeConfig struct {
	Region  string `json:"region"`
	Webhook string `json:"webhook"`
}

func (c *AdminProjectConfig) DecodeValue(dst any) error {
	if c == nil {
		return fmt.Errorf("admin project config is nil")
	}
	if len(c.ConfigValue) == 0 {
		return fmt.Errorf("admin project config %s has empty config_value", c.ConfigName)
	}
	if err := json.Unmarshal(c.ConfigValue, dst); err != nil {
		return fmt.Errorf("decode config_value for %s failed: %w", c.ConfigName, err)
	}
	return nil
}

func NormalizeAdminBaseURL(baseURL string) string {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return DefaultAdminBaseURL
	}
	return strings.TrimRight(trimmed, "/")
}

func ListAdminProjectConfigs(
	ctx context.Context,
	adminBaseURL string,
	timeoutSecond int,
) ([]AdminProjectConfig, error) {
	endpoint := NormalizeAdminBaseURL(adminBaseURL) + "/api/configs"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create admin list request failed: %w", err)
	}

	resp, err := adminHTTPClient(timeoutSecond).Do(req)
	if err != nil {
		return nil, fmt.Errorf("request admin config list failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read admin config list response failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin config list api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var cfgs []AdminProjectConfig
	if err := json.Unmarshal(body, &cfgs); err != nil {
		return nil, fmt.Errorf("decode admin config list response failed: %w", err)
	}
	return cfgs, nil
}

func ListAdminProjectConfigsByType(
	ctx context.Context,
	adminBaseURL string,
	timeoutSecond int,
	configType string,
) ([]AdminProjectConfig, error) {
	trimmedType := strings.TrimSpace(configType)
	if trimmedType == "" {
		return nil, fmt.Errorf("config_type is required")
	}

	endpoint := NormalizeAdminBaseURL(adminBaseURL) + "/api/configs/type/" + url.PathEscape(trimmedType)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create admin list-by-type request failed: %w", err)
	}

	resp, err := adminHTTPClient(timeoutSecond).Do(req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("read admin config list-by-type response failed: %w", readErr)
		}
		if resp.StatusCode == http.StatusOK {
			var cfgs []AdminProjectConfig
			if err := json.Unmarshal(body, &cfgs); err != nil {
				return nil, fmt.Errorf("decode admin config list-by-type response failed: %w", err)
			}
			return cfgs, nil
		}
	}

	cfgs, listErr := ListAdminProjectConfigs(ctx, adminBaseURL, timeoutSecond)
	if listErr != nil {
		if err != nil {
			return nil, fmt.Errorf(
				"request admin config list-by-type failed: %w; fallback full list failed: %v",
				err,
				listErr,
			)
		}
		return nil, listErr
	}

	filtered := make([]AdminProjectConfig, 0)
	for _, cfg := range cfgs {
		if strings.TrimSpace(cfg.ConfigType) == trimmedType {
			filtered = append(filtered, cfg)
		}
	}
	return filtered, nil
}

func LoadSingleAdminProjectConfigByType(
	ctx context.Context,
	adminBaseURL string,
	timeoutSecond int,
	configType string,
) (*AdminProjectConfig, error) {
	cfgs, err := ListAdminProjectConfigsByType(ctx, adminBaseURL, timeoutSecond, configType)
	if err != nil {
		return nil, err
	}
	if len(cfgs) == 0 {
		return nil, nil
	}
	if len(cfgs) > 1 {
		sort.Slice(cfgs, func(i, j int) bool {
			return cfgs[i].ConfigName < cfgs[j].ConfigName
		})
		names := make([]string, 0, len(cfgs))
		for _, cfg := range cfgs {
			names = append(names, cfg.ConfigName)
		}
		return nil, fmt.Errorf("config_type %q expects single config, got %d: %s", configType, len(cfgs), strings.Join(names, ","))
	}
	return &cfgs[0], nil
}

func LoadModelRuntimeConfig(
	ctx context.Context,
	adminBaseURL string,
	timeoutSecond int,
) (*ModelRuntimeConfig, error) {
	cfg, err := LoadSingleAdminProjectConfigByType(ctx, adminBaseURL, timeoutSecond, "model_runtime")
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	if strings.TrimSpace(cfg.ConfigType) != "model_runtime" {
		return nil, fmt.Errorf("config %s type mismatch: got %q want %q", cfg.ConfigName, cfg.ConfigType, "model_runtime")
	}

	var runtimeCfg ModelRuntimeConfig
	if err := cfg.DecodeValue(&runtimeCfg); err != nil {
		return nil, err
	}
	return &runtimeCfg, nil
}

func LoadNotificationsRuntimeConfig(
	ctx context.Context,
	adminBaseURL string,
	timeoutSecond int,
) (*NotificationsRuntimeConfig, error) {
	cfg, err := LoadSingleAdminProjectConfigByType(ctx, adminBaseURL, timeoutSecond, "complik_notifications_runtime")
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	cfgType := strings.TrimSpace(cfg.ConfigType)
	if cfgType != "complik_notifications_runtime" {
		return nil, fmt.Errorf(
			"config %s type mismatch: got %q want %q",
			cfg.ConfigName,
			cfg.ConfigType,
			"complik_notifications_runtime",
		)
	}

	var runtimeCfg NotificationsRuntimeConfig
	if err := cfg.DecodeValue(&runtimeCfg); err != nil {
		return nil, err
	}
	return &runtimeCfg, nil
}

func adminHTTPClient(timeoutSecond int) *http.Client {
	sec := timeoutSecond
	if sec <= 0 {
		sec = DefaultAdminTimeoutSecond
	}
	return &http.Client{Timeout: time.Duration(sec) * time.Second}
}
