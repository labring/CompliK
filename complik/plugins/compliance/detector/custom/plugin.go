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

package custom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
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
	pluginName = constants.ComplianceDetectorCustom
	pluginType = constants.ComplianceDetectorPluginType
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &CustomPlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type CustomPlugin struct {
	log          logger.Logger
	reviewer     *utils.ContentReviewer
	keywords     []utils.CustomKeywordRule
	customConfig CustomConfig
}

func (p *CustomPlugin) Name() string {
	return pluginName
}

func (p *CustomPlugin) Type() string {
	return pluginType
}

type CustomConfig struct {
	TickerMinute       int    `json:"tickerMinute"`
	MaxWorkers         int    `json:"maxWorkers"`
	APIKey             string `json:"apiKey"`
	APIBase            string `json:"apiBase"`
	APIPath            string `json:"apiPath"`
	Model              string `json:"model"`
	AdminBaseURL       string `json:"adminBaseURL"`
	AdminTimeoutSecond int    `json:"adminTimeoutSecond"`
}

func (p *CustomPlugin) getDefaultConfig() CustomConfig {
	return CustomConfig{
		TickerMinute:       600,
		MaxWorkers:         20,
		AdminBaseURL:       config.DefaultAdminBaseURL,
		AdminTimeoutSecond: config.DefaultAdminTimeoutSecond,
	}
}

func (p *CustomPlugin) loadConfig(setting string) error {
	p.customConfig = p.getDefaultConfig()
	p.log.Debug("Loading custom detector configuration")

	if strings.TrimSpace(setting) == "" {
		return errors.New("configuration cannot be empty")
	}

	var configFromJSON CustomConfig
	if err := json.Unmarshal([]byte(setting), &configFromJSON); err != nil {
		p.log.Error("Failed to parse configuration", logger.Fields{"error": err.Error()})
		return err
	}

	if configFromJSON.TickerMinute > 0 {
		p.customConfig.TickerMinute = configFromJSON.TickerMinute
	}
	if configFromJSON.MaxWorkers > 0 {
		p.customConfig.MaxWorkers = configFromJSON.MaxWorkers
	}
	if strings.TrimSpace(configFromJSON.AdminBaseURL) != "" {
		if secureValue, err := config.GetSecureValue(configFromJSON.AdminBaseURL); err == nil {
			p.customConfig.AdminBaseURL = secureValue
		} else {
			p.customConfig.AdminBaseURL = configFromJSON.AdminBaseURL
		}
	}
	if configFromJSON.AdminTimeoutSecond > 0 {
		p.customConfig.AdminTimeoutSecond = configFromJSON.AdminTimeoutSecond
	}
	if err := p.applyModelRuntimeConfig(context.Background()); err != nil {
		return fmt.Errorf("failed to apply model runtime config from admin: %w", err)
	}
	if strings.TrimSpace(p.customConfig.APIKey) == "" ||
		strings.TrimSpace(p.customConfig.APIBase) == "" ||
		strings.TrimSpace(p.customConfig.APIPath) == "" ||
		strings.TrimSpace(p.customConfig.Model) == "" {
		return errors.New("model_runtime config from admin is incomplete")
	}
	if err := p.readFromAdminConfigs(context.Background()); err != nil {
		return fmt.Errorf("failed to load custom rules from admin: %w", err)
	}

	p.log.Info("Custom detector configuration loaded", logger.Fields{
		"api_base":       p.customConfig.APIBase,
		"model":          p.customConfig.Model,
		"admin_base_url": p.customConfig.AdminBaseURL,
		"max_workers":    p.customConfig.MaxWorkers,
		"ticker_minutes": p.customConfig.TickerMinute,
		"keyword_count":  len(p.keywords),
	})
	return nil
}

func (p *CustomPlugin) Start(
	ctx context.Context,
	cfg config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	p.log.Info("Starting custom detector plugin")
	if err := p.loadConfig(cfg.Settings); err != nil {
		p.log.Error("Failed to load configuration", logger.Fields{"error": err.Error()})
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	p.reviewer = utils.NewContentReviewer(
		p.log,
		p.customConfig.APIKey,
		p.customConfig.APIBase,
		p.customConfig.APIPath,
		p.customConfig.Model,
	)
	p.log.Debug("Content reviewer initialized")
	p.log.Info("Custom rules loaded", logger.Fields{"keyword_count": len(p.keywords)})

	subscribe := eventBus.Subscribe(constants.CollectorTopic)
	semaphore := make(chan struct{}, p.customConfig.MaxWorkers)
	ticker := time.NewTicker(time.Duration(p.customConfig.TickerMinute) * time.Minute)
	defer ticker.Stop()

	p.log.Info("Custom detector started", logger.Fields{
		"worker_pool_size":         p.customConfig.MaxWorkers,
		"refresh_interval_minutes": p.customConfig.TickerMinute,
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
						p.log.Error("Goroutine panic in custom detector", logger.Fields{
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

				startTime := time.Now()
				result, err := p.customJudge(ctx, res)
				duration := time.Since(startTime)
				if err != nil {
					p.log.Error("Custom judgement failed", logger.Fields{
						"host":        result.Host,
						"namespace":   result.Namespace,
						"error":       err.Error(),
						"duration_ms": duration.Milliseconds(),
					})
				} else {
					p.log.Debug("Custom detection completed", logger.Fields{
						"host":        result.Host,
						"is_illegal":  result.IsIllegal,
						"duration_ms": duration.Milliseconds(),
					})
				}

				eventBus.Publish(constants.DetectorTopic, eventbus.Event{Payload: result})
			}(event)
		case <-ticker.C:
			p.log.Debug("Scheduled custom rules refresh triggered")
			if err := p.refreshRules(ctx); err != nil {
				p.log.Error("Failed to refresh custom rules from admin", logger.Fields{"error": err.Error()})
				return err
			}
			p.log.Info("Keywords refreshed from admin configs", logger.Fields{"keyword_count": len(p.keywords)})
		case <-ctx.Done():
			p.log.Info("Shutting down custom detector plugin")
			for range p.customConfig.MaxWorkers {
				semaphore <- struct{}{}
			}
			p.log.Debug("All workers finished")
			return nil
		}
	}
}

func (p *CustomPlugin) Stop(ctx context.Context) error {
	p.log.Info("Stopping custom detector plugin")
	return nil
}

func (p *CustomPlugin) refreshRules(ctx context.Context) error {
	return p.readFromAdminConfigs(ctx)
}

func (p *CustomPlugin) readFromAdminConfigs(ctx context.Context) error {
	cfgs, err := config.ListAdminProjectConfigsByType(
		ctx,
		p.customConfig.AdminBaseURL,
		p.customConfig.AdminTimeoutSecond,
		"custom",
	)
	if err != nil {
		return err
	}

	type ruleItem struct {
		name string
		rule utils.CustomKeywordRule
	}
	rules := make([]ruleItem, 0, len(cfgs))
	for _, cfg := range cfgs {
		var payload struct {
			Content string `json:"content"`
		}
		if err := cfg.DecodeValue(&payload); err != nil {
			p.log.Warn("Failed to decode custom rule config_value", logger.Fields{
				"config_name": cfg.ConfigName,
				"error":       err.Error(),
			})
			continue
		}
		rule, parseErr := parseCustomRuleContent(cfg.ConfigName, payload.Content)
		if parseErr != nil {
			p.log.Warn("Failed to parse custom rule content", logger.Fields{
				"config_name": cfg.ConfigName,
				"error":       parseErr.Error(),
			})
			continue
		}
		rules = append(rules, ruleItem{name: cfg.ConfigName, rule: rule})
	}
	if len(rules) == 0 {
		return errors.New("no valid custom rules found in admin configs")
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].name < rules[j].name
	})
	next := make([]utils.CustomKeywordRule, 0, len(rules))
	for _, item := range rules {
		next = append(next, item.rule)
	}
	p.keywords = next
	return nil
}

func parseCustomRuleContent(configName, content string) (utils.CustomKeywordRule, error) {
	text := strings.TrimSpace(content)
	if text == "" {
		return utils.CustomKeywordRule{}, errors.New("content is empty")
	}

	lines := strings.Split(text, "\n")
	var (
		ruleType        string
		ruleDescription string
		keywordSegments []string
		unlabeledLines  []string
	)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "###") {
			ruleType = strings.TrimSpace(strings.TrimPrefix(trimmed, "###"))
			continue
		}
		key, value, ok := parseRuleKeyValue(trimmed)
		if ok {
			switch normalizeRuleKey(key) {
			case "type", "rule", "category", "类型", "规则", "分类":
				if value != "" {
					ruleType = value
				}
				continue
			case "description", "desc", "说明", "描述":
				if value != "" {
					ruleDescription = value
				}
				continue
			case "keywords", "keyword", "keywordslist", "关键词", "关键字", "违禁词", "违规词":
				if value != "" {
					keywordSegments = append(keywordSegments, value)
				}
				continue
			}
		}
		unlabeledLines = append(unlabeledLines, trimmed)
	}

	if ruleType == "" && len(unlabeledLines) > 1 && looksLikeRuleType(unlabeledLines[0]) {
		ruleType = unlabeledLines[0]
		unlabeledLines = unlabeledLines[1:]
	}
	if len(keywordSegments) == 0 && len(unlabeledLines) > 0 {
		keywordSegments = append(keywordSegments, strings.Join(unlabeledLines, "\n"))
	}
	keywords := splitRuleKeywords(strings.Join(keywordSegments, "\n"))
	if len(keywords) == 0 {
		return utils.CustomKeywordRule{}, errors.New("keywords not found in content")
	}

	if ruleType == "" {
		ruleType = deriveRuleTypeFromConfigName(configName)
	}
	if ruleDescription == "" {
		ruleDescription = fmt.Sprintf("%s关键词检测规则", ruleType)
	}

	return utils.CustomKeywordRule{
		Type:        ruleType,
		Description: ruleDescription,
		Keywords:    strings.Join(keywords, ", "),
	}, nil
}

func parseRuleKeyValue(line string) (key string, value string, ok bool) {
	cleaned := strings.TrimSpace(line)
	cleaned = strings.TrimLeft(cleaned, "-* ")
	if cleaned == "" {
		return "", "", false
	}
	for _, sep := range []string{":", "："} {
		if idx := strings.Index(cleaned, sep); idx > 0 {
			key = strings.TrimSpace(cleaned[:idx])
			value = strings.TrimSpace(cleaned[idx+len(sep):])
			return key, value, key != ""
		}
	}
	return "", "", false
}

func normalizeRuleKey(key string) string {
	normalized := strings.ToLower(strings.TrimSpace(key))
	replacer := strings.NewReplacer("-", "", "_", "", " ", "")
	return replacer.Replace(normalized)
}

func looksLikeRuleType(line string) bool {
	candidate := strings.TrimSpace(line)
	if candidate == "" {
		return false
	}
	if strings.ContainsAny(candidate, ",，;；|") {
		return false
	}
	return len([]rune(candidate)) <= 32
}

func deriveRuleTypeFromConfigName(configName string) string {
	name := strings.TrimSpace(configName)
	if name == "" {
		return "custom"
	}
	for _, sep := range []string{"/", ":"} {
		if parts := strings.Split(name, sep); len(parts) > 0 {
			name = parts[len(parts)-1]
		}
	}
	if parts := strings.Split(name, "."); len(parts) > 0 {
		name = parts[len(parts)-1]
	}
	name = regexp.MustCompile(`(?i)[_-]v\d+$`).ReplaceAllString(name, "")
	name = regexp.MustCompile(`^\d+[_-]?`).ReplaceAllString(name, "")
	name = strings.TrimSpace(name)
	if name == "" {
		return "custom"
	}
	return name
}

func splitRuleKeywords(raw string) []string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil
	}
	normalized := strings.NewReplacer(
		"，", ",",
		"、", ",",
		"；", ",",
		";", ",",
		"|", ",",
		"\r", "\n",
	).Replace(text)
	parts := regexp.MustCompile(`[,\n]+`).Split(normalized, -1)
	if len(parts) == 1 && strings.Contains(normalized, ".") {
		parts = strings.Split(normalized, ".")
	}
	seen := make(map[string]struct{}, len(parts))
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		kw := strings.TrimSpace(strings.Trim(part, `"'`))
		if kw == "" {
			continue
		}
		key := strings.ToLower(kw)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, kw)
	}
	return result
}

func (p *CustomPlugin) applyModelRuntimeConfig(ctx context.Context) error {
	modelCfg, err := config.LoadModelRuntimeConfig(
		ctx,
		p.customConfig.AdminBaseURL,
		p.customConfig.AdminTimeoutSecond,
	)
	if err != nil {
		return err
	}
	if modelCfg == nil {
		return errors.New("model_runtime config not found in admin")
	}
	if strings.TrimSpace(modelCfg.APIKey) != "" {
		if secureValue, err := config.GetSecureValue(modelCfg.APIKey); err == nil {
			p.customConfig.APIKey = secureValue
		} else {
			p.customConfig.APIKey = modelCfg.APIKey
		}
	}
	if strings.TrimSpace(modelCfg.APIBase) != "" {
		p.customConfig.APIBase = strings.TrimSpace(modelCfg.APIBase)
	}
	if strings.TrimSpace(modelCfg.APIPath) != "" {
		p.customConfig.APIPath = strings.TrimSpace(modelCfg.APIPath)
	}
	if strings.TrimSpace(modelCfg.Model) != "" {
		p.customConfig.Model = strings.TrimSpace(modelCfg.Model)
	}
	return nil
}

func (p *CustomPlugin) customJudge(
	ctx context.Context,
	collector *models.CollectorInfo,
) (res *models.DetectorInfo, err error) {
	taskCtx, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()

	p.log.Debug("Starting custom judgement", logger.Fields{
		"url":           collector.URL,
		"is_empty":      collector.IsEmpty,
		"keyword_rules": len(p.keywords),
	})

	if collector.IsEmpty {
		p.log.Debug("Skipping empty content", logger.Fields{"host": collector.Host})
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

	result, err := p.reviewer.ReviewSiteContent(taskCtx, collector, p.Name(), p.keywords, "")
	if err != nil {
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
	}
	return result, nil
}
