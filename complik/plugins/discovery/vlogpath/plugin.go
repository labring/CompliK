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

// Package vlogpath provides a discovery plugin that finds real HTML sub-paths
// from gateway access logs and publishes them as discovery events.
//
//nolint:wsl_v5 // Plugin orchestration keeps related config and Kubernetes branches compact.
package vlogpath

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

const (
	pluginName = constants.DiscoveryVLogPathName
	pluginType = constants.DiscoveryInformerPluginType
)

func init() {
	// Register the plugin factory so the manager can create this plugin by name
	// from config.yml without importing concrete types.
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &VLogPathPlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

// VLogPathPlugin discovers real page paths from VLog access logs and publishes
// them through the shared discovery event topic.
type VLogPathPlugin struct {
	log             logger.Logger
	stopChan        chan struct{}
	eventBus        *eventbus.EventBus
	factory         informers.SharedInformerFactory
	ingressInformer cache.SharedIndexInformer
	vlogPathConfig  VLogPathConfig
	seedCache       *SeedCache
	client          *VLogClient
}

// VLogPathConfig holds all runtime knobs for log querying, seed selection, and
// candidate ranking.
type VLogPathConfig struct {
	LogServerPath        string         `json:"logServerPath"`
	LogServerPathSnake   string         `json:"log_server_path"`
	Username             string         `json:"username"`
	Password             string         `json:"password"`
	App                  string         `json:"app"`
	IntervalHour         int            `json:"intervalHour"`
	LookbackHour         int            `json:"lookbackHour"`
	BucketHour           int            `json:"bucketHour"`
	TopNPerHost          int            `json:"topNPerHost"`
	QueryLimitPerBucket  int            `json:"queryLimitPerBucket"`
	MaxGroupsPerRun      int            `json:"maxGroupsPerRun"`
	QueryConcurrency     int            `json:"queryConcurrency"`
	RunTimeoutSecond     int            `json:"runTimeoutSecond"`
	HTTPTimeoutSecond    int            `json:"httpTimeoutSecond"`
	ResyncTimeSecond     int            `json:"resyncTimeSecond"`
	NamespacePrefix      string         `json:"namespacePrefix"`
	HighRiskPrefixes     []string       `json:"highRiskPrefixes"`
	Fields               VLogFields     `json:"fields"`
	ContentTypeAllowlist []string       `json:"contentTypeAllowlist"`
	SeedCacheWarmupDelay int            `json:"seedCacheWarmupDelaySecond"`
	ExtraQueryFilters    map[string]any `json:"extraQueryFilters"`
}

func (p *VLogPathPlugin) getDefaultVLogPathConfig() VLogPathConfig {
	// Defaults favor conservative discovery: HTML pages only, a one-day
	// lookback window, and higher priority for paths that commonly expose risk.
	return VLogPathConfig{
		App:                 "higress",
		IntervalHour:        6,
		LookbackHour:        24,
		BucketHour:          1,
		TopNPerHost:         50,
		QueryLimitPerBucket: 50,
		MaxGroupsPerRun:     500,
		QueryConcurrency:    3,
		RunTimeoutSecond:    900,
		HTTPTimeoutSecond:   30,
		ResyncTimeSecond:    30,
		NamespacePrefix:     "ns-",
		HighRiskPrefixes: []string{
			"/admin",
			"/login",
			"/pay",
			"/payment",
			"/promo",
			"/activity",
		},
		Fields:               DefaultVLogFields(),
		ContentTypeAllowlist: []string{"text/html", "application/xhtml+xml"},
		SeedCacheWarmupDelay: 5,
	}
}

func (p *VLogPathPlugin) Name() string {
	return pluginName
}

func (p *VLogPathPlugin) Type() string {
	return pluginType
}

// Start loads config, prepares dependencies, then starts the Kubernetes
// informer and periodic VLog scanner in background goroutines.
func (p *VLogPathPlugin) Start(
	ctx context.Context,
	cfg config.PluginConfig,
	bus *eventbus.EventBus,
) error {
	if err := p.loadConfig(cfg.Settings); err != nil {
		return err
	}

	p.eventBus = bus
	p.stopChan = make(chan struct{})
	p.seedCache = NewSeedCache()
	p.client = NewVLogClient(VLogClientConfig{
		BaseURL:             p.vlogPathConfig.LogServerPath,
		Username:            p.vlogPathConfig.Username,
		Password:            p.vlogPathConfig.Password,
		App:                 p.vlogPathConfig.App,
		Fields:              p.vlogPathConfig.Fields,
		HTTPTimeout:         time.Duration(p.vlogPathConfig.HTTPTimeoutSecond) * time.Second,
		ExtraQueryFilters:   p.vlogPathConfig.ExtraQueryFilters,
		QueryLimitPerBucket: p.vlogPathConfig.QueryLimitPerBucket,
	})

	go p.startIngressInformer(ctx)
	go p.startTicker(ctx)

	return nil
}

// Stop signals background goroutines to exit through the shared stop channel.
func (p *VLogPathPlugin) Stop(ctx context.Context) error {
	if p.stopChan != nil {
		close(p.stopChan)
	}
	return nil
}

func (p *VLogPathPlugin) loadConfig(setting string) error {
	// The JSON settings are treated as sparse overrides on top of defaults so
	// deploy manifests can specify only values that differ per environment.
	p.vlogPathConfig = p.getDefaultVLogPathConfig()
	if setting == "" {
		p.log.Info("Using default VLogPathDiscovery configuration")
		return nil
	}

	var configFromJSON VLogPathConfig

	err := json.Unmarshal([]byte(setting), &configFromJSON)
	if err != nil {
		p.log.Error("Failed to parse config, using defaults", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if configFromJSON.LogServerPath != "" {
		p.vlogPathConfig.LogServerPath = configFromJSON.LogServerPath
	}
	if configFromJSON.LogServerPathSnake != "" {
		p.vlogPathConfig.LogServerPath = configFromJSON.LogServerPathSnake
	}
	if configFromJSON.Username != "" {
		p.vlogPathConfig.Username = configFromJSON.Username
	}
	if configFromJSON.Password != "" {
		p.vlogPathConfig.Password = configFromJSON.Password
	}
	if configFromJSON.App != "" {
		p.vlogPathConfig.App = configFromJSON.App
	}
	if configFromJSON.IntervalHour > 0 {
		p.vlogPathConfig.IntervalHour = configFromJSON.IntervalHour
	}
	if configFromJSON.LookbackHour > 0 {
		p.vlogPathConfig.LookbackHour = configFromJSON.LookbackHour
	}
	if configFromJSON.BucketHour > 0 {
		p.vlogPathConfig.BucketHour = configFromJSON.BucketHour
	}
	if configFromJSON.TopNPerHost > 0 {
		p.vlogPathConfig.TopNPerHost = configFromJSON.TopNPerHost
	}
	if configFromJSON.QueryLimitPerBucket > 0 {
		p.vlogPathConfig.QueryLimitPerBucket = configFromJSON.QueryLimitPerBucket
	}
	if configFromJSON.MaxGroupsPerRun > 0 {
		p.vlogPathConfig.MaxGroupsPerRun = configFromJSON.MaxGroupsPerRun
	}
	if configFromJSON.QueryConcurrency > 0 {
		p.vlogPathConfig.QueryConcurrency = configFromJSON.QueryConcurrency
	}
	if configFromJSON.RunTimeoutSecond > 0 {
		p.vlogPathConfig.RunTimeoutSecond = configFromJSON.RunTimeoutSecond
	}
	if configFromJSON.HTTPTimeoutSecond > 0 {
		p.vlogPathConfig.HTTPTimeoutSecond = configFromJSON.HTTPTimeoutSecond
	}
	if configFromJSON.ResyncTimeSecond > 0 {
		p.vlogPathConfig.ResyncTimeSecond = configFromJSON.ResyncTimeSecond
	}
	if configFromJSON.NamespacePrefix != "" {
		p.vlogPathConfig.NamespacePrefix = configFromJSON.NamespacePrefix
	}
	if len(configFromJSON.HighRiskPrefixes) > 0 {
		p.vlogPathConfig.HighRiskPrefixes = configFromJSON.HighRiskPrefixes
	}
	p.vlogPathConfig.Fields = mergeVLogFields(p.vlogPathConfig.Fields, configFromJSON.Fields)
	if len(configFromJSON.ContentTypeAllowlist) > 0 {
		p.vlogPathConfig.ContentTypeAllowlist = normalizeContentTypes(
			configFromJSON.ContentTypeAllowlist,
		)
	}
	if configFromJSON.SeedCacheWarmupDelay > 0 {
		p.vlogPathConfig.SeedCacheWarmupDelay = configFromJSON.SeedCacheWarmupDelay
	}
	if len(configFromJSON.ExtraQueryFilters) > 0 {
		p.vlogPathConfig.ExtraQueryFilters = configFromJSON.ExtraQueryFilters
	}

	if err := p.resolveSecureConfigValues(); err != nil {
		return err
	}

	return nil
}

func (p *VLogPathPlugin) resolveSecureConfigValues() error {
	// Credentials and endpoints may be plain values or secure-value references
	// understood by the shared config package.
	logServerPath := strings.TrimSpace(p.vlogPathConfig.LogServerPath)
	if logServerPath != "" {
		resolved, err := config.GetSecureValue(logServerPath)
		if err != nil {
			return fmt.Errorf("resolve VLog logServerPath: %w", err)
		}

		p.vlogPathConfig.LogServerPath = strings.TrimSpace(resolved)
	}

	p.vlogPathConfig.Username = p.resolveOptionalSecureValue("username", p.vlogPathConfig.Username)
	p.vlogPathConfig.Password = p.resolveOptionalSecureValue("password", p.vlogPathConfig.Password)

	return nil
}

func (p *VLogPathPlugin) resolveOptionalSecureValue(field, value string) string {
	// Optional credentials resolve best-effort so an invalid optional secret does
	// not block deployments that rely on anonymous log access.
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	resolved, err := config.GetSecureValue(trimmed)
	if err != nil {
		p.log.Warn("Failed to resolve optional VLog secure config value", logger.Fields{
			"field": field,
			"error": err.Error(),
		})
		return trimmed
	}

	return strings.TrimSpace(resolved)
}

func (p *VLogPathPlugin) startTicker(ctx context.Context) {
	// Give the informer a short head start so the first scan can use an initial
	// cache of Ingress seed paths.
	if p.vlogPathConfig.SeedCacheWarmupDelay > 0 {
		select {
		case <-time.After(time.Duration(p.vlogPathConfig.SeedCacheWarmupDelay) * time.Second):
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		}
	}

	p.runOnce(ctx)

	ticker := time.NewTicker(time.Duration(p.vlogPathConfig.IntervalHour) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.runOnce(ctx)
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		}
	}
}

func (p *VLogPathPlugin) runOnce(ctx context.Context) {
	// Each run queries logs by host and time bucket, then publishes only ranked
	// child paths that are backed by current Ingress seed paths.
	if p.client == nil || p.eventBus == nil || p.seedCache == nil {
		return
	}

	if p.vlogPathConfig.LogServerPath == "" {
		p.log.Warn("VLog server path is empty, skip VLog path discovery")
		return
	}

	groups := p.seedCache.Groups()
	if len(groups) == 0 {
		p.log.Debug("Seed path cache is empty")
		return
	}

	runCtx := ctx
	cancel := func() {}
	if p.vlogPathConfig.RunTimeoutSecond > 0 {
		runCtx, cancel = context.WithTimeout(
			ctx,
			time.Duration(p.vlogPathConfig.RunTimeoutSecond)*time.Second,
		)
	}
	defer cancel()

	now := time.Now()
	windowStart := now.Add(-time.Duration(p.vlogPathConfig.LookbackHour) * time.Hour)
	bucketDuration := time.Duration(p.vlogPathConfig.BucketHour) * time.Hour

	if p.vlogPathConfig.MaxGroupsPerRun > 0 && len(groups) > p.vlogPathConfig.MaxGroupsPerRun {
		p.log.Warn("VLog path discovery group count exceeds per-run limit", logger.Fields{
			"seed_groups":        len(groups),
			"max_groups_per_run": p.vlogPathConfig.MaxGroupsPerRun,
		})
		groups = groups[:p.vlogPathConfig.MaxGroupsPerRun]
	}

	totalPublished := p.processGroups(runCtx, groups, windowStart, now, bucketDuration)

	p.log.Info("VLog path discovery run completed", logger.Fields{
		"seed_groups":     len(groups),
		"published_paths": totalPublished,
	})
}

func (p *VLogPathPlugin) processGroups(
	ctx context.Context,
	groups []SeedPathGroup,
	windowStart time.Time,
	now time.Time,
	bucketDuration time.Duration,
) int {
	concurrency := p.vlogPathConfig.QueryConcurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > len(groups) && len(groups) > 0 {
		concurrency = len(groups)
	}

	groupCh := make(chan SeedPathGroup)
	publishedCh := make(chan int, len(groups))
	var wg sync.WaitGroup

	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for group := range groupCh {
				publishedCh <- p.processGroup(ctx, group, windowStart, now, bucketDuration)
			}
		}()
	}

	go func() {
		defer close(groupCh)
		for _, group := range groups {
			select {
			case <-ctx.Done():
				return
			case groupCh <- group:
			}
		}
	}()

	wg.Wait()
	close(publishedCh)

	totalPublished := 0
	for count := range publishedCh {
		totalPublished += count
	}

	return totalPublished
}

func (p *VLogPathPlugin) processGroup(
	ctx context.Context,
	group SeedPathGroup,
	windowStart time.Time,
	now time.Time,
	bucketDuration time.Duration,
) int {
	candidates := make(map[string]*CandidatePath)
	// Bucketed queries keep individual VLog requests bounded while still
	// covering the full lookback window.
	for start := windowStart; start.Before(now); start = start.Add(bucketDuration) {
		select {
		case <-ctx.Done():
			p.log.Warn("VLog path discovery group processing stopped by context", logger.Fields{
				"host":      group.Host,
				"namespace": group.Namespace,
				"error":     ctx.Err().Error(),
			})
			return 0
		default:
		}

		end := start.Add(bucketDuration)
		if end.After(now) {
			end = now
		}

		entries, err := p.client.Query(
			ctx,
			group.Host,
			start,
			end,
			p.vlogPathConfig.QueryLimitPerBucket,
		)
		if err != nil {
			p.log.Error("Failed to query VLog", logger.Fields{
				"host":      group.Host,
				"namespace": group.Namespace,
				"start":     start.Format(time.RFC3339),
				"end":       end.Format(time.RFC3339),
				"error":     err.Error(),
			})
			continue
		}

		p.collectCandidates(group, entries, candidates)
	}

	ranked := RankCandidates(
		mapCandidates(candidates),
		p.vlogPathConfig.TopNPerHost,
		p.vlogPathConfig.HighRiskPrefixes,
	)
	for _, candidate := range ranked {
		p.publishCandidate(candidate)
	}

	return len(ranked)
}

func (p *VLogPathPlugin) collectCandidates(
	group SeedPathGroup,
	entries []VLogEntry,
	candidates map[string]*CandidatePath,
) {
	for _, entry := range entries {
		// Keep candidates scoped to the host group built from Kubernetes Ingress
		// state; this prevents cross-host log noise from creating discoveries.
		if entry.Host != "" && !strings.EqualFold(entry.Host, group.Host) {
			continue
		}

		if !isPageRequest(entry, p.vlogPathConfig.ContentTypeAllowlist) {
			continue
		}

		normalizedPath, ok := NormalizePath(entry.Path)
		if !ok {
			continue
		}

		seed, ok := group.Match(normalizedPath)
		if !ok {
			continue
		}

		key := fmt.Sprintf("%s\x00%s\x00%s", seed.Namespace, seed.Host, normalizedPath)
		candidate, exists := candidates[key]
		if !exists {
			candidate = &CandidatePath{
				Seed: seed,
				Path: normalizedPath,
			}
			candidates[key] = candidate
		}

		candidate.Count++
		if entry.Time.After(candidate.LatestAccessTime) {
			candidate.LatestAccessTime = entry.Time
		}
	}
}

func (p *VLogPathPlugin) publishCandidate(candidate CandidatePath) {
	// The emitted payload uses the same DiscoveryInfo model as informer-based
	// discovery plugins, allowing downstream detectors to consume it unchanged.
	info := models.DiscoveryInfo{
		DiscoveryName: candidate.Seed.DiscoveryName,
		Name:          candidate.Seed.IngressName,
		Namespace:     candidate.Seed.Namespace,
		Host:          candidate.Seed.Host,
		Path:          []string{candidate.Path},
		ServiceName:   candidate.Seed.ServiceName,
		HasActivePods: candidate.Seed.HasActivePods,
		PodCount:      candidate.Seed.PodCount,
	}

	p.eventBus.Publish(constants.DiscoveryTopic, eventbus.Event{
		Payload: info,
	})

	p.log.Debug("Published VLog discovered path", logger.Fields{
		"namespace": info.Namespace,
		"name":      info.Name,
		"host":      info.Host,
		"path":      info.Path,
		"count":     candidate.Count,
	})
}

func mapCandidates(candidates map[string]*CandidatePath) []CandidatePath {
	// Pre-sort for deterministic ordering before applying the priority ranking.
	items := make([]CandidatePath, 0, len(candidates))
	for _, candidate := range candidates {
		items = append(items, *candidate)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Path < items[j].Path
	})

	return items
}

func isPageRequest(entry VLogEntry, allowlist []string) bool {
	// Discovery focuses on successful page navigations so API calls and static
	// assets do not flood the candidate list.
	if entry.Method != "" && entry.Method != http.MethodGet {
		return false
	}

	if entry.StatusCode > 0 && (entry.StatusCode < 200 || entry.StatusCode >= 400) {
		return false
	}

	return isAllowedContentType(entry.ResponseContentType, allowlist)
}
