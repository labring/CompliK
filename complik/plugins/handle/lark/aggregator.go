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

//nolint:wsl_v5 // Aggregation code keeps related state transitions compact.
package lark

import (
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
)

const (
	defaultAggregationWindow     = 5 * time.Minute
	defaultMaxAggregationBuckets = 1000
	defaultMaxPathsPerBucket     = 50
)

type NotificationAggregator struct {
	mu                sync.Mutex
	window            time.Duration
	maxBuckets        int
	maxPathsPerBucket int
	notifier          *Notifier
	log               logger.Logger
	buckets           map[string]*notificationBucket
	stopped           bool
}

type notificationBucket struct {
	key       string
	alert     AggregatedAlert
	timer     *time.Timer
	createdAt time.Time
}

func NewNotificationAggregator(
	window time.Duration,
	maxBuckets int,
	maxPathsPerBucket int,
	notifier *Notifier,
	log logger.Logger,
) *NotificationAggregator {
	if window <= 0 {
		window = defaultAggregationWindow
	}
	if maxBuckets <= 0 {
		maxBuckets = defaultMaxAggregationBuckets
	}
	if maxPathsPerBucket <= 0 {
		maxPathsPerBucket = defaultMaxPathsPerBucket
	}

	return &NotificationAggregator{
		window:            window,
		maxBuckets:        maxBuckets,
		maxPathsPerBucket: maxPathsPerBucket,
		notifier:          notifier,
		log:               log,
		buckets:           make(map[string]*notificationBucket),
	}
}

func (a *NotificationAggregator) Add(result *models.DetectorInfo) {
	if !shouldAggregate(result) {
		return
	}

	now := time.Now()
	key := aggregateKey(result.Namespace, result.Host)

	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return
	}

	bucket, exists := a.buckets[key]
	if !exists {
		if len(a.buckets) >= a.maxBuckets {
			a.mu.Unlock()
			a.log.Warn("Aggregated notification bucket limit reached", logger.Fields{
				"namespace":   result.Namespace,
				"host":        result.Host,
				"max_buckets": a.maxBuckets,
			})
			return
		}

		bucket = &notificationBucket{
			key: key,
			alert: AggregatedAlert{
				Region:      result.Region,
				Namespace:   result.Namespace,
				Host:        result.Host,
				Resource:    result.Name,
				FirstSeenAt: now,
				LastSeenAt:  now,
				Paths:       make(map[string]*AggregatedPath),
			},
			createdAt: now,
		}
		a.buckets[key] = bucket
		bucket.timer = time.AfterFunc(a.window, func() {
			a.flush(key)
		})
	}

	mergeDetectorInfo(&bucket.alert, result, now, a.maxPathsPerBucket)
	a.mu.Unlock()
}

func (a *NotificationAggregator) Stop() {
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return
	}
	a.stopped = true

	keys := make([]string, 0, len(a.buckets))
	for key := range a.buckets {
		keys = append(keys, key)
	}
	a.mu.Unlock()

	for _, key := range keys {
		a.flush(key)
	}
}

func (a *NotificationAggregator) flush(key string) {
	a.mu.Lock()
	bucket, exists := a.buckets[key]
	if !exists {
		a.mu.Unlock()
		return
	}

	delete(a.buckets, key)
	if bucket.timer != nil {
		bucket.timer.Stop()
	}

	alert := bucket.alert.snapshot()
	a.mu.Unlock()

	if len(alert.Paths) == 0 {
		return
	}

	if err := a.notifier.SendAggregatedNotification(alert); err != nil {
		a.log.Error("Failed to send aggregated notification", logger.Fields{
			"error":      err.Error(),
			"namespace":  alert.Namespace,
			"host":       alert.Host,
			"path_count": len(alert.Paths),
		})

		return
	}

	a.log.Info("Aggregated notification sent", logger.Fields{
		"namespace":  alert.Namespace,
		"host":       alert.Host,
		"path_count": len(alert.Paths),
	})
}

func shouldAggregate(result *models.DetectorInfo) bool {
	return result != nil &&
		result.IsIllegal &&
		strings.TrimSpace(result.Namespace) != "" &&
		strings.TrimSpace(result.Host) != ""
}

func aggregateKey(namespace, host string) string {
	return strings.TrimSpace(namespace) + "\x00" + strings.ToLower(strings.TrimSpace(host))
}

func mergeDetectorInfo(
	alert *AggregatedAlert,
	result *models.DetectorInfo,
	now time.Time,
	maxPaths int,
) {
	if strings.TrimSpace(alert.Region) == "" {
		alert.Region = strings.TrimSpace(result.Region)
	}
	if strings.TrimSpace(alert.Resource) == "" {
		alert.Resource = strings.TrimSpace(result.Name)
	}

	if alert.FirstSeenAt.IsZero() || now.Before(alert.FirstSeenAt) {
		alert.FirstSeenAt = now
	}
	if now.After(alert.LastSeenAt) {
		alert.LastSeenAt = now
	}

	if alert.Paths == nil {
		alert.Paths = make(map[string]*AggregatedPath)
	}

	paths := normalizedResultPaths(result)
	for _, path := range paths {
		item := alert.Paths[path]
		if item == nil {
			if maxPaths > 0 && len(alert.Paths) >= maxPaths {
				alert.OmittedPathCount++
				continue
			}

			item = &AggregatedPath{
				Path:         path,
				URL:          urlForPath(result, path),
				Detectors:    make(map[string]struct{}),
				Keywords:     make(map[string]struct{}),
				Devices:      make(map[string]struct{}),
				Descriptions: make(map[string]struct{}),
				Explanations: make(map[string]struct{}),
			}
			alert.Paths[path] = item
		}

		if strings.TrimSpace(item.URL) == "" {
			item.URL = urlForPath(result, path)
		}

		addSetValue(item.Detectors, result.DetectorName)
		addSetValue(item.Devices, result.DeviceProfile)
		addSetValue(item.Descriptions, result.Description)
		addSetValue(item.Explanations, result.Explanation)
		for _, keyword := range result.Keywords {
			addSetValue(item.Keywords, keyword)
		}
	}
}

func normalizedResultPaths(result *models.DetectorInfo) []string {
	if result == nil {
		return nil
	}

	seen := make(map[string]struct{})
	paths := make([]string, 0, len(result.Path))
	for _, rawPath := range result.Path {
		path := normalizeAlertPath(rawPath)
		if _, exists := seen[path]; exists {
			continue
		}

		seen[path] = struct{}{}
		paths = append(paths, path)
	}

	if len(paths) == 0 {
		paths = append(paths, pathFromURL(result.URL))
	}

	sort.Strings(paths)

	return paths
}

func normalizeAlertPath(value string) string {
	path := strings.TrimSpace(value)
	if path == "" {
		return "/"
	}

	if parsed, err := url.Parse(path); err == nil && parsed.Path != "" {
		path = parsed.Path
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return path
}

func pathFromURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err == nil && strings.TrimSpace(parsed.Path) != "" {
		return normalizeAlertPath(parsed.Path)
	}

	return "/"
}

func urlForPath(result *models.DetectorInfo, path string) string {
	rawURL := strings.TrimSpace(result.URL)
	if rawURL == "" {
		return ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return rawURL
	}

	parsed.Path = normalizeAlertPath(path)
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String()
}

func addSetValue(set map[string]struct{}, value string) {
	item := strings.TrimSpace(value)
	if item == "" {
		return
	}

	set[item] = struct{}{}
}
