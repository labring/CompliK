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

package logger

import (
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"
)

// MetricsCollector collects and reports performance metrics for the application
type MetricsCollector struct {
	mu         sync.RWMutex
	logger     Logger
	interval   time.Duration
	stopChan   chan struct{}
	metrics    *SystemMetrics
	operations map[string]*OperationMetrics
}

// SystemMetrics represents system-level performance metrics
type SystemMetrics struct {
	CPUUsage       float64
	MemoryUsage    uint64
	GoroutineCount int
	GCPauseTime    time.Duration
	Uptime         time.Duration
	StartTime      time.Time
}

// OperationMetrics tracks metrics for specific operations
type OperationMetrics struct {
	Count       int64
	TotalTime   time.Duration
	MinTime     time.Duration
	MaxTime     time.Duration
	LastTime    time.Duration
	ErrorCount  int64
	SuccessRate float64
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(logger Logger, interval time.Duration) *MetricsCollector {
	return &MetricsCollector{
		logger:     logger,
		interval:   interval,
		stopChan:   make(chan struct{}),
		metrics:    &SystemMetrics{StartTime: time.Now()},
		operations: make(map[string]*OperationMetrics),
	}
}

// Start begins collecting and reporting metrics
func (mc *MetricsCollector) Start() {
	go mc.collectSystemMetrics()
	go mc.reportMetrics()
}

// Stop stops the metrics collection
func (mc *MetricsCollector) Stop() {
	close(mc.stopChan)
}

// RecordOperation records metrics for a single operation
func (mc *MetricsCollector) RecordOperation(name string, duration time.Duration, err error) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	op, exists := mc.operations[name]
	if !exists {
		op = &OperationMetrics{
			MinTime: duration,
			MaxTime: duration,
		}
		mc.operations[name] = op
	}

	op.Count++
	op.TotalTime += duration
	op.LastTime = duration

	if duration < op.MinTime {
		op.MinTime = duration
	}

	if duration > op.MaxTime {
		op.MaxTime = duration
	}

	if err != nil {
		op.ErrorCount++
	}

	if op.Count > 0 {
		op.SuccessRate = float64(op.Count-op.ErrorCount) / float64(op.Count) * 100
	}
}

// collectSystemMetrics collects system metrics at regular intervals
func (mc *MetricsCollector) collectSystemMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mc.updateSystemMetrics()
		case <-mc.stopChan:
			return
		}
	}
}

// updateSystemMetrics updates the current system metrics
func (mc *MetricsCollector) updateSystemMetrics() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	mc.metrics.MemoryUsage = m.Alloc

	mc.metrics.GoroutineCount = runtime.NumGoroutine()
	if m.PauseTotalNs > math.MaxInt64 {
		mc.metrics.GCPauseTime = time.Duration(math.MaxInt64)
	} else {
		mc.metrics.GCPauseTime = time.Duration(m.PauseTotalNs)
	}

	mc.metrics.GCPauseTime = time.Duration(m.PauseTotalNs)
	mc.metrics.Uptime = time.Since(mc.metrics.StartTime)
}

// reportMetrics reports metrics to the logger at regular intervals
func (mc *MetricsCollector) reportMetrics() {
	ticker := time.NewTicker(mc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mc.logMetrics()
		case <-mc.stopChan:
			return
		}
	}
}

// logMetrics logs all collected metrics
func (mc *MetricsCollector) logMetrics() {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	// System metrics
	mc.logger.Info("System metrics", Fields{
		"memory_mb":      mc.metrics.MemoryUsage / 1024 / 1024,
		"goroutines":     mc.metrics.GoroutineCount,
		"gc_pause_ms":    mc.metrics.GCPauseTime.Milliseconds(),
		"uptime_minutes": mc.metrics.Uptime.Minutes(),
	})

	// Operation metrics
	for name, op := range mc.operations {
		avgTime := time.Duration(0)
		if op.Count > 0 {
			avgTime = op.TotalTime / time.Duration(op.Count)
		}

		mc.logger.Info("Operation metrics", Fields{
			"operation":    name,
			"count":        op.Count,
			"avg_ms":       avgTime.Milliseconds(),
			"min_ms":       op.MinTime.Milliseconds(),
			"max_ms":       op.MaxTime.Milliseconds(),
			"last_ms":      op.LastTime.Milliseconds(),
			"errors":       op.ErrorCount,
			"success_rate": fmt.Sprintf("%.2f%%", op.SuccessRate),
		})
	}
}

var globalMetrics *MetricsCollector
