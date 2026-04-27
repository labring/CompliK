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

// Package scanner provides the core process scanning and threat detection functionality
// for ProcScan, including scheduling, analysis, and response actions.
package scanner

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/internal/core/alert"
	k8sClient "github.com/bearslyricattack/CompliK/procscan/internal/core/k8s"
	"github.com/bearslyricattack/CompliK/procscan/internal/core/processor"
	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
	"github.com/bearslyricattack/CompliK/procscan/pkg/metrics"
	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

type Scanner struct {
	config     *models.Config
	processor  *processor.Processor
	k8sClient  k8sClientInterface
	notifier   notifierInterface
	metrics    *metrics.Collector
	metricsSrv *metrics.Server
	mu         sync.RWMutex
	ticker     *time.Ticker
}

// k8sClientInterface defines the interface for Kubernetes client operations
type k8sClientInterface interface {
	LabelNamespace(namespaceName string, labels map[string]string) error
}

// notifierInterface defines the interface for notification operations
type notifierInterface interface {
	SendThreatAlert(threat ThreatInfo) error
	SendSimpleNotification(message string) error
}

// ThreatInfo represents threat information structure
type ThreatInfo struct {
	PodName     string
	Namespace   string
	ProcessName string
	ProcessCmd  string
	ThreatType  string
	Severity    string
	Description string
	Labels      map[string]string
}

// K8sClientAdapter adapts Kubernetes clientset to k8sClientInterface
type K8sClientAdapter struct {
	clientset *kubernetes.Clientset
}

func (a *K8sClientAdapter) LabelNamespace(namespaceName string, labels map[string]string) error {
	return k8sClient.LabelNamespace(a.clientset, namespaceName, labels)
}

// NewScanner creates a new scanner instance with the provided configuration
func NewScanner(config *models.Config) *Scanner {
	// Initialize Kubernetes client
	k8sClientset, err := k8sClient.NewK8sClient()
	if err != nil {
		legacy.L.WithError(err).Warn("Failed to create K8s client, labeling feature will be unavailable")
		k8sClientset = nil
	}

	var k8sAdapter k8sClientInterface
	if k8sClientset != nil {
		k8sAdapter = &K8sClientAdapter{clientset: k8sClientset}
	}

	// Initialize metrics collector
	metricsCollector := metrics.NewCollector()

	// Initialize metrics server
	var metricsServer *metrics.Server
	if config.Metrics.Enabled {
		metricsServer = metrics.NewMetricsServerFromConfig(config.Metrics)
		legacy.L.WithFields(logrus.Fields{
			"port": config.Metrics.Port,
			"path": config.Metrics.Path,
		}).Info("Metrics server configured")
	} else {
		legacy.L.Info("Metrics server disabled")
	}

	return &Scanner{
		config:     config,
		processor:  processor.NewProcessor(config),
		k8sClient:  k8sAdapter,
		metrics:    metricsCollector,
		metricsSrv: metricsServer,
	}
}

// UpdateConfig updates the scanner configuration and applies changes
func (s *Scanner) UpdateConfig(newConfig *models.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()

	legacy.L.Info("Applying new configuration...")
	oldConfig := s.config
	s.config = newConfig

	if oldConfig.Scanner.LogLevel != newConfig.Scanner.LogLevel {
		legacy.SetLevel(newConfig.Scanner.LogLevel)
	}
	if oldConfig.Actions.Label.Enabled != newConfig.Actions.Label.Enabled {
		legacy.L.WithFields(logrus.Fields{
			"key":  "actions.label.enabled",
			"from": oldConfig.Actions.Label.Enabled,
			"to":   newConfig.Actions.Label.Enabled,
		}).Info("Configuration changed")
	}

	oldInterval := oldConfig.Scanner.ScanInterval
	newInterval := newConfig.Scanner.ScanInterval
	if oldInterval != newInterval {
		if s.ticker != nil {
			s.ticker.Reset(newInterval)
		}
		legacy.L.WithFields(logrus.Fields{
			"key":  "scanner.scan_interval",
			"from": oldInterval.String(),
			"to":   newInterval.String(),
		}).Info("Configuration changed")
	}

	s.processor.UpdateConfig(newConfig)
	legacy.L.Info("Detection rules refreshed")

	legacy.L.Info("Configuration hot-reloaded successfully")
}

// Start initializes and starts the scanner
func (s *Scanner) Start(ctx context.Context) error {
	s.processor = processor.NewProcessor(s.config)

	// Check service initialization status
	if s.k8sClient != nil {
		legacy.L.Info("K8s client initialized successfully")
	} else {
		legacy.L.Warn("K8s client not initialized, labeling feature will be unavailable")
	}

	// Start metrics server
	if s.metricsSrv != nil {
		go func() {
			if err := s.metricsSrv.StartWithRetry(ctx, 3, 5*time.Second); err != nil {
				legacy.L.WithError(err).Error("Failed to start metrics server")
			}
		}()
	}

	// Start metrics collector
	if s.metrics != nil {
		go s.metrics.StartMetricsUpdater(ctx, 30*time.Second)
		s.metrics.RecordScanStart()
	}

	initialInterval := s.config.Scanner.ScanInterval
	s.ticker = time.NewTicker(initialInterval)

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = "unknown"
	}
	legacy.L.WithFields(logrus.Fields{
		"node":     nodeName,
		"interval": initialInterval.String(),
	}).Info("ProcScan process scanner started")

	return s.runScanLoop(ctx)
}

func (s *Scanner) runScanLoop(ctx context.Context) error {
	defer s.ticker.Stop()
	defer func() {
		if s.metrics != nil {
			metrics.ScannerRunning.Set(0)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			legacy.L.Info("Scanner stopped")
			if s.metricsSrv != nil {
				s.metricsSrv.Stop(ctx)
			}
			return ctx.Err()
		case <-s.ticker.C:
			scanStart := time.Now()
			if err := s.scanProcesses(); err != nil {
				legacy.L.WithError(err).Error("Failed to scan processes")
				if s.metrics != nil {
					s.metrics.RecordScanError()
				}
			} else {
				if s.metrics != nil {
					s.metrics.RecordScanComplete(time.Since(scanStart))
				}
			}
		}
	}
}

func (s *Scanner) scanProcesses() error {
	legacy.L.Info("Starting new scan round...")

	s.mu.RLock()
	currentConfig := s.config
	s.mu.RUnlock()

	pids, err := s.processor.GetAllProcesses()
	if err != nil {
		return err
	}
	legacy.L.WithField("count", len(pids)).Info("Starting process analysis...")

	// Record number of processes to analyze
	if s.metrics != nil {
		s.metrics.RecordProcessesAnalyzed(len(pids))
	}

	numWorkers := runtime.NumCPU()
	pidChan := make(chan int, len(pids))
	resultsChan := make(chan *models.ProcessInfo, len(pids))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for pid := range pidChan {
				processInfo, _ := s.processor.AnalyzeProcess(pid)
				if processInfo != nil {
					resultsChan <- processInfo
				}
			}
		}(i)
	}

	for _, pid := range pids {
		pidChan <- pid
	}
	close(pidChan)

	wg.Wait()
	close(resultsChan)
	legacy.L.Info("All process analysis completed")

	resultsByNamespace := make(map[string][]*models.ProcessInfo)
	for processInfo := range resultsChan {
		resultsByNamespace[processInfo.Namespace] = append(resultsByNamespace[processInfo.Namespace], processInfo)
	}

	if len(resultsByNamespace) == 0 {
		legacy.L.Info("Scan round found 0 suspicious processes")
		return nil
	}

	// Record suspicious process metrics
	if s.metrics != nil {
		for namespace, processInfos := range resultsByNamespace {
			s.metrics.RecordSuspiciousProcesses(len(processInfos), namespace)
		}
	}

	legacy.L.WithFields(logrus.Fields{
		"namespaces_with_violations": len(resultsByNamespace),
	}).Info("Found suspicious processes, starting grouped processing...")

	finalResults := make([]*alert.NamespaceScanResult, 0, len(resultsByNamespace))
	for namespace, processInfos := range resultsByNamespace {
		s.reportProcscanViolations(processInfos)

		labelResult := s.handleGroupedActions(namespace, currentConfig)
		finalResults = append(finalResults, &alert.NamespaceScanResult{
			Namespace:    namespace,
			ProcessInfos: processInfos,
			LabelResult:  labelResult,
		})
	}

	if len(finalResults) > 0 {
		if err := alert.SendGlobalBatchAlert(finalResults, currentConfig.Notifications.Lark.Webhook, currentConfig.Notifications.Region); err != nil {
			legacy.L.WithError(err).Error("Failed to send global batch Lark alert")
		}
	}

	legacy.L.Info("Scan round completed")
	return nil
}

func (s *Scanner) handleGroupedActions(namespace string, config *models.Config) (labelResult string) {
	if config.Actions.Label.Enabled {
		if s.k8sClient != nil {
			labels := config.Actions.Label.Data
			if len(labels) == 0 {
				labels = map[string]string{"clawcloud.run/status": "locked"}
			}
			legacy.L.WithFields(logrus.Fields{
				"namespace": namespace,
				"labels":    labels,
			}).Info("Adding security labels to namespace")
			if err := s.k8sClient.LabelNamespace(namespace, labels); err != nil {
				legacy.L.WithFields(logrus.Fields{
					"namespace": namespace,
				}).WithError(err).Error("Failed to add security labels to namespace")
				labelResult = fmt.Sprintf("Failed: %v", err)
				if s.metrics != nil {
					s.metrics.RecordLabelAction(false)
				}
			} else {
				labelResult = "Success"
				legacy.L.WithFields(logrus.Fields{
					"namespace": namespace,
				}).Info("Security labels added successfully, waiting for external controller to process")
				if s.metrics != nil {
					s.metrics.RecordLabelAction(true)
				}
			}
		} else {
			labelResult = "Cannot execute (K8s client unavailable)"
		}
	} else {
		labelResult = "Feature disabled"
	}
	return
}
