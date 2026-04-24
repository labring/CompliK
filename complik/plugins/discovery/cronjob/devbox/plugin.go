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

package devbox

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/k8s"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
	"github.com/bearslyricattack/CompliK/complik/plugins/discovery/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	pluginName = constants.DiscoveryCronJobDevboxName
	pluginType = constants.DiscoveryCronJobPluginType
)

const (
	DevboxGroup        = "devbox.sealos.io"
	DevboxVersion      = "v1alpha1"
	DevboxResource     = "devboxes"
	DevboxManagerLabel = "cloud.sealos.io/devbox-manager"
)

const (
	IntervalHours = 12 * 60 * time.Minute
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &DevboxPlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type DevboxPlugin struct {
	log          logger.Logger
	devboxConfig DevboxConfig
}

type DevboxConfig struct {
	IntervalMinute  int  `json:"intervalMinute"`
	AutoStart       bool `json:"autoStart"`
	StartTimeSecond int  `json:"startTimeSecond"`
}

func (p *DevboxPlugin) getDefaultDevboxConfig() DevboxConfig {
	return DevboxConfig{
		IntervalMinute:  7 * 24 * 60,
		AutoStart:       false,
		StartTimeSecond: 60,
	}
}

func (p *DevboxPlugin) loadConfig(setting string) error {
	p.log.Debug("Loading DevBox plugin configuration")

	p.devboxConfig = p.getDefaultDevboxConfig()
	if setting == "" {
		p.log.Info("Using default DevBox configuration")
		return nil
	}

	p.log.Debug("Parsing custom configuration", logger.Fields{
		"settingLength": len(setting),
	})

	var configFromJSON DevboxConfig

	err := json.Unmarshal([]byte(setting), &configFromJSON)
	if err != nil {
		p.log.Error("Failed to parse configuration, using defaults", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if configFromJSON.IntervalMinute > 0 {
		p.devboxConfig.IntervalMinute = configFromJSON.IntervalMinute
		p.log.Debug(
			"Set interval from config",
			logger.Fields{"intervalMinute": configFromJSON.IntervalMinute},
		)
	}

	if configFromJSON.AutoStart {
		p.devboxConfig.AutoStart = configFromJSON.AutoStart
		p.log.Debug("Set autoStart from config", logger.Fields{"autoStart": true})
	}

	if configFromJSON.StartTimeSecond > 0 {
		p.devboxConfig.StartTimeSecond = configFromJSON.StartTimeSecond
		p.log.Debug(
			"Set startTime from config",
			logger.Fields{"startTimeSecond": configFromJSON.StartTimeSecond},
		)
	}

	p.log.Info("DevBox configuration loaded successfully", logger.Fields{
		"intervalMinute":  p.devboxConfig.IntervalMinute,
		"autoStart":       p.devboxConfig.AutoStart,
		"startTimeSecond": p.devboxConfig.StartTimeSecond,
	})

	return nil
}

func (p *DevboxPlugin) Name() string {
	return pluginName
}

func (p *DevboxPlugin) Type() string {
	return pluginType
}

func (p *DevboxPlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	p.log.Info("Starting DevBox plugin", logger.Fields{
		"plugin": pluginName,
	})

	err := p.loadConfig(config.Settings)
	if err != nil {
		p.log.Error("Failed to load configuration", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if p.devboxConfig.AutoStart {
		p.log.Info("Auto-start enabled, executing initial task", logger.Fields{
			"startDelay": p.devboxConfig.StartTimeSecond,
		})
		time.Sleep(time.Duration(p.devboxConfig.StartTimeSecond) * time.Second)
		p.executeTask(ctx, eventBus)
	} else {
		p.log.Debug("Auto-start disabled, waiting for scheduled intervals")
	}

	go func() {
		interval := time.Duration(p.devboxConfig.IntervalMinute) * time.Minute
		p.log.Info("Starting scheduled task ticker", logger.Fields{
			"interval": interval.String(),
		})

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p.log.Debug("Scheduled task trigger")

				taskCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				p.executeTask(taskCtx, eventBus)
				cancel()
			case <-ctx.Done():
				p.log.Info("Context cancelled, stopping DevBox plugin scheduler")
				return
			}
		}
	}()

	p.log.Info("DevBox plugin started successfully")

	return nil
}

func (p *DevboxPlugin) Stop(ctx context.Context) error {
	p.log.Info("Stopping DevBox plugin")
	return nil
}

func (p *DevboxPlugin) executeTask(ctx context.Context, eventBus *eventbus.EventBus) {
	select {
	case <-ctx.Done():
		p.log.Warn("Context cancelled before task execution")
		return
	default:
	}

	ingressList, err := p.GetIngressList(ctx)
	if err != nil {
		p.log.Error("Failed to get ingress list", logger.Fields{"error": err.Error()})
		return
	}

	publishedCount := 0
	for i, ingress := range ingressList {
		if i%100 == 0 {
			select {
			case <-ctx.Done():
				p.log.Warn("Context cancelled during task execution", logger.Fields{
					"publishedCount": publishedCount,
					"totalCount":     len(ingressList),
				})

				return
			default:
			}
		}

		eventBus.Publish(constants.DiscoveryTopic, eventbus.Event{
			Payload: ingress,
		})

		publishedCount++
	}
}

func (p *DevboxPlugin) GetIngressList(ctx context.Context) ([]models.DiscoveryInfo, error) {
	p.log.Debug("Getting DevBox ingress list", logger.Fields{
		"labelSelector": DevboxManagerLabel,
	})

	var ingressList []models.DiscoveryInfo

	ingresses, err := k8s.ClientSet.NetworkingV1().
		Ingresses("").
		List(ctx, metav1.ListOptions{
			LabelSelector: DevboxManagerLabel,
		})
	if err != nil {
		p.log.Error("Failed to list DevBox ingresses", logger.Fields{
			"labelSelector": DevboxManagerLabel,
			"error":         err.Error(),
		})

		return nil, fmt.Errorf("failed to list ingresses: %w", err)
	}

	p.log.Debug("Retrieved DevBox ingresses", logger.Fields{
		"ingressCount": len(ingresses.Items),
	})

	devboxGVR := schema.GroupVersionResource{
		Group:    DevboxGroup,
		Version:  DevboxVersion,
		Resource: DevboxResource,
	}

	p.log.Debug("Listing DevBox resources", logger.Fields{
		"group":    DevboxGroup,
		"version":  DevboxVersion,
		"resource": DevboxResource,
	})

	devboxes, err := k8s.DynamicClient.Resource(devboxGVR).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		p.log.Error("Failed to list DevBox resources", logger.Fields{
			"group":    DevboxGroup,
			"version":  DevboxVersion,
			"resource": DevboxResource,
			"error":    err.Error(),
		})

		return nil, fmt.Errorf("failed to list devboxes: %w", err)
	}

	p.log.Debug("Retrieved DevBox resources", logger.Fields{
		"devboxCount": len(devboxes.Items),
	})
	statusMap := make(map[string]string, len(devboxes.Items))

	runningCount := 0
	for _, devbox := range devboxes.Items {
		key := fmt.Sprintf("%s/%s", devbox.GetNamespace(), devbox.GetName())
		if phase, found, err := unstructured.NestedString(
			devbox.Object,
			"status",
			"phase",
		); err == nil &&
			found {
			statusMap[key] = phase
			p.log.Debug("DevBox status retrieved", logger.Fields{
				"devbox": key,
				"phase":  phase,
			})

			if phase == "Running" {
				runningCount++
			}
		} else {
			p.log.Warn("Unable to get DevBox status", logger.Fields{
				"devbox": key,
				"error":  fmt.Sprintf("%v", err),
			})
		}
	}

	p.log.Info("DevBox status summary", logger.Fields{
		"totalDevBoxes": len(devboxes.Items),
		"runningCount":  runningCount,
	})

	processedCount := 0
	activeCount := 0

	skippedCount := 0
	for _, ingress := range ingresses.Items {
		devboxName, ok := ingress.Labels[DevboxManagerLabel]
		if !ok {
			p.log.Debug("Ingress missing DevBox manager label", logger.Fields{
				"ingress":  fmt.Sprintf("%s/%s", ingress.Namespace, ingress.Name),
				"labelKey": DevboxManagerLabel,
			})

			skippedCount++

			continue
		}

		key := fmt.Sprintf("%s/%s", ingress.Namespace, devboxName)
		phase, exists := statusMap[key]

		if exists && phase == "Running" {
			p.log.Debug("Processing active DevBox ingress", logger.Fields{
				"ingress": fmt.Sprintf("%s/%s", ingress.Namespace, ingress.Name),
				"devbox":  key,
				"phase":   phase,
			})
			discoveryInfos := utils.GenerateDiscoveryInfo(ingress, true, 1, p.Name())
			ingressList = append(ingressList, discoveryInfos...)
			activeCount++
		} else {
			p.log.Debug("Processing inactive DevBox ingress", logger.Fields{
				"ingress": fmt.Sprintf("%s/%s", ingress.Namespace, ingress.Name),
				"devbox":  key,
				"phase":   phase,
				"exists":  exists,
			})
			ingressInfo := models.DiscoveryInfo{
				DiscoveryName: p.Name(),
				Name:          ingress.Name,
				Namespace:     ingress.Namespace,
				Host:          "",
				Path:          []string{},
				ServiceName:   "",
				HasActivePods: false,
				PodCount:      0,
			}
			ingressList = append(ingressList, ingressInfo)
		}

		processedCount++
	}

	p.log.Info("DevBox ingress processing completed", logger.Fields{
		"processedCount": processedCount,
		"activeCount":    activeCount,
		"skippedCount":   skippedCount,
		"totalIngresses": len(ingressList),
	})

	return ingressList, nil
}
