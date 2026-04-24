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

// Package complete provides a cron job plugin for complete discovery of ingress resources.
package complete

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/k8s"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
	"github.com/bearslyricattack/CompliK/complik/plugins/discovery/utils"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	pluginName = constants.DiscoveryCronJobCompleteName
	pluginType = constants.DiscoveryCronJobPluginType
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &CompletePlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type CompletePlugin struct {
	log            logger.Logger
	completeConfig CompleteConfig
}

func (p *CompletePlugin) Name() string {
	return pluginName
}

func (p *CompletePlugin) Type() string {
	return pluginType
}

type CompleteConfig struct {
	IntervalMinute  int   `json:"intervalMinute"`
	AutoStart       *bool `json:"autoStart"`
	StartTimeSecond int   `json:"startTimeSecond"`
}

func (p *CompletePlugin) getDefaultCompleteConfig() CompleteConfig {
	b := false

	return CompleteConfig{
		IntervalMinute:  7 * 24 * 60,
		AutoStart:       &b,
		StartTimeSecond: 60,
	}
}

func (p *CompletePlugin) loadConfig(setting string) error {
	p.log.Debug("Loading Complete plugin configuration")

	p.completeConfig = p.getDefaultCompleteConfig()
	if setting == "" {
		p.log.Info("Using default Complete configuration")
		return nil
	}

	p.log.Debug("Parsing custom configuration", logger.Fields{
		"settingLength": len(setting),
	})

	var configFromJSON CompleteConfig

	err := json.Unmarshal([]byte(setting), &configFromJSON)
	if err != nil {
		p.log.Error("Failed to parse configuration, using defaults", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if configFromJSON.IntervalMinute > 0 {
		p.completeConfig.IntervalMinute = configFromJSON.IntervalMinute
		p.log.Debug(
			"Set interval from config",
			logger.Fields{"intervalMinute": configFromJSON.IntervalMinute},
		)
	}

	if configFromJSON.AutoStart != nil {
		p.completeConfig.AutoStart = configFromJSON.AutoStart
		p.log.Debug(
			"Set autoStart from config",
			logger.Fields{"autoStart": *configFromJSON.AutoStart},
		)
	}

	if configFromJSON.StartTimeSecond > 0 {
		p.completeConfig.StartTimeSecond = configFromJSON.StartTimeSecond
		p.log.Debug(
			"Set startTime from config",
			logger.Fields{"startTimeSecond": configFromJSON.StartTimeSecond},
		)
	}

	p.log.Info("Complete configuration loaded successfully", logger.Fields{
		"intervalMinute":  p.completeConfig.IntervalMinute,
		"autoStart":       p.completeConfig.AutoStart != nil && *p.completeConfig.AutoStart,
		"startTimeSecond": p.completeConfig.StartTimeSecond,
	})

	return nil
}

func (p *CompletePlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	p.log.Info("Starting Complete plugin", logger.Fields{
		"plugin": pluginName,
	})

	err := p.loadConfig(config.Settings)
	if err != nil {
		p.log.Error("Failed to load configuration", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if p.completeConfig.AutoStart != nil && *p.completeConfig.AutoStart {
		p.log.Info("Auto-start enabled, executing initial task", logger.Fields{
			"startDelay": p.completeConfig.StartTimeSecond,
		})
		time.Sleep(time.Duration(p.completeConfig.StartTimeSecond) * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		p.executeTask(ctx, eventBus)
		cancel()
	} else {
		p.log.Debug("Auto-start disabled, waiting for scheduled intervals")
	}

	go func() {
		interval := time.Duration(p.completeConfig.IntervalMinute) * time.Minute
		p.log.Info("Starting scheduled task ticker", logger.Fields{
			"interval": interval.String(),
		})

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p.log.Debug("Scheduled task trigger")

				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				p.executeTask(ctx, eventBus)
				cancel()
			case <-ctx.Done():
				p.log.Info("Context cancelled, stopping Complete plugin scheduler")
				return
			}
		}
	}()

	p.log.Info("Complete plugin started successfully")

	return nil
}

func (p *CompletePlugin) executeTask(ctx context.Context, eventBus *eventbus.EventBus) {
	p.log.Debug("Executing Complete discovery task")

	ingressList, err := p.GetIngressList(ctx)
	if err != nil {
		p.log.Error("Failed to get ingress list", logger.Fields{
			"error": err.Error(),
		})
		return
	}

	p.log.Info("Publishing Complete discovery events", logger.Fields{
		"ingressCount": len(ingressList),
	})

	publishedCount := 0
	for i, ingress := range ingressList {
		select {
		case <-ctx.Done():
			p.log.Warn("Context cancelled during task execution", logger.Fields{
				"publishedCount": i,
				"totalCount":     len(ingressList),
			})

			return
		default:
			eventBus.Publish(constants.DiscoveryTopic, eventbus.Event{
				Payload: ingress,
			})

			publishedCount++
		}
	}

	p.log.Info("Complete discovery task completed", logger.Fields{
		"publishedCount": publishedCount,
	})
}

func (p *CompletePlugin) Stop(ctx context.Context) error {
	p.log.Info("Stopping Complete plugin")
	return nil
}

func (p *CompletePlugin) GetIngressList(ctx context.Context) ([]models.DiscoveryInfo, error) {
	p.log.Debug("Getting complete ingress and endpoint slice lists")

	var (
		ingressItems                  *networkingv1.IngressList
		endpointSlicesList            *discoveryv1.EndpointSliceList
		ingressErr, endpointSlicesErr error
		wg                            sync.WaitGroup
	)

	p.log.Debug("Starting parallel fetch of ingresses and endpoint slices")
	wg.Add(2)

	go func() {
		defer wg.Done()

		p.log.Debug("Fetching ingresses from all namespaces")

		ingressItems, ingressErr = k8s.ClientSet.NetworkingV1().
			Ingresses("").
			List(ctx, metav1.ListOptions{})
	}()
	go func() {
		defer wg.Done()

		p.log.Debug("Fetching endpoint slices from all namespaces")

		endpointSlicesList, endpointSlicesErr = k8s.ClientSet.DiscoveryV1().
			EndpointSlices("").
			List(ctx, metav1.ListOptions{})
	}()

	wg.Wait()

	if ingressErr != nil {
		p.log.Error("Failed to get ingress list", logger.Fields{
			"error": ingressErr.Error(),
		})
		return nil, fmt.Errorf("failed to get Ingress list: %w", ingressErr)
	}

	if endpointSlicesErr != nil {
		p.log.Error("Failed to get endpoint slices list", logger.Fields{
			"error": endpointSlicesErr.Error(),
		})
		return nil, fmt.Errorf("failed to get EndpointSlices list: %w", endpointSlicesErr)
	}

	p.log.Debug("Successfully fetched Kubernetes resources", logger.Fields{
		"ingressCount":       len(ingressItems.Items),
		"endpointSliceCount": len(endpointSlicesList.Items),
	})
	p.log.Debug("Deduplicating ingresses by path")
	uniqueIngresses := p.deduplicateIngressesByPath(ingressItems.Items)
	p.log.Debug("Ingress deduplication completed", logger.Fields{
		"originalCount": len(ingressItems.Items),
		"uniqueCount":   len(uniqueIngresses),
	})

	return p.processIngressAndEndpointSlices(uniqueIngresses, endpointSlicesList.Items)
}

func (p *CompletePlugin) deduplicateIngressesByPath(
	ingresses []networkingv1.Ingress,
) []networkingv1.Ingress {
	p.log.Debug("Starting ingress deduplication by path", logger.Fields{
		"totalIngresses": len(ingresses),
	})

	pathMap := make(map[string]networkingv1.Ingress)
	pathCount := 0

	for _, ingress := range ingresses {
		for _, rule := range ingress.Spec.Rules {
			if rule.HTTP != nil {
				for _, path := range rule.HTTP.Paths {
					pathKey := fmt.Sprintf("%s%s", rule.Host, path.Path)
					pathCount++

					if existingIngress, exists := pathMap[pathKey]; !exists {
						pathMap[pathKey] = ingress
						p.log.Debug("Added new path mapping", logger.Fields{
							"pathKey":   pathKey,
							"ingress":   fmt.Sprintf("%s/%s", ingress.Namespace, ingress.Name),
							"timestamp": ingress.CreationTimestamp.Time,
						})
					} else if ingress.CreationTimestamp.After(existingIngress.CreationTimestamp.Time) {
						pathMap[pathKey] = ingress
						p.log.Debug("Updated path mapping with newer ingress", logger.Fields{
							"pathKey": pathKey,
							"oldIngress": fmt.Sprintf(
								"%s/%s",
								existingIngress.Namespace,
								existingIngress.Name,
							),
							"newIngress":   fmt.Sprintf("%s/%s", ingress.Namespace, ingress.Name),
							"oldTimestamp": existingIngress.CreationTimestamp.Time,
							"newTimestamp": ingress.CreationTimestamp.Time,
						})
					}
				}
			}
		}
	}

	p.log.Debug("Path mapping completed", logger.Fields{
		"totalPaths":     pathCount,
		"uniquePaths":    len(pathMap),
		"duplicatePaths": pathCount - len(pathMap),
	})

	uniqueIngressMap := make(map[string]networkingv1.Ingress)
	for _, ingress := range pathMap {
		key := fmt.Sprintf("%s/%s", ingress.Namespace, ingress.Name)
		uniqueIngressMap[key] = ingress
	}

	p.log.Debug("Building unique ingress result", logger.Fields{
		"uniqueIngressCount": len(uniqueIngressMap),
	})

	result := make([]networkingv1.Ingress, 0, len(uniqueIngressMap))
	for _, ingress := range uniqueIngressMap {
		result = append(result, ingress)
	}

	p.log.Debug("Deduplication process completed", logger.Fields{
		"finalCount": len(result),
	})

	return result
}

func (p *CompletePlugin) processIngressAndEndpointSlices(
	ingressItems []networkingv1.Ingress,
	endpointSlicesItems []discoveryv1.EndpointSlice,
) ([]models.DiscoveryInfo, error) {
	p.log.Debug("Processing ingresses and endpoint slices", logger.Fields{
		"ingressCount":       len(ingressItems),
		"endpointSliceCount": len(endpointSlicesItems),
	})

	// Build EndpointSlice mapping: namespace -> serviceName -> []EndpointSlice
	endpointSlicesMap := make(map[string]map[string][]*discoveryv1.EndpointSlice)
	processedEndpointSlices := 0
	skippedEndpointSlices := 0

	for i := range endpointSlicesItems {
		endpointSlice := &endpointSlicesItems[i]
		namespace := endpointSlice.Namespace

		serviceName, exists := endpointSlice.Labels["kubernetes.io/service-name"]
		if !exists {
			skippedEndpointSlices++
			continue
		}

		if endpointSlicesMap[namespace] == nil {
			endpointSlicesMap[namespace] = make(map[string][]*discoveryv1.EndpointSlice)
		}

		endpointSlicesMap[namespace][serviceName] = append(
			endpointSlicesMap[namespace][serviceName],
			endpointSlice,
		)
		processedEndpointSlices++
	}

	p.log.Debug("Endpoint slice mapping completed", logger.Fields{
		"processedEndpointSlices": processedEndpointSlices,
		"skippedEndpointSlices":   skippedEndpointSlices,
		"namespaceCount":          len(endpointSlicesMap),
	})
	// Estimate result size and filter ns- namespaces
	estimatedSize := 0

	validIngresses := 0
	for _, ingress := range ingressItems {
		if !strings.HasPrefix(ingress.Namespace, "ns-") {
			continue
		}

		validIngresses++

		for _, rule := range ingress.Spec.Rules {
			if rule.HTTP != nil {
				estimatedSize += len(rule.HTTP.Paths)
			}
		}
	}

	p.log.Debug("Processing ingress items", logger.Fields{
		"totalIngresses": len(ingressItems),
		"validIngresses": validIngresses,
		"estimatedSize":  estimatedSize,
	})

	ingressList := make([]models.DiscoveryInfo, 0, estimatedSize)
	processedIngresses := 0

	for _, ing := range ingressItems {
		res := utils.GenerateIngressAndPodInfo(ing, endpointSlicesMap, p.Name())
		ingressList = append(ingressList, res...)
		processedIngresses++
	}

	p.log.Info("Successfully generated ingress discovery info", logger.Fields{
		"processedIngresses": processedIngresses,
		"discoveryInfoCount": len(ingressList),
	})

	return ingressList, nil
}
