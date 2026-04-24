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

// Package ingress implements a discovery plugin that monitors Kubernetes Ingress resources
// using informers. It detects changes to Ingress configurations and publishes discovery
// events for ingress endpoints with associated pod information.
package ingress

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

const (
	ingressPluginName = constants.DiscoveryInformerIngressName
	ingressPluginType = constants.DiscoveryInformerPluginType
)

const (
	AppDeployManagerLabel = "cloud.sealos.io/app-deploy-manager"
)

func init() {
	plugin.PluginFactories[ingressPluginName] = func() plugin.Plugin {
		return &IngressPlugin{
			log: logger.GetLogger().WithField("plugin", ingressPluginName),
		}
	}
}

type IngressPlugin struct {
	log             logger.Logger
	stopChan        chan struct{}
	eventBus        *eventbus.EventBus
	factory         informers.SharedInformerFactory
	ingressInformer cache.SharedIndexInformer
	ingressConfig   IngressConfig
}

type IngressConfig struct {
	ResyncTimeSecond   int `json:"resyncTimeSecond"`
	AgeThresholdSecond int `json:"ageThresholdSecond"`
}

func (p *IngressPlugin) getDefaultIngressConfig() IngressConfig {
	return IngressConfig{
		ResyncTimeSecond:   5,
		AgeThresholdSecond: 180,
	}
}

func (p *IngressPlugin) loadConfig(setting string) error {
	p.ingressConfig = p.getDefaultIngressConfig()
	if setting == "" {
		p.log.Info("Using default ingress configuration")
		return nil
	}

	var configFromJSON IngressConfig

	err := json.Unmarshal([]byte(setting), &configFromJSON)
	if err != nil {
		p.log.Error("Failed to parse config, using defaults", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if configFromJSON.ResyncTimeSecond > 0 {
		p.ingressConfig.ResyncTimeSecond = configFromJSON.ResyncTimeSecond
	}

	if configFromJSON.AgeThresholdSecond > 0 {
		p.ingressConfig.AgeThresholdSecond = configFromJSON.AgeThresholdSecond
	}

	return nil
}

func (p *IngressPlugin) Name() string {
	return ingressPluginName
}

func (p *IngressPlugin) Type() string {
	return ingressPluginType
}

func (p *IngressPlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	err := p.loadConfig(config.Settings)
	if err != nil {
		return err
	}

	p.stopChan = make(chan struct{})

	p.eventBus = eventBus
	go p.startIngressInformerWatch(ctx)

	return nil
}

func (p *IngressPlugin) startIngressInformerWatch(ctx context.Context) {
	if p.factory == nil {
		p.factory = informers.NewSharedInformerFactory(
			k8s.ClientSet,
			time.Duration(p.ingressConfig.ResyncTimeSecond)*time.Second,
		)
	}

	if p.ingressInformer == nil {
		p.ingressInformer = p.factory.Networking().V1().Ingresses().Informer()
	}

	_, err := p.ingressInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			ingress, ok := obj.(*networkingv1.Ingress)
			if !ok {
				p.log.Error("Failed to get ingress object", logger.Fields{})
			}

			if time.Since(
				ingress.CreationTimestamp.Time,
			) > time.Duration(
				p.ingressConfig.AgeThresholdSecond,
			)*time.Second {
				return
			}

			if p.shouldProcessIngress(ingress) {
				discoveryInfos, err := p.getIngressWithPodInfo(ingress)
				if err != nil {
					p.log.Error("Failed to get ingress pod info", logger.Fields{
						"error":     err.Error(),
						"ingress":   ingress.Name,
						"namespace": ingress.Namespace,
					})

					return
				}

				p.handleIngressEvent(discoveryInfos)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			oldIngress, ok := oldObj.(*networkingv1.Ingress)
			if !ok {
				p.log.Error("Failed to get ingress object", logger.Fields{
					"object_type": fmt.Sprintf("%T", oldObj),
				})
			}

			newIngress, ok := newObj.(*networkingv1.Ingress)
			if !ok {
				p.log.Error("Failed to get ingress object", logger.Fields{
					"object_type": fmt.Sprintf("%T", newObj),
				})
			}

			if p.shouldProcessIngress(newIngress) {
				hasChanged := p.hasIngressChanged(oldIngress, newIngress)
				if hasChanged {
					discoveryInfos, err := p.getIngressWithPodInfo(newIngress)
					if err != nil {
						p.log.Error("Failed to get ingress pod info", logger.Fields{
							"error":     err.Error(),
							"ingress":   newIngress.Name,
							"namespace": newIngress.Namespace,
						})

						return
					}

					p.handleIngressEvent(discoveryInfos)
				}
			}
		},
		DeleteFunc: func(obj any) {
			ingress, ok := obj.(*networkingv1.Ingress)
			if !ok {
				p.log.Error("Failed to get ingress object", logger.Fields{
					"object_type": fmt.Sprintf("%T", obj),
				})
			}

			if p.shouldProcessIngress(ingress) {
				discoveryInfos := utils.GenerateDiscoveryInfo(*ingress, false, 0, p.Name())
				p.handleIngressEvent(discoveryInfos)
			}
		},
	})
	if err != nil {
		return
	}

	p.factory.Start(p.stopChan)

	if !cache.WaitForCacheSync(p.stopChan, p.ingressInformer.HasSynced) {
		p.log.Error("Failed to wait for ingress caches to sync")
		return
	}

	p.log.Info("Ingress informer watcher started successfully")

	select {
	case <-ctx.Done():
		p.log.Info("Ingress watcher stopping due to context cancellation")
	case <-p.stopChan:
		p.log.Info("Ingress watcher stopping due to stop signal")
	}
}

func (p *IngressPlugin) Stop(ctx context.Context) error {
	if p.stopChan != nil {
		close(p.stopChan)
	}
	return nil
}

func (p *IngressPlugin) shouldProcessIngress(ingress *networkingv1.Ingress) bool {
	return strings.HasPrefix(ingress.Namespace, "ns-")
}

func (p *IngressPlugin) hasIngressChanged(oldIngress, newIngress *networkingv1.Ingress) bool {
	// Check if rules have changed
	if len(oldIngress.Spec.Rules) != len(newIngress.Spec.Rules) {
		return true
	}

	// Check each rule's content
	for i, oldRule := range oldIngress.Spec.Rules {
		newRule := newIngress.Spec.Rules[i]
		if oldRule.Host != newRule.Host {
			return true
		}

		// Check paths
		if oldRule.HTTP == nil && newRule.HTTP == nil {
			continue
		}

		if (oldRule.HTTP == nil) != (newRule.HTTP == nil) {
			return true
		}

		if len(oldRule.HTTP.Paths) != len(newRule.HTTP.Paths) {
			return true
		}

		for j, oldPath := range oldRule.HTTP.Paths {
			newPath := newRule.HTTP.Paths[j]
			if oldPath.Path != newPath.Path {
				return true
			}

			// Check backend service
			if oldPath.Backend.Service == nil && newPath.Backend.Service == nil {
				continue
			}

			if (oldPath.Backend.Service == nil) != (newPath.Backend.Service == nil) {
				return true
			}

			if oldPath.Backend.Service.Name != newPath.Backend.Service.Name {
				return true
			}
		}
	}

	return false
}

func (p *IngressPlugin) handleIngressEvent(discoveryInfo []models.DiscoveryInfo) {
	for _, info := range discoveryInfo {
		p.eventBus.Publish(constants.DiscoveryTopic, eventbus.Event{
			Payload: info,
		})
	}
}

func (p *IngressPlugin) getIngressWithPodInfo(
	ingress *networkingv1.Ingress,
) ([]models.DiscoveryInfo, error) {
	// Get all EndpointSlices in the namespace
	endpointSlices, err := k8s.ClientSet.DiscoveryV1().
		EndpointSlices(ingress.Namespace).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get EndpointSlice list in namespace %s: %w",
			ingress.Namespace,
			err,
		)
	}

	// Build EndpointSlice mapping
	endpointSlicesMap := make(map[string]map[string][]*discoveryv1.EndpointSlice)
	endpointSlicesMap[ingress.Namespace] = make(map[string][]*discoveryv1.EndpointSlice)

	for i := range endpointSlices.Items {
		slice := &endpointSlices.Items[i]
		// Get the service name associated with the EndpointSlice
		serviceName, exists := slice.Labels[discoveryv1.LabelServiceName]
		if !exists {
			continue
		}

		if endpointSlicesMap[ingress.Namespace][serviceName] == nil {
			endpointSlicesMap[ingress.Namespace][serviceName] = []*discoveryv1.EndpointSlice{}
		}

		endpointSlicesMap[ingress.Namespace][serviceName] = append(
			endpointSlicesMap[ingress.Namespace][serviceName],
			slice,
		)
	}

	// Use utils package function to generate DiscoveryInfo with Pod information
	discoveryInfos := utils.GenerateIngressAndPodInfo(*ingress, endpointSlicesMap, p.Name())

	return discoveryInfos, nil
}
