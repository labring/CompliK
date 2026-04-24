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

// Package service implements a discovery plugin that monitors Kubernetes NodePort Service
// resources using informers. It detects changes to NodePort services and publishes discovery
// events containing service endpoints accessible via node IPs and ports.
package service

import (
	"context"
	"encoding/json"
	"errors"
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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

const (
	servicePluginName = constants.DiscoveryInformerServiceNodePortName
	servicePluginType = constants.DiscoveryInformerPluginType
)

const (
	AppDeployManagerLabel = "cloud.sealos.io/app-deploy-manager"
)

func init() {
	plugin.PluginFactories[servicePluginName] = func() plugin.Plugin {
		return &ServicePlugin{
			log: logger.GetLogger().WithField("plugin", servicePluginName),
		}
	}
}

type ServicePlugin struct {
	log             logger.Logger
	stopChan        chan struct{}
	eventBus        *eventbus.EventBus
	factory         informers.SharedInformerFactory
	serviceInformer cache.SharedIndexInformer
	serviceConfig   ServiceConfig
}

type ServiceConfig struct {
	ResyncTimeSecond   int `json:"resyncTimeSecond"`
	AgeThresholdSecond int `json:"ageThresholdSecond"`
}

func (p *ServicePlugin) getDefaultServiceConfig() ServiceConfig {
	return ServiceConfig{
		ResyncTimeSecond:   5,
		AgeThresholdSecond: 180,
	}
}

func (p *ServicePlugin) loadConfig(setting string) error {
	p.serviceConfig = p.getDefaultServiceConfig()
	p.log.Debug("Loading nodeport service configuration")

	if setting == "" {
		p.log.Info("Using default service configuration")
		return nil
	}

	var configFromJSON ServiceConfig

	err := json.Unmarshal([]byte(setting), &configFromJSON)
	if err != nil {
		p.log.Error("Failed to parse configuration, using defaults", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if configFromJSON.ResyncTimeSecond > 0 {
		p.serviceConfig.ResyncTimeSecond = configFromJSON.ResyncTimeSecond
	}

	if configFromJSON.AgeThresholdSecond > 0 {
		p.serviceConfig.AgeThresholdSecond = configFromJSON.AgeThresholdSecond
	}

	p.log.Info("Service configuration loaded", logger.Fields{
		"resync_seconds":        p.serviceConfig.ResyncTimeSecond,
		"age_threshold_seconds": p.serviceConfig.AgeThresholdSecond,
	})

	return nil
}

func (p *ServicePlugin) Name() string {
	return servicePluginName
}

func (p *ServicePlugin) Type() string {
	return servicePluginType
}

func (p *ServicePlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	p.log.Info("Starting NodePort service informer plugin")

	err := p.loadConfig(config.Settings)
	if err != nil {
		p.log.Error("Failed to load configuration", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	p.stopChan = make(chan struct{})
	p.eventBus = eventBus

	p.log.Debug("Starting service informer watcher")

	go p.startServiceInformerWatch(ctx)

	p.log.Info("NodePort service informer started successfully")

	return nil
}

func (p *ServicePlugin) startServiceInformerWatch(ctx context.Context) {
	if p.factory == nil {
		p.factory = informers.NewSharedInformerFactory(
			k8s.ClientSet,
			time.Duration(p.serviceConfig.ResyncTimeSecond)*time.Second,
		)
	}

	if p.serviceInformer == nil {
		p.serviceInformer = p.factory.Core().V1().Services().Informer()
	}

	_, err := p.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			service, ok := obj.(*corev1.Service)
			if !ok {
				p.log.Error("Failed to cast object to Service", logger.Fields{
					"object_type": fmt.Sprintf("%T", service),
				})
			}

			if time.Since(
				service.CreationTimestamp.Time,
			) > time.Duration(
				p.serviceConfig.AgeThresholdSecond,
			)*time.Second {
				return
			}

			if p.shouldProcessService(service) {
				res, err := p.getServiceDiscoveryInfo(service)
				if err != nil {
					p.log.Error("Failed to get service discovery info", logger.Fields{
						"namespace": service.Namespace,
						"name":      service.Name,
						"error":     err.Error(),
					})

					return
				}

				p.log.Debug("Service added", logger.Fields{
					"namespace":  service.Namespace,
					"name":       service.Name,
					"info_count": len(res),
				})
				p.handleServiceEvent(res)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			oldService, ok := oldObj.(*corev1.Service)
			if !ok {
				p.log.Error("Failed to cast object to Service", logger.Fields{
					"object_type": fmt.Sprintf("%T", oldService),
				})
			}

			newService, ok := newObj.(*corev1.Service)
			if !ok {
				p.log.Error("Failed to cast object to Service", logger.Fields{
					"object_type": fmt.Sprintf("%T", newService),
				})
			}

			if p.shouldProcessService(newService) {
				hasChanged := p.hasServiceChanged(oldService, newService)
				if hasChanged {
					res, err := p.getServiceDiscoveryInfo(newService)
					if err != nil {
						p.log.Error("Failed to get service discovery info", logger.Fields{
							"namespace": newService.Namespace,
							"name":      newService.Name,
							"error":     err.Error(),
						})

						return
					}

					p.log.Debug("Service updated", logger.Fields{
						"namespace":  newService.Namespace,
						"name":       newService.Name,
						"info_count": len(res),
					})
					p.handleServiceEvent(res)
				}
			}
		},
	})
	if err != nil {
		return
	}

	p.factory.Start(p.stopChan)

	if !cache.WaitForCacheSync(p.stopChan, p.serviceInformer.HasSynced) {
		p.log.Error("Failed to wait for service caches to sync")
		return
	}

	p.log.Info("Service informer watcher started successfully")

	select {
	case <-ctx.Done():
		p.log.Info("Service watcher stopping due to context cancellation")
	case <-p.stopChan:
		p.log.Info("Service watcher stopping due to stop signal")
	}
}

func (p *ServicePlugin) Stop(ctx context.Context) error {
	p.log.Info("Stopping NodePort service informer plugin")

	if p.stopChan != nil {
		close(p.stopChan)
		p.log.Debug("Stop channel closed")
	}

	return nil
}

func (p *ServicePlugin) shouldProcessService(service *corev1.Service) bool {
	if service.Spec.Type != corev1.ServiceTypeNodePort {
		return false
	}
	return strings.HasPrefix(service.Namespace, "ns-")
}

func (p *ServicePlugin) hasServiceChanged(oldService, newService *corev1.Service) bool {
	oldPorts := extractPortsFromService(oldService)
	newPorts := extractPortsFromService(newService)

	hasChanged := !compareServicePorts(oldPorts, newPorts)
	if hasChanged {
		p.log.Info("Service NodePort changed", logger.Fields{
			"namespace": newService.Namespace,
			"name":      newService.Name,
			"old_ports": oldPorts,
			"new_ports": newPorts,
		})
	}

	return hasChanged
}

func extractPortsFromService(service *corev1.Service) []int32 {
	var ports []int32
	for _, port := range service.Spec.Ports {
		if port.NodePort > 0 {
			ports = append(ports, port.NodePort)
		}
	}

	return ports
}

func compareServicePorts(ports1, ports2 []int32) bool {
	if len(ports1) != len(ports2) {
		return false
	}

	count1 := make(map[int32]int)
	count2 := make(map[int32]int)

	for _, port := range ports1 {
		count1[port]++
	}

	for _, port := range ports2 {
		count2[port]++
	}

	for key, val := range count1 {
		if count2[key] != val {
			return false
		}
	}

	return true
}

func (p *ServicePlugin) handleServiceEvent(discoveryInfo []models.DiscoveryInfo) {
	p.log.Debug("Publishing service discovery events", logger.Fields{
		"event_count": len(discoveryInfo),
	})

	for _, info := range discoveryInfo {
		p.eventBus.Publish(constants.DiscoveryTopic, eventbus.Event{
			Payload: info,
		})
	}
}

func (p *ServicePlugin) getServiceDiscoveryInfo(
	service *corev1.Service,
) ([]models.DiscoveryInfo, error) {
	appName, exists := service.Labels[AppDeployManagerLabel]
	if !exists {
		return []models.DiscoveryInfo{}, nil
	}

	nodes, err := k8s.ClientSet.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node list: %w", err)
	}

	if len(nodes.Items) == 0 {
		return []models.DiscoveryInfo{}, nil
	}

	var nodeIP string
	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeExternalIP {
				nodeIP = addr.Address
				break
			}
		}

		if nodeIP == "" {
			for _, addr := range node.Status.Addresses {
				if addr.Type == corev1.NodeInternalIP {
					nodeIP = addr.Address
					break
				}
			}
		}

		if nodeIP != "" {
			break
		}
	}

	if nodeIP == "" {
		p.log.Error("Unable to get node IP address")
		return nil, errors.New("unable to get node IP address")
	}

	p.log.Debug("Found node IP", logger.Fields{
		"node_ip": nodeIP,
	})

	podCount, hasActivePods, err := p.getPodInfo(service)
	if err != nil {
		p.log.Warn("Failed to get pod info for service", logger.Fields{
			"namespace": service.Namespace,
			"name":      service.Name,
			"error":     err.Error(),
		})
	}

	var discoveryInfos []models.DiscoveryInfo
	for _, port := range service.Spec.Ports {
		if port.NodePort > 0 {
			paths := []string{"/"}
			discoveryInfo := models.DiscoveryInfo{
				DiscoveryName: fmt.Sprintf(
					"nodeport-%s-%s-%d",
					service.Namespace,
					service.Name,
					port.NodePort,
				),
				Name:          appName,
				Namespace:     service.Namespace,
				Host:          fmt.Sprintf("%s:%d", nodeIP, port.NodePort),
				Path:          paths,
				ServiceName:   service.Name,
				HasActivePods: hasActivePods,
				PodCount:      podCount,
			}
			discoveryInfos = append(discoveryInfos, discoveryInfo)

			p.log.Debug("Found NodePort service", logger.Fields{
				"namespace":       service.Namespace,
				"name":            service.Name,
				"host":            fmt.Sprintf("%s:%d", nodeIP, port.NodePort),
				"pod_count":       podCount,
				"has_active_pods": hasActivePods,
			})
		}
	}

	return discoveryInfos, nil
}

func (p *ServicePlugin) getPodInfo(service *corev1.Service) (int, bool, error) {
	if len(service.Spec.Selector) == 0 {
		return 0, false, nil
	}

	selector := metav1.LabelSelector{
		MatchLabels: service.Spec.Selector,
	}

	labelSelector, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return 0, false, fmt.Errorf("failed to build label selector: %w", err)
	}

	pods, err := k8s.ClientSet.CoreV1().
		Pods(service.Namespace).
		List(context.TODO(), metav1.ListOptions{
			LabelSelector: labelSelector.String(),
		})
	if err != nil {
		return 0, false, fmt.Errorf("failed to get Pod list: %w", err)
	}

	totalCount := len(pods.Items)

	activeCount := 0
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			allReady := true
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady {
					if condition.Status != corev1.ConditionTrue {
						allReady = false
					}
					break
				}
			}

			if allReady {
				activeCount++
			}
		}
	}

	return totalCount, activeCount > 0, nil
}
