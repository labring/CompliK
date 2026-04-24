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

// Package deployment implements a discovery plugin that monitors Kubernetes StatefulSet
// resources using informers. It detects changes to StatefulSet container images and
// publishes discovery events for associated Ingress resources.
package deployment

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
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

const (
	statefulsetPluginName = constants.DiscoveryInformerStatefulSetName
	statefulsetPluginType = constants.DiscoveryInformerPluginType
)

const (
	AppDeployManagerLabel = "cloud.sealos.io/app-deploy-manager"
)

func init() {
	plugin.PluginFactories[statefulsetPluginName] = func() plugin.Plugin {
		return &StatefulSetPlugin{
			log: logger.GetLogger().WithField("plugin", statefulsetPluginName),
		}
	}
}

type StatefulSetPlugin struct {
	log                 logger.Logger
	stopChan            chan struct{}
	eventBus            *eventbus.EventBus
	factory             informers.SharedInformerFactory
	statefulsetInformer cache.SharedIndexInformer
	statefulSetConfig   StatefulSetConfig
}
type StatefulSetConfig struct {
	ResyncTimeSecond   int `json:"resyncTimeSecond"`
	AgeThresholdSecond int `json:"ageThresholdSecond"`
}

func (p *StatefulSetPlugin) getDefaultStatefulSetConfig() StatefulSetConfig {
	return StatefulSetConfig{
		ResyncTimeSecond:   5,
		AgeThresholdSecond: 180,
	}
}

func (p *StatefulSetPlugin) loadConfig(setting string) error {
	p.statefulSetConfig = p.getDefaultStatefulSetConfig()
	if setting == "" {
		p.log.Info("Using default browser configuration")
		return nil
	}

	var configFromJSON StatefulSetConfig

	err := json.Unmarshal([]byte(setting), &configFromJSON)
	if err != nil {
		p.log.Error("Failed to parse config, using defaults", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if configFromJSON.ResyncTimeSecond > 0 {
		p.statefulSetConfig.ResyncTimeSecond = configFromJSON.ResyncTimeSecond
	}

	if configFromJSON.AgeThresholdSecond > 0 {
		p.statefulSetConfig.AgeThresholdSecond = configFromJSON.AgeThresholdSecond
	}

	return nil
}

type StatefulSetInfo struct {
	Namespace        string
	Name             string
	Images           []string
	MatchedIngresses []models.DiscoveryInfo
}

func (p *StatefulSetPlugin) Name() string {
	return statefulsetPluginName
}

func (p *StatefulSetPlugin) Type() string {
	return statefulsetPluginType
}

func (p *StatefulSetPlugin) Start(
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
	go p.startStatefulSetInformerWatch(ctx)

	return nil
}

func (p *StatefulSetPlugin) startStatefulSetInformerWatch(ctx context.Context) {
	if p.factory == nil {
		p.factory = informers.NewSharedInformerFactory(
			k8s.ClientSet,
			time.Duration(p.statefulSetConfig.ResyncTimeSecond)*time.Second,
		)
	}

	if p.statefulsetInformer == nil {
		p.statefulsetInformer = p.factory.Apps().V1().StatefulSets().Informer()
	}

	_, err := p.statefulsetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			statefulset, ok := obj.(*appsv1.StatefulSet)
			if !ok {
				p.log.Error("Failed to get StatefulSet related Ingresses", logger.Fields{
					"object_type": fmt.Sprintf("%T", obj),
				})
			}

			if time.Since(
				statefulset.CreationTimestamp.Time,
			) > time.Duration(
				p.statefulSetConfig.AgeThresholdSecond,
			)*time.Second {
				return
			}

			if p.shouldProcessStatefulSet(statefulset) {
				res, err := p.getStatefulSetRelatedIngresses(statefulset)
				if err != nil {
					p.log.Error("Failed to get StatefulSet related Ingresses", logger.Fields{
						"error": err.Error(),
					})
					return
				}

				p.handleStatefulSetEvent(res)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			oldStatefulSet, ok := oldObj.(*appsv1.StatefulSet)
			if !ok {
				p.log.Error("Failed to get StatefulSet related Ingresses", logger.Fields{
					"object_type": fmt.Sprintf("%T", oldStatefulSet),
				})
			}

			newStatefulSet, ok := newObj.(*appsv1.StatefulSet)
			if !ok {
				p.log.Error("Failed to get StatefulSet related Ingresses", logger.Fields{
					"object_type": fmt.Sprintf("%T", newStatefulSet),
				})
			}

			if p.shouldProcessStatefulSet(newStatefulSet) {
				hasChanged := p.hasStatefulSetChanged(oldStatefulSet, newStatefulSet)
				if hasChanged {
					res, err := p.getStatefulSetRelatedIngresses(newStatefulSet)
					if err != nil {
						p.log.Error("Failed to get StatefulSet related Ingresses", logger.Fields{
							"error": err.Error(),
						})
						return
					}

					p.handleStatefulSetEvent(res)
				}
			}
		},
	})
	if err != nil {
		return
	}

	p.factory.Start(p.stopChan)

	if !cache.WaitForCacheSync(p.stopChan, p.statefulsetInformer.HasSynced) {
		p.log.Error("Failed to wait for StatefulSet caches to sync")
		return
	}

	p.log.Info("StatefulSet informer watcher started successfully")

	select {
	case <-ctx.Done():
		p.log.Info("StatefulSet watcher stopping due to context cancellation")
	case <-p.stopChan:
		p.log.Info("StatefulSet watcher stopping due to stop signal")
	}
}

func (p *StatefulSetPlugin) Stop(ctx context.Context) error {
	if p.stopChan != nil {
		close(p.stopChan)
	}
	return nil
}

func (p *StatefulSetPlugin) shouldProcessStatefulSet(statefulset *appsv1.StatefulSet) bool {
	return strings.HasPrefix(statefulset.Namespace, "ns-")
}

func (p *StatefulSetPlugin) hasStatefulSetChanged(
	oldStatefulSet, newStatefulSet *appsv1.StatefulSet,
) bool {
	oldImages := extractImagesFromStatefulSet(oldStatefulSet)
	newImages := extractImagesFromStatefulSet(newStatefulSet)

	hasChanged := !compareStringSlices(oldImages, newImages)
	if hasChanged {
		p.log.Debug("StatefulSet image change detected", logger.Fields{
			"namespace":  newStatefulSet.Namespace,
			"name":       newStatefulSet.Name,
			"old_images": oldImages,
			"new_images": newImages,
		})
	}

	return hasChanged
}

func compareStringSlices(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	count1 := make(map[string]int)
	count2 := make(map[string]int)

	for _, item := range slice1 {
		count1[item]++
	}

	for _, item := range slice2 {
		count2[item]++
	}

	for key, val := range count1 {
		if count2[key] != val {
			return false
		}
	}

	return true
}

func extractImagesFromStatefulSet(statefulset *appsv1.StatefulSet) []string {
	images := make([]string, 0, len(statefulset.Spec.Template.Spec.Containers))
	for _, container := range statefulset.Spec.Template.Spec.Containers {
		images = append(images, container.Image)
	}

	return images
}

func (p *StatefulSetPlugin) handleStatefulSetEvent(discoveryInfo []models.DiscoveryInfo) {
	for _, info := range discoveryInfo {
		p.eventBus.Publish(constants.DiscoveryTopic, eventbus.Event{
			Payload: info,
		})
	}
}

func (p *StatefulSetPlugin) getStatefulSetRelatedIngresses(
	statefulset *appsv1.StatefulSet,
) ([]models.DiscoveryInfo, error) {
	appName, exists := statefulset.Labels[AppDeployManagerLabel]
	if !exists {
		return []models.DiscoveryInfo{}, nil
	}

	ingressItems, err := k8s.ClientSet.NetworkingV1().
		Ingresses(statefulset.Namespace).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get Ingress list in namespace %s: %w",
			statefulset.Namespace,
			err,
		)
	}

	var ingresses []models.DiscoveryInfo
	for _, ingress := range ingressItems.Items {
		if ingressAppName, exists := ingress.Labels[AppDeployManagerLabel]; exists &&
			ingressAppName == appName {
			res := utils.GenerateDiscoveryInfo(ingress, true, 1, p.Name())
			ingresses = append(ingresses, res...)
		}
	}

	return ingresses, nil
}
