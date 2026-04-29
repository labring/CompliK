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

package endPointSlice

import (
	"context"
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
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

const (
	pluginName = constants.DiscoveryInformerEndPointSliceName
	pluginType = constants.DiscoveryInformerPluginType
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &EndPointInformerPlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type EndPointInformerPlugin struct {
	log      logger.Logger
	stopChan chan struct{}
	eventBus *eventbus.EventBus
}

type EndpointSliceInfo struct {
	Namespace         string
	ServiceName       string
	ReadyCount        int
	NotReadyCount     int
	ReadyAddresses    []string
	NotReadyAddresses []string
	PodImages         map[string][]string
	MatchedIngresses  []IngressInfo
}

type IngressInfo struct {
	Name      string
	Namespace string
	Host      string
	Path      string
}

var changeCounter int64

func (p *EndPointInformerPlugin) Name() string {
	return pluginName
}

func (p *EndPointInformerPlugin) Type() string {
	return pluginType
}

func (p *EndPointInformerPlugin) Start(
	ctx context.Context,
	config config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	p.log.Info("Starting EndPointSlice informer plugin", logger.Fields{
		"plugin": pluginName,
	})

	p.stopChan = make(chan struct{})

	p.eventBus = eventBus
	go p.startInformerWatch(ctx)

	p.log.Info("EndPointSlice informer plugin started successfully")

	return nil
}

func (p *EndPointInformerPlugin) startInformerWatch(ctx context.Context) {
	p.log.Info("Starting EndpointSlice informer watch", logger.Fields{
		"resyncPeriod": "60s",
	})

	factory := informers.NewSharedInformerFactory(k8s.ClientSet, 60*time.Second)
	endpointSliceInformer := factory.Discovery().V1().EndpointSlices().Informer()

	_, err := endpointSliceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			endpointSlice, ok := obj.(*discoveryv1.EndpointSlice)
			if !ok {
				p.log.Error("Failed to cast object to EndpointSlice", logger.Fields{
					"object_type": fmt.Sprintf("%T", obj),
				})
				return
			}

			if p.shouldProcessEndpointSlice(endpointSlice) {
				info, err := p.extractEndpointSliceInfo(endpointSlice)
				if err != nil {
					p.log.Error("Failed to extract EndpointSlice info", logger.Fields{
						"namespace": endpointSlice.Namespace,
						"name":      endpointSlice.Name,
						"error":     err.Error(),
					})

					return
				}

				if info == nil {
					p.log.Debug("EndpointSlice info is nil, skipping", logger.Fields{
						"namespace": endpointSlice.Namespace,
						"name":      endpointSlice.Name,
					})

					return
				}

				if len(info.MatchedIngresses) > 0 {
					changeCounter++
					p.logEndpointSliceEvent("ADD", changeCounter, info)
					p.handleEndpointSliceEvent(info)
				} else {
					p.log.Debug("No matching ingresses found for EndpointSlice", logger.Fields{
						"namespace":   endpointSlice.Namespace,
						"name":        endpointSlice.Name,
						"serviceName": info.ServiceName,
					})
				}
			} else {
				p.log.Debug("EndpointSlice filtered out", logger.Fields{
					"namespace": endpointSlice.Namespace,
					"name":      endpointSlice.Name,
					"reason":    "namespace does not start with ns-",
				})
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			oldEndpointSlice, ok := oldObj.(*discoveryv1.EndpointSlice)
			if !ok {
				p.log.Error("Failed to cast object to EndpointSlice", logger.Fields{
					"object_type": fmt.Sprintf("%T", oldObj),
				})
			}

			newEndpointSlice, ok := newObj.(*discoveryv1.EndpointSlice)
			if !ok {
				p.log.Error("Failed to cast object to EndpointSlice", logger.Fields{
					"object_type": fmt.Sprintf("%T", newObj),
				})
			}

			p.log.Debug("EndpointSlice UPDATE event received", logger.Fields{
				"namespace": newEndpointSlice.Namespace,
				"name":      newEndpointSlice.Name,
			})

			if p.shouldProcessEndpointSlice(newEndpointSlice) {
				info, err := p.hasEndpointSliceChanged(oldEndpointSlice, newEndpointSlice)
				if err != nil {
					p.log.Error("Failed to compare EndpointSlice changes", logger.Fields{
						"namespace": newEndpointSlice.Namespace,
						"name":      newEndpointSlice.Name,
						"error":     err.Error(),
					})

					return
				}

				if info == nil {
					p.log.Debug("No significant changes detected in EndpointSlice", logger.Fields{
						"namespace": newEndpointSlice.Namespace,
						"name":      newEndpointSlice.Name,
					})

					return
				}

				changeCounter++
				p.logEndpointSliceEvent("UPDATE", changeCounter, info)
				p.handleEndpointSliceEvent(info)
			} else {
				p.log.Debug("EndpointSlice UPDATE filtered out", logger.Fields{
					"namespace": newEndpointSlice.Namespace,
					"name":      newEndpointSlice.Name,
					"reason":    "namespace does not start with ns-",
				})
			}
		},
	})
	if err != nil {
		return
	}

	p.log.Debug("Starting informer factory")
	factory.Start(p.stopChan)

	p.log.Debug("Waiting for cache sync")

	if !cache.WaitForCacheSync(p.stopChan, endpointSliceInformer.HasSynced) {
		p.log.Error("Failed to wait for caches to sync")
		return
	}

	p.log.Info("EndpointSlice informer watcher started successfully")

	select {
	case <-ctx.Done():
		p.log.Info("EndpointSlice watcher stopping due to context cancellation")
	case <-p.stopChan:
		p.log.Info("EndpointSlice watcher stopping due to stop signal")
	}

	p.log.Info("EndpointSlice informer watcher stopped")
}

func (p *EndPointInformerPlugin) Stop(ctx context.Context) error {
	p.log.Info("Stopping EndPointSlice informer plugin")

	if p.stopChan != nil {
		close(p.stopChan)
		p.log.Debug("Stop channel closed")
	}

	p.log.Info("EndPointSlice informer plugin stopped")

	return nil
}

func (p *EndPointInformerPlugin) shouldProcessEndpointSlice(
	endpointSlice *discoveryv1.EndpointSlice,
) bool {
	return strings.HasPrefix(endpointSlice.Namespace, "ns-")
}

func (p *EndPointInformerPlugin) extractEndpointSliceInfo(
	endpointSlice *discoveryv1.EndpointSlice,
) (*EndpointSliceInfo, error) {
	p.log.Debug("Extracting EndpointSlice info", logger.Fields{
		"namespace": endpointSlice.Namespace,
		"name":      endpointSlice.Name,
	})

	serviceName, exists := endpointSlice.Labels[discoveryv1.LabelServiceName]
	if !exists {
		p.log.Debug("EndpointSlice missing service name label", logger.Fields{
			"namespace": endpointSlice.Namespace,
			"name":      endpointSlice.Name,
			"labelKey":  discoveryv1.LabelServiceName,
		})

		return nil, fmt.Errorf(
			"EndpointSlice %s/%s missing service name label",
			endpointSlice.Namespace,
			endpointSlice.Name,
		)
	}

	p.log.Debug("Checking for matching ingresses", logger.Fields{
		"namespace":   endpointSlice.Namespace,
		"serviceName": serviceName,
	})

	matchedIngresses, err := p.checkServiceHasIngress(endpointSlice.Namespace, serviceName)
	if err != nil {
		p.log.Error("Failed to get ingress info for service", logger.Fields{
			"namespace":   endpointSlice.Namespace,
			"serviceName": serviceName,
			"error":       err.Error(),
		})
	}

	if len(matchedIngresses) == 0 {
		p.log.Debug("No matching ingresses found", logger.Fields{
			"namespace":   endpointSlice.Namespace,
			"serviceName": serviceName,
		})

		return nil, nil
	}

	info := &EndpointSliceInfo{
		Namespace:        endpointSlice.Namespace,
		ServiceName:      serviceName,
		MatchedIngresses: matchedIngresses,
	}

	p.log.Debug("Processing endpoint addresses", logger.Fields{
		"endpointCount": len(endpointSlice.Endpoints),
	})

	for _, endpoint := range endpointSlice.Endpoints {
		if endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready {
			info.ReadyCount++
			info.ReadyAddresses = append(info.ReadyAddresses, endpoint.Addresses...)
		} else {
			info.NotReadyCount++
			info.NotReadyAddresses = append(info.NotReadyAddresses, endpoint.Addresses...)
		}
	}

	p.log.Debug("Endpoint processing completed", logger.Fields{
		"namespace":        endpointSlice.Namespace,
		"serviceName":      serviceName,
		"readyCount":       info.ReadyCount,
		"notReadyCount":    info.NotReadyCount,
		"matchedIngresses": len(matchedIngresses),
	})

	if info.ReadyCount == 0 {
		p.log.Debug("No ready endpoints found", logger.Fields{
			"namespace":   endpointSlice.Namespace,
			"serviceName": serviceName,
		})

		return nil, nil
	}

	return info, nil
}

func (p *EndPointInformerPlugin) logEndpointSliceEvent(
	eventType string,
	counter int64,
	info *EndpointSliceInfo,
) {
	p.log.Info("EndpointSlice event processed", logger.Fields{
		"eventType":     eventType,
		"eventCounter":  counter,
		"namespace":     info.Namespace,
		"serviceName":   info.ServiceName,
		"readyCount":    info.ReadyCount,
		"notReadyCount": info.NotReadyCount,
	})

	for i, ingressInfo := range info.MatchedIngresses {
		host := ingressInfo.Host
		if host == "" {
			host = "*"
		}

		p.log.Info("Matched ingress found", logger.Fields{
			"eventCounter": counter,
			"ingressIndex": i + 1,
			"ingressName":  ingressInfo.Name,
			"host":         host,
			"path":         ingressInfo.Path,
		})
	}

	if len(info.PodImages) > 0 {
		p.log.Debug("Pod image information available", logger.Fields{
			"eventCounter": counter,
			"podImages":    info.PodImages,
		})
	}
}

func (p *EndPointInformerPlugin) hasEndpointSliceChanged(
	oldEndpointSlice, newEndpointSlice *discoveryv1.EndpointSlice,
) (*EndpointSliceInfo, error) {
	p.log.Debug("Comparing EndpointSlice changes", logger.Fields{
		"namespace": newEndpointSlice.Namespace,
		"name":      newEndpointSlice.Name,
	})

	newInfo, err := p.extractEndpointSliceInfo(newEndpointSlice)
	if err != nil {
		p.log.Error("Failed to extract new EndpointSlice info", logger.Fields{
			"namespace": newEndpointSlice.Namespace,
			"name":      newEndpointSlice.Name,
			"error":     err.Error(),
		})

		return nil, err
	}

	oldInfo, err := p.extractEndpointSliceInfo(oldEndpointSlice)
	if err != nil {
		p.log.Error("Failed to extract old EndpointSlice info", logger.Fields{
			"namespace": oldEndpointSlice.Namespace,
			"name":      oldEndpointSlice.Name,
			"error":     err.Error(),
		})

		return nil, err
	}

	if newInfo == nil || len(newInfo.MatchedIngresses) == 0 {
		p.log.Debug("No matching ingresses for new EndpointSlice, skipping change detection")
		return nil, nil
	}

	if oldInfo == nil {
		p.log.Debug("Old EndpointSlice info is nil, treating as new")
		return newInfo, nil
	}

	if oldInfo.ReadyCount != newInfo.ReadyCount {
		p.log.Info("EndpointSlice ready endpoint count changed", logger.Fields{
			"namespace":   newInfo.Namespace,
			"serviceName": newInfo.ServiceName,
			"oldCount":    oldInfo.ReadyCount,
			"newCount":    newInfo.ReadyCount,
		})

		return newInfo, nil
	}
	// Compare address changes when counts are equal
	if len(oldInfo.ReadyAddresses) == len(newInfo.ReadyAddresses) {
		oldAddressSet := p.sliceToSet(oldInfo.ReadyAddresses)
		newAddressSet := p.sliceToSet(newInfo.ReadyAddresses)
		addedAddresses := p.setDifference(newAddressSet, oldAddressSet)

		removedAddresses := p.setDifference(oldAddressSet, newAddressSet)
		if len(addedAddresses) > 0 || len(removedAddresses) > 0 {
			p.log.Info("EndpointSlice addresses changed", logger.Fields{
				"namespace":        newInfo.Namespace,
				"serviceName":      newInfo.ServiceName,
				"addedAddresses":   addedAddresses,
				"removedAddresses": removedAddresses,
			})

			return newInfo, nil
		}

		p.log.Debug("No address changes detected despite same count", logger.Fields{
			"namespace":    newInfo.Namespace,
			"serviceName":  newInfo.ServiceName,
			"addressCount": len(newInfo.ReadyAddresses),
		})

		return nil, nil
	}

	p.log.Info("EndpointSlice ready address count changed", logger.Fields{
		"namespace":   newInfo.Namespace,
		"serviceName": newInfo.ServiceName,
		"oldCount":    len(oldInfo.ReadyAddresses),
		"newCount":    len(newInfo.ReadyAddresses),
	})

	return newInfo, nil
}

func (p *EndPointInformerPlugin) sliceToSet(slice []string) map[string]bool {
	set := make(map[string]bool)
	for _, item := range slice {
		set[item] = true
	}

	return set
}

func (p *EndPointInformerPlugin) setDifference(set1, set2 map[string]bool) []string {
	var diff []string
	for item := range set1 {
		if !set2[item] {
			diff = append(diff, item)
		}
	}

	return diff
}

func (p *EndPointInformerPlugin) handleEndpointSliceEvent(endpointInfo *EndpointSliceInfo) {
	p.log.Debug("Publishing EndpointSlice event", logger.Fields{
		"namespace":        endpointInfo.Namespace,
		"serviceName":      endpointInfo.ServiceName,
		"readyCount":       endpointInfo.ReadyCount,
		"matchedIngresses": len(endpointInfo.MatchedIngresses),
	})

	for _, info := range p.buildDiscoveryInfo(endpointInfo) {
		p.eventBus.Publish(constants.DiscoveryTopic, eventbus.Event{
			Payload: info,
		})
	}

	p.log.Debug("EndpointSlice event published successfully")
}

func (p *EndPointInformerPlugin) buildDiscoveryInfo(
	endpointInfo *EndpointSliceInfo,
) []models.DiscoveryInfo {
	if endpointInfo == nil {
		return nil
	}

	discoveryInfos := make([]models.DiscoveryInfo, 0, len(endpointInfo.MatchedIngresses))
	for _, ingressInfo := range endpointInfo.MatchedIngresses {
		discoveryInfos = append(discoveryInfos, models.DiscoveryInfo{
			DiscoveryName: p.Name(),
			Name:          ingressInfo.Name,
			Namespace:     ingressInfo.Namespace,
			Host:          normalizedIngressHost(ingressInfo.Host),
			Path:          []string{normalizedIngressPath(ingressInfo.Path)},
			ServiceName:   endpointInfo.ServiceName,
			HasActivePods: endpointInfo.ReadyCount > 0,
			PodCount:      endpointInfo.ReadyCount,
		})
	}

	return discoveryInfos
}

func normalizedIngressHost(host string) string {
	if host == "" {
		return "*"
	}
	return host
}

func normalizedIngressPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func (p *EndPointInformerPlugin) checkServiceHasIngress(
	namespace, serviceName string,
) ([]IngressInfo, error) {
	p.log.Debug("Checking service for matching ingresses", logger.Fields{
		"namespace":   namespace,
		"serviceName": serviceName,
	})

	ingressItems, err := k8s.ClientSet.NetworkingV1().
		Ingresses(namespace).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		p.log.Error("Failed to list ingresses", logger.Fields{
			"namespace": namespace,
			"error":     err.Error(),
		})

		return nil, fmt.Errorf("failed to list ingresses in namespace %s: %w", namespace, err)
	}

	p.log.Debug("Retrieved ingresses for namespace", logger.Fields{
		"namespace":    namespace,
		"ingressCount": len(ingressItems.Items),
	})

	var matchedIngresses []IngressInfo

	matchedPaths := 0

	for _, ingress := range ingressItems.Items {
		for _, rule := range ingress.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}

			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service != nil && path.Backend.Service.Name == serviceName {
					matchedPaths++

					ingressInfo := IngressInfo{
						Name:      ingress.Name,
						Namespace: ingress.Namespace,
						Host:      rule.Host,
						Path:      path.Path,
					}

					p.log.Debug("Found matching ingress path", logger.Fields{
						"ingress":     fmt.Sprintf("%s/%s", ingress.Namespace, ingress.Name),
						"host":        ingressInfo.Host,
						"path":        ingressInfo.Path,
						"serviceName": serviceName,
					})
					matchedIngresses = append(matchedIngresses, ingressInfo)
				}
			}
		}
	}

	p.log.Debug("Service ingress matching completed", logger.Fields{
		"namespace":        namespace,
		"serviceName":      serviceName,
		"matchedPaths":     matchedPaths,
		"matchedIngresses": len(matchedIngresses),
	})

	return matchedIngresses, nil
}
