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

package vlogpath

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/k8s"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

// SeedPathInfo captures the Ingress path that acts as the trusted starting
// point for log-derived child path discovery.
type SeedPathInfo struct {
	DiscoveryName string
	Namespace     string
	IngressName   string
	Host          string
	IngressPath   string
	ServiceName   string
	HasActivePods bool
	PodCount      int
	UpdatedAt     time.Time
}

// SeedPathGroup batches seed paths by namespace and host so each VLog host
// query can be matched against only the relevant Ingress routes.
type SeedPathGroup struct {
	Namespace string
	Host      string
	Seeds     []SeedPathInfo
}

// Match returns the most specific seed path that contains candidatePath.
func (g SeedPathGroup) Match(candidatePath string) (SeedPathInfo, bool) {
	var matched SeedPathInfo
	found := false

	for _, seed := range g.Seeds {
		if !IsChildPath(seed.IngressPath, candidatePath) {
			continue
		}

		if !found || len(seed.IngressPath) > len(matched.IngressPath) {
			matched = seed
			found = true
		}
	}

	return matched, found
}

// SeedCache stores the current Ingress-derived seed paths keyed by
// namespace/host and keeps informer updates safe for concurrent scanner reads.
type SeedCache struct {
	mu    sync.RWMutex
	items map[string][]SeedPathInfo
}

func NewSeedCache() *SeedCache {
	return &SeedCache{
		items: make(map[string][]SeedPathInfo),
	}
}

func (c *SeedCache) UpsertIngress(namespace, ingressName string, seeds []SeedPathInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Replace the whole Ingress snapshot so removed paths disappear from future
	// discovery runs after an update event.
	c.deleteIngressLocked(namespace, ingressName)
	for _, seed := range seeds {
		key := seedCacheKey(seed.Namespace, seed.Host)
		c.items[key] = append(c.items[key], seed)
	}
}

func (c *SeedCache) DeleteIngress(namespace, ingressName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.deleteIngressLocked(namespace, ingressName)
}

func (c *SeedCache) Groups() []SeedPathGroup {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return copied, sorted groups so callers can rank/match without holding the
	// cache lock and without mutating stored state.
	groups := make([]SeedPathGroup, 0, len(c.items))
	for key, seeds := range c.items {
		if len(seeds) == 0 {
			continue
		}

		namespace, host := parseSeedCacheKey(key)
		copied := append([]SeedPathInfo(nil), seeds...)
		sort.SliceStable(copied, func(i, j int) bool {
			if len(copied[i].IngressPath) == len(copied[j].IngressPath) {
				return copied[i].IngressPath < copied[j].IngressPath
			}

			return len(copied[i].IngressPath) > len(copied[j].IngressPath)
		})

		groups = append(groups, SeedPathGroup{
			Namespace: namespace,
			Host:      host,
			Seeds:     copied,
		})
	}

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Namespace == groups[j].Namespace {
			return groups[i].Host < groups[j].Host
		}

		return groups[i].Namespace < groups[j].Namespace
	})

	return groups
}

func (c *SeedCache) deleteIngressLocked(namespace, ingressName string) {
	// Filter in place to reduce allocations while rebuilding each host group.
	for key, seeds := range c.items {
		filtered := seeds[:0]
		for _, seed := range seeds {
			if seed.Namespace == namespace && seed.IngressName == ingressName {
				continue
			}

			filtered = append(filtered, seed)
		}

		if len(filtered) == 0 {
			delete(c.items, key)
			continue
		}

		c.items[key] = filtered
	}
}

func seedCacheKey(namespace, host string) string {
	// NUL separates fields because Kubernetes namespaces and DNS hosts cannot
	// contain it, making the key reversible without escaping.
	return namespace + "\x00" + host
}

func parseSeedCacheKey(key string) (string, string) {
	parts := strings.SplitN(key, "\x00", 2)
	if len(parts) != 2 {
		return "", key
	}

	return parts[0], parts[1]
}

func (p *VLogPathPlugin) startIngressInformer(ctx context.Context) {
	// The informer is the authoritative source for seed paths; log-derived paths
	// are published only when they extend a currently observed Ingress route.
	if k8s.ClientSet == nil {
		p.log.Error("Kubernetes client is nil, VLogPathDiscovery informer cannot start")
		return
	}

	factory := informers.NewSharedInformerFactory(
		k8s.ClientSet,
		time.Duration(p.vlogPathConfig.ResyncTimeSecond)*time.Second,
	)
	p.factory = factory

	p.ingressInformer = factory.Networking().V1().Ingresses().Informer()

	_, err := p.ingressInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			ingress, ok := obj.(*networkingv1.Ingress)
			if !ok {
				p.log.Error("Failed to cast object to Ingress", logger.Fields{
					"object_type": fmt.Sprintf("%T", obj),
				})
				return
			}

			p.upsertIngressSeeds(ctx, ingress)
		},
		UpdateFunc: func(oldObj, newObj any) {
			ingress, ok := newObj.(*networkingv1.Ingress)
			if !ok {
				p.log.Error("Failed to cast updated object to Ingress", logger.Fields{
					"object_type": fmt.Sprintf("%T", newObj),
				})
				return
			}

			p.upsertIngressSeeds(ctx, ingress)
		},
		DeleteFunc: func(obj any) {
			ingress, ok := obj.(*networkingv1.Ingress)
			if !ok {
				tombstone, tombstoneOK := obj.(cache.DeletedFinalStateUnknown)
				if tombstoneOK {
					ingress, ok = tombstone.Obj.(*networkingv1.Ingress)
				}
			}
			if !ok {
				p.log.Error("Failed to cast deleted object to Ingress", logger.Fields{
					"object_type": fmt.Sprintf("%T", obj),
				})
				return
			}

			p.seedCache.DeleteIngress(ingress.Namespace, ingress.Name)
		},
	})
	if err != nil {
		p.log.Error("Failed to add Ingress event handler", logger.Fields{
			"error": err.Error(),
		})
		return
	}

	p.factory.Start(p.stopChan)

	if !cache.WaitForCacheSync(p.stopChan, p.ingressInformer.HasSynced) {
		p.log.Error("Failed to wait for VLogPathDiscovery ingress cache sync")
		return
	}

	p.log.Info("VLogPathDiscovery ingress informer started")

	select {
	case <-ctx.Done():
	case <-p.stopChan:
	}
}

func (p *VLogPathPlugin) upsertIngressSeeds(ctx context.Context, ingress *networkingv1.Ingress) {
	if ingress == nil {
		return
	}

	// Namespace filtering keeps discovery scoped to tenant namespaces configured
	// for compliance checks.
	if !p.shouldProcessIngress(ingress) {
		p.seedCache.DeleteIngress(ingress.Namespace, ingress.Name)
		return
	}

	seeds, err := p.buildSeedPaths(ctx, ingress)
	if err != nil {
		p.log.Error("Failed to build VLog seed paths", logger.Fields{
			"namespace": ingress.Namespace,
			"ingress":   ingress.Name,
			"error":     err.Error(),
		})
		return
	}

	p.seedCache.UpsertIngress(ingress.Namespace, ingress.Name, seeds)
	p.log.Debug("Updated VLog seed paths", logger.Fields{
		"namespace": ingress.Namespace,
		"ingress":   ingress.Name,
		"count":     len(seeds),
	})
}

func (p *VLogPathPlugin) shouldProcessIngress(ingress *networkingv1.Ingress) bool {
	if ingress == nil {
		return false
	}

	if p.vlogPathConfig.NamespacePrefix == "" {
		return true
	}

	return strings.HasPrefix(ingress.Namespace, p.vlogPathConfig.NamespacePrefix)
}

func (p *VLogPathPlugin) buildSeedPaths(
	ctx context.Context,
	ingress *networkingv1.Ingress,
) ([]SeedPathInfo, error) {
	// EndpointSlice data annotates each seed with live backend health, matching
	// the discovery payload shape produced by the informer plugins.
	endpointSlices, err := k8s.ClientSet.DiscoveryV1().
		EndpointSlices(ingress.Namespace).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list EndpointSlices: %w", err)
	}

	endpointSlicesMap := buildEndpointSlicesMap(endpointSlices)

	seeds := make([]SeedPathInfo, 0)
	for _, rule := range ingress.Spec.Rules {
		host := strings.TrimSpace(rule.Host)
		if host == "" || host == "*" || rule.HTTP == nil {
			continue
		}

		for _, path := range rule.HTTP.Paths {
			serviceName := ""
			if path.Backend.Service != nil {
				serviceName = path.Backend.Service.Name
			}

			normalizedSeedPath, ok := NormalizePath(path.Path)
			if !ok {
				continue
			}

			hasActivePods, podCount := endpointInfo(endpointSlicesMap, serviceName)
			seeds = append(seeds, SeedPathInfo{
				DiscoveryName: p.Name(),
				Namespace:     ingress.Namespace,
				IngressName:   ingress.Name,
				Host:          host,
				IngressPath:   normalizedSeedPath,
				ServiceName:   serviceName,
				HasActivePods: hasActivePods,
				PodCount:      podCount,
				UpdatedAt:     time.Now(),
			})
		}
	}

	return seeds, nil
}

func buildEndpointSlicesMap(
	list *discoveryv1.EndpointSliceList,
) map[string][]discoveryv1.EndpointSlice {
	// Group EndpointSlices by owning Service so each Ingress backend can be
	// checked with a constant-time map lookup.
	result := make(map[string][]discoveryv1.EndpointSlice)
	if list == nil {
		return result
	}

	for _, endpointSlice := range list.Items {
		serviceName := endpointSlice.Labels[discoveryv1.LabelServiceName]
		if serviceName == "" {
			continue
		}

		result[serviceName] = append(result[serviceName], endpointSlice)
	}

	return result
}

func endpointInfo(
	endpointSlices map[string][]discoveryv1.EndpointSlice,
	serviceName string,
) (bool, int) {
	// Ready endpoints represent pods that can currently serve the Ingress path.
	if serviceName == "" {
		return false, 0
	}

	readyPodCount := 0
	for _, endpointSlice := range endpointSlices[serviceName] {
		for _, endpoint := range endpointSlice.Endpoints {
			if endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready {
				readyPodCount++
			}
		}
	}

	return readyPodCount > 0, readyPodCount
}
