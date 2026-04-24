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

package utils

import (
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

func GenerateDiscoveryInfo(
	ing networkingv1.Ingress,
	hasActivePod bool,
	podCount int,
	discoveryName string,
) []models.DiscoveryInfo {
	var discoveryList []models.DiscoveryInfo
	for _, rule := range ing.Spec.Rules {
		host := "*"
		if rule.Host != "" {
			host = rule.Host
		}

		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				serviceName := ""
				if path.Backend.Service != nil {
					serviceName = path.Backend.Service.Name
				}

				pathPattern := "/"
				if path.Path != "" {
					pathPattern = path.Path
				}

				discoveryInfo := models.DiscoveryInfo{
					DiscoveryName: discoveryName,
					Name:          ing.Name,
					Namespace:     ing.Namespace,
					Host:          host,
					Path: []string{
						pathPattern,
					},
					ServiceName:   serviceName,
					HasActivePods: hasActivePod,
					PodCount:      podCount,
				}
				discoveryList = append(discoveryList, discoveryInfo)
			}
		}
	}

	return discoveryList
}

func GenerateIngressAndPodInfo(
	ing networkingv1.Ingress,
	endpointSlicesMap map[string]map[string][]*discoveryv1.EndpointSlice,
	discoveryName string,
) []models.DiscoveryInfo {
	var discoveryList []models.DiscoveryInfo
	for _, rule := range ing.Spec.Rules {
		host := "*"
		if rule.Host != "" {
			host = rule.Host
		}

		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				serviceName := ""
				if path.Backend.Service != nil {
					serviceName = path.Backend.Service.Name
				}

				pathPattern := "/"
				if path.Path != "" {
					pathPattern = path.Path
				}

				hasActivePod, podCount := getInfoFromEndpointSlices(
					endpointSlicesMap,
					ing.Namespace,
					serviceName,
				)
				discoveryInfo := models.DiscoveryInfo{
					DiscoveryName: discoveryName,
					Name:          ing.Name,
					Namespace:     ing.Namespace,
					Host:          host,
					Path: []string{
						pathPattern,
					},
					ServiceName:   serviceName,
					HasActivePods: hasActivePod,
					PodCount:      podCount,
				}
				discoveryList = append(discoveryList, discoveryInfo)
			}
		}
	}

	return discoveryList
}

func getInfoFromEndpointSlices(
	endpointSlicesMap map[string]map[string][]*discoveryv1.EndpointSlice,
	namespace, serviceName string,
) (bool, int) {
	if serviceName == "" {
		return false, 0
	}

	namespaceEndpointSlices, exists := endpointSlicesMap[namespace]
	if !exists {
		return false, 0
	}

	endpointSlices, exists := namespaceEndpointSlices[serviceName]
	if !exists {
		return false, 0
	}

	readyPodCount := 0
	for _, endpointSlice := range endpointSlices {
		for _, endpoint := range endpointSlice.Endpoints {
			if endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready {
				readyPodCount++
			}
		}
	}

	return readyPodCount > 0, readyPodCount
}
