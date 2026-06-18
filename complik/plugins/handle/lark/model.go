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

package lark

import (
	"sort"
	"time"
)

type LarkMessage struct {
	MsgType string `json:"msg_type"`
	Card    any    `json:"card,omitempty"`
}

type LarkResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

type AggregatedAlert struct {
	Region           string
	Namespace        string
	Host             string
	Resource         string
	FirstSeenAt      time.Time
	LastSeenAt       time.Time
	Paths            map[string]*AggregatedPath
	OmittedPathCount int
}

type AggregatedPath struct {
	Path         string
	URL          string
	Detectors    map[string]struct{}
	Keywords     map[string]struct{}
	Devices      map[string]struct{}
	Descriptions map[string]struct{}
	Explanations map[string]struct{}
}

type AggregatedPathView struct {
	Path         string
	URL          string
	Detectors    []string
	Keywords     []string
	Devices      []string
	Descriptions []string
	Explanations []string
}

func (a AggregatedAlert) snapshot() AggregatedAlert {
	out := AggregatedAlert{
		Region:           a.Region,
		Namespace:        a.Namespace,
		Host:             a.Host,
		Resource:         a.Resource,
		FirstSeenAt:      a.FirstSeenAt,
		LastSeenAt:       a.LastSeenAt,
		Paths:            make(map[string]*AggregatedPath, len(a.Paths)),
		OmittedPathCount: a.OmittedPathCount,
	}

	for key, path := range a.Paths {
		if path == nil {
			continue
		}

		out.Paths[key] = &AggregatedPath{
			Path:         path.Path,
			URL:          path.URL,
			Detectors:    cloneSet(path.Detectors),
			Keywords:     cloneSet(path.Keywords),
			Devices:      cloneSet(path.Devices),
			Descriptions: cloneSet(path.Descriptions),
			Explanations: cloneSet(path.Explanations),
		}
	}

	return out
}

func (a AggregatedAlert) SortedPaths() []AggregatedPathView {
	paths := make([]AggregatedPathView, 0, len(a.Paths))
	for _, path := range a.Paths {
		if path == nil {
			continue
		}

		paths = append(paths, AggregatedPathView{
			Path:         path.Path,
			URL:          path.URL,
			Detectors:    sortedSetValues(path.Detectors),
			Keywords:     sortedSetValues(path.Keywords),
			Devices:      sortedSetValues(path.Devices),
			Descriptions: sortedSetValues(path.Descriptions),
			Explanations: sortedSetValues(path.Explanations),
		})
	}

	sort.Slice(paths, func(i, j int) bool {
		return paths[i].Path < paths[j].Path
	})

	return paths
}

func cloneSet(in map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for key := range in {
		out[key] = struct{}{}
	}

	return out
}

func sortedSetValues(values map[string]struct{}) []string {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}

	sort.Strings(items)

	return items
}
