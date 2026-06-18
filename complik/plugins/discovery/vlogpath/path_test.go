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

//nolint:testpackage,wsl_v5 // Tests exercise unexported ranking and config helpers.
package vlogpath

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeContentType(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "html charset", in: "text/html; charset=utf-8", want: "text/html"},
		{
			name: "xhtml charset",
			in:   "application/xhtml+xml; charset=utf-8",
			want: "application/xhtml+xml",
		},
		{name: "upper", in: "TEXT/HTML", want: "text/html"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeContentType(tt.in)
			if got != tt.want {
				t.Fatalf("NormalizeContentType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "empty", in: "", want: "/", ok: true},
		{name: "query fragment", in: "/a//b/?x=1#top", want: "/a/b", ok: true},
		{name: "decode once", in: "/a/%41", want: "/a/A", ok: true},
		{name: "missing slash", in: "activity/a", want: "/activity/a", ok: true},
		{name: "root trailing", in: "/", want: "/", ok: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizePath(tt.in)
			if ok != tt.ok {
				t.Fatalf("NormalizePath() ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("NormalizePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsChildPath(t *testing.T) {
	tests := []struct {
		name      string
		seed      string
		candidate string
		want      bool
	}{
		{name: "child", seed: "/activity", candidate: "/activity/a", want: true},
		{name: "same", seed: "/activity", candidate: "/activity", want: false},
		{name: "prefix sibling", seed: "/activity", candidate: "/activity-other/a", want: false},
		{name: "root child", seed: "/", candidate: "/login", want: true},
		{name: "root same", seed: "/", candidate: "/", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsChildPath(tt.seed, tt.candidate)
			if got != tt.want {
				t.Fatalf("IsChildPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRankCandidates(t *testing.T) {
	now := time.Now()
	items := []CandidatePath{
		{Path: "/docs/a", Count: 100, LatestAccessTime: now},
		{Path: "/admin/a", Count: 1, LatestAccessTime: now.Add(-time.Hour)},
		{Path: "/login", Count: 2, LatestAccessTime: now.Add(time.Hour)},
	}

	got := RankCandidates(items, 2, []string{"/admin", "/login"})
	if len(got) != 2 {
		t.Fatalf("RankCandidates len = %d, want 2", len(got))
	}

	if got[0].Path != "/login" {
		t.Fatalf("first candidate = %q, want /login", got[0].Path)
	}

	if got[1].Path != "/admin/a" {
		t.Fatalf("second candidate = %q, want /admin/a", got[1].Path)
	}
}

func TestDefaultConfigHasLargeClusterGuards(t *testing.T) {
	cfg := (&VLogPathPlugin{}).getDefaultVLogPathConfig()

	if cfg.MaxGroupsPerRun != 500 {
		t.Fatalf("MaxGroupsPerRun = %d, want 500", cfg.MaxGroupsPerRun)
	}
	if cfg.QueryConcurrency != 3 {
		t.Fatalf("QueryConcurrency = %d, want 3", cfg.QueryConcurrency)
	}
	if cfg.RunTimeoutSecond != 900 {
		t.Fatalf("RunTimeoutSecond = %d, want 900", cfg.RunTimeoutSecond)
	}
}

func TestBuildQueryUsesConfiguredTimeField(t *testing.T) {
	client := NewVLogClient(VLogClientConfig{
		App: "higress-gateway",
		Fields: VLogFields{
			Time: "event_time",
			Host: "authority",
		},
	})

	start := time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	got := client.buildQuery("example.com", start, end, 100)

	want := `event_time:[2026-06-17T00:00:00Z,2026-06-17T01:00:00Z]`
	if !strings.Contains(got, want) {
		t.Fatalf("buildQuery() = %q, want contains %q", got, want)
	}
}
