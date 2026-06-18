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

//nolint:wsl_v5 // Path normalization and ranking keep related checks compact.
package vlogpath

import (
	"net/url"
	"sort"
	"strings"
	"time"
)

const maxNormalizedPathLength = 1024

// CandidatePath is a log-derived child path plus the seed Ingress path that
// proves the host and route belong to a tracked workload.
type CandidatePath struct {
	Seed             SeedPathInfo
	Path             string
	Count            int
	LatestAccessTime time.Time
}

// NormalizeContentType strips parameters such as charset and lowercases the
// media type so allowlist checks can compare stable values.
func NormalizeContentType(value string) string {
	contentType := strings.ToLower(strings.TrimSpace(value))
	if idx := strings.Index(contentType, ";"); idx >= 0 {
		contentType = contentType[:idx]
	}

	return strings.TrimSpace(contentType)
}

func normalizeContentTypes(values []string) []string {
	// Deduplicate after normalization so config can be written naturally while
	// runtime comparisons stay small and predictable.
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))

	for _, value := range values {
		item := NormalizeContentType(value)
		if item == "" {
			continue
		}

		if _, exists := seen[item]; exists {
			continue
		}

		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}

	return normalized
}

func isAllowedContentType(value string, allowlist []string) bool {
	// Empty content types are treated as unknown responses and skipped.
	contentType := NormalizeContentType(value)
	if contentType == "" {
		return false
	}

	for _, allowed := range allowlist {
		if contentType == NormalizeContentType(allowed) {
			return true
		}
	}

	return false
}

// NormalizePath extracts the URL path, decodes it once, removes query/fragment
// data, and normalizes slash/trailing-slash variants for reliable comparison.
func NormalizePath(value string) (string, bool) {
	pathValue := strings.TrimSpace(value)
	if pathValue == "" {
		return "/", true
	}

	if parsed, err := url.Parse(pathValue); err == nil {
		if parsed.Path != "" {
			pathValue = parsed.Path
		}
	}

	if idx := strings.Index(pathValue, "?"); idx >= 0 {
		pathValue = pathValue[:idx]
	}
	if idx := strings.Index(pathValue, "#"); idx >= 0 {
		pathValue = pathValue[:idx]
	}

	if decoded, err := url.PathUnescape(pathValue); err == nil {
		pathValue = decoded
	}

	pathValue = strings.TrimSpace(pathValue)
	if pathValue == "" {
		pathValue = "/"
	}

	if !strings.HasPrefix(pathValue, "/") {
		pathValue = "/" + pathValue
	}

	for strings.Contains(pathValue, "//") {
		pathValue = strings.ReplaceAll(pathValue, "//", "/")
	}

	// Keep "/" intact while making "/foo/" and "/foo" compare as one path.
	if len(pathValue) > 1 {
		pathValue = strings.TrimRight(pathValue, "/")
	}

	if len(pathValue) > maxNormalizedPathLength {
		return "", false
	}

	return pathValue, true
}

// IsChildPath reports whether candidatePath is below seedPath after applying
// the same normalization rules to both sides.
func IsChildPath(seedPath, candidatePath string) bool {
	seed, seedOK := NormalizePath(seedPath)
	candidate, candidateOK := NormalizePath(candidatePath)
	if !seedOK || !candidateOK {
		return false
	}

	if seed == candidate {
		return false
	}

	if seed == "/" {
		return candidate != "/"
	}

	return strings.HasPrefix(candidate, seed+"/")
}

// RankCandidates prioritizes security-sensitive prefixes, then frequent and
// recent paths, and finally path name for deterministic ties.
func RankCandidates(
	items []CandidatePath,
	limit int,
	highRiskPrefixes []string,
) []CandidatePath {
	if limit <= 0 || len(items) == 0 {
		return nil
	}

	sort.SliceStable(items, func(i, j int) bool {
		iRisk := highRiskScore(items[i].Path, highRiskPrefixes)
		jRisk := highRiskScore(items[j].Path, highRiskPrefixes)
		if iRisk != jRisk {
			return iRisk > jRisk
		}

		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}

		if !items[i].LatestAccessTime.Equal(items[j].LatestAccessTime) {
			return items[i].LatestAccessTime.After(items[j].LatestAccessTime)
		}

		return items[i].Path < items[j].Path
	})

	if len(items) > limit {
		return items[:limit]
	}

	return items
}

func highRiskScore(path string, prefixes []string) int {
	// Longer matching prefixes win, so a specific "/admin/pay" prefix outranks
	// a broader "/admin" prefix when both are configured.
	score := 0
	normalizedPath, ok := NormalizePath(path)
	if !ok {
		return score
	}

	for _, prefix := range prefixes {
		normalizedPrefix, prefixOK := NormalizePath(prefix)
		if !prefixOK {
			continue
		}

		if normalizedPath == normalizedPrefix ||
			strings.HasPrefix(normalizedPath, normalizedPrefix+"/") {
			score = max(score, len(normalizedPrefix))
		}
	}

	return score
}
