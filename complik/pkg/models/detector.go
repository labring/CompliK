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

// Package models defines the core data structures used throughout the CompliK system.
package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DetectorInfo contains information about a detected resource and its compliance status
type DetectorInfo struct {
	DiscoveryName string `json:"discovery_name"`
	CollectorName string `json:"collector_name"`
	DetectorName  string `json:"detector_name"`

	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Region    string `json:"region"`

	Host string   `json:"host"`
	Path []string `json:"path"`
	URL  string   `json:"url"`

	Description string   `json:"description,omitempty"`
	Keywords    []string `json:"keywords,omitempty"`

	IsIllegal   bool   `json:"is_illegal"`
	Explanation string `json:"explanation,omitempty"`
}

// SaveToFile persists the detector information to a JSON file in the specified directory
func (d *DetectorInfo) SaveToFile(dirPath string) error {
	if d == nil {
		return errors.New("models.DetectorInfo is nil")
	}

	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("analysis_%s.json", timestamp)
	filePath := filepath.Join(dirPath, filename)

	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
