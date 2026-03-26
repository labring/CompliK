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

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
	"gopkg.in/yaml.v3"
)

// Loader handles configuration file loading and parsing
type Loader struct {
	configPath string
	lastHash   string
}

// NewLoader creates a new configuration loader
func NewLoader(configPath string) *Loader {
	return &Loader{
		configPath: configPath,
	}
}

// Load reads and parses the configuration file
func (l *Loader) Load() (*models.Config, error) {
	if _, err := os.Stat(l.configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file does not exist: %s", l.configPath)
	}

	data, err := os.ReadFile(l.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file is empty: %s", l.configPath)
	}

	var config models.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration file: %w", err)
	}

	if config.Scanner.ScanInterval == 0 {
		config.Scanner.ScanInterval = 100 * time.Second
	}

	// Update last hash
	hash, _ := l.calculateHash()
	l.lastHash = hash

	return &config, nil
}

// HasChanged checks if the configuration file has changed since last load
func (l *Loader) HasChanged() (bool, error) {
	currentHash, err := l.calculateHash()
	if err != nil {
		return false, err
	}

	if l.lastHash == "" {
		l.lastHash = currentHash
		return false, nil
	}

	changed := currentHash != l.lastHash
	if changed {
		l.lastHash = currentHash
	}

	return changed, nil
}

// GetConfigPath returns the configuration file path
func (l *Loader) GetConfigPath() string {
	return l.configPath
}

// GetConfigDir returns the directory containing the configuration file
func (l *Loader) GetConfigDir() string {
	return filepath.Dir(l.configPath)
}

// calculateHash computes SHA256 hash of the configuration file
func (l *Loader) calculateHash() (string, error) {
	file, err := os.Open(l.configPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
