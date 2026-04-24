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

package plugin

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
)

const (
	PluginStopTimeout = 20 * time.Second
)

var PluginFactories = make(map[string]func() Plugin)

type PluginInstance struct {
	Plugin Plugin
	Config config.PluginConfig
}
type Manager struct {
	pluginInstances map[string]*PluginInstance
	eventBus        *eventbus.EventBus
	mu              sync.RWMutex
}

func NewManager(eventBus *eventbus.EventBus) *Manager {
	return &Manager{
		pluginInstances: make(map[string]*PluginInstance),
		eventBus:        eventBus,
	}
}

func (m *Manager) LoadPlugins(pluginConfigs []config.PluginConfig) error {
	log := logger.GetLogger()
	log.Info("Loading plugins", logger.Fields{"count": len(pluginConfigs)})

	for _, pluginConfig := range pluginConfigs {
		if err := m.LoadPlugin(pluginConfig); err != nil {
			log.Error("Failed to load plugin", logger.Fields{
				"plugin": pluginConfig.Name,
				"error":  err.Error(),
			})

			continue
		}
	}

	return nil
}

func (m *Manager) LoadPlugin(pluginConfig config.PluginConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log := logger.GetLogger()

	factory, exists := PluginFactories[pluginConfig.Name]
	if !exists {
		log.Warn("Plugin factory not found", logger.Fields{
			"plugin":    pluginConfig.Name,
			"available": getRegisteredFactoryNames(),
		})

		return nil
	}

	if _, exists := m.pluginInstances[pluginConfig.Name]; exists {
		log.Debug("Plugin already loaded", logger.Fields{"plugin": pluginConfig.Name})
		return nil
	}

	plugin := factory()
	instance := &PluginInstance{
		Plugin: plugin,
		Config: pluginConfig,
	}
	m.pluginInstances[pluginConfig.Name] = instance

	log.Info("Plugin loaded successfully", logger.Fields{
		"plugin":  pluginConfig.Name,
		"type":    pluginConfig.Type,
		"enabled": pluginConfig.Enabled,
	})

	return nil
}

func getRegisteredFactoryNames() []string {
	names := make([]string, 0, len(PluginFactories))
	for name := range PluginFactories {
		names = append(names, name)
	}

	return names
}

func (m *Manager) StartAll() error {
	return m.StartAllWithTimeout()
}

func (m *Manager) StartAllWithTimeout() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	log := logger.GetLogger()

	var wg sync.WaitGroup

	errChan := make(chan error, len(m.pluginInstances))
	for name, instance := range m.pluginInstances {
		if !instance.Config.Enabled {
			log.Debug("Plugin disabled, skipping", logger.Fields{"plugin": name})
			continue
		}

		wg.Add(1)
		log.Info("Starting plugin", logger.Fields{"plugin": name})

		go func(name string, instance *PluginInstance) {
			defer wg.Done()

			pluginLog := log.WithField("plugin", name)
			if err := instance.Plugin.Start(
				context.Background(),
				instance.Config,
				m.eventBus,
			); err != nil {
				pluginLog.Error("Plugin failed", logger.Fields{"error": err.Error()})

				errChan <- fmt.Errorf("plugin %s failed to start: %w", name, err)
			} else {
				pluginLog.Info("Plugin started successfully")
			}
		}(name, instance)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		close(errChan)

		var errors []error
		for err := range errChan {
			errors = append(errors, err)
		}

		if len(errors) > 0 {
			return fmt.Errorf("failed to start %d plugins: %v", len(errors), errors)
		}

		return nil
	}
}

func (m *Manager) StopAll() error {
	ctx, cancel := context.WithTimeout(context.Background(), PluginStopTimeout)

	m.mu.RLock()
	defer m.mu.RUnlock()

	log := logger.GetLogger()
	log.Info("Stopping all plugins")

	for name, instance := range m.pluginInstances {
		log.Info("Stopping plugin", logger.Fields{"plugin": name})

		if err := instance.Plugin.Stop(ctx); err != nil {
			log.Error("Error stopping plugin", logger.Fields{
				"plugin": name,
				"error":  err.Error(),
			})
		} else {
			log.Debug("Plugin stopped", logger.Fields{"plugin": name})
		}
	}

	cancel()
	log.Info("All plugins stopped")

	return nil
}
