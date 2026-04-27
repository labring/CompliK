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

//nolint:testpackage,wsl_v5 // Tests exercise internal plugin manager state directly.
package plugin

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestPluginManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Plugin Manager Suite")
}

// MockPlugin is a test implementation of the Plugin interface
type MockPlugin struct {
	name        string
	pluginType  string
	startCalled bool
	stopCalled  bool
	startErr    error
	stopErr     error
	startDelay  time.Duration
	stopDelay   time.Duration
	mu          sync.Mutex
}

func NewMockPlugin(name, pluginType string) *MockPlugin {
	return &MockPlugin{
		name:       name,
		pluginType: pluginType,
	}
}

func (m *MockPlugin) Name() string {
	return m.name
}

func (m *MockPlugin) Type() string {
	return m.pluginType
}

func (m *MockPlugin) Start(
	ctx context.Context,
	cfg config.PluginConfig,
	eb *eventbus.EventBus,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.startDelay > 0 {
		time.Sleep(m.startDelay)
	}

	m.startCalled = true

	return m.startErr
}

func (m *MockPlugin) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopDelay > 0 {
		time.Sleep(m.stopDelay)
	}

	m.stopCalled = true

	return m.stopErr
}

func (m *MockPlugin) IsStarted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startCalled
}

func (m *MockPlugin) IsStopped() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopCalled
}

var _ = Describe("PluginManager", func() {
	var (
		manager      *Manager
		eb           *eventbus.EventBus
		oldFactories map[string]func() Plugin
	)

	BeforeEach(func() {
		// Save original factories
		oldFactories = make(map[string]func() Plugin)
		maps.Copy(oldFactories, PluginFactories)

		// Clear factories
		PluginFactories = make(map[string]func() Plugin)

		eb = eventbus.NewEventBus(100)
		manager = NewManager(eb)
	})

	AfterEach(func() {
		// Restore original factories
		PluginFactories = oldFactories
	})

	Describe("NewManager", func() {
		It("should create a new manager with event bus", func() {
			Expect(manager).NotTo(BeNil())
			Expect(manager.eventBus).To(Equal(eb))
			Expect(manager.pluginInstances).NotTo(BeNil())
			Expect(manager.pluginInstances).To(BeEmpty())
		})
	})

	Describe("LoadPlugin", func() {
		It("should load a plugin successfully", func() {
			mockPlugin := NewMockPlugin("test-plugin", "discovery")
			PluginFactories["test-plugin"] = func() Plugin {
				return mockPlugin
			}

			cfg := config.PluginConfig{
				Name:    "test-plugin",
				Type:    "discovery",
				Enabled: true,
			}

			err := manager.LoadPlugin(cfg)
			Expect(err).NotTo(HaveOccurred())

			manager.mu.RLock()
			instance, exists := manager.pluginInstances["test-plugin"]
			manager.mu.RUnlock()

			Expect(exists).To(BeTrue())
			Expect(instance).NotTo(BeNil())
			Expect(instance.Plugin).To(Equal(mockPlugin))
			Expect(instance.Config.Name).To(Equal("test-plugin"))
		})

		It("should warn when factory not found", func() {
			cfg := config.PluginConfig{
				Name:    "nonexistent-plugin",
				Type:    "discovery",
				Enabled: true,
			}

			err := manager.LoadPlugin(cfg)
			Expect(err).NotTo(HaveOccurred()) // Should not error, just warn

			manager.mu.RLock()
			_, exists := manager.pluginInstances["nonexistent-plugin"]
			manager.mu.RUnlock()

			Expect(exists).To(BeFalse())
		})

		It("should not reload already loaded plugin", func() {
			mockPlugin := NewMockPlugin("test-plugin", "discovery")
			callCount := 0
			PluginFactories["test-plugin"] = func() Plugin {
				callCount++
				return mockPlugin
			}

			cfg := config.PluginConfig{
				Name:    "test-plugin",
				Type:    "discovery",
				Enabled: true,
			}

			err := manager.LoadPlugin(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(callCount).To(Equal(1))

			// Try loading again
			err = manager.LoadPlugin(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(callCount).To(Equal(1)) // Factory should not be called again
		})
	})

	Describe("LoadPlugins", func() {
		It("should load multiple plugins", func() {
			plugin1 := NewMockPlugin("plugin1", "discovery")
			plugin2 := NewMockPlugin("plugin2", "compliance")
			plugin3 := NewMockPlugin("plugin3", "handler")

			PluginFactories["plugin1"] = func() Plugin { return plugin1 }
			PluginFactories["plugin2"] = func() Plugin { return plugin2 }
			PluginFactories["plugin3"] = func() Plugin { return plugin3 }

			configs := []config.PluginConfig{
				{Name: "plugin1", Type: "discovery", Enabled: true},
				{Name: "plugin2", Type: "compliance", Enabled: true},
				{Name: "plugin3", Type: "handler", Enabled: false},
			}

			err := manager.LoadPlugins(configs)
			Expect(err).NotTo(HaveOccurred())

			manager.mu.RLock()
			Expect(manager.pluginInstances).To(HaveLen(3))
			manager.mu.RUnlock()
		})

		It("should continue loading when one plugin fails", func() {
			plugin1 := NewMockPlugin("plugin1", "discovery")
			plugin3 := NewMockPlugin("plugin3", "handler")

			PluginFactories["plugin1"] = func() Plugin { return plugin1 }
			// plugin2 intentionally not registered
			PluginFactories["plugin3"] = func() Plugin { return plugin3 }

			configs := []config.PluginConfig{
				{Name: "plugin1", Type: "discovery", Enabled: true},
				{Name: "plugin2", Type: "compliance", Enabled: true}, // Will fail
				{Name: "plugin3", Type: "handler", Enabled: true},
			}

			err := manager.LoadPlugins(configs)
			Expect(err).NotTo(HaveOccurred())

			manager.mu.RLock()
			Expect(manager.pluginInstances).To(HaveLen(2))
			_, exists1 := manager.pluginInstances["plugin1"]
			_, exists2 := manager.pluginInstances["plugin2"]
			_, exists3 := manager.pluginInstances["plugin3"]
			manager.mu.RUnlock()

			Expect(exists1).To(BeTrue())
			Expect(exists2).To(BeFalse())
			Expect(exists3).To(BeTrue())
		})
	})

	Describe("StartAll", func() {
		It("should start all enabled plugins", func() {
			plugin1 := NewMockPlugin("plugin1", "discovery")
			plugin2 := NewMockPlugin("plugin2", "compliance")
			plugin3 := NewMockPlugin("plugin3", "handler")

			PluginFactories["plugin1"] = func() Plugin { return plugin1 }
			PluginFactories["plugin2"] = func() Plugin { return plugin2 }
			PluginFactories["plugin3"] = func() Plugin { return plugin3 }

			configs := []config.PluginConfig{
				{Name: "plugin1", Type: "discovery", Enabled: true},
				{Name: "plugin2", Type: "compliance", Enabled: true},
				{Name: "plugin3", Type: "handler", Enabled: false}, // Disabled
			}

			err := manager.LoadPlugins(configs)
			Expect(err).NotTo(HaveOccurred())

			err = manager.StartAll()
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool { return plugin1.IsStarted() }).Should(BeTrue())
			Eventually(func() bool { return plugin2.IsStarted() }).Should(BeTrue())
			Expect(plugin3.IsStarted()).To(BeFalse()) // Should not start disabled plugin
		})

		It("should report errors when plugins fail to start", func() {
			plugin1 := NewMockPlugin("plugin1", "discovery")
			plugin2 := NewMockPlugin("plugin2", "compliance")
			plugin2.startErr = errors.New("failed to initialize")

			PluginFactories["plugin1"] = func() Plugin { return plugin1 }
			PluginFactories["plugin2"] = func() Plugin { return plugin2 }

			configs := []config.PluginConfig{
				{Name: "plugin1", Type: "discovery", Enabled: true},
				{Name: "plugin2", Type: "compliance", Enabled: true},
			}

			Expect(manager.LoadPlugins(configs)).To(Succeed())
			err := manager.StartAll()

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to start"))
		})

		It("should start plugins concurrently", func() {
			plugin1 := NewMockPlugin("plugin1", "discovery")
			plugin2 := NewMockPlugin("plugin2", "compliance")
			plugin1.startDelay = 100 * time.Millisecond
			plugin2.startDelay = 100 * time.Millisecond

			PluginFactories["plugin1"] = func() Plugin { return plugin1 }
			PluginFactories["plugin2"] = func() Plugin { return plugin2 }

			configs := []config.PluginConfig{
				{Name: "plugin1", Type: "discovery", Enabled: true},
				{Name: "plugin2", Type: "compliance", Enabled: true},
			}

			Expect(manager.LoadPlugins(configs)).To(Succeed())

			start := time.Now()
			err := manager.StartAll()
			elapsed := time.Since(start)

			Expect(err).NotTo(HaveOccurred())
			// If sequential, would take 200ms+. Concurrent should be ~100ms
			Expect(elapsed).To(BeNumerically("<", 150*time.Millisecond))
		})
	})

	Describe("StopAll", func() {
		It("should stop all plugins", func() {
			plugin1 := NewMockPlugin("plugin1", "discovery")
			plugin2 := NewMockPlugin("plugin2", "compliance")

			PluginFactories["plugin1"] = func() Plugin { return plugin1 }
			PluginFactories["plugin2"] = func() Plugin { return plugin2 }

			configs := []config.PluginConfig{
				{Name: "plugin1", Type: "discovery", Enabled: true},
				{Name: "plugin2", Type: "compliance", Enabled: true},
			}

			Expect(manager.LoadPlugins(configs)).To(Succeed())
			Expect(manager.StartAll()).To(Succeed())

			err := manager.StopAll()
			Expect(err).NotTo(HaveOccurred())

			Expect(plugin1.IsStopped()).To(BeTrue())
			Expect(plugin2.IsStopped()).To(BeTrue())
		})

		It("should handle stop errors gracefully", func() {
			plugin1 := NewMockPlugin("plugin1", "discovery")
			plugin2 := NewMockPlugin("plugin2", "compliance")
			plugin1.stopErr = errors.New("stop failed")

			PluginFactories["plugin1"] = func() Plugin { return plugin1 }
			PluginFactories["plugin2"] = func() Plugin { return plugin2 }

			configs := []config.PluginConfig{
				{Name: "plugin1", Type: "discovery", Enabled: true},
				{Name: "plugin2", Type: "compliance", Enabled: true},
			}

			Expect(manager.LoadPlugins(configs)).To(Succeed())
			Expect(manager.StartAll()).To(Succeed())

			err := manager.StopAll()
			Expect(err).NotTo(HaveOccurred()) // Should not propagate errors

			// Both should still be attempted to stop
			Expect(plugin1.IsStopped()).To(BeTrue())
			Expect(plugin2.IsStopped()).To(BeTrue())
		})
	})

	Describe("Concurrency", func() {
		It("should handle concurrent plugin loading safely", func() {
			// Pre-register factories to avoid concurrent map writes
			for i := range 10 {
				pluginName := "plugin" + string(rune('0'+i))
				mockPlugin := NewMockPlugin(pluginName, "test")
				localPlugin := mockPlugin // Capture for closure
				PluginFactories[pluginName] = func() Plugin { return localPlugin }
			}

			var wg sync.WaitGroup
			for i := range 10 {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					pluginName := "plugin" + string(rune('0'+id))

					cfg := config.PluginConfig{
						Name:    pluginName,
						Type:    "test",
						Enabled: true,
					}
					Expect(manager.LoadPlugin(cfg)).To(Succeed())
				}(i)
			}

			wg.Wait()

			manager.mu.RLock()
			count := len(manager.pluginInstances)
			manager.mu.RUnlock()

			Expect(count).To(Equal(10))
		})
	})

	Describe("getRegisteredFactoryNames", func() {
		It("should return list of registered factory names", func() {
			PluginFactories["plugin1"] = func() Plugin { return nil }
			PluginFactories["plugin2"] = func() Plugin { return nil }
			PluginFactories["plugin3"] = func() Plugin { return nil }

			names := getRegisteredFactoryNames()
			Expect(names).To(HaveLen(3))
			Expect(names).To(ContainElement("plugin1"))
			Expect(names).To(ContainElement("plugin2"))
			Expect(names).To(ContainElement("plugin3"))
		})

		It("should return empty list when no factories registered", func() {
			names := getRegisteredFactoryNames()
			Expect(names).To(BeEmpty())
		})
	})
})
