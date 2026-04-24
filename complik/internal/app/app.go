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

package app

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/k8s"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
)

func Run(configPath string) error {
	log := logger.GetLogger()

	log.Info("Loading configuration", logger.Fields{"path": configPath})

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Error("Failed to load configuration", logger.Fields{"error": err.Error()})
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	log.Info("Initializing Kubernetes client", logger.Fields{"kubeconfig": cfg.Kubeconfig})

	if err := k8s.InitClient(cfg.Kubeconfig); err != nil {
		log.Error("Failed to initialize Kubernetes client", logger.Fields{"error": err.Error()})
		return fmt.Errorf("failed to initialize Kubernetes client: %w", err)
	}

	log.Info("Creating event bus")

	eventBus := eventbus.NewEventBus(100)

	log.Info("Initializing plugin manager")

	m := plugin.NewManager(eventBus)

	log.Info("Loading plugins", logger.Fields{"count": len(cfg.Plugins)})

	if err := m.LoadPlugins(cfg.Plugins); err != nil {
		log.Error("Failed to load plugins", logger.Fields{"error": err.Error()})
		return fmt.Errorf("failed to load plugins: %w", err)
	}

	log.Info("Starting all plugins")

	if err := m.StartAll(); err != nil {
		log.Error("Failed to start plugins", logger.Fields{"error": err.Error()})
		return fmt.Errorf("failed to start plugins: %w", err)
	}

	log.Info("Application started successfully, waiting for shutdown signal")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	log.Info("Received shutdown signal", logger.Fields{"signal": sig.String()})
	log.Info("Shutting down gracefully...")

	if err := m.StopAll(); err != nil {
		log.Error("Failed to stop plugins", logger.Fields{"error": err.Error()})
		return fmt.Errorf("failed to stop plugins: %w", err)
	}

	log.Info("Application shutdown completed")

	return nil
}
