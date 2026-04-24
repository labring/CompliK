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

// Package utils provides a browser pool implementation for managing headless browser instances.
// The pool supports concurrent access, automatic instance expiration, and graceful cleanup.
// It includes a wait queue mechanism to handle requests when the pool is at capacity.
package utils

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
)

type BrowserInstance struct {
	Browser  *rod.Browser
	Launcher *launcher.Launcher
	Created  time.Time
	InUse    bool
}

type BrowserPool struct {
	instances []*BrowserInstance
	mu        sync.RWMutex // Read-write lock for optimized concurrency
	maxSize   int
	maxAge    time.Duration
	waitQueue chan chan *BrowserInstance // Wait queue for requests when pool is full
	closed    bool
	log       logger.Logger
}

func NewBrowserPool(maxSize int, maxAge time.Duration) *BrowserPool {
	pool := &BrowserPool{
		instances: make([]*BrowserInstance, 0, maxSize),
		maxSize:   maxSize,
		maxAge:    maxAge,
		waitQueue: make(chan chan *BrowserInstance, 100), // Buffered queue
		log:       logger.GetLogger().WithField("component", "browser_pool"),
	}

	pool.log.Info("Browser pool created", logger.Fields{
		"max_size":        maxSize,
		"max_age_minutes": maxAge.Minutes(),
	})

	// Start background cleanup goroutine
	go pool.backgroundCleanup()

	return pool
}

func (p *BrowserPool) Get(ctx context.Context) (*BrowserInstance, error) {
	p.mu.RLock()

	for _, instance := range p.instances {
		if !instance.InUse && time.Since(instance.Created) < p.maxAge {
			p.mu.RUnlock()
			p.mu.Lock()

			if !instance.InUse {
				instance.InUse = true

				p.mu.Unlock()
				return instance, nil
			}

			p.mu.Unlock()
			p.mu.RLock()
		}
	}

	p.mu.RUnlock()
	p.mu.Lock()

	if len(p.instances) < p.maxSize {
		instance, err := p.createInstance()
		if err != nil {
			p.mu.Unlock()
			return nil, err
		}

		instance.InUse = true
		p.instances = append(p.instances, instance)
		p.mu.Unlock()

		return instance, nil
	}

	p.mu.Unlock()
	p.log.Debug("Browser pool full, waiting for available instance")

	waitChan := make(chan *BrowserInstance, 1)
	select {
	case p.waitQueue <- waitChan:
		select {
		case instance := <-waitChan:
			p.log.Debug("Got instance from wait queue")
			return instance, nil
		case <-ctx.Done():
			p.log.Warn("Timeout waiting for browser instance")
			return nil, errors.New("timeout waiting for browser instance")
		}
	default:
		p.log.Error("Browser pool full and wait queue full")
		return nil, errors.New("browser pool is full, cannot create new instance")
	}
}

func (p *BrowserPool) Put(instance *BrowserInstance) {
	if instance == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if time.Since(instance.Created) >= p.maxAge {
		p.removeInstance(instance)

		go p.cleanupInstance(instance)
		return
	}

	// Check if there are any waiters
	select {
	case waitChan := <-p.waitQueue:
		// Assign directly to waiter
		instance.InUse = true
		waitChan <- instance
		return
	default:
		// No waiters, mark as available
		instance.InUse = false
	}
}

func (p *BrowserPool) createInstance() (*BrowserInstance, error) {
	p.log.Debug("Creating new browser instance")

	l := launcher.New().
		Set("no-sandbox", "").
		Set("disable-dev-shm-usage", "").
		Set("disable-gpu", "").
		Set("disable-web-security", "").
		Set("disable-features", "VizDisplayCompositor").
		Headless(true)

	u, err := l.Launch()
	if err != nil {
		p.log.Error("Failed to launch browser", logger.Fields{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to launch browser: %w", err)
	}

	browser := rod.New().
		ControlURL(u).
		MustConnect().
		MustIgnoreCertErrors(true)

	instance := &BrowserInstance{
		Browser:  browser,
		Launcher: l,
		Created:  time.Now(),
		InUse:    false,
	}

	p.log.Debug("Browser instance created successfully", logger.Fields{
		"instance_count": len(p.instances) + 1,
	})

	return instance, nil
}

func (p *BrowserPool) cleanupExpired() {
	var (
		validInstances   []*BrowserInstance
		expiredInstances []*BrowserInstance
	)

	for _, instance := range p.instances {
		if time.Since(instance.Created) >= p.maxAge || instance.Browser == nil {
			expiredInstances = append(expiredInstances, instance)
		} else {
			validInstances = append(validInstances, instance)
		}
	}

	if len(expiredInstances) > 0 {
		p.log.Info("Cleaning up expired browser instances", logger.Fields{
			"expired_count":   len(expiredInstances),
			"remaining_count": len(validInstances),
		})
	}

	p.instances = validInstances
	for _, instance := range expiredInstances {
		go p.cleanupInstance(instance)
	}
}

func (p *BrowserPool) removeInstance(target *BrowserInstance) {
	for i, instance := range p.instances {
		if instance == target {
			p.instances = append(p.instances[:i], p.instances[i+1:]...)
			break
		}
	}
}

func (p *BrowserPool) cleanupInstance(instance *BrowserInstance) {
	defer func() {
		if r := recover(); r != nil {
			p.log.Error("Panic during browser cleanup", logger.Fields{"panic": r})
		}
	}()

	if instance.Browser != nil {
		if err := instance.Browser.Close(); err != nil {
			p.log.Warn("Browser close failed, will force kill launcher", logger.Fields{
				"error": err.Error(),
			})
		} else {
			p.log.Debug("Browser closed gracefully")
		}
	}

	if instance.Launcher != nil {
		instance.Launcher.Kill()
		p.log.Debug("Launcher killed")
		time.Sleep(100 * time.Millisecond)
	}
}

func (p *BrowserPool) backgroundCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()

		if p.closed {
			p.mu.Unlock()
			return
		}

		p.cleanupExpired()
		p.mu.Unlock()
	}
}

// Close closes the browser pool and cleans up all instances.
func (p *BrowserPool) Close() {
	p.log.Info("Closing browser pool")

	p.mu.Lock()
	p.closed = true
	instances := p.instances
	p.instances = nil
	p.mu.Unlock()

	p.log.Info("Cleaning up browser instances", logger.Fields{
		"instance_count": len(instances),
	})

	// Clean up all instances
	for _, instance := range instances {
		go p.cleanupInstance(instance)
	}

	// Close wait queue
	close(p.waitQueue)

	p.log.Info("Browser pool closed")
}
