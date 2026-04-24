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

// Package eventbus provides a lightweight publish-subscribe event bus for
// decoupled communication between components in the system.
package eventbus

import (
	"sync"
)

// Event represents a message that can be published to the event bus
type Event struct {
	Payload any
}

// EventChan is a channel for delivering events to subscribers
type EventChan chan Event

// EventBus manages topic-based event subscriptions and publications
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[string][]EventChan
	bufferSize  int
}

// NewEventBus creates a new event bus with the specified channel buffer size
func NewEventBus(bufferSize int) *EventBus {
	if bufferSize <= 0 {
		bufferSize = 10000
	}

	return &EventBus{
		subscribers: make(map[string][]EventChan),
		bufferSize:  bufferSize,
	}
}

// Publish sends an event to all subscribers of the specified topic
func (eb *EventBus) Publish(topic string, event Event) {
	eb.mu.RLock()
	subscribers := eb.subscribers[topic]
	eb.mu.RUnlock()

	for _, subscriber := range subscribers {
		go func(sub chan Event) {
			sub <- event
		}(subscriber)
	}
}

// Subscribe creates a new subscription to the specified topic and returns a channel for receiving events
func (eb *EventBus) Subscribe(topic string) EventChan {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	ch := make(EventChan, eb.bufferSize)
	eb.subscribers[topic] = append(eb.subscribers[topic], ch)

	return ch
}

// Unsubscribe removes a subscription from the specified topic and closes the channel
func (eb *EventBus) Unsubscribe(topic string, ch EventChan) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if subscribers, ok := eb.subscribers[topic]; ok {
		for i, subscriber := range subscribers {
			if ch == subscriber {
				eb.subscribers[topic] = append(subscribers[:i], subscribers[i+1:]...)

				close(ch)

				for range ch {
				}

				return
			}
		}
	}
}
