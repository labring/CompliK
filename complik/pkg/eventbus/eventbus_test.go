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

//nolint:testpackage,wsl_v5 // Tests exercise internal event bus state directly.
package eventbus

import (
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestEventBus(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "EventBus Suite")
}

var _ = Describe("EventBus", func() {
	var eb *EventBus

	BeforeEach(func() {
		eb = NewEventBus(100)
	})

	Describe("NewEventBus", func() {
		It("should create event bus with specified buffer size", func() {
			eb := NewEventBus(50)
			Expect(eb).NotTo(BeNil())
			Expect(eb.bufferSize).To(Equal(50))
			Expect(eb.subscribers).NotTo(BeNil())
		})

		It("should use default buffer size when given zero", func() {
			eb := NewEventBus(0)
			Expect(eb.bufferSize).To(Equal(10000))
		})

		It("should use default buffer size when given negative", func() {
			eb := NewEventBus(-10)
			Expect(eb.bufferSize).To(Equal(10000))
		})
	})

	Describe("Subscribe", func() {
		It("should create a subscription and return a channel", func() {
			ch := eb.Subscribe("test-topic")
			Expect(ch).NotTo(BeNil())
			Expect(ch).To(HaveCap(100))
		})

		It("should allow multiple subscriptions to the same topic", func() {
			ch1 := eb.Subscribe("topic")
			ch2 := eb.Subscribe("topic")
			ch3 := eb.Subscribe("topic")

			Expect(ch1).NotTo(Equal(ch2))
			Expect(ch2).NotTo(Equal(ch3))

			eb.mu.RLock()
			Expect(eb.subscribers["topic"]).To(HaveLen(3))
			eb.mu.RUnlock()
		})

		It("should allow subscriptions to different topics", func() {
			ch1 := eb.Subscribe("topic1")
			ch2 := eb.Subscribe("topic2")

			Expect(ch1).NotTo(BeNil())
			Expect(ch2).NotTo(BeNil())

			eb.mu.RLock()
			Expect(eb.subscribers).To(HaveLen(2))
			eb.mu.RUnlock()
		})
	})

	Describe("Publish", func() {
		It("should deliver event to single subscriber", func(done Done) {
			ch := eb.Subscribe("test")
			event := Event{Payload: "hello"}

			go func() {
				eb.Publish("test", event)
			}()

			received := <-ch
			Expect(received.Payload).To(Equal("hello"))
			close(done)
		}, 1.0)

		It("should deliver event to multiple subscribers", func(done Done) {
			ch1 := eb.Subscribe("broadcast")
			ch2 := eb.Subscribe("broadcast")
			ch3 := eb.Subscribe("broadcast")

			event := Event{Payload: "broadcast message"}

			var wg sync.WaitGroup
			wg.Add(3)

			go func() {
				defer wg.Done()
				received := <-ch1
				Expect(received.Payload).To(Equal("broadcast message"))
			}()

			go func() {
				defer wg.Done()
				received := <-ch2
				Expect(received.Payload).To(Equal("broadcast message"))
			}()

			go func() {
				defer wg.Done()
				received := <-ch3
				Expect(received.Payload).To(Equal("broadcast message"))
			}()

			eb.Publish("broadcast", event)
			wg.Wait()
			close(done)
		}, 2.0)

		It("should not deliver event to subscribers of different topics", func() {
			ch1 := eb.Subscribe("topic1")
			ch2 := eb.Subscribe("topic2")

			event := Event{Payload: "specific"}
			eb.Publish("topic1", event)

			Eventually(ch1).Should(Receive(Equal(event)))
			Consistently(ch2, 100*time.Millisecond).ShouldNot(Receive())
		})

		It("should handle publishing to topic with no subscribers", func() {
			event := Event{Payload: "nobody listening"}
			Expect(func() {
				eb.Publish("nonexistent-topic", event)
			}).NotTo(Panic())
		})

		It("should handle complex payload types", func(done Done) {
			type ComplexPayload struct {
				ID    int
				Name  string
				Items []string
			}

			ch := eb.Subscribe("complex")
			payload := ComplexPayload{
				ID:    123,
				Name:  "test",
				Items: []string{"a", "b", "c"},
			}

			go func() {
				eb.Publish("complex", Event{Payload: payload})
			}()

			received := <-ch
			receivedPayload, ok := received.Payload.(ComplexPayload)
			Expect(ok).To(BeTrue())
			Expect(receivedPayload.ID).To(Equal(123))
			Expect(receivedPayload.Name).To(Equal("test"))
			Expect(receivedPayload.Items).To(Equal([]string{"a", "b", "c"}))
			close(done)
		}, 1.0)
	})

	Describe("Unsubscribe", func() {
		It("should remove subscription and close channel", func() {
			ch := eb.Subscribe("test")
			eb.Unsubscribe("test", ch)

			eb.mu.RLock()
			Expect(eb.subscribers["test"]).To(BeEmpty())
			eb.mu.RUnlock()

			// Channel should be closed
			Eventually(ch).Should(BeClosed())
		})

		It("should only remove the specified subscription", func() {
			ch1 := eb.Subscribe("topic")
			ch2 := eb.Subscribe("topic")
			ch3 := eb.Subscribe("topic")

			eb.Unsubscribe("topic", ch2)

			eb.mu.RLock()
			subscribers := eb.subscribers["topic"]
			eb.mu.RUnlock()

			Expect(subscribers).To(HaveLen(2))
			Expect(subscribers).To(ContainElement(ch1))
			Expect(subscribers).To(ContainElement(ch3))
			Expect(subscribers).NotTo(ContainElement(ch2))
		})

		It("should handle unsubscribing from non-existent topic", func() {
			ch := make(EventChan, 10)
			Expect(func() {
				eb.Unsubscribe("non-existent", ch)
			}).NotTo(Panic())
		})

		It("should handle unsubscribing non-subscribed channel", func() {
			eb.Subscribe("topic")
			foreignCh := make(EventChan, 10)

			Expect(func() {
				eb.Unsubscribe("topic", foreignCh)
			}).NotTo(Panic())
		})
	})

	Describe("Concurrency", func() {
		It("should handle concurrent subscriptions safely", func() {
			var wg sync.WaitGroup
			channels := make([]EventChan, 100)

			for i := range 100 {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					channels[idx] = eb.Subscribe("concurrent")
				}(i)
			}

			wg.Wait()

			eb.mu.RLock()
			Expect(eb.subscribers["concurrent"]).To(HaveLen(100))
			eb.mu.RUnlock()
		})

		It("should handle concurrent publishes safely", func() {
			ch := eb.Subscribe("parallel")
			var wg sync.WaitGroup

			for i := range 50 {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					eb.Publish("parallel", Event{Payload: id})
				}(i)
			}

			received := make(map[int]bool)
			receivedCount := 0

			go func() {
				for event := range ch {
					id, ok := event.Payload.(int)
					Expect(ok).To(BeTrue())
					received[id] = true
					receivedCount++
					if receivedCount == 50 {
						return
					}
				}
			}()

			wg.Wait()
			Eventually(func() int { return receivedCount }).Should(Equal(50))
		})

		It("should handle concurrent unsubscribes safely", func() {
			channels := make([]EventChan, 50)
			for i := range 50 {
				channels[i] = eb.Subscribe("cleanup")
			}

			var wg sync.WaitGroup
			for i := range 50 {
				wg.Add(1)
				go func(ch EventChan) {
					defer wg.Done()
					eb.Unsubscribe("cleanup", ch)
				}(channels[i])
			}

			wg.Wait()

			eb.mu.RLock()
			Expect(eb.subscribers["cleanup"]).To(BeEmpty())
			eb.mu.RUnlock()
		})
	})

	Describe("Event Delivery", func() {
		It("should deliver events in order for single subscriber", func(done Done) {
			ch := eb.Subscribe("ordered")
			events := []int{1, 2, 3, 4, 5}

			go func() {
				for _, val := range events {
					eb.Publish("ordered", Event{Payload: val})
					time.Sleep(10 * time.Millisecond)
				}
			}()

			received := make([]int, 0, len(events))
			for range 5 {
				event := <-ch
				payload, ok := event.Payload.(int)
				Expect(ok).To(BeTrue())
				received = append(received, payload)
			}

			Expect(received).To(Equal(events))
			close(done)
		}, 2.0)

		It("should not block when buffer is available", func() {
			ch := eb.Subscribe("buffered")

			// Publish more events than we're receiving immediately
			for i := range 50 {
				eb.Publish("buffered", Event{Payload: i})
			}

			// Should not block or panic
			received := make([]int, 0, 50)
			for range 50 {
				event := <-ch
				payload, ok := event.Payload.(int)
				Expect(ok).To(BeTrue())
				received = append(received, payload)
			}

			Expect(received).To(HaveLen(50))
		})
	})

	Describe("Edge Cases", func() {
		It("should handle nil payload", func(done Done) {
			ch := eb.Subscribe("nil-test")

			go func() {
				eb.Publish("nil-test", Event{Payload: nil})
			}()

			received := <-ch
			Expect(received.Payload).To(BeNil())
			close(done)
		}, 1.0)

		It("should handle empty topic names", func() {
			ch := eb.Subscribe("")
			Expect(ch).NotTo(BeNil())

			event := Event{Payload: "empty topic"}
			eb.Publish("", event)

			Eventually(ch).Should(Receive(Equal(event)))
		})
	})
})
