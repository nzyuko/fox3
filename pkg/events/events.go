package events

import (
	"log/slog"
	"sync"
)

// EventType identifies the kind of server-sent event.
type EventType string

const (
	EventAgentCheckin  EventType = "agent_checkin"
	EventAgentRemoved  EventType = "agent_removed"
	EventJobComplete   EventType = "job_complete"
	EventListenerStart EventType = "listener_start"
	EventListenerStop  EventType = "listener_stop"
	EventScreenshot    EventType = "screenshot"
	EventPivotCreate   EventType = "pivot_create"
	EventPivotRemove   EventType = "pivot_remove"
)

// Event is a structured server-sent event payload.
type Event struct {
	Type    EventType `json:"type"`
	Payload any       `json:"payload,omitempty"`
}

// eventBus is the global pub/sub bus for SSE consumers.
type eventBus struct {
	mu          sync.Mutex
	subscribers map[chan Event]struct{}
}

var globalBus = &eventBus{subscribers: make(map[chan Event]struct{})}

// Subscribe registers a new consumer channel and returns it.
func Subscribe() chan Event {
	ch := make(chan Event, 64)
	globalBus.mu.Lock()
	globalBus.subscribers[ch] = struct{}{}
	globalBus.mu.Unlock()
	return ch
}

// Unsubscribe removes and closes a consumer channel.
func Unsubscribe(ch chan Event) {
	globalBus.mu.Lock()
	delete(globalBus.subscribers, ch)
	globalBus.mu.Unlock()
	close(ch)
}

// Publish broadcasts an event to all current subscribers.
func Publish(e Event) {
	globalBus.mu.Lock()
	defer globalBus.mu.Unlock()
	for ch := range globalBus.subscribers {
		select {
		case ch <- e:
		default:
			slog.Warn("SSE: event dropped for slow consumer", "event_type", e.Type)
		}
	}
}
