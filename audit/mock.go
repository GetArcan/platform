package audit

import (
	"context"
	"sync"
)

// MockDispatcher captures emitted events for test assertions.
type MockDispatcher struct {
	mu     sync.Mutex
	events []Event
}

// NewMockDispatcher creates a mock dispatcher that records events synchronously.
func NewMockDispatcher() *MockDispatcher {
	return &MockDispatcher{}
}

// Emit captures the event synchronously for test predictability.
func (m *MockDispatcher) Emit(ctx context.Context, event Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

// Events returns all captured events.
func (m *MockDispatcher) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Event, len(m.events))
	copy(result, m.events)
	return result
}

// Reset clears captured events.
func (m *MockDispatcher) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = nil
}

// LastEvent returns the most recent event, or nil if none captured.
func (m *MockDispatcher) LastEvent() *Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) == 0 {
		return nil
	}
	e := m.events[len(m.events)-1]
	return &e
}
