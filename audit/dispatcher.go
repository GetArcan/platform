package audit

import (
	"context"
	"log/slog"
	"time"
)

const defaultBufferSize = 1000

// Dispatcher fans out audit events to all registered sinks.
// Events are dispatched asynchronously via a buffered channel.
// Sink failures are logged but never block the caller.
type Dispatcher struct {
	sinks   []Sink
	store   Store // optional database sink
	ch      chan Event
	product string
	bufSize int
	done    chan struct{}
}

// NewDispatcher creates and starts a dispatcher with the given options.
// A background goroutine drains the event channel and delivers to all sinks.
func NewDispatcher(opts ...Option) *Dispatcher {
	d := &Dispatcher{
		bufSize: defaultBufferSize,
	}
	for _, opt := range opts {
		opt(d)
	}
	d.ch = make(chan Event, d.bufSize)
	d.done = make(chan struct{})

	go d.loop()
	return d
}

// Emit sends an event to all sinks asynchronously.
// Safe to call from request handlers — never blocks.
// If the channel is full, the event is dropped and a warning is logged.
func (d *Dispatcher) Emit(ctx context.Context, event Event) {
	select {
	case d.ch <- event:
	default:
		slog.Warn("audit event dropped: channel full", "event", event.Type)
	}
}

// Close drains the event channel and shuts down the dispatcher.
// Blocks until all pending events are delivered or the timeout expires.
func (d *Dispatcher) Close(timeout time.Duration) error {
	close(d.ch)
	select {
	case <-d.done:
		return nil
	case <-time.After(timeout):
		return &closeTimeoutError{timeout: timeout}
	}
}

func (d *Dispatcher) loop() {
	defer close(d.done)
	for event := range d.ch {
		d.dispatch(event)
	}
}

func (d *Dispatcher) dispatch(event Event) {
	if d.product != "" {
		event.Product = d.product
	}

	// Write to store if configured (synchronous within the loop).
	if d.store != nil {
		if err := d.store.InsertAuditEvent(context.Background(), event); err != nil {
			slog.Warn("audit store write failed", "error", err)
		}
	}

	// Fan out to all sinks (each in its own goroutine, fire-and-forget).
	for _, sink := range d.sinks {
		go func(s Sink, ev Event) {
			if err := s.Send(context.Background(), ev); err != nil {
				slog.Warn("audit sink failed", "sink", s.Name(), "error", err)
			}
		}(sink, event)
	}
}

// closeTimeoutError is returned when Close exceeds the given timeout.
type closeTimeoutError struct {
	timeout time.Duration
}

func (e *closeTimeoutError) Error() string {
	return "audit dispatcher close timed out after " + e.timeout.String()
}
