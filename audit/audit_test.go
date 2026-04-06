package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Compile-time interface checks.
var (
	_ Sink = (*WebhookSink)(nil)
	_ Sink = (*SyslogSink)(nil)
)

// --- helpers ---

type memoryStore struct {
	mu     sync.Mutex
	events []Event
}

func (s *memoryStore) InsertAuditEvent(_ context.Context, event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *memoryStore) getEvents() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	return out
}

type captureSink struct {
	name   string
	mu     sync.Mutex
	events []Event
}

func (s *captureSink) Send(_ context.Context, event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *captureSink) Name() string { return s.name }

func (s *captureSink) getEvents() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	return out
}

func testEvent(typ string) Event {
	return Event{
		Type:      typ,
		Timestamp: time.Now().UTC(),
		Actor:     "user-1",
		ActorType: "user",
		Realm:     "default",
		IP:        "127.0.0.1",
		Data:      map[string]string{"key": "value"},
	}
}

// --- Dispatcher tests ---

func TestNewDispatcher_DefaultBufferSize(t *testing.T) {
	d := NewDispatcher()
	defer d.Close(time.Second)

	if cap(d.ch) != defaultBufferSize {
		t.Errorf("expected default buffer size %d, got %d", defaultBufferSize, cap(d.ch))
	}
}

func TestEmit_DeliversToStore(t *testing.T) {
	store := &memoryStore{}
	d := NewDispatcher(WithStoreSink(store))
	defer d.Close(time.Second)

	d.Emit(context.Background(), testEvent("secret.created"))

	// Wait for async delivery.
	time.Sleep(100 * time.Millisecond)

	events := store.getEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 store event, got %d", len(events))
	}
	if events[0].Type != "secret.created" {
		t.Errorf("expected event type %q, got %q", "secret.created", events[0].Type)
	}
}

func TestEmit_DeliversToMultipleSinks(t *testing.T) {
	sink1 := &captureSink{name: "sink1"}
	sink2 := &captureSink{name: "sink2"}
	d := NewDispatcher(WithSink(sink1), WithSink(sink2))
	defer d.Close(time.Second)

	d.Emit(context.Background(), testEvent("lease.created"))

	time.Sleep(100 * time.Millisecond)

	for _, sink := range []*captureSink{sink1, sink2} {
		events := sink.getEvents()
		if len(events) != 1 {
			t.Errorf("sink %s: expected 1 event, got %d", sink.name, len(events))
		}
	}
}

func TestEmit_SetsProductField(t *testing.T) {
	store := &memoryStore{}
	d := NewDispatcher(WithStoreSink(store), WithProductName("arcan"))
	defer d.Close(time.Second)

	d.Emit(context.Background(), testEvent("auth.login"))

	time.Sleep(100 * time.Millisecond)

	events := store.getEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Product != "arcan" {
		t.Errorf("expected product %q, got %q", "arcan", events[0].Product)
	}
}

func TestEmit_NonBlocking(t *testing.T) {
	// Use a small buffer and a slow store to verify Emit doesn't block.
	d := NewDispatcher(WithBufferSize(2000))
	defer d.Close(2 * time.Second)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			d.Emit(context.Background(), testEvent(fmt.Sprintf("event.%d", i)))
		}
		close(done)
	}()

	select {
	case <-done:
		// OK — all emits returned without blocking.
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked — should be non-blocking")
	}
}

func TestClose_DrainsPendingEvents(t *testing.T) {
	store := &memoryStore{}
	d := NewDispatcher(WithStoreSink(store), WithBufferSize(100))

	for i := 0; i < 50; i++ {
		d.Emit(context.Background(), testEvent(fmt.Sprintf("drain.%d", i)))
	}

	if err := d.Close(5 * time.Second); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	events := store.getEvents()
	if len(events) != 50 {
		t.Errorf("expected 50 drained events, got %d", len(events))
	}
}

// --- WebhookSink tests ---

func TestWebhookSink_CorrectHMACSignature(t *testing.T) {
	secret := "test-secret-key"
	var receivedSig string
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Audit-Signature")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL, secret)
	event := testEvent("secret.created")

	if err := sink.Send(context.Background(), event); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Verify HMAC.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(receivedBody)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if receivedSig != expectedSig {
		t.Errorf("signature mismatch:\n  got:  %s\n  want: %s", receivedSig, expectedSig)
	}
}

func TestWebhookSink_RetriesOnFailure(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL, "secret")
	err := sink.Send(context.Background(), testEvent("retry.test"))
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}

	if got := attempts.Load(); got < 3 {
		t.Errorf("expected at least 3 attempts, got %d", got)
	}
}

// --- SyslogSink tests ---

func TestSyslogSink_FormatsCorrectly(t *testing.T) {
	// Start a TCP listener to capture syslog messages.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
	}()

	sink := NewSyslogSink("tcp", ln.Addr().String())
	event := testEvent("auth.login")
	event.Product = "testapp"

	if err := sink.Send(context.Background(), event); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	select {
	case msg := <-received:
		// Verify RFC 5424 structure.
		if !strings.HasPrefix(msg, "<134>1 ") {
			t.Errorf("expected RFC 5424 prefix '<134>1 ', got: %s", msg[:20])
		}
		if !strings.Contains(msg, "testapp") {
			t.Error("expected product name in syslog message")
		}
		// Verify the JSON body is valid.
		idx := strings.LastIndex(msg, "- {")
		if idx == -1 {
			t.Fatal("expected JSON body in syslog message")
		}
		jsonPart := strings.TrimSpace(msg[idx+2:])
		var parsed Event
		if err := json.Unmarshal([]byte(jsonPart), &parsed); err != nil {
			t.Errorf("syslog JSON body is not valid: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for syslog message")
	}
}

// --- MockDispatcher tests ---

func TestMockDispatcher_CapturesEvents(t *testing.T) {
	m := NewMockDispatcher()
	m.Emit(context.Background(), testEvent("a"))
	m.Emit(context.Background(), testEvent("b"))

	events := m.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Type != "a" || events[1].Type != "b" {
		t.Errorf("unexpected event types: %q, %q", events[0].Type, events[1].Type)
	}
}

func TestMockDispatcher_LastEvent(t *testing.T) {
	m := NewMockDispatcher()

	if m.LastEvent() != nil {
		t.Error("expected nil LastEvent on empty mock")
	}

	m.Emit(context.Background(), testEvent("first"))
	m.Emit(context.Background(), testEvent("second"))

	last := m.LastEvent()
	if last == nil {
		t.Fatal("expected non-nil LastEvent")
	}
	if last.Type != "second" {
		t.Errorf("expected last event type %q, got %q", "second", last.Type)
	}
}

func TestMockDispatcher_Reset(t *testing.T) {
	m := NewMockDispatcher()
	m.Emit(context.Background(), testEvent("a"))
	m.Reset()

	if len(m.Events()) != 0 {
		t.Error("expected 0 events after Reset")
	}
}
