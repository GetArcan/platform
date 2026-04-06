package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// SyslogSink sends events via syslog (TCP or UDP) in RFC 5424 format.
type SyslogSink struct {
	proto string // "tcp" or "udp"
	addr  string // "host:port"

	mu   sync.Mutex
	conn net.Conn
}

// NewSyslogSink creates a syslog sink for the given protocol and address.
func NewSyslogSink(proto, addr string) *SyslogSink {
	return &SyslogSink{
		proto: proto,
		addr:  addr,
	}
}

func (s *SyslogSink) Name() string { return "syslog" }

// Send formats the event as an RFC 5424 message and writes it to the syslog connection.
// Reconnects automatically on failure.
func (s *SyslogSink) Send(ctx context.Context, event Event) error {
	msg, err := s.formatRFC5424(event)
	if err != nil {
		return fmt.Errorf("formatting syslog message: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Lazy connect or reconnect on failure.
	if s.conn == nil {
		if err := s.connect(); err != nil {
			return fmt.Errorf("syslog connect to %s (%s): %w", s.addr, s.proto, err)
		}
	}

	s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = s.conn.Write(msg)
	if err != nil {
		// Connection may be stale — close and retry once.
		s.conn.Close()
		s.conn = nil
		if err := s.connect(); err != nil {
			return fmt.Errorf("syslog reconnect: %w", err)
		}
		s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err = s.conn.Write(msg); err != nil {
			return fmt.Errorf("syslog write after reconnect: %w", err)
		}
	}
	return nil
}

func (s *SyslogSink) connect() error {
	conn, err := net.DialTimeout(s.proto, s.addr, 5*time.Second)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// formatRFC5424 produces a minimal RFC 5424 syslog message:
//
//	<PRI>1 TIMESTAMP HOSTNAME APP-NAME - MSGID - MSG
//
// Facility: local0 (16). Severity: informational (6).
// PRI = 16*8 + 6 = 134.
func (s *SyslogSink) formatRFC5424(event Event) ([]byte, error) {
	// PRI: facility=local0 (16), severity=informational (6)
	pri := 16*8 + 6

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "-"
	}

	appName := event.Product
	if appName == "" {
		appName = "platform"
	}

	data, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("marshaling event: %w", err)
	}

	ts := event.Timestamp.UTC().Format(time.RFC3339)
	msg := fmt.Sprintf("<%d>1 %s %s %s - - - %s\n",
		pri, ts, hostname, appName, string(data))

	return []byte(msg), nil
}
