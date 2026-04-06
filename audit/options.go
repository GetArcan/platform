package audit

// Option configures a Dispatcher.
type Option func(*Dispatcher)

// WithWebhookSink adds an HMAC-signed webhook sink.
func WithWebhookSink(url, secret string) Option {
	return func(d *Dispatcher) {
		d.sinks = append(d.sinks, NewWebhookSink(url, secret))
	}
}

// WithSyslogSink adds an RFC 5424 syslog sink.
func WithSyslogSink(proto, addr string) Option {
	return func(d *Dispatcher) {
		d.sinks = append(d.sinks, NewSyslogSink(proto, addr))
	}
}

// WithStoreSink sets the database persistence store.
func WithStoreSink(store Store) Option {
	return func(d *Dispatcher) {
		d.store = store
	}
}

// WithBufferSize sets the event channel buffer size (default 1000).
func WithBufferSize(n int) Option {
	return func(d *Dispatcher) {
		d.bufSize = n
	}
}

// WithProductName tags all events with the given product name.
func WithProductName(name string) Option {
	return func(d *Dispatcher) {
		d.product = name
	}
}

// WithSink adds a custom sink implementation.
func WithSink(sink Sink) Option {
	return func(d *Dispatcher) {
		d.sinks = append(d.sinks, sink)
	}
}
