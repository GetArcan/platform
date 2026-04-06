package telemetry

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Counter is a simple counter metric.
type Counter struct {
	name   string
	labels []string
	mu     sync.Mutex
	values map[string]int64
}

// NewCounter creates a new counter with the given name and label names.
func NewCounter(name string, labels ...string) *Counter {
	return &Counter{
		name:   name,
		labels: labels,
		values: make(map[string]int64),
	}
}

// Inc increments the counter by 1.
func (c *Counter) Inc(labelValues ...string) {
	c.Add(1, labelValues...)
}

// Add increments the counter by n.
func (c *Counter) Add(n int64, labelValues ...string) {
	key := labelKey(labelValues)
	c.mu.Lock()
	c.values[key] += n
	c.mu.Unlock()
}

// Histogram tracks value distributions.
type Histogram struct {
	name   string
	labels []string
	mu     sync.Mutex
	values map[string][]float64
}

// NewHistogram creates a new histogram with the given name and label names.
func NewHistogram(name string, labels ...string) *Histogram {
	return &Histogram{
		name:   name,
		labels: labels,
		values: make(map[string][]float64),
	}
}

// Observe records a value in the histogram.
func (h *Histogram) Observe(value float64, labelValues ...string) {
	key := labelKey(labelValues)
	h.mu.Lock()
	h.values[key] = append(h.values[key], value)
	h.mu.Unlock()
}

// Registry holds all metrics for exposition.
type Registry struct {
	mu         sync.RWMutex
	counters   []*Counter
	histograms []*Histogram
}

// NewRegistry creates a new metric registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// RegisterCounter adds a counter to the registry.
func (r *Registry) RegisterCounter(c *Counter) {
	r.mu.Lock()
	r.counters = append(r.counters, c)
	r.mu.Unlock()
}

// RegisterHistogram adds a histogram to the registry.
func (r *Registry) RegisterHistogram(h *Histogram) {
	r.mu.Lock()
	r.histograms = append(r.histograms, h)
	r.mu.Unlock()
}

// Handler returns an http.HandlerFunc that serves metrics in Prometheus text format.
func (r *Registry) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.mu.RLock()
		defer r.mu.RUnlock()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		var b strings.Builder

		for _, c := range r.counters {
			c.mu.Lock()
			fmt.Fprintf(&b, "# TYPE %s counter\n", c.name)
			keys := sortedKeys(c.values)
			for _, key := range keys {
				v := c.values[key]
				if key == "" {
					fmt.Fprintf(&b, "%s %d\n", c.name, v)
				} else {
					fmt.Fprintf(&b, "%s{%s} %d\n", c.name, formatLabels(c.labels, key), v)
				}
			}
			c.mu.Unlock()
		}

		for _, h := range r.histograms {
			h.mu.Lock()
			fmt.Fprintf(&b, "# TYPE %s histogram\n", h.name)
			keys := sortedStringKeys(h.values)
			for _, key := range keys {
				vals := h.values[key]
				sum, count := histogramStats(vals)
				labelSuffix := ""
				if key != "" {
					labelSuffix = formatLabels(h.labels, key)
				}
				if labelSuffix == "" {
					fmt.Fprintf(&b, "%s_sum %s\n", h.name, formatFloat(sum))
					fmt.Fprintf(&b, "%s_count %d\n", h.name, count)
				} else {
					fmt.Fprintf(&b, "%s_sum{%s} %s\n", h.name, labelSuffix, formatFloat(sum))
					fmt.Fprintf(&b, "%s_count{%s} %d\n", h.name, labelSuffix, count)
				}
			}
			h.mu.Unlock()
		}

		w.Write([]byte(b.String()))
	}
}

// labelKey joins label values into a lookup key.
func labelKey(values []string) string {
	return strings.Join(values, "\x00")
}

// formatLabels produces Prometheus-style label pairs: method="GET",path="/api"
func formatLabels(names []string, key string) string {
	values := strings.Split(key, "\x00")
	var parts []string
	for i, name := range names {
		val := ""
		if i < len(values) {
			val = values[i]
		}
		parts = append(parts, fmt.Sprintf("%s=%q", name, val))
	}
	return strings.Join(parts, ",")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedStringKeys(m map[string][]float64) []string {
	return sortedKeys(m)
}

func histogramStats(vals []float64) (sum float64, count int) {
	for _, v := range vals {
		sum += v
	}
	return sum, len(vals)
}

func formatFloat(f float64) string {
	if f == math.Trunc(f) && !math.IsInf(f, 0) {
		return fmt.Sprintf("%.0f", f)
	}
	return fmt.Sprintf("%g", f)
}
