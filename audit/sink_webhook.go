package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WebhookSink sends events via HTTP POST with HMAC-SHA256 signature.
type WebhookSink struct {
	url    string
	secret string
	client *http.Client
}

// NewWebhookSink creates a webhook sink that signs payloads with the given secret.
func NewWebhookSink(url, secret string) *WebhookSink {
	return &WebhookSink{
		url:    url,
		secret: secret,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *WebhookSink) Name() string { return "webhook" }

// Send marshals the event to JSON, signs it with HMAC-SHA256, and POSTs it.
// Retries up to 3 times with exponential backoff (1s, 3s, 9s).
func (s *WebhookSink) Send(ctx context.Context, event Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshaling audit event: %w", err)
	}

	sig := computeHMAC(body, []byte(s.secret))

	var lastErr error
	backoffs := []time.Duration{0, 1 * time.Second, 3 * time.Second, 9 * time.Second}

	for attempt := 0; attempt < len(backoffs); attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("webhook delivery cancelled: %w", ctx.Err())
			case <-time.After(backoffs[attempt]):
			}
		}

		lastErr = s.post(ctx, body, sig)
		if lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("webhook delivery failed after %d attempts: %w", len(backoffs), lastErr)
}

func (s *WebhookSink) post(ctx context.Context, body []byte, sig string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Audit-Signature", "sha256="+sig)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func computeHMAC(data, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
