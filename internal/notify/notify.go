// Package notify tells operators about important events without flooding
// them. Notices are buffered and sent as one digest per window (or sooner
// when the buffer fills), so an attack that raises 300 detections produces
// one message, not 300. Channels are a generic JSON webhook (which Slack,
// Mattermost and Teams-compatible endpoints accept) and Telegram.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Notice is one thing worth telling an operator.
type Notice struct {
	Severity string // low | medium | high | critical
	Title    string
	Detail   string
	At       time.Time
}

// Channel delivers a rendered digest.
type Channel interface {
	Name() string
	Send(ctx context.Context, text string) error
}

var severityRank = map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}

// Notifier buffers notices and flushes them as digests.
type Notifier struct {
	Channels []Channel
	// MinSeverity filters notices out at the door; default "high".
	MinSeverity string
	// Window is the longest a notice waits before being sent; default 5m.
	Window time.Duration
	// MaxBuffer flushes early once this many notices are waiting; default 50.
	MaxBuffer int
	// Hostname identifies the gateway in the digest.
	Hostname string
	// Now defaults to time.Now; overridable for tests.
	Now func() time.Time

	mu      sync.Mutex
	pending []Notice
	dropped int
}

func (n *Notifier) now() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now()
}

func (n *Notifier) maxBuffer() int {
	if n.MaxBuffer > 0 {
		return n.MaxBuffer
	}
	return 50
}

// Notify queues a notice. It never blocks on the network.
func (n *Notifier) Notify(nt Notice) {
	if n == nil || len(n.Channels) == 0 {
		return
	}
	min := n.MinSeverity
	if min == "" {
		min = "high"
	}
	if severityRank[nt.Severity] < severityRank[min] {
		return
	}
	if nt.At.IsZero() {
		nt.At = n.now()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	// Hard cap so a runaway source cannot grow memory; the digest says how
	// many were dropped.
	if len(n.pending) >= 10*n.maxBuffer() {
		n.dropped++
		return
	}
	n.pending = append(n.pending, nt)
}

func (n *Notifier) full() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.pending) >= n.maxBuffer()
}

// Flush sends whatever is waiting as one digest and returns how many notices
// it covered. If every channel fails the notices are put back, once.
func (n *Notifier) Flush(ctx context.Context) int {
	n.mu.Lock()
	batch, dropped := n.pending, n.dropped
	n.pending, n.dropped = nil, 0
	n.mu.Unlock()
	if len(batch) == 0 {
		return 0
	}

	text := Digest(n.Hostname, batch, dropped)
	delivered := false
	for _, ch := range n.Channels {
		if err := ch.Send(ctx, text); err != nil {
			log.Printf("notify: %s: %v", ch.Name(), err)
			continue
		}
		delivered = true
	}
	if !delivered {
		n.mu.Lock()
		if len(n.pending) == 0 { // retry later, but never let a dead channel grow the queue
			n.pending, n.dropped = batch, dropped
		}
		n.mu.Unlock()
		return 0
	}
	return len(batch)
}

// Run flushes every Window, or sooner when the buffer fills, until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	if n == nil || len(n.Channels) == 0 {
		return
	}
	window := n.Window
	if window <= 0 {
		window = 5 * time.Minute
	}
	t := time.NewTicker(window)
	defer t.Stop()
	check := time.NewTicker(10 * time.Second)
	defer check.Stop()
	for {
		select {
		case <-ctx.Done():
			n.Flush(context.Background()) // last words
			return
		case <-t.C:
			n.Flush(ctx)
		case <-check.C:
			if n.full() {
				n.Flush(ctx)
			}
		}
	}
}

// Digest renders notices as plain text: counts by severity, then the most
// severe first, capped at 15 lines.
func Digest(host string, notices []Notice, dropped int) string {
	sorted := append([]Notice(nil), notices...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityRank[sorted[i].Severity] > severityRank[sorted[j].Severity]
	})
	counts := map[string]int{}
	for _, nt := range notices {
		counts[nt.Severity]++
	}
	var b strings.Builder
	if host == "" {
		host = "Konsol Gateway"
	}
	fmt.Fprintf(&b, "[%s] %d peringatan", host, len(notices)+dropped)
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if c := counts[sev]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, sev))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(parts, ", "))
	}
	b.WriteString("\n")
	const maxLines = 15
	for i, nt := range sorted {
		if i == maxLines {
			fmt.Fprintf(&b, "... dan %d lainnya\n", len(sorted)-maxLines+dropped)
			dropped = 0
			break
		}
		fmt.Fprintf(&b, "- [%s] %s", strings.ToUpper(nt.Severity), nt.Title)
		if nt.Detail != "" {
			fmt.Fprintf(&b, ": %s", oneLine(nt.Detail, 160))
		}
		b.WriteString("\n")
	}
	if dropped > 0 {
		fmt.Fprintf(&b, "... %d peringatan tambahan dibuang karena antrean penuh\n", dropped)
	}
	return b.String()
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// Webhook posts {"text": "..."} to a URL.
type Webhook struct {
	URL    string
	Client *http.Client
}

func (w *Webhook) Name() string { return "webhook" }

func (w *Webhook) Send(ctx context.Context, text string) error {
	body, _ := json.Marshal(map[string]string{"text": text})
	return post(ctx, w.Client, w.URL, "application/json", body)
}

// Telegram sends the digest through the Bot API.
type Telegram struct {
	Token, ChatID string
	Client        *http.Client
	// BaseURL overrides https://api.telegram.org; tests point it at httptest.
	BaseURL string
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) Send(ctx context.Context, text string) error {
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	form := url.Values{"chat_id": {t.ChatID}, "text": {text}, "disable_web_page_preview": {"true"}}
	return post(ctx, t.Client, base+"/bot"+t.Token+"/sendMessage", "application/x-www-form-urlencoded", []byte(form.Encode()))
}

func post(ctx context.Context, c *http.Client, target, contentType string, body []byte) error {
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return redactURL(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := c.Do(req)
	if err != nil {
		return redactURL(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// redactURL strips the request URL out of a transport error. Webhook and
// Telegram URLs contain secrets (tokens), and net/http includes the URL in
// its error text, which would otherwise end up in the logs.
func redactURL(err error) error {
	var ue *url.Error
	if e, ok := err.(*url.Error); ok {
		ue = e
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}
