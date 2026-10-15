// Package canary watches HAProxy for a few minutes after a configuration
// apply and puts the previous configuration back if the error rate jumps.
// A config that passes "haproxy -c" can still be wrong (a bad ACL sends
// every request to a dead backend); this is the safety net for that case.
package canary

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/store"
)

// LogSource yields newly appended access-log lines; *haproxylog.Tailer is one.
type LogSource interface {
	ReadNew() ([]haproxylog.Line, error)
}

// Thresholds decide when a window of traffic counts as a regression.
type Thresholds struct {
	// MinRequests is how many requests must be seen before the ratio means
	// anything; on a quiet gateway a single 502 is not a verdict.
	MinRequests int
	// MaxErrorRatio is the share of 5xx responses at or above which the
	// apply is rolled back.
	MaxErrorRatio float64
}

// DefaultThresholds roll back when a quarter of at least 20 requests fail.
func DefaultThresholds() Thresholds { return Thresholds{MinRequests: 20, MaxErrorRatio: 0.25} }

// Auditor records what the watcher did.
type Auditor interface {
	Record(store.AuditEntry) error
}

// Watcher runs one canary at a time; a newer apply supersedes the old watch.
type Watcher struct {
	// Window returns how long to watch after an apply; zero or less disables
	// the canary.
	Window func() time.Duration
	// NewSource opens a log source positioned at the current end of the log.
	NewSource func() (LogSource, error)
	// Rollback re-applies prev, the configuration that was live before.
	Rollback func(prev string) error
	// Alert raises an operator-visible alert (optional).
	Alert func(rule, severity, subject, message string)
	Audit Auditor

	Thresholds Thresholds
	// Interval is how often the log is polled; defaults to 10s.
	Interval time.Duration
	// Sleep and Now default to the real clock; tests replace them.
	Sleep func(time.Duration)
	Now   func() time.Time

	mu     sync.Mutex
	cancel context.CancelFunc
}

// Watch starts a canary in the background for a config that was just
// applied by `by`, with prev being the configuration it replaced. It returns
// at once, and does nothing when the canary is disabled or prev is empty.
func (w *Watcher) Watch(prev, by string) {
	if w.Window == nil || w.Window() <= 0 || prev == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.mu.Lock()
	if w.cancel != nil {
		w.cancel() // a newer apply replaces the previous watch
	}
	w.cancel = cancel
	w.mu.Unlock()

	go func() {
		defer cancel()
		if _, err := w.Run(ctx, prev, by); err != nil {
			log.Printf("canary: %v", err)
		}
	}()
}

// Run watches synchronously and reports whether it rolled back.
func (w *Watcher) Run(ctx context.Context, prev, by string) (bool, error) {
	window := w.Window()
	src, err := w.NewSource()
	if err != nil {
		return false, fmt.Errorf("open log: %w", err)
	}
	thr := w.Thresholds
	if thr.MinRequests == 0 && thr.MaxErrorRatio == 0 {
		thr = DefaultThresholds()
	}
	interval := w.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	now, sleep := w.Now, w.Sleep
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = time.Sleep
	}

	deadline := now().Add(window)
	var total, errs int
	for now().Before(deadline) {
		if ctx.Err() != nil {
			return false, nil
		}
		sleep(interval)
		lines, err := src.ReadNew()
		if err != nil {
			return false, fmt.Errorf("read log: %w", err)
		}
		for _, l := range lines {
			if l.StatusCode <= 0 {
				continue
			}
			total++
			if l.StatusCode >= 500 {
				errs++
			}
		}
		if total >= thr.MinRequests && thr.MinRequests > 0 && float64(errs)/float64(total) >= thr.MaxErrorRatio {
			return true, w.rollback(prev, by, errs, total)
		}
	}
	w.audit(by, "config.canary_ok", fmt.Sprintf("%d of %d requests were 5xx in %s", errs, total, window))
	return false, nil
}

func (w *Watcher) rollback(prev, by string, errs, total int) error {
	msg := fmt.Sprintf("%d of %d requests were 5xx after the apply by %s", errs, total, by)
	if err := w.Rollback(prev); err != nil {
		w.audit(by, "config.canary_rollback_failed", msg+": "+err.Error())
		w.alert("config_canary", "critical", by, "Automatic rollback FAILED: "+msg+": "+err.Error())
		return fmt.Errorf("rollback failed: %w", err)
	}
	w.audit(by, "config.canary_rollback", msg)
	w.alert("config_canary", "high", by, "Configuration rolled back automatically: "+msg)
	return nil
}

func (w *Watcher) audit(user, action, detail string) {
	if w.Audit != nil {
		_ = w.Audit.Record(store.AuditEntry{UserEmail: user, Action: action, Detail: detail})
	}
}

func (w *Watcher) alert(rule, severity, subject, message string) {
	if w.Alert != nil {
		w.Alert(rule, severity, subject, message)
	}
}
