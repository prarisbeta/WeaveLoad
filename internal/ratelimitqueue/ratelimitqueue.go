// Package ratelimitqueue turns HAProxy access-log entries rejected by a
// pool's rate limit into events a caller can push onto a queue (Redis, via
// internal/redisping, wired up from the Settings page). It only extracts
// events from the log — pushing them, deciding how often to run, and
// deciding whether a queue is even configured are the caller's job, kept
// out of this package so it stays trivial to test without a real Redis.
package ratelimitqueue

import (
	"strings"
	"time"

	"haproxy-gui/internal/haproxylog"
)

// Event is one rate-limit rejection worth recording.
type Event struct {
	Time   time.Time `json:"time"`
	Pool   string    `json:"pool"`
	Status int       `json:"status"`
	Raw    string    `json:"raw"`
}

// Extract reads path's log for today and returns, oldest first, every line
// newer than since whose status is blockStatus (HAProxy answers 429 for
// both "deny" and "tarpit" rate-limit actions — see haproxycfg.SetRateLimit)
// and whose backend matches one of limitedPools. It also returns the
// newest timestamp seen, so a caller polling on an interval can pass that
// back in as the next call's since and never process the same line twice.
// An empty limitedPools always yields no events without reading the log.
func Extract(path string, since time.Time, limitedPools map[string]bool, blockStatus int) ([]Event, time.Time, error) {
	newest := since
	if len(limitedPools) == 0 {
		return nil, newest, nil
	}
	lines, err := haproxylog.Read(path, haproxylog.Filter{Date: time.Now(), Limit: 5000})
	if err != nil {
		return nil, since, err
	}

	var events []Event
	for i := len(lines) - 1; i >= 0; i-- { // Read returns newest-first; walk oldest-first
		l := lines[i]
		if l.Time.IsZero() || !l.Time.After(since) || l.StatusCode != blockStatus {
			continue
		}
		pool := matchPool(l.Raw, limitedPools)
		if pool == "" {
			continue
		}
		events = append(events, Event{Time: l.Time, Pool: pool, Status: l.StatusCode, Raw: l.Raw})
		if l.Time.After(newest) {
			newest = l.Time
		}
	}
	return events, newest, nil
}

// matchPool finds which limited pool a log line's "backend/server" field
// names, by the plain substring HAProxy's httplog format always uses:
// "<space>backend_name/server_name<space>".
func matchPool(raw string, limitedPools map[string]bool) string {
	for name := range limitedPools {
		if strings.Contains(raw, " "+name+"/") {
			return name
		}
	}
	return ""
}
