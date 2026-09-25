package ratelimitqueue

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// logLine builds one HAProxy httplog line for "today" (Extract always
// filters the log to today), so tests don't depend on which day they run.
func logLine(t time.Time, backend, server string, status int) string {
	accept := t.Format("02/Jan/2006:15:04:05.000")
	syslogPrefix := t.Format("Jan _2 15:04:05")
	return syslogPrefix + " haproxy-cni haproxy[100]: 10.0.0.1:1111 [" + accept + "] http_in " + backend + "/" + server +
		" 0/0/0/1/1 " + strconv.Itoa(status) + " 612 - - ---- 1/1/0/0/0 0/0 \"GET / HTTP/1.1\"\n"
}

func writeLog(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "haproxy.log")
	content := ""
	for _, l := range lines {
		content += l
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtract_NoLimitedPools_ReadsNothing(t *testing.T) {
	now := time.Now()
	path := writeLog(t, logLine(now, "http_oms", "node1", 429))
	events, newest, err := Extract(path, time.Time{}, nil, 429)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("events = %v, want none when no pools are limited", events)
	}
	if !newest.IsZero() {
		t.Errorf("newest = %v, want zero value unchanged", newest)
	}
}

func TestExtract_MatchesLimitedPoolAndStatus(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	path := writeLog(t,
		logLine(now, "http_oms", "node1", 200),                    // wrong status
		logLine(now, "http_other", "node1", 429),                  // pool not limited
		logLine(now.Add(1*time.Second), "http_oms", "node2", 429), // match
	)
	events, newest, err := Extract(path, time.Time{}, map[string]bool{"http_oms": true}, 429)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1; got %+v", len(events), events)
	}
	if events[0].Pool != "http_oms" || events[0].Status != 429 {
		t.Errorf("event = %+v", events[0])
	}
	if !newest.Equal(events[0].Time) {
		t.Errorf("newest = %v, want %v", newest, events[0].Time)
	}
}

func TestExtract_SinceExcludesAlreadySeenLines(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	older := now
	newer := now.Add(5 * time.Second)
	path := writeLog(t,
		logLine(older, "http_oms", "node1", 429),
		logLine(newer, "http_oms", "node1", 429),
	)
	events, _, err := Extract(path, older, map[string]bool{"http_oms": true}, 429)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(events) != 1 || !events[0].Time.Equal(newer) {
		t.Fatalf("events = %+v, want only the line after `since`", events)
	}
}

func TestExtract_OldestFirst(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	a := now
	b := now.Add(1 * time.Second)
	c := now.Add(2 * time.Second)
	// Real log files are append-only, so lines are already chronological —
	// write them that way here too (Extract, like haproxylog.Read, relies
	// on file order to determine "oldest", it doesn't sort by timestamp).
	path := writeLog(t,
		logLine(a, "http_oms", "n", 429),
		logLine(b, "http_oms", "n", 429),
		logLine(c, "http_oms", "n", 429),
	)
	events, _, err := Extract(path, time.Time{}, map[string]bool{"http_oms": true}, 429)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(events) != 3 || !events[0].Time.Equal(a) || !events[1].Time.Equal(b) || !events[2].Time.Equal(c) {
		t.Fatalf("events not oldest-first: %+v", events)
	}
}
