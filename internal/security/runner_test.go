package security

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/redisping"
	"haproxy-gui/internal/store"
)

type fakeStore struct {
	events []store.SecurityEvent
	risk   map[string]store.IPRisk
}

func newFakeStore() *fakeStore { return &fakeStore{risk: map[string]store.IPRisk{}} }

func (f *fakeStore) UpsertSecurityEvent(ev store.SecurityEvent) (int64, bool, error) {
	for i, e := range f.events {
		if e.Fingerprint == ev.Fingerprint {
			f.events[i] = ev
			return int64(i + 1), false, nil
		}
	}
	f.events = append(f.events, ev)
	return int64(len(f.events)), true, nil
}

func (f *fakeStore) UpsertIPRisk(r store.IPRisk) error {
	f.risk[r.IP] = r
	return nil
}

func (f *fakeStore) GetIPRisk(ip string) (store.IPRisk, error) {
	r, ok := f.risk[ip]
	if !ok {
		return store.IPRisk{}, store.ErrNotFound
	}
	return r, nil
}

func (f *fakeStore) ListSecurityEvents(filter store.SecurityFilter) ([]store.SecurityEvent, int, error) {
	var out []store.SecurityEvent
	for _, e := range f.events {
		if filter.Subject != "" && e.Subject != filter.Subject {
			continue
		}
		out = append(out, e)
	}
	return out, len(out), nil
}

func writeLogFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "haproxy.log")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func appendToFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func TestRunner_Tick_PersistsDetectionAndRiskScore(t *testing.T) {
	path := writeLogFile(t, "")
	tailer, err := haproxylog.NewTailerAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}
	thr := DefaultThresholds()
	thr.BruteForceThreshold = 1
	fs := newFakeStore()
	r := &Runner{Store: fs, Engine: NewEngine(thr), Tailer: tailer}

	appendToFile(t, path, `Sep 26 08:21:12 h haproxy[1]: 10.0.0.9:1234 [26/Sep/2026:08:21:12.000] http_in http_oms/node1 0/0/0/1/1 401 100 - - ---- 1/1/0/0/0 0/0 "POST /login HTTP/1.1"`+"\n")

	if err := r.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(fs.events) != 1 || fs.events[0].Rule != string(RuleBruteForce) {
		t.Fatalf("events = %+v, want one brute_force event", fs.events)
	}
	risk, ok := fs.risk["10.0.0.9"]
	if !ok {
		t.Fatal("expected a risk profile to be persisted for the offending IP")
	}
	if risk.Score <= 0 {
		t.Errorf("risk.Score = %v, want > 0", risk.Score)
	}
}

func TestRunner_Tick_NoNewLinesIsANoop(t *testing.T) {
	path := writeLogFile(t, "existing line\n")
	tailer, err := haproxylog.NewTailerAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}
	fs := newFakeStore()
	r := &Runner{Store: fs, Engine: NewEngine(DefaultThresholds()), Tailer: tailer}

	if err := r.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(fs.events) != 0 {
		t.Errorf("events = %+v, want none", fs.events)
	}
}

func TestRunner_Tick_PublishesRiskSnapshotForAtRiskIP(t *testing.T) {
	path := writeLogFile(t, "")
	tailer, err := haproxylog.NewTailerAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}
	thr := DefaultThresholds()
	thr.BruteForceThreshold = 1
	thr.BruteForceHighThreshold = 1 // force high severity -> score above "watch"
	fs := newFakeStore()

	fakeAddr := startFakeRedisForTest(t)
	r := &Runner{
		Store: fs, Engine: NewEngine(thr), Tailer: tailer,
		RedisOpts: func() (redisping.Options, bool) {
			host, port, _ := splitAddr(fakeAddr)
			return redisping.Options{Host: host, Port: port, Timeout: 2 * time.Second}, true
		},
	}
	appendToFile(t, path, `Sep 26 08:21:12 h haproxy[1]: 10.0.0.9:1234 [26/Sep/2026:08:21:12.000] http_in http_oms/node1 0/0/0/1/1 401 100 - - ---- 1/1/0/0/0 0/0 "POST /login HTTP/1.1"`+"\n")

	if err := r.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got := fakeRedisLastCommand(); len(got) < 2 || got[0] != "SET" || got[1] != "security:10.0.0.9" {
		t.Errorf("redis command = %v, want a SET of security:10.0.0.9", got)
	}
}

func TestRunner_Tick_SkipsRedisWhenNotConfigured(t *testing.T) {
	path := writeLogFile(t, "")
	tailer, err := haproxylog.NewTailerAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}
	thr := DefaultThresholds()
	thr.BruteForceThreshold = 1
	fs := newFakeStore()
	r := &Runner{Store: fs, Engine: NewEngine(thr), Tailer: tailer} // RedisOpts nil

	appendToFile(t, path, `Sep 26 08:21:12 h haproxy[1]: 10.0.0.9:1234 [26/Sep/2026:08:21:12.000] http_in http_oms/node1 0/0/0/1/1 401 100 - - ---- 1/1/0/0/0 0/0 "POST /login HTTP/1.1"`+"\n")

	if err := r.Tick(); err != nil {
		t.Fatalf("Tick with no RedisOpts should not error: %v", err)
	}
}
