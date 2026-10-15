package security

import (
	"sort"
	"testing"
	"time"

	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/redisping"
	"haproxy-gui/internal/store"
)

// ListTopRisk makes fakeStore a riskLister, as the real store is.
func (f *fakeStore) ListTopRisk(n int) ([]store.IPRisk, error) {
	var out []store.IPRisk
	for _, r := range f.risk {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

func decayRunner(t *testing.T, fs *fakeStore) *Runner {
	t.Helper()
	path := writeLogFile(t, "")
	tailer, err := haproxylog.NewTailerAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}
	addr := startFakeRedisForTest(t)
	return &Runner{
		Store: fs, Engine: NewEngine(DefaultThresholds()), Tailer: tailer,
		RedisOpts: func() (redisping.Options, bool) {
			host, port, _ := splitAddr(addr)
			return redisping.Options{Host: host, Port: port, Timeout: 2 * time.Second}, true
		},
	}
}

// An IP whose score has decayed to normal must lose its Redis snapshot instead
// of keeping it for the rest of its 24h TTL.
func TestRunner_UpdateRisk_ReleasesRedisKeyWhenIPIsNormal(t *testing.T) {
	fs := newFakeStore()
	r := decayRunner(t, fs)

	r.updateRisk("10.0.0.9", time.Now()) // no events for this IP => score 0 => normal

	got := fakeRedisLastCommand()
	if len(got) < 2 || got[0] != "DEL" || got[1] != "security:10.0.0.9" {
		t.Errorf("redis command = %v, want DEL security:10.0.0.9", got)
	}
	if fs.risk["10.0.0.9"].State != string(RiskNormal) {
		t.Errorf("state = %q, want normal", fs.risk["10.0.0.9"].State)
	}
}

func TestRunner_DecayRisks_RescoresFlaggedIPsAndKeepsLastSeen(t *testing.T) {
	fs := newFakeStore()
	longAgo := time.Now().Add(-6 * time.Hour).UTC().Truncate(time.Second)
	fs.risk["10.0.0.9"] = store.IPRisk{IP: "10.0.0.9", Score: 70, State: string(RiskHigh), FirstSeen: longAgo, LastSeen: longAgo}
	fs.risk["10.0.0.10"] = store.IPRisk{IP: "10.0.0.10", Score: 0, State: string(RiskNormal), FirstSeen: longAgo, LastSeen: longAgo}
	r := decayRunner(t, fs)

	if n := r.DecayRisks(time.Now()); n != 1 {
		t.Fatalf("re-scored %d IPs, want only the flagged one", n)
	}
	got := fs.risk["10.0.0.9"]
	if got.State != string(RiskNormal) || got.Score != 0 {
		t.Errorf("after decay: %+v, want normal with score 0 (no events left)", got)
	}
	if !got.LastSeen.Equal(longAgo) {
		t.Errorf("LastSeen = %v, want it untouched (%v): a decay pass is not activity", got.LastSeen, longAgo)
	}
	if cmd := fakeRedisLastCommand(); len(cmd) < 2 || cmd[0] != "DEL" || cmd[1] != "security:10.0.0.9" {
		t.Errorf("redis command = %v, want DEL security:10.0.0.9", cmd)
	}
}

func TestRunner_Tick_DecaysAtMostOncePerInterval(t *testing.T) {
	fs := newFakeStore()
	longAgo := time.Now().Add(-6 * time.Hour)
	fs.risk["10.0.0.9"] = store.IPRisk{IP: "10.0.0.9", Score: 70, State: string(RiskHigh), FirstSeen: longAgo, LastSeen: longAgo}
	r := decayRunner(t, fs)
	now := time.Now()
	r.Now = func() time.Time { return now }

	if err := r.Tick(); err != nil {
		t.Fatal(err)
	}
	if fs.risk["10.0.0.9"].State != string(RiskNormal) {
		t.Fatal("the first Tick should run the decay pass")
	}

	fs.risk["10.0.0.9"] = store.IPRisk{IP: "10.0.0.9", Score: 70, State: string(RiskHigh), FirstSeen: longAgo, LastSeen: longAgo}
	now = now.Add(10 * time.Minute)
	if err := r.Tick(); err != nil {
		t.Fatal(err)
	}
	if fs.risk["10.0.0.9"].State != string(RiskHigh) {
		t.Error("a second Tick 10 minutes later must not decay again")
	}

	now = now.Add(time.Hour)
	if err := r.Tick(); err != nil {
		t.Fatal(err)
	}
	if fs.risk["10.0.0.9"].State != string(RiskNormal) {
		t.Error("after the interval the decay pass should run again")
	}
}
