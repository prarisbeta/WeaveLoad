package security

import (
	"context"
	"testing"
	"time"

	"haproxy-gui/internal/threatintel"
)

type fakeIntel struct {
	res   map[string]threatintel.Result
	lives []string
}

func (f *fakeIntel) Lookup(_ context.Context, ip string, live bool) threatintel.Result {
	if live {
		f.lives = append(f.lives, ip)
	}
	if r, ok := f.res[ip]; ok {
		return r
	}
	return threatintel.Result{IP: ip, AbuseScore: -1}
}

func TestCheckIntel_RecordsListedIPs(t *testing.T) {
	st := newFakeStore()
	r := &Runner{Store: st, Intel: &fakeIntel{res: map[string]threatintel.Result{
		"203.0.113.5": {IP: "203.0.113.5", Feeds: []string{"spamhaus_drop"}, AbuseScore: -1},
	}}}
	now := time.Now()

	if !r.checkIntel("203.0.113.5", now, false) {
		t.Fatal("a feed-listed IP produced no detection")
	}
	r.checkIntel("203.0.113.5", now.Add(time.Minute), false) // same day: merges, no duplicate
	if len(st.events) != 1 || st.events[0].Rule != string(RuleKnownBadIP) || st.events[0].Severity != "high" {
		t.Fatalf("events = %+v", st.events)
	}
	if feeds, _ := st.events[0].Evidence["feeds"].([]string); len(feeds) != 1 || feeds[0] != "spamhaus_drop" {
		t.Errorf("evidence = %+v", st.events[0].Evidence)
	}
	if r.checkIntel("192.0.2.1", now, false) {
		t.Error("a clean IP produced a detection")
	}
}

func TestCheckIntel_LiveScoreThreshold(t *testing.T) {
	st := newFakeStore()
	r := &Runner{Store: st, Intel: &fakeIntel{res: map[string]threatintel.Result{
		"198.51.100.1": {IP: "198.51.100.1", AbuseScore: 90, Reports: 40, Country: "RU"},
		"198.51.100.2": {IP: "198.51.100.2", AbuseScore: 20},
	}}}
	if !r.checkIntel("198.51.100.1", time.Now(), true) {
		t.Error("a high AbuseIPDB score must count as known bad")
	}
	if r.checkIntel("198.51.100.2", time.Now(), true) {
		t.Error("a low AbuseIPDB score must not")
	}
}

func TestCheckIntel_NilIntelIsNoOp(t *testing.T) {
	if (&Runner{Store: newFakeStore()}).checkIntel("1.2.3.4", time.Now(), true) {
		t.Error("no intel configured, yet a detection was recorded")
	}
}
