package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"haproxy-gui/internal/store"
)

func TestParseList(t *testing.T) {
	in := "# header\n; comment\n1.2.3.4\n10.0.0.0/8 ; SBL123\n\n2001:db8::/32\nnot-an-ip\n::ffff:5.6.7.8\n 9.9.9.9   # trailing\n"
	got := ParseList(strings.NewReader(in))
	want := []string{"1.2.3.4/32", "10.0.0.0/8", "2001:db8::/32", "5.6.7.8/32", "9.9.9.9/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, p := range got {
		if p.String() != want[i] {
			t.Errorf("entry %d = %s, want %s", i, p, want[i])
		}
	}
}

func TestFeedsFromNames_OnlyKnownFeeds(t *testing.T) {
	feeds, unknown := FeedsFromNames([]string{"tor_exit", " spamhaus_drop ", "tor_exit", "http://evil.example/x", ""})
	if len(feeds) != 2 || feeds[0].Name != "tor_exit" || feeds[1].Name != "spamhaus_drop" {
		t.Errorf("feeds = %+v", feeds)
	}
	if len(unknown) != 1 || unknown[0] != "http://evil.example/x" {
		t.Errorf("unknown = %v, an arbitrary URL must be rejected", unknown)
	}
	for _, f := range KnownFeeds {
		if !strings.HasPrefix(f.URL, "https://") {
			t.Errorf("%s uses a non-HTTPS URL %s", f.Name, f.URL)
		}
	}
}

func feedServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRefreshAndLookup(t *testing.T) {
	drop := feedServer(t, "203.0.113.0/24 ; SBL1\n", 200)
	tor := feedServer(t, "198.51.100.7\n", 200)
	s := &Service{Feeds: []Feed{{Name: "spamhaus_drop", URL: drop.URL}, {Name: "tor_exit", URL: tor.URL}}}
	s.Refresh(context.Background())

	if r := s.Lookup(context.Background(), "203.0.113.50", false); len(r.Feeds) != 1 || r.Feeds[0] != "spamhaus_drop" || !r.Listed() {
		t.Errorf("CIDR match: %+v", r)
	}
	if r := s.Lookup(context.Background(), "198.51.100.7", false); len(r.Feeds) != 1 || r.Feeds[0] != "tor_exit" {
		t.Errorf("host match: %+v", r)
	}
	if r := s.Lookup(context.Background(), "192.0.2.1", false); r.Listed() || r.AbuseScore != -1 {
		t.Errorf("clean IP: %+v", r)
	}
	if r := s.Lookup(context.Background(), "garbage", false); r.Listed() {
		t.Errorf("invalid IP: %+v", r)
	}
	st := s.Status()
	if len(st) != 2 || st[0].Entries != 1 || st[0].Error != "" || st[0].Refreshed.IsZero() {
		t.Errorf("status = %+v", st)
	}
}

func TestRefresh_FailedFeedKeepsPreviousEntries(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer srv.Close()
	s := &Service{Feeds: []Feed{{Name: "et_compromised", URL: srv.URL}}}
	s.Refresh(context.Background())
	fail.Store(true)
	s.Refresh(context.Background())

	if !s.Lookup(context.Background(), "203.0.113.9", false).Listed() {
		t.Error("a feed outage emptied the blocklist")
	}
	if st := s.Status(); st[0].Error == "" || !strings.Contains(st[0].Error, "503") {
		t.Errorf("outage not reported: %+v", st)
	}
}

func TestRefresh_EmptyFeedIsAnError(t *testing.T) {
	srv := feedServer(t, "# nothing here\n", 200)
	s := &Service{Feeds: []Feed{{Name: "tor_exit", URL: srv.URL}}}
	s.Refresh(context.Background())
	if st := s.Status(); st[0].Error == "" {
		t.Errorf("an empty feed must not count as a successful refresh: %+v", st)
	}
}

type memIntel struct{ m map[string]store.IPIntel }

func (c *memIntel) GetIPIntel(ip string) (store.IPIntel, error) {
	v, ok := c.m[ip]
	if !ok {
		return store.IPIntel{}, store.ErrNotFound
	}
	return v, nil
}
func (c *memIntel) UpsertIPIntel(in store.IPIntel) error { c.m[in.IP] = in; return nil }

func TestAbuseLookup_CachesAndHonoursTheDailyLimit(t *testing.T) {
	var calls atomic.Int32
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		gotKey = r.Header.Get("Key")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":92,"totalReports":14,"countryCode":"RU","isp":"Evil ISP"}}`))
	}))
	defer srv.Close()

	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	s := &Service{AbuseKey: "secret", AbuseBaseURL: srv.URL, AbuseDailyLimit: 2, Store: &memIntel{m: map[string]store.IPIntel{}}, Now: func() time.Time { return now }}

	r := s.Lookup(context.Background(), "203.0.113.1", true)
	if r.AbuseScore != 92 || r.Country != "RU" || r.Reports != 14 || gotKey != "secret" {
		t.Fatalf("result = %+v key=%q", r, gotKey)
	}
	s.Lookup(context.Background(), "203.0.113.1", true) // served from the cache
	if calls.Load() != 1 {
		t.Errorf("cache miss: %d upstream calls", calls.Load())
	}
	s.Lookup(context.Background(), "203.0.113.2", true)
	if r := s.Lookup(context.Background(), "203.0.113.3", true); r.AbuseScore != -1 || calls.Load() != 2 {
		t.Errorf("daily limit not enforced: %+v calls=%d", r, calls.Load())
	}
	now = now.Add(24 * time.Hour) // next UTC day: quota resets
	if r := s.Lookup(context.Background(), "203.0.113.3", true); r.AbuseScore != 92 {
		t.Errorf("quota did not reset: %+v", r)
	}
}

func TestLookup_NoLiveCallWithoutKeyOrWhenNotRequested(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()
	(&Service{AbuseBaseURL: srv.URL}).Lookup(context.Background(), "203.0.113.1", true)
	(&Service{AbuseKey: "k", AbuseBaseURL: srv.URL}).Lookup(context.Background(), "203.0.113.1", false)
	if calls.Load() != 0 {
		t.Errorf("%d unexpected upstream calls", calls.Load())
	}
}
