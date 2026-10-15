// Package threatintel answers "is this IP known to be bad?". It combines
// public blocklist feeds (downloaded on a schedule and matched in memory)
// with an optional live AbuseIPDB check for IPs the local detectors already
// distrust. It is opt-in, outbound-only and degrades quietly: with no feeds
// configured, or with the network blocked, every lookup simply says "unknown".
package threatintel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"haproxy-gui/internal/store"
)

// Feed is one downloadable blocklist.
type Feed struct {
	Name string
	URL  string
}

// KnownFeeds are the only feeds the gateway will download. Operators pick
// from this list by name; there is no way to point the gateway at an
// arbitrary URL, which keeps the feature from being an SSRF primitive.
var KnownFeeds = map[string]Feed{
	"spamhaus_drop":  {Name: "spamhaus_drop", URL: "https://www.spamhaus.org/drop/drop.txt"},
	"tor_exit":       {Name: "tor_exit", URL: "https://check.torproject.org/torbulkexitlist"},
	"et_compromised": {Name: "et_compromised", URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
}

// FeedsFromNames resolves feed names, returning the names it does not know.
func FeedsFromNames(names []string) (feeds []Feed, unknown []string) {
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		if f, ok := KnownFeeds[n]; ok {
			feeds = append(feeds, f)
		} else {
			unknown = append(unknown, n)
		}
	}
	return feeds, unknown
}

const (
	maxFeedBytes   = 8 << 20
	maxFeedEntries = 200000
	feedTimeout    = 30 * time.Second
	abuseCacheTTL  = 24 * time.Hour
)

// IntelStore persists live-lookup results; *store.Store satisfies it.
type IntelStore interface {
	GetIPIntel(ip string) (store.IPIntel, error)
	UpsertIPIntel(store.IPIntel) error
}

// Service holds the feed sets and answers lookups. It is safe for concurrent use.
type Service struct {
	Feeds []Feed
	HTTP  *http.Client
	Store IntelStore // optional cache for live lookups

	// AbuseKey enables the live AbuseIPDB check; AbuseDailyLimit caps its
	// calls per UTC day (the free tier allows 1000). AbuseBaseURL is
	// overridable for tests.
	AbuseKey        string
	AbuseDailyLimit int
	AbuseBaseURL    string

	// Now defaults to time.Now; overridable for tests.
	Now func() time.Time

	mu        sync.RWMutex
	sets      map[string]*feedSet
	abuseDay  string
	abuseUsed int
}

type feedSet struct {
	prefixes  []netip.Prefix
	count     int
	refreshed time.Time
	err       string
}

// FeedStatus describes one feed for the UI.
type FeedStatus struct {
	Name      string
	Entries   int
	Refreshed time.Time
	Error     string
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: feedTimeout}
}

// ParseList reads a plain-text blocklist: one IP or CIDR per line, with "#"
// or ";" starting a comment (Spamhaus writes "1.2.3.0/24 ; SBL123").
func ParseList(r io.Reader) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(io.LimitReader(r, maxFeedBytes))
	for sc.Scan() && len(out) < maxFeedEntries {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if p, err := netip.ParsePrefix(fields[0]); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(fields[0]); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// Refresh downloads every configured feed. A feed that fails keeps its
// previous entries, so a feed outage never empties the blocklist.
func (s *Service) Refresh(ctx context.Context) {
	for _, f := range s.Feeds {
		prefixes, err := s.fetch(ctx, f)
		s.mu.Lock()
		if s.sets == nil {
			s.sets = map[string]*feedSet{}
		}
		cur := s.sets[f.Name]
		if cur == nil {
			cur = &feedSet{}
			s.sets[f.Name] = cur
		}
		if err != nil {
			cur.err = err.Error()
		} else {
			cur.prefixes, cur.count, cur.refreshed, cur.err = prefixes, len(prefixes), s.now(), ""
		}
		s.mu.Unlock()
		if err != nil {
			log.Printf("threatintel: feed %s: %v", f.Name, err)
		}
	}
}

func (s *Service) fetch(ctx context.Context, f Feed) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	prefixes := ParseList(resp.Body)
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("feed contained no usable entries")
	}
	return prefixes, nil
}

// Run refreshes once at start and then every interval until ctx ends.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if len(s.Feeds) == 0 {
		return
	}
	s.Refresh(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Refresh(ctx)
		}
	}
}

// Status reports each configured feed's size and freshness.
func (s *Service) Status() []FeedStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]FeedStatus, 0, len(s.Feeds))
	for _, f := range s.Feeds {
		st := FeedStatus{Name: f.Name}
		if fs := s.sets[f.Name]; fs != nil {
			st.Entries, st.Refreshed, st.Error = fs.count, fs.refreshed, fs.err
		}
		out = append(out, st)
	}
	return out
}

// Result is what is known about one IP.
type Result struct {
	IP         string
	Feeds      []string // blocklist feeds that list the IP
	AbuseScore int      // AbuseIPDB confidence 0-100; -1 when not checked
	Reports    int
	Country    string
	ISP        string
	CheckedAt  time.Time
}

// Listed reports whether any feed lists the IP.
func (r Result) Listed() bool { return len(r.Feeds) > 0 }

// Lookup checks ip against the feeds and, when live is true and a key is
// configured, AbuseIPDB (cached for a day, capped per day).
func (s *Service) Lookup(ctx context.Context, ip string, live bool) Result {
	res := Result{IP: ip, AbuseScore: -1}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return res
	}
	addr = addr.Unmap()

	s.mu.RLock()
	for _, f := range s.Feeds {
		if fs := s.sets[f.Name]; fs != nil && containsAddr(fs.prefixes, addr) {
			res.Feeds = append(res.Feeds, f.Name)
		}
	}
	s.mu.RUnlock()
	sort.Strings(res.Feeds)

	if live && s.AbuseKey != "" {
		s.fillAbuse(ctx, &res)
	}
	return res
}

// Peek is Lookup without any network call: the feed match plus whatever live
// result is already cached. Pages use it so viewing an IP never spends quota.
func (s *Service) Peek(ip string) Result {
	res := s.Lookup(context.Background(), ip, false)
	if s.Store != nil {
		if c, err := s.Store.GetIPIntel(ip); err == nil && c.AbuseScore >= 0 {
			res.AbuseScore, res.Reports, res.Country, res.ISP, res.CheckedAt = c.AbuseScore, c.Reports, c.Country, c.ISP, c.CheckedAt
		}
	}
	return res
}

func containsAddr(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s *Service) fillAbuse(ctx context.Context, res *Result) {
	if s.Store != nil {
		if c, err := s.Store.GetIPIntel(res.IP); err == nil && s.now().Sub(c.CheckedAt) < abuseCacheTTL && c.AbuseScore >= 0 {
			res.AbuseScore, res.Reports, res.Country, res.ISP, res.CheckedAt = c.AbuseScore, c.Reports, c.Country, c.ISP, c.CheckedAt
			return
		}
	}
	if !s.takeAbuseQuota() {
		return
	}
	score, reports, country, isp, err := s.queryAbuse(ctx, res.IP)
	if err != nil {
		log.Printf("threatintel: abuseipdb %s: %v", res.IP, err)
		return
	}
	res.AbuseScore, res.Reports, res.Country, res.ISP, res.CheckedAt = score, reports, country, isp, s.now()
	if s.Store != nil {
		_ = s.Store.UpsertIPIntel(store.IPIntel{
			IP: res.IP, AbuseScore: score, Reports: reports, Country: country, ISP: isp, CheckedAt: res.CheckedAt,
		})
	}
}

func (s *Service) takeAbuseQuota() bool {
	limit := s.AbuseDailyLimit
	if limit <= 0 {
		limit = 900
	}
	day := s.now().UTC().Format("2006-01-02")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.abuseDay != day {
		s.abuseDay, s.abuseUsed = day, 0
	}
	if s.abuseUsed >= limit {
		return false
	}
	s.abuseUsed++
	return true
}

func (s *Service) queryAbuse(ctx context.Context, ip string) (score, reports int, country, isp string, err error) {
	base := s.AbuseBaseURL
	if base == "" {
		base = "https://api.abuseipdb.com"
	}
	q := url.Values{"ipAddress": {ip}, "maxAgeInDays": {"90"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v2/check?"+q.Encode(), nil)
	if err != nil {
		return 0, 0, "", "", err
	}
	req.Header.Set("Key", s.AbuseKey)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client().Do(req)
	if err != nil {
		return 0, 0, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Score   int    `json:"abuseConfidenceScore"`
			Reports int    `json:"totalReports"`
			Country string `json:"countryCode"`
			ISP     string `json:"isp"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return 0, 0, "", "", err
	}
	return body.Data.Score, body.Data.Reports, body.Data.Country, body.Data.ISP, nil
}
