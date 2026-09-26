package security

import (
	"testing"
	"time"

	"haproxy-gui/internal/haproxylog"
)

func testThresholds() Thresholds {
	return DefaultThresholds()
}

func line(ip, method, path string, status int) haproxylog.Line {
	return haproxylog.Line{ClientIP: ip, Method: method, Path: path, StatusCode: status, Backend: "http_test"}
}

func TestEngine_BruteForce_FiresAtThresholdNotBefore(t *testing.T) {
	thr := testThresholds()
	thr.BruteForceThreshold = 3
	e := NewEngine(thr)
	now := time.Now()

	var lines []haproxylog.Line
	for i := 0; i < 2; i++ {
		lines = append(lines, line("1.2.3.4", "POST", "/login", 401))
	}
	if got := e.Ingest(lines, now); len(got) != 0 {
		t.Fatalf("below threshold: got %d detections, want 0: %+v", len(got), got)
	}

	got := e.Ingest([]haproxylog.Line{line("1.2.3.4", "POST", "/login", 401)}, now)
	if len(got) != 1 || got[0].Rule != RuleBruteForce {
		t.Fatalf("at threshold: got %+v, want one brute_force detection", got)
	}
	if got[0].Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", got[0].Severity)
	}
}

func TestEngine_BruteForce_EscalatesToHighSeverity(t *testing.T) {
	thr := testThresholds()
	thr.BruteForceThreshold = 2
	thr.BruteForceHighThreshold = 4
	e := NewEngine(thr)
	now := time.Now()

	var lines []haproxylog.Line
	for i := 0; i < 4; i++ {
		lines = append(lines, line("1.2.3.4", "POST", "/login", 401))
	}
	got := e.Ingest(lines, now)
	if len(got) != 1 || got[0].Severity != SeverityHigh {
		t.Fatalf("got %+v, want one high-severity brute_force detection", got)
	}
}

func TestEngine_BruteForce_IgnoresAllowlistedIP(t *testing.T) {
	thr := testThresholds()
	thr.BruteForceThreshold = 1
	thr.AllowCIDRs = []string{"1.2.3.0/24"}
	e := NewEngine(thr)
	now := time.Now()

	got := e.Ingest([]haproxylog.Line{line("1.2.3.4", "POST", "/login", 401)}, now)
	if len(got) != 0 {
		t.Fatalf("got %+v, want no detections for an allow-listed IP", got)
	}
}

func TestEngine_RateAnomaly_FiresAboveFloor(t *testing.T) {
	thr := testThresholds()
	thr.RateAnomalyFloor = 5
	e := NewEngine(thr)
	now := time.Now()

	var lines []haproxylog.Line
	for i := 0; i < 5; i++ {
		lines = append(lines, line("9.9.9.9", "GET", "/", 200))
	}
	got := e.Ingest(lines, now)
	if len(got) != 1 || got[0].Rule != RuleRateAnomaly {
		t.Fatalf("got %+v, want one rate_anomaly detection", got)
	}
}

func TestEngine_PathScan_RequiresBothUniquePathsAnd404Ratio(t *testing.T) {
	thr := testThresholds()
	thr.PathScanMinRequests = 4
	thr.PathScanUniqueThresh = 4
	thr.PathScan404Ratio = 0.5
	e := NewEngine(thr)
	now := time.Now()

	// All 200s: unique paths high but no 404 ratio, should not fire.
	var okLines []haproxylog.Line
	for i := 0; i < 4; i++ {
		okLines = append(okLines, line("5.5.5.5", "GET", "/p"+string(rune('a'+i)), 200))
	}
	if got := e.Ingest(okLines, now); len(got) != 0 {
		t.Fatalf("no 404s: got %+v, want no path_scan", got)
	}

	var scanLines []haproxylog.Line
	for i := 0; i < 4; i++ {
		scanLines = append(scanLines, line("6.6.6.6", "GET", "/q"+string(rune('a'+i)), 404))
	}
	got := e.Ingest(scanLines, now)
	if len(got) != 1 || got[0].Rule != RulePathScan {
		t.Fatalf("got %+v, want one path_scan detection", got)
	}
}

func TestEngine_SensitiveProbe_SingleHitIsLowSeverity(t *testing.T) {
	e := NewEngine(testThresholds())
	now := time.Now()

	got := e.Ingest([]haproxylog.Line{line("7.7.7.7", "GET", "/.env", 404)}, now)
	if len(got) != 1 || got[0].Rule != RuleSensitiveProbe || got[0].Severity != SeverityLow {
		t.Fatalf("got %+v, want one low-severity sensitive_probe detection", got)
	}
}

func TestEngine_SensitiveProbe_MultipleDistinctPatternsEscalateToHigh(t *testing.T) {
	thr := testThresholds()
	thr.SensitiveHighDistinct = 2
	e := NewEngine(thr)
	now := time.Now()

	lines := []haproxylog.Line{
		line("8.8.8.8", "GET", "/.env", 404),
		line("8.8.8.8", "GET", "/wp-admin/setup.php", 404),
	}
	got := e.Ingest(lines, now)
	if len(got) != 1 || got[0].Severity != SeverityHigh {
		t.Fatalf("got %+v, want escalated high-severity sensitive_probe", got)
	}
}

func TestEngine_HTTPAbuse_PostFlood(t *testing.T) {
	thr := testThresholds()
	thr.HTTPAbusePostPerWindow = 3
	e := NewEngine(thr)
	now := time.Now()

	var lines []haproxylog.Line
	for i := 0; i < 3; i++ {
		lines = append(lines, line("2.2.2.2", "POST", "/submit", 200))
	}
	got := e.Ingest(lines, now)
	if len(got) != 1 || got[0].Rule != RuleHTTPAbuse {
		t.Fatalf("got %+v, want one http_abuse detection", got)
	}
}

func TestEngine_RateLimited_FiresOn429Burst(t *testing.T) {
	thr := testThresholds()
	thr.RateLimitedThreshold = 3
	e := NewEngine(thr)
	now := time.Now()

	var lines []haproxylog.Line
	for i := 0; i < 3; i++ {
		lines = append(lines, line("3.3.3.3", "GET", "/", 429))
	}
	got := e.Ingest(lines, now)
	if len(got) != 1 || got[0].Rule != RuleRateLimited || got[0].Severity != SeverityLow {
		t.Fatalf("got %+v, want one low-severity rate_limited detection", got)
	}
}

func TestEngine_BackendAbuse_FiresOnTimeouts(t *testing.T) {
	thr := testThresholds()
	thr.BackendAbuseTimeouts = 2
	e := NewEngine(thr)
	now := time.Now()

	lines := []haproxylog.Line{
		{Backend: "http_slow", Tc: -1, Termination: "sQ--"},
		{Backend: "http_slow", Tc: -1, Termination: "sQ--"},
	}
	got := e.Ingest(lines, now)
	if len(got) != 1 || got[0].Rule != RuleBackendAbuse || got[0].SubjectType != SubjectBackend {
		t.Fatalf("got %+v, want one backend_abuse detection for the backend", got)
	}
	if got[0].Subject != "http_slow" {
		t.Errorf("subject = %q, want http_slow", got[0].Subject)
	}
}

func TestEngine_Dedup_DoesNotRefireWithinSameMinute(t *testing.T) {
	thr := testThresholds()
	thr.BruteForceThreshold = 1
	e := NewEngine(thr)
	now := time.Now()

	first := e.Ingest([]haproxylog.Line{line("4.4.4.4", "POST", "/login", 401)}, now)
	if len(first) != 1 {
		t.Fatalf("first ingest: got %+v, want one detection", first)
	}
	second := e.Ingest([]haproxylog.Line{line("4.4.4.4", "POST", "/login", 401)}, now.Add(time.Second))
	if len(second) != 0 {
		t.Fatalf("second ingest within same minute: got %+v, want no re-fire", second)
	}
}

func TestEngine_Dedup_EscalationReFires(t *testing.T) {
	thr := testThresholds()
	thr.BruteForceThreshold = 1
	thr.BruteForceHighThreshold = 2
	e := NewEngine(thr)
	now := time.Now()

	first := e.Ingest([]haproxylog.Line{line("4.4.4.5", "POST", "/login", 401)}, now)
	if len(first) != 1 || first[0].Severity != SeverityMedium {
		t.Fatalf("first: got %+v", first)
	}
	second := e.Ingest([]haproxylog.Line{line("4.4.4.5", "POST", "/login", 401)}, now.Add(time.Second))
	if len(second) != 1 || second[0].Severity != SeverityHigh {
		t.Fatalf("escalation: got %+v, want one high-severity re-fire", second)
	}
}

func TestEngine_EvictIdle_DropsWindowsAfterEvictAfter(t *testing.T) {
	e := NewEngine(testThresholds())
	now := time.Now()
	e.Ingest([]haproxylog.Line{line("1.1.1.1", "GET", "/", 200)}, now)
	if _, ok := e.ips["1.1.1.1"]; !ok {
		t.Fatal("expected IP to be tracked after ingest")
	}
	e.Ingest(nil, now.Add(evictAfter+time.Minute))
	if _, ok := e.ips["1.1.1.1"]; ok {
		t.Fatal("expected idle IP window to be evicted")
	}
}

func TestEngine_UnparseableLineWithNoClientIPIsSkippedForIPRules(t *testing.T) {
	e := NewEngine(testThresholds())
	got := e.Ingest([]haproxylog.Line{{Raw: "unparseable"}}, time.Now())
	if len(got) != 0 {
		t.Fatalf("got %+v, want no detections for a line with no ClientIP", got)
	}
}
