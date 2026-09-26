package security

import "time"

// Thresholds configures every detector. Nothing in engine.go is hardcoded;
// callers construct Thresholds (DefaultThresholds is a sane starting point)
// and can later expose it as an editable setting.
type Thresholds struct {
	// AllowCIDRs are IPs (given as CIDR, e.g. "10.0.0.0/8" or "1.2.3.4/32")
	// exempt from every IP-keyed rule — internal ranges, health checkers,
	// the VPN. Detections never fire for these subjects.
	AllowCIDRs []string

	// LoginPaths are request paths (case-insensitive, exact match after
	// trimming a trailing "*" for prefix match) considered authentication
	// endpoints for the brute-force rule.
	LoginPaths []string
	// LoginFailStatuses are HTTP status codes on a LoginPaths POST counted
	// as a failed login attempt.
	LoginFailStatuses []int

	// BruteForceWindow is how far back failed logins are counted.
	BruteForceWindow time.Duration
	// BruteForceThreshold is the failure count that fires the rule at
	// SeverityMedium; BruteForceHighThreshold escalates it to SeverityHigh.
	BruteForceThreshold     int
	BruteForceHighThreshold int

	// RateAnomalyWindow is the bucket size used to measure an IP's request
	// rate.
	RateAnomalyWindow time.Duration
	// RateAnomalyMinBaseline is the minimum requests/window before an IP is
	// judged solely against RateAnomalyFloor rather than its own baseline
	// (too little history to trust an EWMA yet).
	RateAnomalyMinHistory time.Duration
	// RateAnomalyMultiplier is how far above an IP's own baseline rate
	// triggers the rule; RateAnomalyFloor is an absolute requests/window
	// floor applied regardless of baseline, so a brand-new IP can still
	// trip the rule.
	RateAnomalyMultiplier float64
	RateAnomalyFloor      int
	RateAnomalyHighFloor  int
	RateAnomalyEWMAAlpha  float64

	// PathScanWindow bounds unique-path counting for the scan rule.
	PathScanWindow           time.Duration
	PathScanMinRequests      int
	PathScanUniqueThresh     int
	PathScanUniqueHighThresh int
	PathScan404Ratio         float64

	// SensitivePatterns are case-insensitive substrings of a request path
	// that indicate probing for sensitive files/admin surfaces.
	SensitivePatterns []string
	// SensitiveWindow bounds how hits on SensitivePatterns are grouped.
	SensitiveWindow       time.Duration
	SensitiveHighDistinct int // distinct patterns hit -> SeverityHigh

	// HTTPAbuseWindow bounds the counters below.
	HTTPAbuseWindow        time.Duration
	HTTPAbusePostPerWindow int
	HTTPAbuse4xxPerWindow  int
	HTTPAbuse4xxRatio      float64
	HTTPAbuse5xxPerWindow  int
	HTTPAbuseBurstWindow   time.Duration
	HTTPAbuseBurstCount    int

	// BackendAbuseWindow is the short window compared against a longer
	// baseline (BackendAbuseBaselineWindow) to catch queueing/timeout/error
	// regressions on one backend.
	BackendAbuseWindow           time.Duration
	BackendAbuseBaselineWindow   time.Duration
	BackendAbuseQueueMultiplier  float64
	BackendAbuseQueueFloorMillis int
	BackendAbuseTimeouts         int
	BackendAbuse5xxRatio         float64

	// RateLimitedWindow/Threshold turn a burst of 429s (the same signal
	// ratelimitqueue already captures) into a low-severity contributor to
	// an IP's risk score.
	RateLimitedWindow    time.Duration
	RateLimitedThreshold int
}

// DefaultThresholds returns reasonable starting values. All are meant to be
// tuned per deployment (see the Phase 7 settings page in the design).
func DefaultThresholds() Thresholds {
	return Thresholds{
		LoginPaths:        []string{"/login", "/api/login", "/auth/*", "/sso/login"},
		LoginFailStatuses: []int{401, 403},

		BruteForceWindow:        5 * time.Minute,
		BruteForceThreshold:     10,
		BruteForceHighThreshold: 30,

		RateAnomalyWindow:     time.Minute,
		RateAnomalyMinHistory: 10 * time.Minute,
		RateAnomalyMultiplier: 3,
		RateAnomalyFloor:      120,
		RateAnomalyHighFloor:  1200,
		RateAnomalyEWMAAlpha:  0.1,

		PathScanWindow:           5 * time.Minute,
		PathScanMinRequests:      40,
		PathScanUniqueThresh:     30,
		PathScanUniqueHighThresh: 100,
		PathScan404Ratio:         0.5,

		SensitivePatterns: []string{
			"/.env", "/.git", "wp-admin", "wp-login", "phpinfo",
			"/vendor/", "/debug", "/actuator", "/.aws", "/server-status",
			".bak", ".sql", ".swp", "/.ssh",
		},
		SensitiveWindow:       10 * time.Minute,
		SensitiveHighDistinct: 3,

		HTTPAbuseWindow:        time.Minute,
		HTTPAbusePostPerWindow: 60,
		HTTPAbuse4xxPerWindow:  50,
		HTTPAbuse4xxRatio:      0.7,
		HTTPAbuse5xxPerWindow:  20,
		HTTPAbuseBurstWindow:   10 * time.Second,
		HTTPAbuseBurstCount:    50,

		BackendAbuseWindow:           5 * time.Minute,
		BackendAbuseBaselineWindow:   time.Hour,
		BackendAbuseQueueMultiplier:  3,
		BackendAbuseQueueFloorMillis: 500,
		BackendAbuseTimeouts:         20,
		BackendAbuse5xxRatio:         0.05,

		RateLimitedWindow:    5 * time.Minute,
		RateLimitedThreshold: 20,
	}
}
