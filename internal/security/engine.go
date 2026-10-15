package security

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"haproxy-gui/internal/cti"
	"haproxy-gui/internal/haproxylog"
)

// Engine holds all in-memory detector state. It is not safe for concurrent
// use — callers (the runner in runner.go) serialize ticks.
type Engine struct {
	thr      Thresholds
	allow    []*net.IPNet
	ips      map[string]*ipWindow
	backends map[string]*backendWindow
	fired    map[string]firedState // rule|subject -> last emission
}

type firedState struct {
	bucket   int64 // window-bucket (Unix seconds, truncated) last emitted
	severity Severity
}

// NewEngine builds an Engine from the given thresholds, parsing AllowCIDRs
// up front. A malformed CIDR is skipped rather than failing construction —
// thresholds may come from user-edited settings.
func NewEngine(thr Thresholds) *Engine {
	e := &Engine{
		thr:      thr,
		ips:      map[string]*ipWindow{},
		backends: map[string]*backendWindow{},
		fired:    map[string]firedState{},
	}
	for _, cidr := range thr.AllowCIDRs {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			e.allow = append(e.allow, n)
		}
	}
	return e
}

func (e *Engine) allowed(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range e.allow {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Ingest processes a batch of log lines and returns newly created or
// escalated Detections. Lines with no ClientIP (unparseable) or an
// allow-listed ClientIP are skipped for IP-keyed rules; backend-keyed rules
// still run for them.
func (e *Engine) Ingest(lines []haproxylog.Line, now time.Time) []Detection {
	var out []Detection
	touchedIPs := map[string]bool{}
	touchedBackends := map[string]bool{}

	for _, l := range lines {
		if l.Backend != "" {
			e.recordBackend(l, now)
			touchedBackends[l.Backend] = true
		}
		if l.ClientIP == "" || e.allowed(l.ClientIP) {
			continue
		}
		e.recordIP(l, now)
		touchedIPs[l.ClientIP] = true
	}

	for ip := range touchedIPs {
		out = append(out, e.detectIP(ip, now)...)
	}
	for be := range touchedBackends {
		out = append(out, e.detectBackend(be, now)...)
	}

	e.evictIdle(now)
	return out
}

func (e *Engine) recordIP(l haproxylog.Line, now time.Time) {
	w, ok := e.ips[l.ClientIP]
	if !ok {
		w = &ipWindow{firstSeen: now}
		e.ips[l.ClientIP] = w
	}
	w.lastActive = now
	b := w.bucketFor(now)
	b.req++
	if strings.EqualFold(l.Method, "POST") {
		b.post++
	}
	switch {
	case l.StatusCode == 429:
		b.s429++
	case l.StatusCode >= 500:
		b.s5xx++
	case l.StatusCode == 404:
		b.s404++
		b.s4xx++
	case l.StatusCode >= 400:
		b.s4xx++
	}
	if l.Path != "" && len(b.paths) < maxPathsPerBucket {
		b.paths[l.Path] = struct{}{}
	}
	if e.isLoginFailure(l) {
		b.loginFail++
	}
	if pat := e.matchedSensitivePattern(l.Path); pat != "" {
		b.patternsHit[pat] = struct{}{}
	}
	for _, m := range cti.Detect(l.Target) {
		if b.threats == nil {
			b.threats = map[string]int{}
		}
		b.threats[m.ID]++
	}
	if !now.IsZero() {
		cutoff := now.Add(-e.thr.HTTPAbuseBurstWindow)
		kept := b.burst[:0]
		for _, ts := range b.burst {
			if ts.After(cutoff) {
				kept = append(kept, ts)
			}
		}
		b.burst = append(kept, now)
	}
}

func (e *Engine) isLoginFailure(l haproxylog.Line) bool {
	if !strings.EqualFold(l.Method, "POST") {
		return false
	}
	matched := false
	for _, p := range e.thr.LoginPaths {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(strings.ToLower(l.Path), strings.ToLower(strings.TrimSuffix(p, "*"))) {
				matched = true
				break
			}
		} else if strings.EqualFold(l.Path, p) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, s := range e.thr.LoginFailStatuses {
		if l.StatusCode == s {
			return true
		}
	}
	return false
}

func (e *Engine) matchedSensitivePattern(path string) string {
	lower := strings.ToLower(path)
	for _, pat := range e.thr.SensitivePatterns {
		if strings.Contains(lower, strings.ToLower(pat)) {
			return pat
		}
	}
	return ""
}

func (e *Engine) recordBackend(l haproxylog.Line, now time.Time) {
	w, ok := e.backends[l.Backend]
	if !ok {
		w = &backendWindow{}
		e.backends[l.Backend] = w
	}
	w.lastActive = now
	b := w.bucketFor(now)
	b.req++
	if l.StatusCode >= 500 {
		b.s5xx++
	}
	if l.Tc < 0 || l.Tr < 0 || strings.Contains(l.Termination, "Q") {
		b.timeouts++
	}
	if l.Tw >= 0 {
		b.tw = append(b.tw, l.Tw)
	}
}

// detectIP runs every IP-keyed rule for one IP and returns any resulting
// new-or-escalated Detections.
func (e *Engine) detectIP(ip string, now time.Time) []Detection {
	w := e.ips[ip]
	if w == nil {
		return nil
	}
	var out []Detection

	if d, ok := e.checkBruteForce(ip, w, now); ok {
		out = appendIfNew(out, e, d)
	}
	if d, ok := e.checkRateAnomaly(ip, w, now); ok {
		out = appendIfNew(out, e, d)
	}
	if d, ok := e.checkPathScan(ip, w, now); ok {
		out = appendIfNew(out, e, d)
	}
	if d, ok := e.checkSensitiveProbe(ip, w, now); ok {
		out = appendIfNew(out, e, d)
	}
	if d, ok := e.checkHTTPAbuse(ip, w, now); ok {
		out = appendIfNew(out, e, d)
	}
	if d, ok := e.checkRateLimited(ip, w, now); ok {
		out = appendIfNew(out, e, d)
	}
	if d, ok := e.checkThreatIntel(ip, w, now); ok {
		out = appendIfNew(out, e, d)
	}
	return out
}

// checkThreatIntel turns CTI signature hits (see internal/cti) in the window
// into one detection per IP. Severity is the worst matched signature's,
// raised from medium to high once the IP keeps trying.
func (e *Engine) checkThreatIntel(ip string, w *ipWindow, now time.Time) (Detection, bool) {
	hitsByID := map[string]int{}
	total := 0
	for _, b := range w.since(now, e.thr.CTIWindow) {
		for id, n := range b.threats {
			hitsByID[id] += n
			total += n
		}
	}
	if total == 0 {
		return Detection{}, false
	}

	ids := make([]string, 0, len(hitsByID))
	for id := range hitsByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var names, mitre []string
	seenMitre := map[string]bool{}
	worst := cti.Match{}
	for _, id := range ids {
		m, ok := cti.Lookup(id)
		if !ok {
			continue
		}
		names = append(names, m.Name)
		for _, t := range m.MITRE {
			if !seenMitre[t] {
				seenMitre[t] = true
				mitre = append(mitre, t)
			}
		}
		if cti.Rank(m.Severity) > cti.Rank(worst.Severity) {
			worst = m
		}
	}
	if worst.ID == "" {
		return Detection{}, false
	}
	sort.Strings(mitre)

	sev := Severity(worst.Severity)
	if sev == SeverityMedium && e.thr.CTIEscalateHits > 0 && total >= e.thr.CTIEscalateHits {
		sev = SeverityHigh
	}
	return e.newDetection(RuleThreatIntel, sev, SubjectIP, ip, "", w.firstSeen, now, total,
		map[string]any{
			"signatures":         ids,
			"threats":            names,
			"mitre":              mitre,
			"recommended_action": worst.Action,
			"hits":               total,
		}, e.thr.CTIWindow, now), true
}

func (e *Engine) checkBruteForce(ip string, w *ipWindow, now time.Time) (Detection, bool) {
	var fails int
	for _, b := range w.since(now, e.thr.BruteForceWindow) {
		fails += b.loginFail
	}
	if fails < e.thr.BruteForceThreshold {
		return Detection{}, false
	}
	sev := SeverityMedium
	if fails >= e.thr.BruteForceHighThreshold {
		sev = SeverityHigh
	}
	return e.newDetection(RuleBruteForce, sev, SubjectIP, ip, "", w.firstSeen, now, fails,
		map[string]any{"login_failures": fails, "window_seconds": int(e.thr.BruteForceWindow.Seconds())},
		e.thr.BruteForceWindow, now), true
}

func (e *Engine) checkRateAnomaly(ip string, w *ipWindow, now time.Time) (Detection, bool) {
	cur := 0
	if bs := w.since(now, e.thr.RateAnomalyWindow); len(bs) > 0 {
		for _, b := range bs {
			cur += b.req
		}
	}
	warm := now.Sub(w.firstSeen) >= e.thr.RateAnomalyMinHistory
	baseline := w.ewmaRate
	// Update EWMA after evaluating, so this minute's spike is judged against
	// history, not itself.
	defer func() {
		a := e.thr.RateAnomalyEWMAAlpha
		if a <= 0 {
			a = 0.1
		}
		w.ewmaRate = a*float64(cur) + (1-a)*w.ewmaRate
	}()

	floor := e.thr.RateAnomalyFloor
	if warm && baseline > 0 {
		byBaseline := int(float64(baseline) * e.thr.RateAnomalyMultiplier)
		if byBaseline < floor {
			floor = byBaseline
		} else if byBaseline > 0 {
			floor = byBaseline
		}
	}
	if floor <= 0 {
		floor = e.thr.RateAnomalyFloor
	}
	if cur < floor {
		return Detection{}, false
	}
	sev := SeverityMedium
	if cur >= e.thr.RateAnomalyHighFloor {
		sev = SeverityHigh
	}
	return e.newDetection(RuleRateAnomaly, sev, SubjectIP, ip, "", w.firstSeen, now, cur,
		map[string]any{"requests_per_min": cur, "baseline_per_min": baseline}, e.thr.RateAnomalyWindow, now), true
}

func (e *Engine) checkPathScan(ip string, w *ipWindow, now time.Time) (Detection, bool) {
	bs := w.since(now, e.thr.PathScanWindow)
	req, err404 := 0, 0
	unique := map[string]struct{}{}
	for _, b := range bs {
		req += b.req
		err404 += b.s404
		for p := range b.paths {
			unique[p] = struct{}{}
		}
	}
	if req < e.thr.PathScanMinRequests || len(unique) < e.thr.PathScanUniqueThresh {
		return Detection{}, false
	}
	ratio := float64(err404) / float64(req)
	if ratio < e.thr.PathScan404Ratio {
		return Detection{}, false
	}
	sev := SeverityMedium
	if len(unique) >= e.thr.PathScanUniqueHighThresh {
		sev = SeverityHigh
	}
	return e.newDetection(RulePathScan, sev, SubjectIP, ip, "", w.firstSeen, now, len(unique),
		map[string]any{"unique_paths": len(unique), "requests": req, "404_ratio": ratio}, e.thr.PathScanWindow, now), true
}

func (e *Engine) checkSensitiveProbe(ip string, w *ipWindow, now time.Time) (Detection, bool) {
	patterns := map[string]struct{}{}
	hits := 0
	for _, b := range w.since(now, e.thr.SensitiveWindow) {
		hits += len(b.patternsHit)
		for p := range b.patternsHit {
			patterns[p] = struct{}{}
		}
	}
	if hits == 0 {
		return Detection{}, false
	}
	sev := SeverityLow
	if len(patterns) >= e.thr.SensitiveHighDistinct {
		sev = SeverityHigh
	}
	names := make([]string, 0, len(patterns))
	for p := range patterns {
		names = append(names, p)
	}
	return e.newDetection(RuleSensitiveProbe, sev, SubjectIP, ip, "", w.firstSeen, now, hits,
		map[string]any{"patterns": names, "hits": hits}, e.thr.SensitiveWindow, now), true
}

func (e *Engine) checkHTTPAbuse(ip string, w *ipWindow, now time.Time) (Detection, bool) {
	bs := w.since(now, e.thr.HTTPAbuseWindow)
	var req, post, s4xx, s5xx int
	var burst int
	for _, b := range bs {
		req += b.req
		post += b.post
		s4xx += b.s4xx
		s5xx += b.s5xx
		if len(b.burst) > burst {
			burst = len(b.burst)
		}
	}
	fires := false
	reason := ""
	switch {
	case post >= e.thr.HTTPAbusePostPerWindow:
		fires, reason = true, "post_flood"
	case req > 0 && s4xx >= e.thr.HTTPAbuse4xxPerWindow && float64(s4xx)/float64(req) >= e.thr.HTTPAbuse4xxRatio:
		fires, reason = true, "4xx_flood"
	case s5xx >= e.thr.HTTPAbuse5xxPerWindow:
		fires, reason = true, "5xx_flood"
	case burst >= e.thr.HTTPAbuseBurstCount:
		fires, reason = true, "burst"
	}
	if !fires {
		return Detection{}, false
	}
	return e.newDetection(RuleHTTPAbuse, SeverityMedium, SubjectIP, ip, "", w.firstSeen, now, req,
		map[string]any{"reason": reason, "requests": req, "post": post, "4xx": s4xx, "5xx": s5xx, "burst": burst},
		e.thr.HTTPAbuseWindow, now), true
}

func (e *Engine) checkRateLimited(ip string, w *ipWindow, now time.Time) (Detection, bool) {
	var n int
	for _, b := range w.since(now, e.thr.RateLimitedWindow) {
		n += b.s429
	}
	if n < e.thr.RateLimitedThreshold {
		return Detection{}, false
	}
	return e.newDetection(RuleRateLimited, SeverityLow, SubjectIP, ip, "", w.firstSeen, now, n,
		map[string]any{"count_429": n}, e.thr.RateLimitedWindow, now), true
}

func (e *Engine) detectBackend(name string, now time.Time) []Detection {
	w := e.backends[name]
	if w == nil {
		return nil
	}
	shortBs := w.since(now, e.thr.BackendAbuseWindow)
	baseBs := w.since(now, e.thr.BackendAbuseBaselineWindow)

	var req, s5xx, timeouts int
	var twSum, twCount int
	for _, b := range shortBs {
		req += b.req
		s5xx += b.s5xx
		timeouts += b.timeouts
		for _, v := range b.tw {
			twSum += v
			twCount++
		}
	}
	var baseTwSum, baseTwCount int
	for _, b := range baseBs {
		for _, v := range b.tw {
			baseTwSum += v
			baseTwCount++
		}
	}

	fires := false
	reason := ""
	if timeouts >= e.thr.BackendAbuseTimeouts {
		fires, reason = true, "timeouts"
	} else if req > 0 && float64(s5xx)/float64(req) >= e.thr.BackendAbuse5xxRatio {
		fires, reason = true, "5xx_ratio"
	} else if twCount > 0 {
		cur := twSum / twCount
		base := 0
		if baseTwCount > 0 {
			base = baseTwSum / baseTwCount
		}
		floor := e.thr.BackendAbuseQueueFloorMillis
		threshold := floor
		if base > 0 {
			byBase := int(float64(base) * e.thr.BackendAbuseQueueMultiplier)
			if byBase > threshold {
				threshold = byBase
			}
		}
		if cur >= threshold && cur >= floor {
			fires, reason = true, "queue_time"
		}
	}
	if !fires {
		return nil
	}
	d := e.newDetection(RuleBackendAbuse, SeverityHigh, SubjectBackend, name, name, w.lastActive, now, req,
		map[string]any{"reason": reason, "requests": req, "5xx": s5xx, "timeouts": timeouts},
		e.thr.BackendAbuseWindow, now)
	if fp := e.dedupe(d); fp {
		return []Detection{d}
	}
	return nil
}

// newDetection builds a Detection and computes its Fingerprint from the
// rule, subject, and the window bucket (the window duration truncation of
// now) it fired in — so repeated ticks within the same window collapse to
// one logical event, while a later window produces a distinct one.
func (e *Engine) newDetection(rule Rule, sev Severity, st SubjectType, subject, pool string, first, last time.Time, count int, evidence map[string]any, window time.Duration, now time.Time) Detection {
	bucket := now.Truncate(window)
	return Detection{
		Rule:        rule,
		Severity:    sev,
		SubjectType: st,
		Subject:     subject,
		Pool:        pool,
		FirstSeen:   first,
		LastSeen:    last,
		Count:       count,
		Evidence:    evidence,
		Fingerprint: fmt.Sprintf("%s|%s|%d", rule, subject, bucket.Unix()),
	}
}

// appendIfNew applies dedup/escalation and appends d to out only when it
// represents new information (see dedupe).
func appendIfNew(out []Detection, e *Engine, d Detection) []Detection {
	if e.dedupe(d) {
		return append(out, d)
	}
	return out
}

// dedupe reports whether d is worth emitting: either this rule+subject
// hasn't fired in the current window bucket yet, or its severity has
// escalated since the last emission.
func (e *Engine) dedupe(d Detection) bool {
	key := string(d.Rule) + "|" + d.Subject
	bucketUnix := d.LastSeen.Truncate(bucketWindowFor(d)).Unix()
	prev, ok := e.fired[key]
	if ok && prev.bucket == bucketUnix && !severityHigher(d.Severity, prev.severity) {
		return false
	}
	e.fired[key] = firedState{bucket: bucketUnix, severity: d.Severity}
	return true
}

var severityRank = map[Severity]int{SeverityLow: 0, SeverityMedium: 1, SeverityHigh: 2, SeverityCritical: 3}

func severityHigher(a, b Severity) bool { return severityRank[a] > severityRank[b] }

// bucketWindowFor recovers the window duration encoded in a Detection's
// Fingerprint indirectly isn't possible, so dedupe instead just uses the
// Detection's own LastSeen truncated to a minute — coarse, but sufficient
// since detectors are only invoked once per Ingest call for a touched
// subject, and Ingest is expected to run on a multi-second tick.
func bucketWindowFor(d Detection) time.Duration { return time.Minute }

// evictIdle drops per-IP/backend state untouched for longer than
// evictAfter, and if still over maxTrackedIPs, drops the oldest-idle
// remainder.
func (e *Engine) evictIdle(now time.Time) {
	for ip, w := range e.ips {
		if now.Sub(w.lastActive) > evictAfter {
			delete(e.ips, ip)
		}
	}
	if len(e.ips) <= maxTrackedIPs {
		return
	}
	type entry struct {
		ip   string
		last time.Time
	}
	entries := make([]entry, 0, len(e.ips))
	for ip, w := range e.ips {
		entries = append(entries, entry{ip, w.lastActive})
	}
	// Simple partial sort: repeatedly find and drop the oldest until under
	// the cap. maxTrackedIPs is large enough that this only runs rarely.
	for len(e.ips) > maxTrackedIPs {
		oldestIdx := 0
		for i, en := range entries {
			if en.last.Before(entries[oldestIdx].last) {
				oldestIdx = i
			}
		}
		delete(e.ips, entries[oldestIdx].ip)
		entries = append(entries[:oldestIdx], entries[oldestIdx+1:]...)
	}
}
