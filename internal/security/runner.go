package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"haproxy-gui/internal/anomaly"
	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/redisping"
	"haproxy-gui/internal/store"
	"haproxy-gui/internal/threatintel"
)

// Store is the persistence the Runner needs — satisfied by *store.Store,
// narrowed here so the runner can be tested against a fake.
type Store interface {
	UpsertSecurityEvent(store.SecurityEvent) (id int64, created bool, err error)
	UpsertIPRisk(store.IPRisk) error
	GetIPRisk(ip string) (store.IPRisk, error)
	ListSecurityEvents(store.SecurityFilter) ([]store.SecurityEvent, int, error)
}

// maxLinesPerTick caps how many new log lines one Tick processes, so a
// sudden backlog (the process was down a while, or the log grew very fast)
// doesn't block a tick indefinitely. Any remainder is picked up on the next
// tick, since the Tailer's offset only advances past what was consumed.
const maxLinesPerTick = 50000

// Runner drives the Engine from a live access log on a periodic Tick,
// persisting detections and risk scores and optionally publishing a
// snapshot to Redis for other systems to read.
type Runner struct {
	Store  Store
	Engine *Engine
	Tailer *haproxylog.Tailer

	// RedisOpts, when non-nil, returns the options to use for publishing
	// the security:{ip} snapshot, and whether Redis is configured at all.
	// A nil RedisOpts (or a false second return) disables publishing —
	// the engine and persistence work the same either way.
	RedisOpts func() (redisping.Options, bool)

	// Policy, when set, receives block requests for critical threat-intel
	// detections. The detector only observes; whether anything happens is the
	// Policy Engine's decision.
	Policy Submitter

	// Anomaly, when set, learns each backend's normal traffic per hour of the
	// week and records deviations.
	Anomaly *anomaly.Tracker

	// Intel, when set, enriches every IP that trips a detector with feed
	// and reputation data; a listed IP also gets a known_bad_ip detection.
	Intel IntelLookup

	// Now defaults to time.Now; overridable for tests.
	Now func() time.Time
}

// Submitter is the slice of *policy.Engine the Runner uses.
type Submitter interface {
	Submit(policy.Action) (store.PolicyAction, policy.Decision, error)
}

// Tick reads whatever new log lines are available, runs them through the
// Engine, persists any resulting Detections and updated risk scores, and —
// if Redis is configured — publishes a snapshot for at-risk IPs. It's
// best-effort: a Redis publish failure is logged, not returned, so a
// flaky Redis never stops detection or persistence.
func (r *Runner) Tick() error {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	t := now()

	lines, err := r.Tailer.ReadNew()
	if err != nil {
		return fmt.Errorf("read new log lines: %w", err)
	}
	if len(lines) > maxLinesPerTick {
		log.Printf("security: %d new log lines this tick, processing only the first %d; remainder follows next tick", len(lines), maxLinesPerTick)
		lines = lines[:maxLinesPerTick]
	}
	// Even with no new lines the tracker must run: a quiet period is exactly
	// when the previous 5-minute bucket closes and a traffic collapse shows.
	r.runAnomaly(lines, t)
	if len(lines) == 0 {
		return nil
	}

	detections := r.Engine.Ingest(lines, t)
	touchedIPs := map[string]bool{}
	for _, d := range detections {
		if _, _, err := r.Store.UpsertSecurityEvent(toStoreEvent(d)); err != nil {
			log.Printf("security: persist detection %s for %s: %v", d.Rule, d.Subject, err)
			continue
		}
		if d.SubjectType == SubjectIP {
			touchedIPs[d.Subject] = true
		}
	}

	scores := map[string]float64{}
	for ip := range touchedIPs {
		r.checkIntel(ip, t, false)
		scores[ip] = r.updateRisk(ip, t)
		// The live reputation lookup spends a rate-limited API quota, so it
		// is reserved for IPs the local detectors already distrust.
		if scores[ip] >= liveLookupScore && r.checkIntel(ip, t, true) {
			scores[ip] = r.updateRisk(ip, t)
		}
	}
	r.proposeBlocks(detections, scores)
	return nil
}

// runAnomaly feeds the seasonal-baseline tracker and records what it finds as
// traffic_anomaly events on the affected backend.
func (r *Runner) runAnomaly(lines []haproxylog.Line, now time.Time) {
	if r.Anomaly == nil {
		return
	}
	for _, a := range r.Anomaly.Ingest(lines, now) {
		sev := SeverityMedium
		if a.Severity == "high" {
			sev = SeverityHigh
		}
		d := Detection{
			Rule: RuleTrafficAnomaly, Severity: sev, SubjectType: SubjectBackend, Subject: a.Backend, Pool: a.Backend,
			FirstSeen: a.Bucket, LastSeen: a.Bucket.Add(anomaly.BucketSize), Count: int(a.Observed),
			Fingerprint: a.Fingerprint(),
			Evidence: map[string]any{
				"metric": string(a.Metric), "direction": a.Direction,
				"observed": a.Observed, "expected": a.Expected, "z_score": a.Z,
			},
		}
		if _, _, err := r.Store.UpsertSecurityEvent(toStoreEvent(d)); err != nil {
			log.Printf("security: persist traffic anomaly for %s: %v", a.Backend, err)
		}
	}
}

// IntelLookup is the slice of *threatintel.Service the Runner uses.
type IntelLookup interface {
	Lookup(ctx context.Context, ip string, live bool) threatintel.Result
}

const (
	// liveLookupScore is the risk score at which an IP is worth a live
	// reputation lookup.
	liveLookupScore = 35
	// abuseDetectionScore is the AbuseIPDB confidence at which an IP counts
	// as a known-bad source.
	abuseDetectionScore = 75
)

// checkIntel looks ip up in the threat-intelligence feeds (or, when live,
// at AbuseIPDB) and records a known_bad_ip detection if it is listed. It
// reports whether it recorded one.
func (r *Runner) checkIntel(ip string, now time.Time, live bool) bool {
	if r.Intel == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res := r.Intel.Lookup(ctx, ip, live)

	evidence := map[string]any{}
	switch {
	case res.Listed():
		evidence["feeds"] = res.Feeds
	case res.AbuseScore >= abuseDetectionScore:
		evidence["abuse_confidence"], evidence["reports"] = res.AbuseScore, res.Reports
	default:
		return false
	}
	if res.Country != "" {
		evidence["country"] = res.Country
	}
	if res.ISP != "" {
		evidence["isp"] = res.ISP
	}
	d := Detection{
		Rule: RuleKnownBadIP, Severity: SeverityHigh, SubjectType: SubjectIP, Subject: ip,
		FirstSeen: now, LastSeen: now, Count: 1, Evidence: evidence,
		Fingerprint: fmt.Sprintf("%s|%s|%s", RuleKnownBadIP, ip, now.UTC().Format("20060102")),
	}
	if _, _, err := r.Store.UpsertSecurityEvent(toStoreEvent(d)); err != nil {
		log.Printf("security: persist known_bad_ip for %s: %v", ip, err)
		return false
	}
	return true
}

// autoBlockScore is the risk score an IP must reach before a critical CTI
// detection asks the Policy Engine to block it.
const autoBlockScore = 60

// proposeBlocks hands critical threat-intel detections to the Policy Engine.
// The engine, not this code, decides whether that means nothing (off),
// a logged "would block" (shadow), a queued proposal or an automatic block.
func (r *Runner) proposeBlocks(detections []Detection, scores map[string]float64) {
	if r.Policy == nil {
		return
	}
	for _, d := range detections {
		if d.Rule != RuleThreatIntel || d.Severity != SeverityCritical || d.SubjectType != SubjectIP {
			continue
		}
		if scores[d.Subject] < autoBlockScore {
			continue
		}
		evidence, _ := json.Marshal(d.Evidence)
		_, _, err := r.Policy.Submit(policy.Action{
			Type:       policy.BlockIP,
			Target:     d.Subject,
			Reason:     fmt.Sprintf("critical threat-intel detection (%d hits)", d.Count),
			Evidence:   string(evidence),
			Source:     "auto:threat_intel",
			Confidence: 0.9,
		})
		if err != nil {
			log.Printf("security: submit block for %s: %v", d.Subject, err)
		}
	}
}

// updateRisk recomputes and stores ip's risk score and returns it (0 when the
// score could not be computed).
func (r *Runner) updateRisk(ip string, now time.Time) (score float64) {
	events, _, err := r.Store.ListSecurityEvents(store.SecurityFilter{
		Subject: ip,
		Since:   now.Add(-24 * time.Hour),
		Limit:   500,
	})
	if err != nil {
		log.Printf("security: list events for risk scoring %s: %v", ip, err)
		return
	}
	dets := make([]Detection, 0, len(events))
	for _, e := range events {
		dets = append(dets, Detection{Rule: Rule(e.Rule), Severity: Severity(e.Severity), LastSeen: e.LastSeen})
	}
	score = Score(dets, now)
	state := State(score)

	firstSeen := now
	if existing, err := r.Store.GetIPRisk(ip); err == nil {
		firstSeen = existing.FirstSeen
	}
	risk := store.IPRisk{
		IP: ip, Score: score, State: string(state),
		FirstSeen: firstSeen, LastSeen: now, Detections24h: len(dets),
	}
	if err := r.Store.UpsertIPRisk(risk); err != nil {
		log.Printf("security: persist risk for %s: %v", ip, err)
		return
	}

	if r.RedisOpts == nil {
		return
	}
	opts, ok := r.RedisOpts()
	if !ok {
		return
	}
	if state == RiskNormal {
		return // only publish for IPs worth another system's attention
	}
	payload, err := json.Marshal(map[string]any{
		"score": score, "state": state, "last_seen": now.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return
	}
	if err := redisping.Set(opts, "security:"+ip, string(payload), 24*time.Hour); err != nil {
		log.Printf("security: publish risk snapshot for %s: %v", ip, err)
	}
	return score
}

func toStoreEvent(d Detection) store.SecurityEvent {
	return store.SecurityEvent{
		Fingerprint: d.Fingerprint,
		Rule:        string(d.Rule),
		Severity:    string(d.Severity),
		SubjectType: string(d.SubjectType),
		Subject:     d.Subject,
		Pool:        d.Pool,
		FirstSeen:   d.FirstSeen,
		LastSeen:    d.LastSeen,
		Count:       d.Count,
		Evidence:    d.Evidence,
	}
}
