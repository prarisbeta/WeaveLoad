// Package security detects abusive traffic patterns (brute force, path
// scanning, sensitive-file probing, backend abuse, and similar) from the
// HAProxy access log and maintains a per-IP risk score. It only observes:
// it never blocks or modifies traffic itself.
package security

import "time"

// Rule identifies which detector produced a Detection.
type Rule string

const (
	RuleBruteForce     Rule = "brute_force"
	RuleRateAnomaly    Rule = "rate_anomaly"
	RulePathScan       Rule = "path_scan"
	RuleSensitiveProbe Rule = "sensitive_probe"
	RuleHTTPAbuse      Rule = "http_abuse"
	RuleBackendAbuse   Rule = "backend_abuse"
	RuleRateLimited    Rule = "rate_limited"
)

// Severity ranks how serious a Detection is. Higher severities contribute
// more weight to a subject's risk score (see Score in risk.go).
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityWeight is the base contribution of one Detection at a given
// severity to a subject's risk score, before rule multiplier and time
// decay are applied.
var severityWeight = map[Severity]float64{
	SeverityLow:      5,
	SeverityMedium:   15,
	SeverityHigh:     30,
	SeverityCritical: 50,
}

// SubjectType distinguishes what a Detection is about.
type SubjectType string

const (
	SubjectIP      SubjectType = "ip"
	SubjectBackend SubjectType = "backend"
)

// RiskState buckets a computed risk Score into a human-meaningful state.
// BLOCKED is never assigned by Score — it is a manual or policy-engine
// override recorded separately, per the product's "observe only, no
// auto-block" rule for this stage.
type RiskState string

const (
	RiskNormal     RiskState = "normal"
	RiskWatch      RiskState = "watch"
	RiskSuspicious RiskState = "suspicious"
	RiskHigh       RiskState = "high_risk"
	RiskBlocked    RiskState = "blocked"
)

// Detection is one occurrence (or escalation) of a rule firing for a
// subject within a time window. Repeated firings within the same window
// update an existing Detection (see Engine.Ingest) rather than creating a
// new one, keyed by Fingerprint.
type Detection struct {
	Rule        Rule
	Severity    Severity
	SubjectType SubjectType
	Subject     string // an IP address, or a backend name
	Pool        string // the backend/pool name, when known, even for SubjectIP
	FirstSeen   time.Time
	LastSeen    time.Time
	Count       int
	Evidence    map[string]any
	SampleLines []string // up to a handful of raw log lines, for triage
	Fingerprint string
}

// IncidentSeed is the subset of a Detection an Incident Management module
// would use to open or extend an incident. Defining this now, even though
// no such module exists yet, keeps the eventual integration additive: it
// only needs to add an incidents table and start calling Seed.
type IncidentSeed struct {
	Rule      Rule
	Severity  Severity
	Subject   string
	Pool      string
	FirstSeen time.Time
	LastSeen  time.Time
	Evidence  map[string]any
}

// Seed extracts the IncidentSeed for a Detection.
func (d Detection) Seed() IncidentSeed {
	return IncidentSeed{
		Rule:      d.Rule,
		Severity:  d.Severity,
		Subject:   d.Subject,
		Pool:      d.Pool,
		FirstSeen: d.FirstSeen,
		LastSeen:  d.LastSeen,
		Evidence:  d.Evidence,
	}
}
