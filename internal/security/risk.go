package security

import (
	"math"
	"time"
)

// ruleMultiplier weights how much a rule's Detections contribute to risk
// relative to a plain severity weight — a scanner probing sensitive paths
// is worse than the same severity of generic rate anomaly.
var ruleMultiplier = map[Rule]float64{
	RuleThreatIntel:    1.5,
	RuleKnownBadIP:     1.2,
	RuleSensitiveProbe: 1.5,
	RuleBruteForce:     1.3,
	RulePathScan:       1.2,
	RuleHTTPAbuse:      1.0,
	RuleBackendAbuse:   1.0,
	RuleRateAnomaly:    0.8,
	RuleRateLimited:    0.5,
}

// riskHalfLife is how quickly a past Detection's contribution to Score
// decays: after this long, it counts for half as much.
const riskHalfLife = 2 * time.Hour

// diversityBonus rewards (penalizes, from the subject's perspective) an IP
// that trips several different rules within one hour — a broader attack
// pattern is worse than the same total count concentrated in one rule.
const diversityBonus = 10
const diversityWindow = time.Hour
const diversityMinRules = 3

// Score computes a subject's 0-100 risk score from its recent Detections
// (typically the last 24h, but Score itself doesn't filter by age beyond
// what decay already does — callers should still avoid handing it
// arbitrarily old history).
func Score(detections []Detection, now time.Time) float64 {
	var total float64
	rulesSeen := map[Rule]bool{}
	recentRules := map[Rule]bool{}

	for _, d := range detections {
		age := now.Sub(d.LastSeen)
		if age < 0 {
			age = 0
		}
		decay := math.Pow(0.5, age.Hours()/riskHalfLife.Hours())
		mult := ruleMultiplier[d.Rule]
		if mult == 0 {
			mult = 1
		}
		total += severityWeight[d.Severity] * mult * decay
		rulesSeen[d.Rule] = true
		if age <= diversityWindow {
			recentRules[d.Rule] = true
		}
	}
	if len(recentRules) >= diversityMinRules {
		total += diversityBonus
	}
	if total > 100 {
		total = 100
	}
	if total < 0 {
		total = 0
	}
	return total
}

// State buckets a Score into a RiskState. BLOCKED is deliberately
// unreachable here — see the RiskBlocked doc comment.
func State(score float64) RiskState {
	switch {
	case score >= 60:
		return RiskHigh
	case score >= 35:
		return RiskSuspicious
	case score >= 15:
		return RiskWatch
	default:
		return RiskNormal
	}
}
