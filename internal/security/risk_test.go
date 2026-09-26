package security

import (
	"testing"
	"time"
)

func TestScore_NoDetectionsIsZero(t *testing.T) {
	if s := Score(nil, time.Now()); s != 0 {
		t.Errorf("Score(nil) = %v, want 0", s)
	}
}

func TestScore_DecaysWithAge(t *testing.T) {
	now := time.Now()
	fresh := Score([]Detection{{Rule: RuleRateAnomaly, Severity: SeverityMedium, LastSeen: now}}, now)
	old := Score([]Detection{{Rule: RuleRateAnomaly, Severity: SeverityMedium, LastSeen: now.Add(-24 * time.Hour)}}, now)
	if !(fresh > old) {
		t.Errorf("fresh score %v should exceed decayed old score %v", fresh, old)
	}
}

func TestScore_CapsAt100(t *testing.T) {
	now := time.Now()
	var dets []Detection
	for i := 0; i < 20; i++ {
		dets = append(dets, Detection{Rule: RuleSensitiveProbe, Severity: SeverityCritical, LastSeen: now})
	}
	if s := Score(dets, now); s != 100 {
		t.Errorf("Score = %v, want capped at 100", s)
	}
}

func TestScore_DiversityBonusForMultipleDistinctRules(t *testing.T) {
	now := time.Now()
	single := Score([]Detection{
		{Rule: RuleRateAnomaly, Severity: SeverityLow, LastSeen: now},
		{Rule: RuleRateAnomaly, Severity: SeverityLow, LastSeen: now},
		{Rule: RuleRateAnomaly, Severity: SeverityLow, LastSeen: now},
	}, now)
	diverse := Score([]Detection{
		{Rule: RuleRateAnomaly, Severity: SeverityLow, LastSeen: now},
		{Rule: RuleBruteForce, Severity: SeverityLow, LastSeen: now},
		{Rule: RulePathScan, Severity: SeverityLow, LastSeen: now},
	}, now)
	if !(diverse > single) {
		t.Errorf("diverse score %v should exceed single-rule score %v", diverse, single)
	}
}

func TestState_Buckets(t *testing.T) {
	cases := []struct {
		score float64
		want  RiskState
	}{
		{0, RiskNormal},
		{14.9, RiskNormal},
		{15, RiskWatch},
		{34.9, RiskWatch},
		{35, RiskSuspicious},
		{59.9, RiskSuspicious},
		{60, RiskHigh},
		{100, RiskHigh},
	}
	for _, c := range cases {
		if got := State(c.score); got != c.want {
			t.Errorf("State(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestState_NeverReturnsBlocked(t *testing.T) {
	if got := State(1000); got == RiskBlocked {
		t.Error("State should never compute RiskBlocked — it's a manual/policy override")
	}
}
