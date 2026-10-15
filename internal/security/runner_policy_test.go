package security

import (
	"testing"

	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/store"
)

type captureSubmitter struct{ got []policy.Action }

func (c *captureSubmitter) Submit(a policy.Action) (store.PolicyAction, policy.Decision, error) {
	c.got = append(c.got, a)
	return store.PolicyAction{}, policy.Decision{Allowed: true}, nil
}

func TestProposeBlocks_OnlyCriticalThreatIntelWithHighScore(t *testing.T) {
	sub := &captureSubmitter{}
	r := &Runner{Policy: sub}
	dets := []Detection{
		{Rule: RuleThreatIntel, Severity: SeverityCritical, SubjectType: SubjectIP, Subject: "9.9.9.1", Count: 2, Evidence: map[string]any{"mitre": []string{"T1190"}}},
		{Rule: RuleThreatIntel, Severity: SeverityHigh, SubjectType: SubjectIP, Subject: "9.9.9.2"},         // not critical
		{Rule: RuleBruteForce, Severity: SeverityCritical, SubjectType: SubjectIP, Subject: "9.9.9.3"},      // wrong rule
		{Rule: RuleThreatIntel, Severity: SeverityCritical, SubjectType: SubjectIP, Subject: "9.9.9.4"},     // score too low
		{Rule: RuleThreatIntel, Severity: SeverityCritical, SubjectType: SubjectBackend, Subject: "be_one"}, // not an IP
	}
	r.proposeBlocks(dets, map[string]float64{"9.9.9.1": 75, "9.9.9.2": 90, "9.9.9.3": 90, "9.9.9.4": 20})

	if len(sub.got) != 1 {
		t.Fatalf("submitted %d actions, want exactly the first detection: %+v", len(sub.got), sub.got)
	}
	a := sub.got[0]
	if a.Type != policy.BlockIP || a.Target != "9.9.9.1" || a.Source != "auto:threat_intel" || a.Evidence == "" {
		t.Errorf("action = %+v", a)
	}
	if a.MaxMode != "" {
		t.Errorf("detector-sourced actions may run automatically when policy allows, MaxMode = %q", a.MaxMode)
	}
}

func TestProposeBlocks_NilPolicyIsNoOp(t *testing.T) {
	r := &Runner{}
	r.proposeBlocks([]Detection{{Rule: RuleThreatIntel, Severity: SeverityCritical, SubjectType: SubjectIP, Subject: "9.9.9.1"}}, map[string]float64{"9.9.9.1": 99})
}
