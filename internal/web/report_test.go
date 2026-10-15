package web

import (
	"testing"
	"time"

	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/store"
)

func TestBuildWeeklyReport(t *testing.T) {
	e, s, _ := policyHarness(t, policy.ModePropose)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

	add := func(fp, rule, sev string, at time.Time, ev map[string]any) {
		t.Helper()
		if _, _, err := s.UpsertSecurityEvent(store.SecurityEvent{
			Fingerprint: fp, Rule: rule, Severity: sev, SubjectType: "ip", Subject: "9.9.9.9",
			FirstSeen: at, LastSeen: at, Count: 1, Evidence: ev,
		}); err != nil {
			t.Fatal(err)
		}
	}
	add("1", "threat_intel", "critical", now.Add(-time.Hour), map[string]any{"mitre": []string{"T1190", "T1059"}})
	add("2", "threat_intel", "high", now.Add(-2*time.Hour), map[string]any{"mitre": []string{"T1190"}})
	add("3", "brute_force", "medium", now.Add(-24*time.Hour), nil)
	add("old", "brute_force", "medium", now.AddDate(0, 0, -30), nil) // outside the window

	if _, err := s.CreateIncident(store.Incident{Title: "a", Severity: "high"}, nil); err != nil {
		t.Fatal(err)
	}
	_, _, _ = e.Submit(policy.Action{Type: policy.BlockIP, Target: "9.9.9.9"})
	_ = s.UpsertIPRisk(store.IPRisk{IP: "9.9.9.9", Score: 90, State: "high_risk", FirstSeen: now, LastSeen: now})

	rep, err := BuildWeeklyReport(s, now)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Events != 3 {
		t.Errorf("events = %d, want 3 (the 30-day-old one is outside the window)", rep.Events)
	}
	if len(rep.ByRule) != 2 || rep.ByRule[0].Label != "threat_intel" || rep.ByRule[0].Count != 2 {
		t.Errorf("by rule = %+v", rep.ByRule)
	}
	if len(rep.MITRE) != 2 || rep.MITRE[0].Label != "T1190" || rep.MITRE[0].Count != 2 {
		t.Errorf("mitre = %+v", rep.MITRE)
	}
	if rep.PolicyTotal != 0 && rep.PolicyByState[0].Label != "pending" {
		t.Errorf("policy = %+v", rep.PolicyByState)
	}
	if len(rep.TopIPs) != 1 || rep.StillOpen != 1 {
		t.Errorf("top=%+v stillOpen=%d", rep.TopIPs, rep.StillOpen)
	}
}

func TestRankedIsDeterministic(t *testing.T) {
	got := ranked(map[string]int{"b": 2, "a": 2, "c": 5})
	if got[0].Label != "c" || got[1].Label != "a" || got[2].Label != "b" {
		t.Errorf("ranked = %+v", got)
	}
}
