package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/store"
)

type fakeStatSource struct{ csv string }

func (f fakeStatSource) ShowStat() (string, error) { return f.csv, nil }

func TestMetrics_ExposesGaugesInPrometheusFormat(t *testing.T) {
	e, s, _ := policyHarness(t, policy.ModePropose)
	now := time.Now()
	for i, sev := range []string{"high", "high", "critical"} {
		if _, _, err := s.UpsertSecurityEvent(store.SecurityEvent{
			Fingerprint: string(rune('a' + i)), Rule: "threat_intel", Severity: sev, SubjectType: "ip", Subject: "9.9.9.9",
			FirstSeen: now, LastSeen: now, Count: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.UpsertIPRisk(store.IPRisk{IP: "9.9.9.9", Score: 80, State: "high_risk", FirstSeen: now, LastSeen: now})
	_, _, _ = e.Submit(policy.Action{Type: policy.BlockIP, Target: "9.9.9.9"})

	h := &MetricsHandler{Store: s, Engine: e}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("content type = %q", ct)
	}
	for _, want := range []string{
		"# TYPE konsolgw_security_events_open gauge",
		`konsolgw_security_events_open{severity="high"} 2`,
		`konsolgw_security_events_open{severity="critical"} 1`,
		"konsolgw_ips_high_risk 1",
		"konsolgw_incidents_open 0",
		`konsolgw_policy_actions{status="pending"} 1`,
		"konsolgw_policy_kill_switch 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "konsolgw_haproxy_up") {
		t.Error("haproxy gauges appeared without a stats source")
	}
}

func TestMetrics_HAProxyDownIsReportedNotHidden(t *testing.T) {
	_, s, _ := policyHarness(t, policy.ModePropose)
	h := &MetricsHandler{Store: s, Stats: fakeStatSource{csv: "garbage"}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "konsolgw_haproxy_up 0") {
		t.Errorf("body = %s", rec.Body)
	}
}
