package store

import (
	"testing"
	"time"
)

func TestPruneStaleSecurityEvents_KeepsRecentAndIncidentLinked(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	old := now.Add(-100 * 24 * time.Hour)

	mk := func(fp string, last time.Time) int64 {
		id, _, err := s.UpsertSecurityEvent(SecurityEvent{
			Fingerprint: fp, Rule: "rate_anomaly", Severity: "low", SubjectType: "ip", Subject: "1.2.3.4",
			FirstSeen: last, LastSeen: last, Count: 1,
		})
		if err != nil {
			t.Fatalf("upsert %s: %v", fp, err)
		}
		return id
	}
	staleID := mk("stale", old)
	linkedID := mk("linked", old)
	recentID := mk("recent", now)
	if _, err := s.db.Exec(`UPDATE security_events SET incident_id = 7 WHERE id = ?`, linkedID); err != nil {
		t.Fatal(err)
	}

	n, err := s.PruneStaleSecurityEvents(now.Add(-90 * 24 * time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, err %v; want exactly the stale event", n, err)
	}
	if _, err := s.GetSecurityEvent(staleID); err == nil {
		t.Error("stale event survived")
	}
	for name, id := range map[string]int64{"incident-linked": linkedID, "recent": recentID} {
		if _, err := s.GetSecurityEvent(id); err != nil {
			t.Errorf("%s event was pruned: %v", name, err)
		}
	}
}

func TestPruneIPRisk_KeepsOverridesAndRecent(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	old := now.Add(-100 * 24 * time.Hour)

	for _, r := range []IPRisk{
		{IP: "1.1.1.1", State: "watch", FirstSeen: old, LastSeen: old},
		{IP: "2.2.2.2", State: "watch", FirstSeen: old, LastSeen: old, StateOverride: "blocked", OverrideBy: "a@b", OverrideReason: "abuse"},
		{IP: "3.3.3.3", State: "watch", FirstSeen: now, LastSeen: now},
	} {
		if err := s.UpsertIPRisk(r); err != nil {
			t.Fatalf("upsert %s: %v", r.IP, err)
		}
	}
	n, err := s.PruneIPRisk(now.Add(-90 * 24 * time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, err %v; want only 1.1.1.1", n, err)
	}
	if _, err := s.GetIPRisk("1.1.1.1"); err == nil {
		t.Error("stale profile survived")
	}
	for _, ip := range []string{"2.2.2.2", "3.3.3.3"} {
		if _, err := s.GetIPRisk(ip); err != nil {
			t.Errorf("%s was pruned: %v", ip, err)
		}
	}
}

func TestPruneAlerts_NeverTouchesActive(t *testing.T) {
	s := openTestStore(t)
	oldTS := time.Now().Add(-100 * 24 * time.Hour).UTC().Format(alertTimeLayout)

	for _, status := range []string{"active", "acked", "resolved"} {
		if _, err := s.db.Exec(
			`INSERT INTO alerts (rule, severity, subject, message, status, created_at) VALUES ('r','low','s','m',?,?)`,
			status, oldTS); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.PruneAlerts(time.Now().Add(-90 * 24 * time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("pruned %d, err %v; want the acked and resolved alerts", n, err)
	}
	var left int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE status = 'active'`).Scan(&left); err != nil || left != 1 {
		t.Errorf("active alerts left = %d (err %v), want 1", left, err)
	}
}
