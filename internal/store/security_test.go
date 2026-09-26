package store

import (
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestUpsertSecurityEvent_CreatesThenMergesOnSameFingerprint(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	ev := SecurityEvent{
		Fingerprint: "brute_force|1.2.3.4|100",
		Rule:        "brute_force", Severity: "medium", SubjectType: "ip", Subject: "1.2.3.4",
		FirstSeen: now, LastSeen: now, Count: 10, Evidence: map[string]any{"login_failures": 10},
	}
	id1, created1, err := s.UpsertSecurityEvent(ev)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !created1 {
		t.Error("expected first upsert to create a new row")
	}

	ev.Count = 15
	ev.Severity = "high"
	ev.LastSeen = now.Add(time.Minute)
	id2, created2, err := s.UpsertSecurityEvent(ev)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if created2 {
		t.Error("expected second upsert with same fingerprint to merge, not create")
	}
	if id1 != id2 {
		t.Errorf("ids differ: %d vs %d, want the same row", id1, id2)
	}

	got, err := s.GetSecurityEvent(id1)
	if err != nil {
		t.Fatalf("GetSecurityEvent: %v", err)
	}
	if got.Count != 15 || got.Severity != "high" {
		t.Errorf("got Count=%d Severity=%q, want 15/high after merge", got.Count, got.Severity)
	}
	if got.Evidence["login_failures"] != float64(10) {
		// merge in this test didn't change evidence's login_failures key
	}
}

func TestListSecurityEvents_FiltersAndOrdersNewestFirst(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	mk := func(fp, rule, subject string, age time.Duration) SecurityEvent {
		return SecurityEvent{
			Fingerprint: fp, Rule: rule, Severity: "low", SubjectType: "ip", Subject: subject,
			FirstSeen: now.Add(-age), LastSeen: now.Add(-age), Count: 1, Evidence: map[string]any{},
		}
	}
	if _, _, err := s.UpsertSecurityEvent(mk("a", "path_scan", "1.1.1.1", 2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertSecurityEvent(mk("b", "brute_force", "2.2.2.2", time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertSecurityEvent(mk("c", "brute_force", "3.3.3.3", 0)); err != nil {
		t.Fatal(err)
	}

	all, total, err := s.ListSecurityEvents(SecurityFilter{})
	if err != nil {
		t.Fatalf("ListSecurityEvents: %v", err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("total=%d len=%d, want 3", total, len(all))
	}
	if all[0].Fingerprint != "c" || all[2].Fingerprint != "a" {
		t.Errorf("order = %v, want newest (c) first, oldest (a) last", []string{all[0].Fingerprint, all[1].Fingerprint, all[2].Fingerprint})
	}

	bf, total, err := s.ListSecurityEvents(SecurityFilter{Rule: "brute_force"})
	if err != nil {
		t.Fatalf("ListSecurityEvents filtered: %v", err)
	}
	if total != 2 || len(bf) != 2 {
		t.Fatalf("filtered total=%d len=%d, want 2", total, len(bf))
	}
}

func TestSetSecurityEventStatus_UpdatesStatusAndAck(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	id, _, err := s.UpsertSecurityEvent(SecurityEvent{
		Fingerprint: "x", Rule: "path_scan", Severity: "medium", SubjectType: "ip", Subject: "9.9.9.9",
		FirstSeen: now, LastSeen: now, Count: 1, Evidence: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecurityEventStatus(id, "acknowledged", "admin@x.id"); err != nil {
		t.Fatalf("SetSecurityEventStatus: %v", err)
	}
	got, err := s.GetSecurityEvent(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "acknowledged" || got.AckedBy != "admin@x.id" || got.AckedAt == nil {
		t.Errorf("got %+v, want acknowledged by admin@x.id with AckedAt set", got)
	}
}

func TestSetSecurityEventStatus_UnknownID_ErrNotFound(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetSecurityEventStatus(9999, "dismissed", "a@x.id"); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestUpsertIPRisk_RoundTrips(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	r := IPRisk{IP: "5.5.5.5", Score: 42.5, State: "suspicious", FirstSeen: now, LastSeen: now, Detections24h: 3}
	if err := s.UpsertIPRisk(r); err != nil {
		t.Fatalf("UpsertIPRisk: %v", err)
	}
	got, err := s.GetIPRisk("5.5.5.5")
	if err != nil {
		t.Fatalf("GetIPRisk: %v", err)
	}
	if got.Score != 42.5 || got.State != "suspicious" || got.Detections24h != 3 {
		t.Errorf("got %+v", got)
	}

	r.Score = 80
	r.State = "high_risk"
	if err := s.UpsertIPRisk(r); err != nil {
		t.Fatalf("second UpsertIPRisk: %v", err)
	}
	got, _ = s.GetIPRisk("5.5.5.5")
	if got.Score != 80 || got.State != "high_risk" {
		t.Errorf("got %+v after update, want score 80/high_risk", got)
	}
}

func TestGetIPRisk_UnknownIP_ErrNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.GetIPRisk("1.2.3.4"); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestListTopRisk_OrdersByScoreDescending(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	for ip, score := range map[string]float64{"1.1.1.1": 10, "2.2.2.2": 90, "3.3.3.3": 50} {
		if err := s.UpsertIPRisk(IPRisk{IP: ip, Score: score, State: "watch", FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	top, err := s.ListTopRisk(2)
	if err != nil {
		t.Fatalf("ListTopRisk: %v", err)
	}
	if len(top) != 2 || top[0].IP != "2.2.2.2" || top[1].IP != "3.3.3.3" {
		t.Fatalf("top = %+v, want [2.2.2.2 (90), 3.3.3.3 (50)]", top)
	}
}

func TestPruneSecurityEvents_OnlyRemovesOldDismissedEvents(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	oldDismissed, _, _ := s.UpsertSecurityEvent(SecurityEvent{
		Fingerprint: "old-dismissed", Rule: "path_scan", Severity: "low", SubjectType: "ip", Subject: "1.1.1.1",
		FirstSeen: now.Add(-48 * time.Hour), LastSeen: now.Add(-48 * time.Hour), Count: 1, Evidence: map[string]any{},
	})
	s.SetSecurityEventStatus(oldDismissed, "dismissed", "a@x.id")

	oldOpen, _, _ := s.UpsertSecurityEvent(SecurityEvent{
		Fingerprint: "old-open", Rule: "path_scan", Severity: "low", SubjectType: "ip", Subject: "2.2.2.2",
		FirstSeen: now.Add(-48 * time.Hour), LastSeen: now.Add(-48 * time.Hour), Count: 1, Evidence: map[string]any{},
	})

	n, err := s.PruneSecurityEvents(now.Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("PruneSecurityEvents: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1", n)
	}
	if _, err := s.GetSecurityEvent(oldDismissed); err != ErrNotFound {
		t.Error("expected the old dismissed event to be pruned")
	}
	if _, err := s.GetSecurityEvent(oldOpen); err != nil {
		t.Errorf("expected the old but still-open event to survive pruning, got err=%v", err)
	}
}
