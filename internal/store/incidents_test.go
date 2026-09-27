package store

import (
	"testing"
	"time"
)

func TestIncidentManagement_CRUD(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open mem db: %v", err)
	}
	defer s.Close()

	// Seed two security events
	now := time.Now().UTC()
	ev1ID, _, err := s.UpsertSecurityEvent(SecurityEvent{
		Fingerprint: "fp1",
		Rule:        "brute_force",
		Severity:    "high",
		SubjectType: "ip",
		Subject:     "192.168.1.50",
		Pool:        "backend_auth",
		FirstSeen:   now,
		LastSeen:    now,
		Count:       15,
		Evidence:    map[string]any{"failures": 15},
	})
	if err != nil {
		t.Fatalf("upsert ev1: %v", err)
	}

	ev2ID, _, err := s.UpsertSecurityEvent(SecurityEvent{
		Fingerprint: "fp2",
		Rule:        "sensitive_probe",
		Severity:    "critical",
		SubjectType: "ip",
		Subject:     "192.168.1.50",
		Pool:        "backend_auth",
		FirstSeen:   now,
		LastSeen:    now,
		Count:       4,
		Evidence:    map[string]any{"paths": []string{"/.env"}},
	})
	if err != nil {
		t.Fatalf("upsert ev2: %v", err)
	}

	// 1. Create Incident linking ev1
	incID, err := s.CreateIncident(Incident{
		Title:    "Credential Stuffing Attack against backend_auth",
		Severity: "high",
		Status:   "open",
		Owner:    "soc@example.com",
		Summary:  "Multiple brute force detections observed from 192.168.1.50",
	}, []int64{ev1ID})
	if err != nil {
		t.Fatalf("create incident: %v", err)
	}
	if incID <= 0 {
		t.Fatalf("invalid incident id: %d", incID)
	}

	// Verify ev1 status changed to escalated
	ev1, err := s.GetSecurityEvent(ev1ID)
	if err != nil {
		t.Fatalf("get ev1: %v", err)
	}
	if ev1.Status != "escalated" || ev1.IncidentID == nil || *ev1.IncidentID != incID {
		t.Errorf("ev1 status=%s incID=%v, want escalated / %d", ev1.Status, ev1.IncidentID, incID)
	}

	// 2. Add Note
	noteID, err := s.AddIncidentNote(incID, "soc@example.com", "IP has been placed under temporary watch")
	if err != nil {
		t.Fatalf("add note: %v", err)
	}
	if noteID <= 0 {
		t.Fatalf("invalid note id: %d", noteID)
	}

	// 3. Link ev2
	if err := s.LinkEventsToIncident(incID, []int64{ev2ID}); err != nil {
		t.Fatalf("link ev2: %v", err)
	}

	// 4. Get Incident
	inc, events, notes, err := s.GetIncident(incID)
	if err != nil {
		t.Fatalf("get incident: %v", err)
	}
	if inc.Title != "Credential Stuffing Attack against backend_auth" {
		t.Errorf("inc.Title = %q", inc.Title)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if len(notes) != 1 {
		t.Fatalf("len(notes) = %d, want 1", len(notes))
	}

	// 5. Update Status to investigating then mitigated then resolved
	if err := s.UpdateIncidentStatus(incID, "investigating", "sre@example.com", "Investigating blast radius", ""); err != nil {
		t.Fatalf("update status: %v", err)
	}
	inc, _, _, _ = s.GetIncident(incID)
	if inc.Status != "investigating" || inc.Owner != "sre@example.com" {
		t.Errorf("status=%s owner=%s", inc.Status, inc.Owner)
	}

	if err := s.UpdateIncidentStatus(incID, "resolved", "", "", "sre@example.com"); err != nil {
		t.Fatalf("resolve incident: %v", err)
	}
	inc, _, _, _ = s.GetIncident(incID)
	if inc.Status != "resolved" || inc.ResolvedAt == nil || inc.ResolvedBy != "sre@example.com" {
		t.Errorf("resolved status=%s at=%v by=%s", inc.Status, inc.ResolvedAt, inc.ResolvedBy)
	}

	// 6. List Incidents
	list, total, err := s.ListIncidents(IncidentFilter{})
	if err != nil {
		t.Fatalf("list incidents: %v", err)
	}
	if total != 1 || len(list) != 1 {
		t.Fatalf("total=%d len=%d", total, len(list))
	}
	if list[0].EventCount != 2 {
		t.Errorf("list[0].EventCount = %d, want 2", list[0].EventCount)
	}

	// 7. Unlink ev2
	if err := s.UnlinkEventFromIncident(ev2ID); err != nil {
		t.Fatalf("unlink ev2: %v", err)
	}
	_, eventsAfterUnlink, _, _ := s.GetIncident(incID)
	if len(eventsAfterUnlink) != 1 {
		t.Errorf("len(eventsAfterUnlink) = %d, want 1", len(eventsAfterUnlink))
	}
}
