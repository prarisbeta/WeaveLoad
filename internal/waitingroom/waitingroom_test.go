package waitingroom

import (
	"testing"
	"time"

	"haproxy-gui/internal/haproxylog"
)

var now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func ln(ip string, ago time.Duration, status int, backend string) haproxylog.Line {
	return haproxylog.Line{ClientIP: ip, Time: now.Add(-ago), StatusCode: status, Backend: backend}
}

func TestComputeSeparatesWaitingAdmittedAndAbandoned(t *testing.T) {
	lines := []haproxylog.Line{
		// 1.1.1.1: rejected twice, still retrying 10s ago => waiting, held since 70s ago.
		ln("1.1.1.1", 70*time.Second, 429, "oms"),
		ln("1.1.1.1", 10*time.Second, 429, "oms"),
		// 2.2.2.2: rejected, then served => admitted.
		ln("2.2.2.2", 60*time.Second, 429, "oms"),
		ln("2.2.2.2", 20*time.Second, 200, "oms"),
		// 3.3.3.3: rejected 5 minutes ago and never came back => abandoned.
		ln("3.3.3.3", 5*time.Minute, 429, "portal"),
		// 4.4.4.4: never rejected => not part of the waiting room at all.
		ln("4.4.4.4", 30*time.Second, 200, "oms"),
	}
	s := Compute(lines, now, 10*time.Minute)

	if s.Waiting != 1 || s.Admitted != 1 || s.Abandoned != 1 {
		t.Fatalf("waiting=%d admitted=%d abandoned=%d, want 1/1/1", s.Waiting, s.Admitted, s.Abandoned)
	}
	if s.Rejections != 4 {
		t.Errorf("rejections = %d, want 4", s.Rejections)
	}
	if len(s.LongestWaiting) != 1 || s.LongestWaiting[0].IP != "1.1.1.1" || s.LongestWaiting[0].WaitingSeconds != 70 {
		t.Errorf("longest waiting = %+v, want 1.1.1.1 held for 70s", s.LongestWaiting)
	}
	if s.LongestWaitSeconds != 70 {
		t.Errorf("longest wait = %d, want 70", s.LongestWaitSeconds)
	}
}

func TestComputeIsOrderIndependentAndRejectedAgainAfterAdmissionWaitsAgain(t *testing.T) {
	// Given newest-first (the way haproxylog.Read returns it): 429, 200, 429.
	lines := []haproxylog.Line{
		ln("5.5.5.5", 5*time.Second, 429, "oms"),
		ln("5.5.5.5", 40*time.Second, 200, "oms"),
		ln("5.5.5.5", 80*time.Second, 429, "oms"),
	}
	s := Compute(lines, now, 10*time.Minute)
	if s.Waiting != 1 || s.Admitted != 0 {
		t.Fatalf("waiting=%d admitted=%d, want 1/0: the latest request was a 429", s.Waiting, s.Admitted)
	}
	// The wait counts from the new rejection streak, not the first one.
	if s.LongestWaiting[0].WaitingSeconds != 5 {
		t.Errorf("waiting_seconds = %d, want 5", s.LongestWaiting[0].WaitingSeconds)
	}
}

func TestComputeByPoolAndWindow(t *testing.T) {
	lines := []haproxylog.Line{
		ln("1.1.1.1", 5*time.Second, 429, "oms"),
		ln("2.2.2.2", 6*time.Second, 429, "oms"),
		ln("3.3.3.3", 7*time.Second, 429, "portal"),
		ln("9.9.9.9", 2*time.Hour, 429, "oms"), // outside the window
	}
	s := Compute(lines, now, 5*time.Minute)
	if s.Waiting != 3 || s.Rejections != 3 {
		t.Fatalf("waiting=%d rejections=%d, want 3/3 (old line ignored)", s.Waiting, s.Rejections)
	}
	if len(s.ByPool) != 2 || s.ByPool[0].Name != "oms" || s.ByPool[0].Waiting != 2 || s.ByPool[1].Name != "portal" {
		t.Errorf("by pool = %+v, want oms(2) then portal(1)", s.ByPool)
	}
	if s.WindowSeconds != 300 {
		t.Errorf("window = %d, want 300", s.WindowSeconds)
	}
}

func TestComputeEmptyIsAllZeroWithNonNilLists(t *testing.T) {
	s := Compute(nil, now, time.Minute)
	if s.Waiting != 0 || s.Admitted != 0 || s.Abandoned != 0 || s.Rejections != 0 {
		t.Errorf("snapshot = %+v, want zeros", s)
	}
	if s.ByPool == nil || s.LongestWaiting == nil {
		t.Error("lists must be empty arrays, not null, in the JSON")
	}
	if s.Note == "" {
		t.Error("the snapshot must say that counts are distinct IPs")
	}
}

func TestComputeListsAtMostTenLongestWaiting(t *testing.T) {
	var lines []haproxylog.Line
	for i := 0; i < 15; i++ {
		ip := "10.0.0." + string(rune('a'+i))
		lines = append(lines, ln(ip, time.Duration(i+1)*time.Second, 429, "oms"))
	}
	s := Compute(lines, now, 10*time.Minute)
	if s.Waiting != 15 || len(s.LongestWaiting) != maxListed {
		t.Errorf("waiting=%d listed=%d, want 15 counted and %d listed", s.Waiting, len(s.LongestWaiting), maxListed)
	}
}
