package retention

import (
	"errors"
	"testing"
	"time"
)

type fakeStore struct {
	audit          time.Duration
	events, risk   time.Time
	alerts         time.Time
	called         map[string]bool
	failEvents     bool
	sessionsPruned int64
}

func (f *fakeStore) mark(k string) {
	if f.called == nil {
		f.called = map[string]bool{}
	}
	f.called[k] = true
}
func (f *fakeStore) PruneExpiredSessions() (int64, error) {
	f.mark("sessions")
	return f.sessionsPruned, nil
}
func (f *fakeStore) PruneAudit(d time.Duration) (int64, error) {
	f.mark("audit")
	f.audit = d
	return 1, nil
}
func (f *fakeStore) PruneStaleSecurityEvents(t time.Time) (int64, error) {
	f.mark("security_events")
	f.events = t
	if f.failEvents {
		return 0, errors.New("disk full")
	}
	return 2, nil
}
func (f *fakeStore) PruneIPRisk(t time.Time) (int64, error) {
	f.mark("ip_risk")
	f.risk = t
	return 3, nil
}
func (f *fakeStore) PrunePolicyActions(time.Time) (int64, error) {
	f.mark("policy_actions")
	return 6, nil
}
func (f *fakeStore) PruneIPIntel(time.Time) (int64, error) {
	f.mark("ip_intel")
	return 7, nil
}
func (f *fakeStore) PruneAlerts(t time.Time) (int64, error) {
	f.mark("alerts")
	f.alerts = t
	return 4, nil
}

type fakeBackups struct{ keep int }

func (b *fakeBackups) PruneBackups(keep int) (int, error) { b.keep = keep; return 5, nil }

func TestSweep_AppliesPolicyCutoffs(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	st, bk := &fakeStore{}, &fakeBackups{}
	s := &Sweeper{Store: st, Backups: bk, Policy: DefaultPolicy(), Now: func() time.Time { return now }}

	res := s.Sweep()
	if st.audit != 30*24*time.Hour {
		t.Errorf("audit retention = %v", st.audit)
	}
	if want := now.Add(-90 * 24 * time.Hour); !st.events.Equal(want) || !st.risk.Equal(want) || !st.alerts.Equal(want) {
		t.Errorf("cutoffs = %v %v %v, want %v", st.events, st.risk, st.alerts, want)
	}
	if bk.keep != 50 {
		t.Errorf("keep backups = %d", bk.keep)
	}
	if res.Deleted["security_events"] != 2 || res.Deleted["config_backups"] != 5 || len(res.Errors) != 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestSweep_ZeroPolicyDeletesNothing(t *testing.T) {
	st, bk := &fakeStore{}, &fakeBackups{}
	s := &Sweeper{Store: st, Backups: bk}
	s.Sweep()
	for _, kind := range []string{"audit", "security_events", "ip_risk", "alerts"} {
		if st.called[kind] {
			t.Errorf("%s pruned with a zero policy", kind)
		}
	}
	if bk.keep != 0 {
		t.Error("backups pruned with a zero policy")
	}
	if !st.called["sessions"] {
		t.Error("expired sessions are always safe to prune")
	}
}

func TestSweep_OneFailureDoesNotStopTheRest(t *testing.T) {
	st := &fakeStore{failEvents: true}
	s := &Sweeper{Store: st, Policy: DefaultPolicy()}
	res := s.Sweep()
	if res.Errors["security_events"] == nil {
		t.Error("failure not reported")
	}
	if !st.called["ip_risk"] || !st.called["alerts"] {
		t.Error("later prunes were skipped after a failure")
	}
}
