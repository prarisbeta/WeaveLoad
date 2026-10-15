package canary

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/store"
)

// scriptedSource returns one batch of lines per poll.
type scriptedSource struct {
	batches [][]haproxylog.Line
	err     error
}

func (s *scriptedSource) ReadNew() ([]haproxylog.Line, error) {
	if s.err != nil {
		return nil, s.err
	}
	if len(s.batches) == 0 {
		return nil, nil
	}
	b := s.batches[0]
	s.batches = s.batches[1:]
	return b, nil
}

func lines(status, n int) []haproxylog.Line {
	out := make([]haproxylog.Line, n)
	for i := range out {
		out[i] = haproxylog.Line{StatusCode: status}
	}
	return out
}

type audit struct{ actions []string }

func (a *audit) Record(e store.AuditEntry) error { a.actions = append(a.actions, e.Action); return nil }

type harness struct {
	w          *Watcher
	rolledBack []string
	alerts     []string
	audit      *audit
}

func newHarness(src LogSource, rollbackErr error) *harness {
	clock := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	h := &harness{audit: &audit{}}
	h.w = &Watcher{
		Window:    func() time.Duration { return 3 * time.Minute },
		NewSource: func() (LogSource, error) { return src, nil },
		Rollback: func(prev string) error {
			h.rolledBack = append(h.rolledBack, prev)
			return rollbackErr
		},
		Alert:    func(rule, sev, subj, msg string) { h.alerts = append(h.alerts, sev+":"+msg) },
		Audit:    h.audit,
		Interval: 10 * time.Second,
		Sleep:    func(d time.Duration) { clock = clock.Add(d) },
		Now:      func() time.Time { return clock },
	}
	return h
}

func TestRun_RollsBackOnErrorSpike(t *testing.T) {
	src := &scriptedSource{batches: [][]haproxylog.Line{lines(200, 10), append(lines(502, 15), lines(200, 5)...)}}
	h := newHarness(src, nil)

	rolled, err := h.w.Run(context.Background(), "OLD CONFIG", "ops@x")
	if err != nil || !rolled {
		t.Fatalf("rolled=%v err=%v, want a rollback", rolled, err)
	}
	if len(h.rolledBack) != 1 || h.rolledBack[0] != "OLD CONFIG" {
		t.Errorf("rolled back to %v", h.rolledBack)
	}
	if len(h.alerts) != 1 || !strings.HasPrefix(h.alerts[0], "high:") {
		t.Errorf("alerts = %v", h.alerts)
	}
	if len(h.audit.actions) != 1 || h.audit.actions[0] != "config.canary_rollback" {
		t.Errorf("audit = %v", h.audit.actions)
	}
}

func TestRun_HealthyTrafficKeepsTheConfig(t *testing.T) {
	src := &scriptedSource{batches: [][]haproxylog.Line{lines(200, 100), append(lines(200, 95), lines(500, 2)...)}}
	h := newHarness(src, nil)
	rolled, err := h.w.Run(context.Background(), "OLD", "ops@x")
	if err != nil || rolled || len(h.rolledBack) != 0 {
		t.Fatalf("rolled=%v err=%v rollbacks=%v", rolled, err, h.rolledBack)
	}
	if len(h.audit.actions) != 1 || h.audit.actions[0] != "config.canary_ok" {
		t.Errorf("audit = %v", h.audit.actions)
	}
}

func TestRun_TooLittleTrafficIsNotAVerdict(t *testing.T) {
	src := &scriptedSource{batches: [][]haproxylog.Line{lines(502, 3)}}
	h := newHarness(src, nil)
	if rolled, _ := h.w.Run(context.Background(), "OLD", "ops@x"); rolled {
		t.Error("rolled back on 3 requests; below MinRequests")
	}
}

func TestRun_IgnoresUnparsedLines(t *testing.T) {
	src := &scriptedSource{batches: [][]haproxylog.Line{lines(0, 200)}}
	h := newHarness(src, nil)
	if rolled, _ := h.w.Run(context.Background(), "OLD", "ops@x"); rolled {
		t.Error("unparsed lines (status 0) were counted")
	}
}

func TestRun_FailedRollbackRaisesACriticalAlert(t *testing.T) {
	src := &scriptedSource{batches: [][]haproxylog.Line{lines(503, 50)}}
	h := newHarness(src, errors.New("haproxy -c failed"))
	rolled, err := h.w.Run(context.Background(), "OLD", "ops@x")
	if !rolled || err == nil {
		t.Fatalf("rolled=%v err=%v, want a reported failure", rolled, err)
	}
	if len(h.alerts) != 1 || !strings.HasPrefix(h.alerts[0], "critical:") {
		t.Errorf("alerts = %v", h.alerts)
	}
}

func TestRun_StopsWhenSuperseded(t *testing.T) {
	src := &scriptedSource{batches: [][]haproxylog.Line{lines(502, 50)}}
	h := newHarness(src, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rolled, err := h.w.Run(ctx, "OLD", "ops@x"); rolled || err != nil {
		t.Errorf("a cancelled watch must stop quietly: rolled=%v err=%v", rolled, err)
	}
}

func TestWatch_DisabledOrNoPreviousIsANoOp(t *testing.T) {
	opened := false
	w := &Watcher{
		Window:    func() time.Duration { return 0 },
		NewSource: func() (LogSource, error) { opened = true; return &scriptedSource{}, nil },
	}
	w.Watch("OLD", "ops@x")
	w.Window = func() time.Duration { return time.Minute }
	w.Watch("", "ops@x")
	time.Sleep(20 * time.Millisecond)
	if opened {
		t.Error("watch started although disabled or without a previous config")
	}
}
