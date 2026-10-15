package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/runtime"
	"haproxy-gui/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

type fakeExec struct {
	blocked, drained map[string]bool
	err              error
}

func newFakeExec() *fakeExec {
	return &fakeExec{blocked: map[string]bool{}, drained: map[string]bool{}}
}
func (f *fakeExec) BlockIP(ip string) error {
	if f.err != nil {
		return f.err
	}
	f.blocked[ip] = true
	return nil
}
func (f *fakeExec) UnblockIP(ip string) error {
	if f.err != nil {
		return f.err
	}
	delete(f.blocked, ip)
	return nil
}
func (f *fakeExec) Drain(b, s string) error {
	if f.err != nil {
		return f.err
	}
	f.drained[b+"/"+s] = true
	return nil
}
func (f *fakeExec) Undrain(b, s string) error {
	if f.err != nil {
		return f.err
	}
	delete(f.drained, b+"/"+s)
	return nil
}

type captureAudit struct{ actions []string }

func (c *captureAudit) Record(e store.AuditEntry) error {
	c.actions = append(c.actions, e.Action)
	return nil
}

type harness struct {
	e     *Engine
	x     *fakeExec
	audit *captureAudit
	clock *time.Time
}

func newHarness(t *testing.T, mode Mode) harness {
	t.Helper()
	clock := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	h := harness{x: newFakeExec(), audit: &captureAudit{}, clock: &clock}
	h.e = &Engine{Repo: openStore(t), Exec: h.x, Audit: h.audit, Now: func() time.Time { return *h.clock }}
	c := DefaultConfig()
	c.Modes[BlockIP], c.Modes[DrainServer] = mode, mode
	if err := h.e.SaveConfig(c, "admin"); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestDefaultConfigNeverAutoRuns(t *testing.T) {
	c := DefaultConfig()
	for _, ty := range Types {
		if c.Modes[ty] == ModeAuto {
			t.Errorf("%s defaults to auto", ty)
		}
	}
}

func TestModes(t *testing.T) {
	cases := []struct {
		mode        Mode
		wantStatus  string
		wantBlocked bool
	}{
		{ModeShadow, "shadow", false},
		{ModePropose, "pending", false},
		{ModeAuto, "executed", true},
	}
	for _, c := range cases {
		t.Run(string(c.mode), func(t *testing.T) {
			h := newHarness(t, c.mode)
			rec, d, err := h.e.Submit(Action{Type: BlockIP, Target: "9.9.9.9", Reason: "test", Source: "auto:test"})
			if err != nil || !d.Allowed {
				t.Fatalf("Submit: %+v, %v", d, err)
			}
			if rec.Status != c.wantStatus || h.x.blocked["9.9.9.9"] != c.wantBlocked {
				t.Errorf("status=%s blocked=%v, want %s/%v", rec.Status, h.x.blocked["9.9.9.9"], c.wantStatus, c.wantBlocked)
			}
		})
	}
}

func TestOffAndKillSwitchRefuse(t *testing.T) {
	h := newHarness(t, ModeOff)
	if _, d, _ := h.e.Submit(Action{Type: BlockIP, Target: "9.9.9.9"}); d.Allowed {
		t.Error("off mode accepted an action")
	}
	h2 := newHarness(t, ModeAuto)
	c := h2.e.Config()
	c.KillSwitch = true
	if err := h2.e.SaveConfig(c, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, d, _ := h2.e.Submit(Action{Type: BlockIP, Target: "9.9.9.9"}); d.Allowed || len(h2.x.blocked) != 0 {
		t.Errorf("kill switch let an action through: %+v", d)
	}
	if len(h.x.blocked) != 0 {
		t.Error("off mode executed")
	}
}

func TestMaxModeCapsAutoToPropose(t *testing.T) {
	h := newHarness(t, ModeAuto)
	rec, d, _ := h.e.Submit(Action{Type: BlockIP, Target: "9.9.9.9", MaxMode: ModePropose, Source: "api:tok"})
	if !d.Allowed || rec.Status != "pending" || len(h.x.blocked) != 0 {
		t.Errorf("API-sourced action must stop at propose: rec=%+v blocked=%v", rec, h.x.blocked)
	}
}

func TestValidationRefusals(t *testing.T) {
	h := newHarness(t, ModeAuto)
	c := h.e.Config()
	c.ProtectedCIDRs = []string{"10.0.0.0/8"}
	if err := h.e.SaveConfig(c, "admin"); err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]Action{
		"not an ip":      {Type: BlockIP, Target: "evil.example"},
		"loopback":       {Type: BlockIP, Target: "127.0.0.1"},
		"protected cidr": {Type: BlockIP, Target: "10.1.2.3"},
		"ttl too long":   {Type: BlockIP, Target: "9.9.9.9", TTL: 48 * time.Hour},
		"bad drain":      {Type: DrainServer, Target: "nobackendserver"},
		"unknown type":   {Type: "format_disk", Target: "x"},
	} {
		if _, d, _ := h.e.Submit(a); d.Allowed {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDuplicateIsRefused(t *testing.T) {
	h := newHarness(t, ModePropose)
	if _, d, _ := h.e.Submit(Action{Type: BlockIP, Target: "9.9.9.9"}); !d.Allowed {
		t.Fatal("first submit refused")
	}
	if _, d, _ := h.e.Submit(Action{Type: BlockIP, Target: "9.9.9.9"}); d.Allowed {
		t.Error("duplicate accepted")
	}
}

func TestHourlyCap(t *testing.T) {
	h := newHarness(t, ModeAuto)
	c := h.e.Config()
	c.MaxPerHour[BlockIP] = 2
	_ = h.e.SaveConfig(c, "admin")
	for _, ip := range []string{"9.9.9.1", "9.9.9.2"} {
		if rec, _, _ := h.e.Submit(Action{Type: BlockIP, Target: ip}); rec.Status != "executed" {
			t.Fatalf("%s not executed", ip)
		}
	}
	_, d, _ := h.e.Submit(Action{Type: BlockIP, Target: "9.9.9.3"})
	if d.Allowed || h.x.blocked["9.9.9.3"] {
		t.Errorf("third block exceeded the cap: %+v", d)
	}
}

func TestApproveRejectAndAudit(t *testing.T) {
	h := newHarness(t, ModePropose)
	r1, _, _ := h.e.Submit(Action{Type: BlockIP, Target: "9.9.9.1", Source: "auto:t"})
	r2, _, _ := h.e.Submit(Action{Type: BlockIP, Target: "9.9.9.2", Source: "auto:t"})

	got, err := h.e.Approve(r1.ID, "ops@x")
	if err != nil || got.Status != "executed" || !h.x.blocked["9.9.9.1"] || got.ExpiresAt == nil {
		t.Fatalf("Approve: %+v, %v", got, err)
	}
	if err := h.e.Reject(r2.ID, "ops@x"); err != nil || h.x.blocked["9.9.9.2"] {
		t.Fatalf("Reject: %v", err)
	}
	if _, err := h.e.Approve(r1.ID, "ops@x"); err == nil {
		t.Error("approving an executed action must fail")
	}
	joined := strings.Join(h.audit.actions, ",")
	for _, want := range []string{"policy.config", "policy.pending", "policy.executed", "policy.rejected"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit trail missing %s: %s", want, joined)
		}
	}
}

func TestExecutorFailureIsRecorded(t *testing.T) {
	h := newHarness(t, ModeAuto)
	h.x.err = errors.New("socket closed")
	rec, _, _ := h.e.Submit(Action{Type: BlockIP, Target: "9.9.9.9"})
	if rec.Status != "failed" || !strings.Contains(rec.Result, "socket closed") {
		t.Errorf("rec = %+v", rec)
	}
}

func TestExpireAndRevert(t *testing.T) {
	h := newHarness(t, ModeAuto)
	rec, _, _ := h.e.Submit(Action{Type: BlockIP, Target: "9.9.9.9", TTL: time.Hour})
	r2, _, _ := h.e.Submit(Action{Type: DrainServer, Target: "be/s1", TTL: 2 * time.Hour})
	if !h.x.blocked["9.9.9.9"] || !h.x.drained["be/s1"] {
		t.Fatal("not applied")
	}
	if n, _ := h.e.ExpireDue(); n != 0 {
		t.Errorf("expired %d before TTL", n)
	}
	*h.clock = h.clock.Add(90 * time.Minute)
	if n, err := h.e.ExpireDue(); n != 1 || err != nil || h.x.blocked["9.9.9.9"] || !h.x.drained["be/s1"] {
		t.Errorf("after 90m: n=%d err=%v blocked=%v drained=%v", n, err, h.x.blocked, h.x.drained)
	}
	if err := h.e.Revert(r2.ID, "ops@x"); err != nil || h.x.drained["be/s1"] {
		t.Errorf("Revert: %v drained=%v", err, h.x.drained)
	}
	if got, _ := h.e.Repo.GetPolicyAction(rec.ID); got.Status != "expired" {
		t.Errorf("status = %s", got.Status)
	}
}

func TestExpireRetriesWhenUndoFails(t *testing.T) {
	h := newHarness(t, ModeAuto)
	rec, _, _ := h.e.Submit(Action{Type: BlockIP, Target: "9.9.9.9", TTL: time.Minute})
	*h.clock = h.clock.Add(time.Hour)
	h.x.err = errors.New("socket closed")
	if n, err := h.e.ExpireDue(); n != 0 || err == nil {
		t.Fatalf("n=%d err=%v, want a reported failure", n, err)
	}
	if got, _ := h.e.Repo.GetPolicyAction(rec.ID); got.Status != "executed" {
		t.Errorf("failed undo must stay executed for a retry, got %s", got.Status)
	}
	h.x.err = nil
	if n, _ := h.e.ExpireDue(); n != 1 {
		t.Errorf("retry expired %d, want 1", n)
	}
}

type fakeMaps struct{ added, deleted []string }

func (f *fakeMaps) AddMapEntry(_, k, _ string) error { f.added = append(f.added, k); return nil }
func (f *fakeMaps) DelMapEntry(_, k string) error {
	f.deleted = append(f.deleted, k)
	return errors.New("entry not found")
}

type fakeServers struct{ states []runtime.ServerState }

func (f *fakeServers) SetServerState(_, _ string, s runtime.ServerState) error {
	f.states = append(f.states, s)
	return nil
}

func TestHAProxyExecutorKeepsBlocklistFileInStep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maps", "blocklist_ip.lst")
	maps, srv := &fakeMaps{}, &fakeServers{}
	x := &HAProxyExecutor{Maps: maps, Servers: srv, BlocklistPath: path}

	for _, ip := range []string{"1.2.3.4", "1.2.3.4", "5.6.7.8"} { // second one is a repeat
		if err := x.BlockIP(ip); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(path)
	if string(b) != "1.2.3.4\n5.6.7.8\n" {
		t.Fatalf("file = %q", b)
	}
	// A "not found" from the runtime socket must not stop the file cleanup.
	if err := x.UnblockIP("1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if string(b) != "5.6.7.8\n" {
		t.Errorf("file after unblock = %q", b)
	}
	_ = x.Drain("be", "s1")
	_ = x.Undrain("be", "s1")
	if len(srv.states) != 2 || srv.states[0] != runtime.StateDrain || srv.states[1] != runtime.StateReady {
		t.Errorf("states = %v", srv.states)
	}
}
