package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/store"
)

type recExec struct{ blocked []string }

func (r *recExec) BlockIP(ip string) error   { r.blocked = append(r.blocked, ip); return nil }
func (r *recExec) UnblockIP(string) error    { return nil }
func (r *recExec) Drain(_, _ string) error   { return nil }
func (r *recExec) Undrain(_, _ string) error { return nil }

func policyHarness(t *testing.T, mode policy.Mode) (*policy.Engine, *store.Store, *recExec) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	x := &recExec{}
	e := &policy.Engine{Repo: s, Exec: x, Audit: s}
	c := policy.DefaultConfig()
	c.Modes[policy.BlockIP] = mode
	if err := e.SaveConfig(c, "admin"); err != nil {
		t.Fatal(err)
	}
	return e, s, x
}

func asUser(r *http.Request) *http.Request {
	return r.WithContext(auth.WithUser(r.Context(),
		store.User{Email: "ops@cni.net.id", Role: store.RolePlatformAdmin}, store.Session{CSRFToken: "t"}))
}

func TestProposalWithAction_NeverAutoRunsEvenInAutoMode(t *testing.T) {
	e, s, x := policyHarness(t, policy.ModeAuto)
	h := &APIV1ProposalHandler{Store: s, Audit: s, Policy: e}

	body := `{"reason":"SQLi burst","evidence":"40 hits","action":"block_ip","target":"9.9.9.9","ttl_seconds":600}`
	req := asUser(httptest.NewRequest("POST", "/api/v1/proposals", strings.NewReader(body)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("code = %d: %s", rec.Code, rec.Body)
	}
	if len(x.blocked) != 0 {
		t.Fatalf("an API-sourced proposal executed: %v", x.blocked)
	}
	pending, _ := s.ListPolicyActions("pending", 10)
	if len(pending) != 1 || pending[0].Target != "9.9.9.9" || pending[0].TTLSeconds != 600 {
		t.Errorf("pending = %+v", pending)
	}
}

func TestProposalWithBadAction_StillRecordsTheAlertAndExplainsTheRefusal(t *testing.T) {
	e, s, _ := policyHarness(t, policy.ModePropose)
	h := &APIV1ProposalHandler{Store: s, Audit: s, Policy: e}
	body := `{"reason":"r","evidence":"e","action":"block_ip","target":"127.0.0.1"}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, asUser(httptest.NewRequest("POST", "/api/v1/proposals", strings.NewReader(body))))

	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), "refused") {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body)
	}
	if pending, _ := s.ListPolicyActions("pending", 10); len(pending) != 0 {
		t.Errorf("a refused action was queued: %+v", pending)
	}
}

func TestPolicyCheck_IsADryRun(t *testing.T) {
	e, s, x := policyHarness(t, policy.ModeAuto)
	h := &APIV1PolicyCheckHandler{Engine: e}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, asUser(httptest.NewRequest("POST", "/api/v1/policy/check", strings.NewReader(`{"action":"block_ip","target":"9.9.9.9"}`))))

	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"allowed":true`) || !strings.Contains(rec.Body.String(), `"mode":"propose"`) {
		t.Errorf("code=%d body=%s (token callers are capped at propose)", rec.Code, rec.Body)
	}
	if all, _ := s.ListPolicyActions("", 10); len(all) != 0 || len(x.blocked) != 0 {
		t.Errorf("a dry run recorded or ran something: %+v %v", all, x.blocked)
	}
}

func TestPolicyDecisionAndKillSwitchActions(t *testing.T) {
	e, s, x := policyHarness(t, policy.ModePropose)
	rec, _, _ := e.Submit(policy.Action{Type: policy.BlockIP, Target: "9.9.9.9", Source: "auto:t"})

	approve := &PolicyDecisionAction{Engine: e, Verb: "approve"}
	mux := http.NewServeMux()
	mux.Handle("POST /api/policy/{id}/approve", approve)
	mux.Handle("POST /api/policy/kill-switch", &PolicyKillSwitchAction{Engine: e})

	req := asUser(httptest.NewRequest("POST", "/api/policy/"+itoa(rec.ID)+"/approve", nil))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther || len(x.blocked) != 1 {
		t.Fatalf("approve: code=%d blocked=%v", w.Code, x.blocked)
	}
	if got, _ := s.GetPolicyAction(rec.ID); got.Status != "executed" || got.DecidedBy != "ops@cni.net.id" {
		t.Errorf("record = %+v", got)
	}

	form := url.Values{"on": {"1"}}
	kill := asUser(httptest.NewRequest("POST", "/api/policy/kill-switch", strings.NewReader(form.Encode())))
	kill.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(httptest.NewRecorder(), kill)
	if !e.Config().KillSwitch {
		t.Error("kill switch did not turn on")
	}
}

func TestPolicyFlashCannotBeSpoofedFromTheURL(t *testing.T) {
	r := httptest.NewRequest("GET", "/policy?notice=Your+password+expired", nil)
	if got := takeFlash(httptest.NewRecorder(), r); got != "" {
		t.Errorf("notice taken from the URL: %q", got)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
