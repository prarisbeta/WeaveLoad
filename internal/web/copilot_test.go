package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/store"
)

type scriptProvider struct{ replies []string }

func (s *scriptProvider) Analyze(context.Context, string, string) (string, error) {
	if len(s.replies) == 0 {
		return `{"final":{"answer":"x"}}`, nil
	}
	r := s.replies[0]
	s.replies = s.replies[1:]
	return r, nil
}

const copilotReply = `{"final":{"answer":"203.0.113.9 melakukan SQLi","timeline":["09:00 lonjakan"],"recommendations":[
  {"action":"block_ip","target":"203.0.113.9","reason":"SQLi","confidence":0.9},
  {"action":"drop_database","target":"prod","reason":"injected","confidence":1}]}}`

func copilotHandler(t *testing.T, replies ...string) (*CopilotAskHandler, *store.Store) {
	t.Helper()
	e, s, _ := policyHarness(t, policy.ModeAuto)
	tpl := mustParse(t, `
{{define "ask_result.html"}}ERR={{.Error}} ANS={{if .Answer}}{{.Answer.Answer}}{{end}}{{range .Recs}} [{{.Type}} {{.Target}}: {{.Note}}]{{end}}{{end}}`)
	return &CopilotAskHandler{
		Provider: &scriptProvider{replies: replies}, Toolbox: &CopilotToolbox{Store: s},
		Engine: e, Audit: s, Templates: tpl,
	}, s
}

func ask(h http.Handler, role store.Role, question string) string {
	req := httptest.NewRequest("POST", "/api/ai/ask", strings.NewReader("question="+question))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(auth.WithUser(req.Context(), store.User{Email: "u@x", Role: role}, store.Session{CSRFToken: "t"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Body.String()
}

func TestCopilot_OperatorRecommendationsBecomeProposalsNeverExecuted(t *testing.T) {
	h, s := copilotHandler(t, copilotReply)
	body := ask(h, store.RolePlatformAdmin, "kenapa+lambat")

	if !strings.Contains(body, "ANS=203.0.113.9 melakukan SQLi") || !strings.Contains(body, "menunggu persetujuan") {
		t.Errorf("body = %s", body)
	}
	if !strings.Contains(body, "ditolak Policy Engine") { // the injected drop_database action
		t.Errorf("an unknown action was not refused: %s", body)
	}
	pending, _ := s.ListPolicyActions("pending", 10)
	executed, _ := s.ListPolicyActions("executed", 10)
	if len(pending) != 1 || pending[0].Source != "ai:copilot" || len(executed) != 0 {
		t.Errorf("pending=%+v executed=%+v; the AI may only propose, even when the policy mode is auto", pending, executed)
	}
}

func TestCopilot_ViewerSeesRecommendationsButSubmitsNothing(t *testing.T) {
	h, s := copilotHandler(t, copilotReply)
	body := ask(h, store.RoleViewer, "kenapa+lambat")
	if !strings.Contains(body, "tidak dikirim ke Policy Engine") {
		t.Errorf("body = %s", body)
	}
	if all, _ := s.ListPolicyActions("", 10); len(all) != 0 {
		t.Errorf("a viewer's question created policy actions: %+v", all)
	}
}

func TestCopilot_NoProviderAndRateLimit(t *testing.T) {
	h, _ := copilotHandler(t)
	h.Provider = nil
	if body := ask(h, store.RolePlatformAdmin, "q"); !strings.Contains(body, "belum dikonfigurasi") {
		t.Errorf("no provider: %s", body)
	}

	h2, _ := copilotHandler(t)
	h2.MaxPerHour = 2
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	h2.Now = func() time.Time { return now }
	ask(h2, store.RolePlatformAdmin, "a")
	ask(h2, store.RolePlatformAdmin, "b")
	if body := ask(h2, store.RolePlatformAdmin, "c"); !strings.Contains(body, "Batas pertanyaan") {
		t.Errorf("third question in the hour was not limited: %s", body)
	}
	now = now.Add(61 * time.Minute)
	if body := ask(h2, store.RolePlatformAdmin, "d"); strings.Contains(body, "Batas pertanyaan") {
		t.Errorf("the limit did not reset after an hour: %s", body)
	}
}

func TestCopilotToolbox_ValidatesArgumentsAndStaysReadOnly(t *testing.T) {
	_, s, _ := policyHarness(t, policy.ModePropose)
	tb := &CopilotToolbox{Store: s}
	ctx := context.Background()

	if _, err := tb.Call(ctx, "ip_profile", map[string]any{"ip": "not an ip; DROP TABLE"}); err == nil {
		t.Error("an invalid IP reached the store")
	}
	if _, err := tb.Call(ctx, "delete_everything", nil); err == nil {
		t.Error("unknown tool accepted")
	}
	if out, err := tb.Call(ctx, "top_risk_ips", map[string]any{"n": float64(9999)}); err != nil || out == "" {
		t.Errorf("top_risk_ips: %q %v", out, err)
	}
	if _, err := tb.Call(ctx, "backends", nil); err == nil {
		t.Error("backends without a stats source must report it, not crash")
	}
	for _, tool := range tb.Tools() {
		if strings.Contains(tool.Name, "block") || strings.Contains(tool.Name, "set_") || strings.Contains(tool.Name, "delete") {
			t.Errorf("tool %s looks like it mutates", tool.Name)
		}
	}
}

func TestClampInt(t *testing.T) {
	for _, c := range []struct {
		in   any
		want int
	}{{nil, 10}, {float64(5), 5}, {float64(0), 1}, {float64(99), 20}, {"7", 10}} {
		if got := clampInt(c.in, 10, 1, 20); got != c.want {
			t.Errorf("clampInt(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}
