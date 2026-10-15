package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/store"
)

// --- API token create / revoke ---

type fakeTokenStore struct {
	created   []string
	revoked   []int64
	createErr error
	revokeErr error
	list      []store.APIToken
}

func (f *fakeTokenStore) ListAPITokens() ([]store.APIToken, error) { return f.list, nil }
func (f *fakeTokenStore) CreateAPIToken(name, by string) (string, store.APIToken, error) {
	if f.createErr != nil {
		return "", store.APIToken{}, f.createErr
	}
	f.created = append(f.created, name+"|"+by)
	return "kgw_secretsecretsecretsecretsecret", store.APIToken{ID: 4, Name: name, Prefix: "kgw_secr"}, nil
}
func (f *fakeTokenStore) RevokeAPIToken(id int64) error {
	f.revoked = append(f.revoked, id)
	return f.revokeErr
}

type failingAudit struct{}

func (failingAudit) Record(store.AuditEntry) error { return errors.New("disk full") }

func formPost(target, form string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return withUser(req, store.User{Email: "admin@x.id", Role: store.RolePlatformAdmin})
}

func TestAPITokenCreate_ShowsPlaintextOnceAndIsAudited(t *testing.T) {
	ts := &fakeTokenStore{}
	au := &fakeAudit{}
	tpl := mustParse(t, `{{define "api_token_result.html"}}LANG={{.Language}} NAME={{.Name}} TOKEN={{.Token}} URL={{.MCPURL}}{{end}}`)
	h := &APITokenCreateAction{Store: ts, Audit: au, Templates: tpl}

	req := formPost("/api/settings/api-tokens", "name=claude-code")
	req.Host = "103.31.159.8:9443"
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "TOKEN=kgw_secret") || !strings.Contains(body, "URL=https://103.31.159.8:9443/mcp") || !strings.Contains(body, "LANG=id") {
		t.Fatalf("status=%d body=%q", rec.Code, body)
	}
	if len(ts.created) != 1 || ts.created[0] != "claude-code|admin@x.id" {
		t.Errorf("created = %v", ts.created)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "api_token.create" {
		t.Fatalf("audit = %+v", au.entries)
	}
	if strings.Contains(au.entries[0].Detail, "secretsecret") {
		t.Error("the token itself must never reach the audit log")
	}
}

func TestAPITokenCreate_BlankNameIs400_AuditFailureRevokesTheToken(t *testing.T) {
	tpl := mustParse(t, `{{define "api_token_result.html"}}x{{end}}`)

	rec := httptest.NewRecorder()
	(&APITokenCreateAction{Store: &fakeTokenStore{}, Audit: &fakeAudit{}, Templates: tpl}).ServeHTTP(rec, formPost("/x", "name=+++"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("blank name: status = %d", rec.Code)
	}

	ts := &fakeTokenStore{}
	rec = httptest.NewRecorder()
	(&APITokenCreateAction{Store: ts, Audit: failingAudit{}, Templates: tpl}).ServeHTTP(rec, formPost("/x", "name=n8n"))
	if rec.Code != http.StatusInternalServerError || len(ts.revoked) != 1 || ts.revoked[0] != 4 {
		t.Errorf("status=%d revoked=%v, want the unaudited token revoked", rec.Code, ts.revoked)
	}
	if strings.Contains(rec.Body.String(), "kgw_") {
		t.Error("a token that was revoked must not be displayed")
	}
}

func TestAPITokenRevoke(t *testing.T) {
	ts := &fakeTokenStore{}
	au := &fakeAudit{}
	h := &APITokenRevokeAction{Store: ts, Audit: au}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, formPost("/x", "id=4"))
	if rec.Code != http.StatusNoContent || rec.Header().Get("HX-Refresh") != "true" || len(ts.revoked) != 1 {
		t.Fatalf("status=%d refresh=%q revoked=%v", rec.Code, rec.Header().Get("HX-Refresh"), ts.revoked)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "api_token.revoke" || au.entries[0].Target != "4" {
		t.Errorf("audit = %+v", au.entries)
	}

	for form, want := range map[string]int{"id=abc": 400, "id=0": 400, "": 400} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, formPost("/x", form))
		if rec.Code != want {
			t.Errorf("%q: status = %d, want %d", form, rec.Code, want)
		}
	}
	rec = httptest.NewRecorder()
	(&APITokenRevokeAction{Store: &fakeTokenStore{revokeErr: store.ErrNotFound}, Audit: au}).ServeHTTP(rec, formPost("/x", "id=9"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown id: status = %d", rec.Code)
	}
}

func TestSettingsHandler_ListsAPITokensOnlyWhenWired(t *testing.T) {
	tpl := mustParse(t, `{{define "settings.html"}}SHOW={{.ShowAPITokens}} N={{len .APITokens}} URL={{.MCPURL}}{{end}}`)
	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/settings", nil)
		r.Host = "gw.example:9443"
		return r
	}

	rec := httptest.NewRecorder()
	(&SettingsHandler{Store: &fakeSettingsStore{}, Templates: tpl}).ServeHTTP(rec, req())
	if !strings.Contains(rec.Body.String(), "SHOW=false N=0") {
		t.Errorf("without Tokens: %q", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	(&SettingsHandler{Store: &fakeSettingsStore{}, Templates: tpl, Tokens: &fakeTokenStore{list: []store.APIToken{{ID: 1, Name: "a"}}}}).ServeHTTP(rec, req())
	if !strings.Contains(rec.Body.String(), "SHOW=true N=1 URL=http://gw.example:9443/mcp") {
		t.Errorf("with Tokens: %q", rec.Body.String())
	}
}

// --- proposals ---

type fakeProposalStore struct {
	subject, message string
	err              error
}

func (f *fakeProposalStore) CreateAlert(rule, severity, subject, message string) (store.Alert, error) {
	f.subject, f.message = subject, message
	return store.Alert{ID: 12, Rule: rule}, f.err
}

func proposalReq(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/proposals", strings.NewReader(body))
	return withUser(req, store.User{Email: "api-token:claude", Role: store.RoleAuditor})
}

func TestProposal_RecordedAsAnAlertForAHumanAndAudited(t *testing.T) {
	ps, au := &fakeProposalStore{}, &fakeAudit{}
	rec := httptest.NewRecorder()
	(&APIV1ProposalHandler{Store: ps, Audit: au}).ServeHTTP(rec, proposalReq(`{"reason":"5xx spike","evidence":"100 errors"}`))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if ps.subject != "api-token:claude" || !strings.Contains(ps.message, "5xx spike") || !strings.Contains(ps.message, "100 errors") {
		t.Errorf("alert = %q / %q", ps.subject, ps.message)
	}
	var resp APIResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Success || resp.Data.(map[string]any)["id"].(float64) != 12 {
		t.Errorf("resp = %+v", resp)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "proposal.create" {
		t.Errorf("audit = %+v", au.entries)
	}
}

func TestProposal_Validation(t *testing.T) {
	h := &APIV1ProposalHandler{Store: &fakeProposalStore{}, Audit: &fakeAudit{}}
	long := strings.Repeat("x", maxProposalField+1)
	cases := map[string]int{
		`not json`:                                 400,
		`{"reason":"a"}`:                           400,
		`{"reason":" ","evidence":"b"}`:            400,
		`{"reason":"` + long + `","evidence":"b"}`: 413,
		`{"reason":"a","evidence":"` + long + `"}`: 413,
	}
	for body, want := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, proposalReq(body))
		if rec.Code != want {
			t.Errorf("%.40q: status = %d, want %d", body, rec.Code, want)
		}
	}
}

// --- /mcp end to end through the real auth middleware ---

type tokenDB struct{ valid map[string]store.APIToken }

func (d tokenDB) VerifyAPIToken(p string) (store.APIToken, error) {
	if t, ok := d.valid[p]; ok {
		return t, nil
	}
	return store.APIToken{}, store.ErrNotFound
}

type noSessions struct{}

func (noSessions) Session(string) (store.Session, error) { return store.Session{}, store.ErrNotFound }
func (noSessions) UserByID(int64) (store.User, error)    { return store.User{}, store.ErrNotFound }
func (noSessions) DeleteSession(string) error            { return nil }

func mcpFixture() http.Handler {
	tokens := tokenDB{valid: map[string]store.APIToken{"kgw_validvalidvalidvalidvalidvalid": {ID: 1, Name: "claude", CreatedAt: time.Now()}}}
	mux := http.NewServeMux()
	require := auth.RequireAuthOrToken(noSessions{}, tokens)
	viewSecurity := auth.RequireCapability(store.CapViewSecurity)
	manageConfig := auth.RequireCapability(store.CapManageConfig)

	mux.Handle("GET /api/v1/status", require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFromContext(r.Context())
		w.Write([]byte(`{"success":true,"data":{"caller":"` + u.Email + `"}}`))
	})))
	mux.Handle("GET /api/v1/servers", require(manageConfig(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`secret server list`))
	}))))
	mux.Handle("POST /api/v1/proposals", require(auth.RequireCSRF(viewSecurity(&APIV1ProposalHandler{Store: &fakeProposalStore{}, Audit: &fakeAudit{}}))))

	mcpH := NewMCPHandler(mux)
	mux.Handle("OPTIONS /mcp", http.HandlerFunc(mcpH.Preflight))
	mux.Handle("POST /mcp", auth.RequireAPIToken(tokens)(mcpH))
	return mux
}

func mcpPost(h http.Handler, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func toolText(t *testing.T, rec *httptest.ResponseRecorder) (string, bool) {
	t.Helper()
	var resp struct {
		Result struct {
			Content []struct{ Text string } `json:"content"`
			IsError bool                    `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Result.Content) == 0 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	return resp.Result.Content[0].Text, resp.Result.IsError
}

const validTok = "kgw_validvalidvalidvalidvalidvalid"

func TestMCP_RequiresAValidToken(t *testing.T) {
	h := mcpFixture()
	for _, tok := range []string{"", "kgw_wrongwrongwrongwrongwrongwrong", "not-a-token"} {
		rec := mcpPost(h, tok, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("token %q: status = %d", tok, rec.Code)
		}
	}
}

func TestMCP_ToolCallRunsAsTheTokenThroughTheAPI(t *testing.T) {
	h := mcpFixture()
	rec := mcpPost(h, validTok, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status"}}`)
	text, isErr := toolText(t, rec)
	if isErr || !strings.Contains(text, `"caller":"api-token:claude"`) {
		t.Errorf("text=%q isError=%v", text, isErr)
	}
}

func TestMCP_ATokenCannotReachMoreThroughMCPThanThroughTheAPI(t *testing.T) {
	h := mcpFixture()
	rec := mcpPost(h, validTok, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_servers"}}`)
	text, isErr := toolText(t, rec)
	if !isErr || !strings.Contains(text, "HTTP 403") || strings.Contains(text, "secret server list") {
		t.Errorf("text=%q isError=%v, want the capability check to refuse it", text, isErr)
	}
}

func TestMCP_ProposeActionWorksWithATokenWithoutCSRF(t *testing.T) {
	h := mcpFixture()
	rec := mcpPost(h, validTok, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"propose_action","arguments":{"reason":"r","evidence":"e"}}}`)
	text, isErr := toolText(t, rec)
	if isErr || !strings.Contains(text, "not executed") || !strings.Contains(text, `"id":12`) {
		t.Errorf("text=%q isError=%v", text, isErr)
	}
}

func TestMCP_PreflightNeedsNoCredentials(t *testing.T) {
	h := mcpFixture()
	req := httptest.NewRequest(http.MethodOptions, "/mcp", nil)
	req.Header.Set("Origin", "https://inspector.example")
	req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("status=%d headers=%v", rec.Code, rec.Header())
	}
}
