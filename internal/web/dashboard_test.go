package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"haproxy-gui/internal/runtime"
	"haproxy-gui/internal/store"
)

type fakeStats struct {
	body string
	err  error
}

func (f fakeStats) ShowStat() (string, error) { return f.body, f.err }

type fakeRuntime struct {
	states  map[string]runtime.ServerState
	weights map[string]string
	err     error
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{states: map[string]runtime.ServerState{}, weights: map[string]string{}}
}

func (f *fakeRuntime) SetServerState(backend, server string, state runtime.ServerState) error {
	if f.err != nil {
		return f.err
	}
	f.states[backend+"/"+server] = state
	return nil
}

func (f *fakeRuntime) SetServerWeight(backend, server, weight string) error {
	if f.err != nil {
		return f.err
	}
	f.weights[backend+"/"+server] = weight
	return nil
}

type fakeAudit struct {
	entries []store.AuditEntry
	failErr error
}

func (f *fakeAudit) Record(e store.AuditEntry) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.entries = append(f.entries, e)
	return nil
}

const testFixture = `# pxname,svname,status,weight,check_status,last_chk,scur
http_oms,node1,UP,1,L7OK,,0
http_oms,BACKEND,UP,,,,0
`

func testTemplates(t *testing.T) *template.Template {
	t.Helper()
	tpl := template.Must(template.New("dashboard.html").Parse(`{{define "dashboard.html"}}FULL PAGE{{template "dashboard_table.html" .}}{{end}}`))
	tpl = template.Must(tpl.New("dashboard_table.html").Parse(`{{define "dashboard_table.html"}}{{range .Snapshot.Backends}}{{.Name}}{{end}}{{end}}`))
	return tpl
}

func TestDashboardHandler_RendersFullPageOnNormalRequest(t *testing.T) {
	h := &DashboardHandler{Stats: fakeStats{body: testFixture}, Templates: testTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "FULL PAGE") {
		t.Errorf("expected full page render, got %q", rec.Body.String())
	}
}

func TestDashboardHandler_RendersFragmentOnHTMXRequest(t *testing.T) {
	h := &DashboardHandler{Stats: fakeStats{body: testFixture}, Templates: testTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "FULL PAGE") {
		t.Errorf("expected fragment only, got full page: %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "http_oms") {
		t.Errorf("expected backend name in fragment, got %q", rec.Body.String())
	}
}

func TestDashboardHandler_RuntimeUnreachable_502(t *testing.T) {
	h := &DashboardHandler{Stats: fakeStats{err: assertErr("connection refused")}, Templates: testTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestServerActionHandler_Drain_CallsRuntimeAndAudits(t *testing.T) {
	rt := newFakeRuntime()
	au := &fakeAudit{}
	h := &ServerActionHandler{Runtime: rt, Audit: au}

	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader("backend=http_oms&server=node1&action=drain"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if rt.states["http_oms/node1"] != runtime.StateDrain {
		t.Errorf("runtime state = %+v, want drain applied", rt.states)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "server.drain" {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestServerActionHandler_RejectsInvalidBackendName(t *testing.T) {
	rt := newFakeRuntime()
	au := &fakeAudit{}
	h := &ServerActionHandler{Runtime: rt, Audit: au}

	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader("backend=evil;drop&server=node1&action=drain"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if len(rt.states) != 0 {
		t.Error("runtime should never have been called with an invalid name")
	}
}

func TestServerActionHandler_RuntimeErrorStillAudited(t *testing.T) {
	rt := newFakeRuntime()
	rt.err = assertErr("no such server")
	au := &fakeAudit{}
	h := &ServerActionHandler{Runtime: rt, Audit: au}

	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader("backend=http_oms&server=node1&action=maint"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if len(au.entries) != 1 {
		t.Fatalf("expected a failed action to still be audit-logged, got %d entries", len(au.entries))
	}
	if !strings.Contains(au.entries[0].Detail, "error:") {
		t.Errorf("audit detail = %q, expected it to record the failure", au.entries[0].Detail)
	}
}

func TestServerActionHandler_AuditFailure_500(t *testing.T) {
	rt := newFakeRuntime()
	au := &fakeAudit{failErr: assertErr("disk full")}
	h := &ServerActionHandler{Runtime: rt, Audit: au}

	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader("backend=http_oms&server=node1&action=drain"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when the action succeeded but audit logging failed", rec.Code)
	}
}

func TestServerActionHandler_UnknownAction_400(t *testing.T) {
	rt := newFakeRuntime()
	au := &fakeAudit{}
	h := &ServerActionHandler{Runtime: rt, Audit: au}

	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader("backend=http_oms&server=node1&action=explode"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestServerActionHandler_Weight_JSONBody(t *testing.T) {
	rt := newFakeRuntime()
	au := &fakeAudit{}
	h := &ServerActionHandler{Runtime: rt, Audit: au}

	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(`{"backend":"http_oms","server":"node1","action":"weight","weight":"50"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if rt.weights["http_oms/node1"] != "50" {
		t.Errorf("weights = %+v", rt.weights)
	}
}

func TestServerActionHandler_RefreshesTableWhenWired(t *testing.T) {
	rt := newFakeRuntime()
	au := &fakeAudit{}
	h := &ServerActionHandler{
		Runtime:   rt,
		Audit:     au,
		Refresh:   fakeStats{body: testFixture},
		Templates: testTemplates(t),
	}

	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader("backend=http_oms&server=node1&action=drain"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "FULL PAGE") {
		t.Errorf("expected the table fragment only, got full page: %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "http_oms") {
		t.Errorf("expected refreshed backend name in response, got %q", rec.Body.String())
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }
