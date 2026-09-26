package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/store"
)

type fakeSecurityStore struct {
	events  []store.SecurityEvent
	risk    map[string]store.IPRisk
	statusN int
	lastID  int64
	lastSt  string
	lastBy  string
}

func (f *fakeSecurityStore) ListSecurityEvents(filter store.SecurityFilter) ([]store.SecurityEvent, int, error) {
	var out []store.SecurityEvent
	for _, e := range f.events {
		if filter.Rule != "" && e.Rule != filter.Rule {
			continue
		}
		if filter.Subject != "" && e.Subject != filter.Subject {
			continue
		}
		out = append(out, e)
	}
	return out, len(out), nil
}

func (f *fakeSecurityStore) GetSecurityEvent(id int64) (store.SecurityEvent, error) {
	for _, e := range f.events {
		if e.ID == id {
			return e, nil
		}
	}
	return store.SecurityEvent{}, store.ErrNotFound
}

func (f *fakeSecurityStore) SetSecurityEventStatus(id int64, status, actor string) error {
	f.statusN++
	f.lastID, f.lastSt, f.lastBy = id, status, actor
	for i, e := range f.events {
		if e.ID == id {
			f.events[i].Status = status
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fakeSecurityStore) GetIPRisk(ip string) (store.IPRisk, error) {
	r, ok := f.risk[ip]
	if !ok {
		return store.IPRisk{}, store.ErrNotFound
	}
	return r, nil
}

func (f *fakeSecurityStore) ListTopRisk(n int) ([]store.IPRisk, error) {
	var out []store.IPRisk
	for _, r := range f.risk {
		out = append(out, r)
	}
	return out, nil
}

func securityTemplates(t *testing.T) *template.Template {
	t.Helper()
	tpl, err := template.New("").Parse(`
{{define "security.html"}}security-page total={{.Total}}{{range .Events}} ev={{.ID}}{{end}}{{end}}
{{define "security_table.html"}}security-table total={{.Total}}{{end}}
{{define "security_event.html"}}event {{.Event.ID}} status={{.Event.Status}}{{end}}
{{define "security_ip.html"}}ip {{.IP}} total={{.Total}}{{end}}
`)
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}

func TestSecurityHandler_ListsEvents(t *testing.T) {
	fs := &fakeSecurityStore{
		events: []store.SecurityEvent{{ID: 1, Rule: "brute_force", Subject: "1.2.3.4", LastSeen: time.Now()}},
		risk:   map[string]store.IPRisk{},
	}
	h := &SecurityHandler{Store: fs, Templates: securityTemplates(t)}

	req := httptest.NewRequest(http.MethodGet, "/security", nil)
	req = withUser(req, store.User{Email: "a@x.id", Role: store.RoleSOCAnalyst})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !contains(rec.Body.String(), "ev=1") {
		t.Errorf("body = %q, want it to include the event", rec.Body.String())
	}
}

func TestSecurityHandler_RejectsInvalidRuleFilter(t *testing.T) {
	h := &SecurityHandler{Store: &fakeSecurityStore{risk: map[string]store.IPRisk{}}, Templates: securityTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/security?rule=drop_table", nil)
	req = withUser(req, store.User{Email: "a@x.id", Role: store.RoleSOCAnalyst})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an unrecognized rule", rec.Code)
	}
}

func TestSecurityHandler_RejectsInvalidIPFilter(t *testing.T) {
	h := &SecurityHandler{Store: &fakeSecurityStore{risk: map[string]store.IPRisk{}}, Templates: securityTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/security?ip=not-an-ip", nil)
	req = withUser(req, store.User{Email: "a@x.id", Role: store.RoleSOCAnalyst})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an invalid ip filter", rec.Code)
	}
}

func TestSecurityHandler_HXRequestRendersPartial(t *testing.T) {
	h := &SecurityHandler{Store: &fakeSecurityStore{risk: map[string]store.IPRisk{}}, Templates: securityTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/security", nil)
	req.Header.Set("HX-Request", "true")
	req = withUser(req, store.User{Email: "a@x.id", Role: store.RoleSOCAnalyst})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !contains(rec.Body.String(), "security-table") {
		t.Errorf("body = %q, want the partial template for an HX-Request", rec.Body.String())
	}
}

func TestSecurityEventDetail_RendersEvent(t *testing.T) {
	fs := &fakeSecurityStore{events: []store.SecurityEvent{{ID: 5, Status: "open"}}, risk: map[string]store.IPRisk{}}
	h := &SecurityEventDetail{Store: fs, Templates: securityTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/security/events/5", nil)
	req.SetPathValue("id", "5")
	req = withUser(req, store.User{Email: "a@x.id", Role: store.RoleSOCAnalyst})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !contains(rec.Body.String(), "status=open") {
		t.Errorf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSecurityEventDetail_UnknownID_404(t *testing.T) {
	h := &SecurityEventDetail{Store: &fakeSecurityStore{risk: map[string]store.IPRisk{}}, Templates: securityTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/security/events/999", nil)
	req.SetPathValue("id", "999")
	req = withUser(req, store.User{Email: "a@x.id", Role: store.RoleSOCAnalyst})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestSecurityIPHandler_RejectsInvalidIP(t *testing.T) {
	h := &SecurityIPHandler{Store: &fakeSecurityStore{risk: map[string]store.IPRisk{}}, Templates: securityTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/security/ip/nope", nil)
	req.SetPathValue("ip", "nope")
	req = withUser(req, store.User{Email: "a@x.id", Role: store.RoleSOCAnalyst})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestSecurityIPHandler_RendersKnownIP(t *testing.T) {
	fs := &fakeSecurityStore{
		events: []store.SecurityEvent{{ID: 1, Subject: "9.9.9.9"}},
		risk:   map[string]store.IPRisk{"9.9.9.9": {IP: "9.9.9.9", Score: 50}},
	}
	h := &SecurityIPHandler{Store: fs, Templates: securityTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/security/ip/9.9.9.9", nil)
	req.SetPathValue("ip", "9.9.9.9")
	req = withUser(req, store.User{Email: "a@x.id", Role: store.RoleSOCAnalyst})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !contains(rec.Body.String(), "ip 9.9.9.9") {
		t.Errorf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSecurityEventStatusAction_UpdatesAndAudits(t *testing.T) {
	fs := &fakeSecurityStore{events: []store.SecurityEvent{{ID: 1, Status: "open"}}}
	audit := &fakeAudit{}
	h := &SecurityEventStatusAction{Store: fs, Audit: audit}

	form := "status=acknowledged"
	req := httptest.NewRequest(http.MethodPost, "/api/security/events/1/status", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", "1")
	req = withUser(req, store.User{Email: "a@x.id", Role: store.RoleSecurityAdmin})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if fs.lastSt != "acknowledged" || fs.lastBy != "a@x.id" {
		t.Errorf("lastSt=%q lastBy=%q", fs.lastSt, fs.lastBy)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "security.event.acknowledged" {
		t.Errorf("audit entries = %+v", audit.entries)
	}
}

func TestSecurityEventStatusAction_RejectsInvalidStatus(t *testing.T) {
	fs := &fakeSecurityStore{events: []store.SecurityEvent{{ID: 1}}}
	h := &SecurityEventStatusAction{Store: fs, Audit: &fakeAudit{}}

	req := httptest.NewRequest(http.MethodPost, "/api/security/events/1/status", strings.NewReader("status=deleted_forever"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", "1")
	req = withUser(req, store.User{Email: "a@x.id", Role: store.RoleSecurityAdmin})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an unrecognized status value", rec.Code)
	}
}

func TestSecurityEventStatusAction_UnknownID_404(t *testing.T) {
	h := &SecurityEventStatusAction{Store: &fakeSecurityStore{}, Audit: &fakeAudit{}}
	req := httptest.NewRequest(http.MethodPost, "/api/security/events/999/status", strings.NewReader("status=dismissed"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", "999")
	req = withUser(req, store.User{Email: "a@x.id", Role: store.RoleSecurityAdmin})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}
