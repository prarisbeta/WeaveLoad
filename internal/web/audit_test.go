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

type fakeAuditLister struct {
	entries    []store.AuditEntry
	err        error
	lastFilter store.AuditFilter
}

func (f *fakeAuditLister) ListAudit(filter store.AuditFilter) ([]store.AuditEntry, error) {
	f.lastFilter = filter
	return f.entries, f.err
}

func auditTemplates(t *testing.T) *template.Template {
	return mustParse(t, `{{define "audit.html"}}{{range .Entries}}{{.UserEmail}}:{{.Action}} {{end}}{{end}}`)
}

func TestAuditHandler_ListsEntries(t *testing.T) {
	al := &fakeAuditLister{entries: []store.AuditEntry{{UserEmail: "a@x.id", Action: "server.drain", Timestamp: time.Now()}}}
	h := &AuditHandler{Store: al, Templates: auditTemplates(t)}

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "a@x.id:server.drain") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestAuditHandler_PassesQueryFilters(t *testing.T) {
	al := &fakeAuditLister{}
	h := &AuditHandler{Store: al, Templates: auditTemplates(t)}

	req := httptest.NewRequest(http.MethodGet, "/audit?user=a@x.id&action=server.drain", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if al.lastFilter.UserEmail != "a@x.id" || al.lastFilter.Action != "server.drain" {
		t.Errorf("filter = %+v", al.lastFilter)
	}
}

func TestAuditHandler_StoreError_500(t *testing.T) {
	h := &AuditHandler{Store: &fakeAuditLister{err: assertErr("db closed")}, Templates: auditTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}
