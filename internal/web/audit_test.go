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

func TestAuditExportHandler_WritesCSV(t *testing.T) {
	al := &fakeAuditLister{entries: []store.AuditEntry{
		{UserEmail: "a@x.id", RemoteIP: "10.0.0.1", Action: "server.drain", Target: "http_oms/node1", Detail: "result=ok", Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
	}}
	h := &AuditExportHandler{Store: al}

	req := httptest.NewRequest(http.MethodGet, "/audit/export", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content-type = %q, want text/csv", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "waktu,pengguna,ip,aksi,target,detail") {
		t.Errorf("missing CSV header: %q", body)
	}
	if !strings.Contains(body, "a@x.id") || !strings.Contains(body, "server.drain") {
		t.Errorf("missing entry data: %q", body)
	}
}

func TestAuditExportHandler_PassesQueryFilters(t *testing.T) {
	al := &fakeAuditLister{}
	h := &AuditExportHandler{Store: al}

	req := httptest.NewRequest(http.MethodGet, "/audit/export?user=a@x.id&action=server.drain", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if al.lastFilter.UserEmail != "a@x.id" || al.lastFilter.Action != "server.drain" {
		t.Errorf("filter = %+v", al.lastFilter)
	}
}

func TestAuditExportHandler_StoreError_500(t *testing.T) {
	h := &AuditExportHandler{Store: &fakeAuditLister{err: assertErr("db closed")}}
	req := httptest.NewRequest(http.MethodGet, "/audit/export", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}
