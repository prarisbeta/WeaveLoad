package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"haproxy-gui/internal/errorpages"
)

func testErrorPagesTemplates(t *testing.T) *template.Template {
	t.Helper()
	return mustParse(t, `
{{define "error_pages.html"}}ERROR_PAGES active={{.ActiveCode}} pages={{len .Pages}}{{end}}
`)
}

func TestErrorPagesHandler(t *testing.T) {
	mgr := errorpages.NewManager(t.TempDir())
	audit := &fakeAudit{}
	h := &ErrorPagesHandler{Manager: mgr, Audit: audit, Templates: testErrorPagesTemplates(t)}

	req := httptest.NewRequest(http.MethodGet, "/config/error-pages?code=503", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "active=503") {
		t.Errorf("body = %q, want active=503", rec.Body.String())
	}
}

func TestErrorPageSaveAction(t *testing.T) {
	mgr := errorpages.NewManager(t.TempDir())
	audit := &fakeAudit{}
	h := &ErrorPageSaveAction{Manager: mgr, Audit: audit}

	form := url.Values{
		"code":    {"429"},
		"content": {"HTTP/1.1 429 Too Many Requests\r\n\r\n<html><body>Test Waiting</body></html>"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/config/error-pages/429", strings.NewReader(form.Encode()))
	req.SetPathValue("code", "429")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	p, err := mgr.Get(429)
	if err != nil || !strings.Contains(p.HTMLBody, "Test Waiting") {
		t.Errorf("saved page mismatch: %+v, err=%v", p, err)
	}
}

func TestErrorPagePreviewHandler(t *testing.T) {
	mgr := errorpages.NewManager(t.TempDir())
	h := &ErrorPagePreviewHandler{Manager: mgr}

	req := httptest.NewRequest(http.MethodGet, "/api/config/error-pages/429/preview", nil)
	req.SetPathValue("code", "429")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Ruang Tunggu") {
		t.Errorf("preview HTML missing waiting room content")
	}
}
