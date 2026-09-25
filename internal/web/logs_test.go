package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const logFixture = `Sep 25 09:00:00 haproxy-cni haproxy[100]: 10.0.0.2:2222 [25/Sep/2026:09:00:00.000] http_in http_oms/node1 0/0/0/1/1 404 200 - - ---- 1/1/0/0/0 0/0 "GET /missing HTTP/1.1"
Sep 25 09:05:00 haproxy-cni haproxy[100]: 10.0.0.3:3333 [25/Sep/2026:09:05:00.000] http_in http_oms/node2 0/0/0/2/2 500 100 - - ---- 1/1/0/0/0 0/0 "GET /err HTTP/1.1"
`

func writeLogFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "haproxy.log")
	if err := os.WriteFile(path, []byte(logFixture), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func logTemplates(t *testing.T) *template.Template {
	return mustParse(t, `{{define "logs.html"}}{{range .Lines}}{{.StatusCode}}:{{.Raw}}|{{end}}{{end}}`)
}

func TestLogHandler_ListsLines(t *testing.T) {
	h := &LogHandler{Path: writeLogFixture(t), Templates: logTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "404:") || !strings.Contains(rec.Body.String(), "500:") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestLogHandler_FiltersByDate(t *testing.T) {
	h := &LogHandler{Path: writeLogFixture(t), Templates: logTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/logs?date=2026-09-24", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if strings.TrimSpace(rec.Body.String()) != "" {
		t.Errorf("expected no lines for a date with no entries, got %q", rec.Body.String())
	}
}

func TestLogHandler_FiltersByKeyword(t *testing.T) {
	h := &LogHandler{Path: writeLogFixture(t), Templates: logTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/logs?q=node2", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "500:") || strings.Contains(rec.Body.String(), "404:") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestLogHandler_InvalidDate_400(t *testing.T) {
	h := &LogHandler{Path: writeLogFixture(t), Templates: logTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/logs?date=not-a-date", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestLogHandler_MissingFile_500(t *testing.T) {
	h := &LogHandler{Path: filepath.Join(t.TempDir(), "missing.log"), Templates: logTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}
