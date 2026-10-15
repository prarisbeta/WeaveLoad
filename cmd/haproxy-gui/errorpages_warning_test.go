package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"haproxy-gui/internal/errorpages"
	"haproxy-gui/internal/web"
)

func errorPagesBody(t *testing.T, config, code string) string {
	t.Helper()
	mgr := errorpages.NewManager("/etc/haproxy/errors")
	h := &web.ErrorPagesHandler{Manager: mgr, Templates: realTemplates(t), Config: fileConfig{config}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/error-pages?code="+code, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	return rec.Body.String()
}

const wiredConfig = `defaults
        errorfile 429 /etc/haproxy/errors/429.http
        errorfile 503 /etc/haproxy/errors/503.http
`

// The reported bug: the page was saved but the config had no errorfile 429, so
// visitors kept seeing HAProxy's built-in page and nothing in the UI said so.
func TestErrorPagesWarnsWhenNoErrorfileLine(t *testing.T) {
	body := errorPagesBody(t, "defaults\n        errorfile 503 /etc/haproxy/errors/503.http\n", "429")
	if !strings.Contains(body, `id="errorfile-warning"`) {
		t.Fatal("expected a warning for 429, which has no errorfile line")
	}
	if !strings.Contains(body, "errorfile 429 /etc/haproxy/errors/429.http") {
		t.Error("the warning must show the exact line to add")
	}
	if strings.Contains(body, `id="errorfile-reload-hint"`) {
		t.Error("the plain reload hint belongs to the healthy case only")
	}
}

func TestErrorPagesWarnsWhenErrorfilePointsElsewhere(t *testing.T) {
	body := errorPagesBody(t, "defaults\n        errorfile 429 /var/www/old/429.http\n", "429")
	if !strings.Contains(body, `id="errorfile-warning"`) || !strings.Contains(body, "/var/www/old/429.http") {
		t.Error("expected a warning naming the file the config really uses")
	}
}

func TestErrorPagesNoWarningWhenWired(t *testing.T) {
	body := errorPagesBody(t, wiredConfig, "429")
	if strings.Contains(body, `id="errorfile-warning"`) {
		t.Error("a correctly wired page must not warn")
	}
	if !strings.Contains(body, `id="errorfile-reload-hint"`) {
		t.Error("expected the reload reminder instead")
	}
}

func TestErrorPagesMarksInactiveTabs(t *testing.T) {
	// 429 is wired, 503 is not mentioned: its tab carries the "not active" badge.
	body := errorPagesBody(t, "defaults\n        errorfile 429 /etc/haproxy/errors/429.http\n", "429")
	if !strings.Contains(body, "belum aktif") {
		t.Error("expected at least one tab marked as not active")
	}
}

func TestErrorPagesWithoutConfigReaderShowsNoWarning(t *testing.T) {
	h := &web.ErrorPagesHandler{Manager: errorpages.NewManager("/etc/haproxy/errors"), Templates: realTemplates(t)}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/error-pages?code=429", nil))
	if strings.Contains(rec.Body.String(), `id="errorfile-warning"`) {
		t.Error("with no config to check there is nothing to warn about")
	}
}
