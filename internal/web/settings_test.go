package web

import (
	"html/template"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/store"
)

type fakeSettingsStore struct {
	redis      store.RedisSettings
	getErr     error
	setErr     error
	saved      []store.RedisSettings
	queueToken string
}

func (f *fakeSettingsStore) GetRedisSettings() (store.RedisSettings, error) {
	return f.redis, f.getErr
}

func (f *fakeSettingsStore) SetRedisSettings(rs store.RedisSettings) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.saved = append(f.saved, rs)
	f.redis = rs
	return nil
}

func (f *fakeSettingsStore) GetQueueAPIToken() (string, error) { return f.queueToken, nil }

func (f *fakeSettingsStore) SetQueueAPIToken(token string) error {
	f.queueToken = token
	return nil
}

func testSettingsTemplates(t *testing.T) *template.Template {
	t.Helper()
	return mustParse(t, `
{{define "redis_test_result.html"}}OK={{.OK}} MSG={{.Message}}{{end}}
`)
}

func TestRedisTestAction_RequiresHostAndPort(t *testing.T) {
	h := &RedisTestAction{Templates: testSettingsTemplates(t)}
	req := httptest.NewRequest(http.MethodPost, "/api/settings/redis/test", strings.NewReader("host=&port="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestRedisTestAction_SuccessAndFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("+PONG\r\n"))
			conn.Close()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())

	h := &RedisTestAction{Templates: testSettingsTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/settings/redis/test", strings.NewReader("host="+host+"&port="+port))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "OK=true") {
		t.Errorf("body = %q, want OK=true against a real listener", rec.Body.String())
	}

	// Nothing listens on this port (kept closed for the duration of the test).
	closedLn, _ := net.Listen("tcp", "127.0.0.1:0")
	closedHost, closedPort, _ := net.SplitHostPort(closedLn.Addr().String())
	closedLn.Close()

	req2 := httptest.NewRequest(http.MethodPost, "/api/settings/redis/test", strings.NewReader("host="+closedHost+"&port="+closedPort))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rec2, req2)
	if !strings.Contains(rec2.Body.String(), "OK=false") {
		t.Errorf("body = %q, want OK=false against a closed port", rec2.Body.String())
	}
	if time.Since(start) > 5*time.Second {
		t.Error("test against a closed port took too long — timeout not applied")
	}
}

func TestRedisSaveAction_SavesAndAudits(t *testing.T) {
	ss := &fakeSettingsStore{}
	au := &fakeAudit{}
	h := &RedisSaveAction{Store: ss, Audit: au, Templates: testSettingsTemplates(t)}

	form := "host=10.0.0.5&port=6379&password=secret&db=2&tls=1"
	req := httptest.NewRequest(http.MethodPost, "/api/settings/redis", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{Email: "admin@example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if len(ss.saved) != 1 || ss.saved[0].Host != "10.0.0.5" || ss.saved[0].DB != 2 || !ss.saved[0].TLS {
		t.Errorf("saved = %+v", ss.saved)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "settings.redis.save" {
		t.Errorf("audit entries = %+v", au.entries)
	}
	// The password itself must never land in the audit trail.
	if strings.Contains(au.entries[0].Detail, "secret") {
		t.Errorf("audit detail leaked the password: %q", au.entries[0].Detail)
	}
}

func TestRedisSaveAction_RequiresHostAndPort(t *testing.T) {
	h := &RedisSaveAction{Store: &fakeSettingsStore{}, Audit: &fakeAudit{}, Templates: testSettingsTemplates(t)}
	req := httptest.NewRequest(http.MethodPost, "/api/settings/redis", strings.NewReader("host=&port="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
