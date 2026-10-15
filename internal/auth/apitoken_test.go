package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"haproxy-gui/internal/store"
)

type fakeTokens struct{ valid map[string]store.APIToken }

func (f fakeTokens) VerifyAPIToken(plain string) (store.APIToken, error) {
	t, ok := f.valid[plain]
	if !ok {
		return store.APIToken{}, store.ErrNotFound
	}
	return t, nil
}

func tokenFixture() fakeTokens {
	return fakeTokens{valid: map[string]store.APIToken{
		"kgw_goodtoken0000000000000000000000": {ID: 7, Name: "claude-code"},
	}}
}

func bearerReq(method, target, token string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// whoami echoes what the middleware put in the context.
func whoami(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFromContext(r.Context())
	_, viaToken := APITokenFromContext(r.Context())
	w.Header().Set("X-User", u.Email)
	w.Header().Set("X-Role", string(u.Role))
	if viaToken {
		w.Header().Set("X-Via", "token")
	}
	w.WriteHeader(http.StatusOK)
}

func TestRequireAuthOrToken_ValidTokenGetsAReadOnlyRoleAndNoSession(t *testing.T) {
	h := RequireAuthOrToken(newFakeSessions(), tokenFixture())(http.HandlerFunc(whoami))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, bearerReq(http.MethodGet, "/api/v1/status", "kgw_goodtoken0000000000000000000000"))

	if rec.Code != http.StatusOK || rec.Header().Get("X-Via") != "token" {
		t.Fatalf("status=%d via=%q", rec.Code, rec.Header().Get("X-Via"))
	}
	if rec.Header().Get("X-User") != "api-token:claude-code" {
		t.Errorf("user = %q", rec.Header().Get("X-User"))
	}
	role := store.Role(rec.Header().Get("X-Role"))
	for _, c := range []store.Capability{store.CapManageConfig, store.CapManageUsers, store.CapManageSettings, store.CapRuntimeControl, store.CapManageIncidents} {
		if role.Can(c) {
			t.Errorf("token role %q must not have %q", role, c)
		}
	}
	if !role.Can(store.CapViewSecurity) {
		t.Errorf("token role %q must be able to read security data for /api/v1/incidents", role)
	}
}

func TestRequireAuthOrToken_BadTokenIs401WithChallengeAndNeverRedirects(t *testing.T) {
	h := RequireAuthOrToken(newFakeSessions(), tokenFixture())(okHandler())
	for _, tok := range []string{"kgw_wrongwrongwrongwrongwrongwrong00", "kgw_"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, bearerReq(http.MethodGet, "/api/v1/status", tok))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%q: status = %d, want 401 (not a login redirect)", tok, rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%q: missing WWW-Authenticate challenge", tok)
		}
	}
}

func TestRequireAuthOrToken_SessionStillWorks(t *testing.T) {
	f := newFakeSessions()
	f.users[1] = store.User{ID: 1, Email: "a@x.id", Role: store.RoleSOCAnalyst, Enabled: true}
	f.sessions["sess-1"] = store.Session{ID: "sess-1", UserID: 1, ExpiresAt: time.Now().Add(time.Hour)}
	h := RequireAuthOrToken(f, tokenFixture())(http.HandlerFunc(whoami))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sess-1"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Header().Get("X-User") != "a@x.id" || rec.Header().Get("X-Via") != "" {
		t.Errorf("status=%d user=%q via=%q", rec.Code, rec.Header().Get("X-User"), rec.Header().Get("X-Via"))
	}
}

func TestRequireAuthOrToken_NoCredentials_BrowserRedirectsAPIGets401(t *testing.T) {
	h := RequireAuthOrToken(newFakeSessions(), tokenFixture())(okHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if rec.Code != http.StatusFound {
		t.Errorf("plain GET: status = %d, want the same login redirect RequireAuth gives", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/proposals", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST: status = %d, want 401", rec.Code)
	}
}

func TestRequireAPIToken_RejectsSessionsAndAcceptsOnlyTokens(t *testing.T) {
	f := newFakeSessions()
	f.users[1] = store.User{ID: 1, Email: "a@x.id", Role: store.RolePlatformAdmin, Enabled: true}
	f.sessions["sess-1"] = store.Session{ID: "sess-1", UserID: 1, ExpiresAt: time.Now().Add(time.Hour)}
	h := RequireAPIToken(tokenFixture())(http.HandlerFunc(whoami))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sess-1"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("session cookie on /mcp: status = %d, want 401", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bearerReq(http.MethodPost, "/mcp", "sess-1"))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("session id as bearer on /mcp: status = %d, want 401", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bearerReq(http.MethodPost, "/mcp", "kgw_goodtoken0000000000000000000000"))
	if rec.Code != http.StatusOK {
		t.Errorf("valid token on /mcp: status = %d", rec.Code)
	}
}

func TestRequireCSRF_SkippedOnlyForTokenCallers(t *testing.T) {
	chain := RequireAuthOrToken(newFakeSessions(), tokenFixture())(RequireCSRF(okHandler()))

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, bearerReq(http.MethodPost, "/api/v1/proposals", "kgw_goodtoken0000000000000000000000"))
	if rec.Code != http.StatusOK {
		t.Errorf("token POST: status = %d, want 200 (no browser session to CSRF)", rec.Code)
	}

	f := newFakeSessions()
	f.users[1] = store.User{ID: 1, Email: "a@x.id", Role: store.RolePlatformAdmin, Enabled: true}
	f.sessions["s"] = store.Session{ID: "s", UserID: 1, CSRFToken: "good", ExpiresAt: time.Now().Add(time.Hour)}
	chain = RequireAuthOrToken(f, tokenFixture())(RequireCSRF(okHandler()))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/proposals", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "s"})
	rec = httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("session POST without CSRF token: status = %d, want 403", rec.Code)
	}
}
