package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"haproxy-gui/internal/store"
)

// fakeSessions is an in-memory stand-in for *store.Store, so middleware
// tests never touch SQLite.
type fakeSessions struct {
	sessions map[string]store.Session
	users    map[int64]store.User
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{sessions: map[string]store.Session{}, users: map[int64]store.User{}}
}

func (f *fakeSessions) Session(id string) (store.Session, error) {
	s, ok := f.sessions[id]
	if !ok {
		return store.Session{}, store.ErrNotFound
	}
	if time.Now().After(s.ExpiresAt) {
		return store.Session{}, store.ErrNotFound
	}
	return s, nil
}

func (f *fakeSessions) UserByID(id int64) (store.User, error) {
	u, ok := f.users[id]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

func (f *fakeSessions) DeleteSession(id string) error {
	delete(f.sessions, id)
	return nil
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRequireAuth_NoCookie_HTMX_401(t *testing.T) {
	f := newFakeSessions()
	h := RequireAuth(f)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireAuth_NoCookie_BrowserGET_RedirectsToLogin(t *testing.T) {
	f := newFakeSessions()
	h := RequireAuth(f)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

func TestRequireAuth_NoCookie_POST_401(t *testing.T) {
	f := newFakeSessions()
	h := RequireAuth(f)(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for non-GET", rec.Code)
	}
}

func TestRequireAuth_ValidSession_PassesThrough(t *testing.T) {
	f := newFakeSessions()
	f.users[1] = store.User{ID: 1, Email: "u@example.com", Role: store.RoleViewer, Enabled: true}
	f.sessions["tok"] = store.Session{ID: "tok", UserID: 1, CSRFToken: "csrf1", ExpiresAt: time.Now().Add(time.Hour)}

	var sawUser store.User
	h := RequireAuth(f)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawUser, _ = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if sawUser.Email != "u@example.com" {
		t.Errorf("user in context = %+v", sawUser)
	}
}

func TestRequireAuth_ExpiredSession_401(t *testing.T) {
	f := newFakeSessions()
	f.users[1] = store.User{ID: 1, Enabled: true}
	f.sessions["tok"] = store.Session{ID: "tok", UserID: 1, ExpiresAt: time.Now().Add(-time.Minute)}

	h := RequireAuth(f)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for expired session", rec.Code)
	}
}

func TestRequireAuth_DisabledUser_403(t *testing.T) {
	f := newFakeSessions()
	f.users[1] = store.User{ID: 1, Enabled: false}
	f.sessions["tok"] = store.Session{ID: "tok", UserID: 1, ExpiresAt: time.Now().Add(time.Hour)}

	h := RequireAuth(f)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for disabled account", rec.Code)
	}
}

func TestRequireCapability_MissingCapability_403(t *testing.T) {
	h := RequireCapability(store.CapManageConfig)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := WithUser(req.Context(), store.User{Role: store.RoleViewer}, store.Session{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestRequireCapability_GrantedCapability_PassesThrough(t *testing.T) {
	h := RequireCapability(store.CapRuntimeControl)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := WithUser(req.Context(), store.User{Role: store.RolePlatformAdmin}, store.Session{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequireCSRF_GetPassesWithoutToken(t *testing.T) {
	h := RequireCSRF(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET status = %d, want 200", rec.Code)
	}
}

func TestRequireCSRF_PostMissingToken_403(t *testing.T) {
	h := RequireCSRF(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := WithUser(req.Context(), store.User{}, store.Session{CSRFToken: "expected"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for missing CSRF token", rec.Code)
	}
}

func TestRequireCSRF_PostWrongToken_403(t *testing.T) {
	h := RequireCSRF(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-CSRF-Token", "wrong")
	ctx := WithUser(req.Context(), store.User{}, store.Session{CSRFToken: "expected"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for wrong CSRF token", rec.Code)
	}
}

func TestRequireCSRF_PostCorrectToken_PassesThrough(t *testing.T) {
	h := RequireCSRF(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-CSRF-Token", "expected")
	ctx := WithUser(req.Context(), store.User{}, store.Session{CSRFToken: "expected"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for correct CSRF token", rec.Code)
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("abc", "abc") {
		t.Error("expected equal strings to match")
	}
	if constantTimeEqual("abc", "abd") {
		t.Error("expected different strings to not match")
	}
	if constantTimeEqual("abc", "abcd") {
		t.Error("expected different-length strings to not match")
	}
}
