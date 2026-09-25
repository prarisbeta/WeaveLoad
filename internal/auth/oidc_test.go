package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"haproxy-gui/internal/store"
)

func newTestStoreDB(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCompleteLogin_CreatesUserAndSessionCookie(t *testing.T) {
	s := newTestStoreDB(t)
	claims := Claims{Subject: "sub-1", Email: "Budi@Example.com", Name: "Budi"}

	rec := httptest.NewRecorder()
	u, err := CompleteLogin(rec, s, claims, true)
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if u.Email != "budi@example.com" {
		t.Errorf("email = %q", u.Email)
	}
	if u.Role != store.RoleViewer {
		t.Errorf("new SSO user role = %q, want viewer", u.Role)
	}

	resp := rec.Result()
	var found *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookieName {
			found = c
		}
	}
	if found == nil {
		t.Fatal("expected session cookie to be set")
	}
	if !found.HttpOnly || !found.Secure || found.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie insufficiently locked down: %+v", found)
	}
}

func TestCompleteLogin_RejectsMissingEmail(t *testing.T) {
	s := newTestStoreDB(t)
	rec := httptest.NewRecorder()
	_, err := CompleteLogin(rec, s, Claims{Subject: "sub-1"}, true)
	if err == nil {
		t.Fatal("expected error for claims with no email")
	}
}

func TestCompleteLogin_RejectsDisabledAccount(t *testing.T) {
	s := newTestStoreDB(t)
	u, err := s.UpsertSSOUser("disabled@example.com", "Disabled", "sub-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnabled(u.ID, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}

	rec := httptest.NewRecorder()
	_, err = CompleteLogin(rec, s, Claims{Subject: "sub-2", Email: "disabled@example.com", Name: "Disabled"}, true)
	if err == nil {
		t.Fatal("expected error for disabled account")
	}
}
