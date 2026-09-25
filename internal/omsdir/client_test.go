package omsdir

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakeServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnabled_RequiresBaseURLAndCredentials(t *testing.T) {
	if (&Client{}).Enabled() {
		t.Error("empty client should not be enabled")
	}
	if !New("https://oms.cni.net.id", "id", "secret").Enabled() {
		t.Error("fully configured client should be enabled")
	}
}

func TestLookupByEmail_SendsClientHeadersAndQuery(t *testing.T) {
	var gotPath, gotEmail, gotID, gotSecret string
	srv := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotEmail = r.URL.Query().Get("email")
		gotID = r.Header.Get("X-Client-Id")
		gotSecret = r.Header.Get("X-Client-Secret")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": map[string]string{"id": "1", "name": "Budi", "email": "budi@cni.net.id"},
		})
	})
	c := New(srv.URL, "client-1", "secret-1")

	u, err := c.LookupByEmail("budi@cni.net.id")
	if err != nil {
		t.Fatalf("LookupByEmail: %v", err)
	}
	if gotPath != "/sso/users" || gotEmail != "budi@cni.net.id" {
		t.Errorf("path=%q email=%q", gotPath, gotEmail)
	}
	if gotID != "client-1" || gotSecret != "secret-1" {
		t.Errorf("headers: id=%q secret=%q", gotID, gotSecret)
	}
	if u == nil || u.Name != "Budi" {
		t.Errorf("user = %+v", u)
	}
}

func TestLookupByEmail_NoMatchReturnsNilUser(t *testing.T) {
	srv := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"user": nil})
	})
	c := New(srv.URL, "id", "secret")

	u, err := c.LookupByEmail("nobody@cni.net.id")
	if err != nil {
		t.Fatalf("LookupByEmail: %v", err)
	}
	if u != nil {
		t.Errorf("expected nil user, got %+v", u)
	}
}

func TestLookupByEmail_EmptyEmailIsNoOp(t *testing.T) {
	srv := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should never call the API for an empty email")
	})
	c := New(srv.URL, "id", "secret")
	u, err := c.LookupByEmail("  ")
	if err != nil || u != nil {
		t.Errorf("u=%+v err=%v, want nil,nil", u, err)
	}
}

func TestLookupByEmail_NonOKStatusIsError(t *testing.T) {
	srv := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	c := New(srv.URL, "id", "secret")
	if _, err := c.LookupByEmail("x@cni.net.id"); err == nil {
		t.Error("expected error for non-200 response")
	}
}

func TestSearch_EmailQueryDoesExactLookupOnly(t *testing.T) {
	calls := 0
	srv := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("email") != "a@cni.net.id" {
			t.Errorf("expected exact email lookup, got query %q", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": map[string]string{"id": "1", "name": "A", "email": "a@cni.net.id"},
		})
	})
	c := New(srv.URL, "id", "secret")

	users, err := c.Search("a@cni.net.id")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(users) != 1 || users[0].Email != "a@cni.net.id" {
		t.Errorf("users = %+v", users)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no fallback needed for a direct email match)", calls)
	}
}

func TestSearch_BareNameTriesCniDomainThenFallsBackToFreeTextSearch(t *testing.T) {
	srv := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("email") == "budi@cni.net.id":
			_ = json.NewEncoder(w).Encode(map[string]any{"user": nil})
		case r.URL.Query().Get("q") == "budi":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]string{
					{"id": "1", "name": "Budi Santoso", "email": "budi.santoso@cni.net.id"},
				},
			})
		default:
			t.Errorf("unexpected query: %q", r.URL.RawQuery)
		}
	})
	c := New(srv.URL, "id", "secret")

	users, err := c.Search("budi")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(users) != 1 || users[0].Email != "budi.santoso@cni.net.id" {
		t.Errorf("users = %+v", users)
	}
}

func TestSearch_TooShortQueryIsNoOp(t *testing.T) {
	srv := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should never call the API for a query shorter than 2 chars")
	})
	c := New(srv.URL, "id", "secret")
	users, err := c.Search("a")
	if err != nil || users != nil {
		t.Errorf("users=%+v err=%v, want nil,nil", users, err)
	}
}
