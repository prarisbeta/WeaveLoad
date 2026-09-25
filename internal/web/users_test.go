package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"haproxy-gui/internal/store"
)

type fakeUserAdmin struct {
	users    []store.User
	listErr  error
	roleErr  error
	enErr    error
	lastRole store.Role
	lastID   int64
	lastEn   *bool
}

func (f *fakeUserAdmin) ListUsers() ([]store.User, error) { return f.users, f.listErr }
func (f *fakeUserAdmin) SetRole(id int64, role store.Role) error {
	f.lastID, f.lastRole = id, role
	return f.roleErr
}
func (f *fakeUserAdmin) SetEnabled(id int64, enabled bool) error {
	f.lastID, f.lastEn = id, &enabled
	return f.enErr
}

func usersTemplates(t *testing.T) *template.Template {
	return mustParse(t, `
{{define "users.html"}}{{template "users_table.html" .}}{{end}}
{{define "users_table.html"}}{{range .Users}}{{.Email}}:{{.Role}} {{end}}{{end}}
`)
}

func TestUsersHandler_ListsUsers(t *testing.T) {
	ua := &fakeUserAdmin{users: []store.User{{ID: 1, Email: "a@x.id", Role: store.RoleAdmin}}}
	h := &UsersHandler{Store: ua, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "a@x.id:admin") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestUserUpdateHandler_SetRole(t *testing.T) {
	ua := &fakeUserAdmin{users: []store.User{{ID: 2, Email: "b@x.id", Role: store.RoleOperator}}}
	au := &fakeAudit{}
	h := &UserUpdateHandler{Store: ua, Audit: au, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/update", strings.NewReader("user_id=2&action=set_role&role=operator"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{ID: 1, Email: "admin@x.id"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if ua.lastID != 2 || ua.lastRole != store.RoleOperator {
		t.Errorf("SetRole called with id=%d role=%s", ua.lastID, ua.lastRole)
	}
	if len(au.entries) != 1 {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestUserUpdateHandler_CannotDemoteSelf(t *testing.T) {
	ua := &fakeUserAdmin{}
	h := &UserUpdateHandler{Store: ua, Audit: &fakeAudit{}, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/update", strings.NewReader("user_id=1&action=set_role&role=viewer"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{ID: 1, Email: "admin@x.id"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (an admin must not be able to demote themselves)", rec.Code)
	}
	if ua.lastRole != "" {
		t.Error("SetRole should never have been called")
	}
}

func TestUserUpdateHandler_CannotDisableSelf(t *testing.T) {
	ua := &fakeUserAdmin{}
	h := &UserUpdateHandler{Store: ua, Audit: &fakeAudit{}, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/update", strings.NewReader("user_id=1&action=disable"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{ID: 1, Email: "admin@x.id"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if ua.lastEn != nil {
		t.Error("SetEnabled should never have been called")
	}
}

func TestUserUpdateHandler_DisableOtherUser_OK(t *testing.T) {
	ua := &fakeUserAdmin{}
	au := &fakeAudit{}
	h := &UserUpdateHandler{Store: ua, Audit: au, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/update", strings.NewReader("user_id=2&action=disable"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{ID: 1, Email: "admin@x.id"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if ua.lastEn == nil || *ua.lastEn != false {
		t.Errorf("SetEnabled call = %+v", ua.lastEn)
	}
}

func TestUserUpdateHandler_UnknownAction_400(t *testing.T) {
	h := &UserUpdateHandler{Store: &fakeUserAdmin{}, Audit: &fakeAudit{}, Templates: usersTemplates(t)}
	req := httptest.NewRequest(http.MethodPost, "/api/users/update", strings.NewReader("user_id=2&action=explode"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{ID: 1})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestUserUpdateHandler_InvalidUserID_400(t *testing.T) {
	h := &UserUpdateHandler{Store: &fakeUserAdmin{}, Audit: &fakeAudit{}, Templates: usersTemplates(t)}
	req := httptest.NewRequest(http.MethodPost, "/api/users/update", strings.NewReader("user_id=abc&action=enable"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
