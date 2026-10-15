package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/omsdir"
	"haproxy-gui/internal/store"
)

type fakeDirectory struct {
	enabled bool
	results []omsdir.User
	err     error
	lastQ   string
}

func (f *fakeDirectory) Enabled() bool { return f.enabled }
func (f *fakeDirectory) Search(q string) ([]omsdir.User, error) {
	f.lastQ = q
	return f.results, f.err
}

type fakeUserAdmin struct {
	users     []store.User
	listErr   error
	roleErr   error
	enErr     error
	createErr error
	delErr    error
	resetErr  error
	lastRole  store.Role
	lastID    int64
	deletedID int64
	resetID   int64
	resetPW   string
	lastEn    *bool
	created   *store.User // last CreateUser call's (email, name, role), for assertions
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
func (f *fakeUserAdmin) CreateUser(email, name string, role store.Role) (store.User, error) {
	if f.createErr != nil {
		return store.User{}, f.createErr
	}
	u := store.User{ID: 99, Email: email, Name: name, Role: role, Enabled: true}
	f.created = &u
	f.users = append(f.users, u)
	return u, nil
}
func (f *fakeUserAdmin) DeleteUser(id int64) error {
	f.deletedID = id
	return f.delErr
}
func (f *fakeUserAdmin) ResetPassword(id int64, newPW string) error {
	f.resetID, f.resetPW = id, newPW
	return f.resetErr
}

func usersTemplates(t *testing.T) *template.Template {
	return mustParse(t, `
{{define "users.html"}}{{template "users_table.html" .}}{{end}}
{{define "users_table.html"}}{{range .Users}}{{.Email}}:{{.Role}} {{end}}{{end}}
{{define "user_search_results.html"}}{{if not .Enabled}}DISABLED{{else if .Error}}ERR:{{.Error}}{{else}}{{range .Results}}{{.Email}}({{.Name}}){{end}}{{end}}{{end}}
`)
}

func TestUsersHandler_ListsUsers(t *testing.T) {
	ua := &fakeUserAdmin{users: []store.User{{ID: 1, Email: "a@x.id", Role: store.RolePlatformAdmin}}}
	h := &UsersHandler{Store: ua, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "a@x.id:platform_admin") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestUserUpdateHandler_SetRole(t *testing.T) {
	ua := &fakeUserAdmin{users: []store.User{{ID: 2, Email: "b@x.id", Role: store.RoleNOCOperator}}}
	au := &fakeAudit{}
	h := &UserUpdateHandler{Store: ua, Audit: au, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/update", strings.NewReader("user_id=2&action=set_role&role=noc_operator"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{ID: 1, Email: "admin@x.id"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if ua.lastID != 2 || ua.lastRole != store.RoleNOCOperator {
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

func TestUserUpdateHandler_CannotDeleteSelf(t *testing.T) {
	ua := &fakeUserAdmin{}
	h := &UserUpdateHandler{Store: ua, Audit: &fakeAudit{}, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/update", strings.NewReader("user_id=1&action=delete"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{ID: 1, Email: "admin@x.id"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (an admin must not be able to delete themselves)", rec.Code)
	}
	if ua.deletedID != 0 {
		t.Error("DeleteUser should never have been called")
	}
}

func TestUserUpdateHandler_DeleteOtherUser_OK(t *testing.T) {
	ua := &fakeUserAdmin{}
	au := &fakeAudit{}
	h := &UserUpdateHandler{Store: ua, Audit: au, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/update", strings.NewReader("user_id=2&action=delete"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{ID: 1, Email: "admin@x.id"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if ua.deletedID != 2 {
		t.Errorf("deletedID = %d, want 2", ua.deletedID)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "user.delete" {
		t.Errorf("audit entries = %+v", au.entries)
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

func TestUserCreateHandler_PreRegistersAccount(t *testing.T) {
	ua := &fakeUserAdmin{}
	au := &fakeAudit{}
	h := &UserCreateHandler{Store: ua, Audit: au, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/create", strings.NewReader("email=Baru@Example.id&name=Baru&role=noc_operator"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{ID: 1, Email: "admin@x.id"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if ua.created == nil || ua.created.Email != "Baru@Example.id" || ua.created.Role != store.RoleNOCOperator {
		t.Errorf("CreateUser called with = %+v", ua.created)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "user.create" {
		t.Errorf("audit entries = %+v", au.entries)
	}
	if !strings.Contains(rec.Body.String(), "Baru@Example.id:noc_operator") {
		t.Errorf("expected the new user in the re-rendered list, got %q", rec.Body.String())
	}
}

func TestUserCreateHandler_RejectsInvalidEmail(t *testing.T) {
	ua := &fakeUserAdmin{}
	h := &UserCreateHandler{Store: ua, Audit: &fakeAudit{}, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/create", strings.NewReader("email=not-an-email&role=viewer"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if ua.created != nil {
		t.Error("CreateUser should never have been called for an invalid email")
	}
}

func TestUserCreateHandler_RejectsUnknownRole(t *testing.T) {
	ua := &fakeUserAdmin{}
	h := &UserCreateHandler{Store: ua, Audit: &fakeAudit{}, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/create", strings.NewReader("email=x@example.id&role=superuser"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if ua.created != nil {
		t.Error("CreateUser should never have been called for an invalid role")
	}
}

func TestUserCreateHandler_DuplicateEmail_409(t *testing.T) {
	ua := &fakeUserAdmin{createErr: store.ErrEmailTaken}
	au := &fakeAudit{}
	h := &UserCreateHandler{Store: ua, Audit: au, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/create", strings.NewReader("email=dup@example.id&role=viewer"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{ID: 1, Email: "admin@x.id"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
	if len(au.entries) != 1 {
		t.Errorf("a failed create should still be audit-logged, got %+v", au.entries)
	}
}

func TestUserSearchHandler_DisabledDirectory(t *testing.T) {
	h := &UserSearchHandler{Directory: &fakeDirectory{enabled: false}, Templates: usersTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/api/users/search?q=budi", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DISABLED") {
		t.Errorf("body = %q, want the disabled branch", rec.Body.String())
	}
}

func TestUserSearchHandler_NilDirectoryIsTreatedAsDisabled(t *testing.T) {
	h := &UserSearchHandler{Directory: nil, Templates: usersTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/api/users/search?q=budi", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "DISABLED") {
		t.Errorf("body = %q, want the disabled branch for a nil Directory", rec.Body.String())
	}
}

func TestUserSearchHandler_ReturnsResults(t *testing.T) {
	dir := &fakeDirectory{enabled: true, results: []omsdir.User{{Name: "Budi", Email: "budi@cni.net.id"}}}
	h := &UserSearchHandler{Directory: dir, Templates: usersTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/api/users/search?q=budi", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if dir.lastQ != "budi" {
		t.Errorf("query passed to Search = %q", dir.lastQ)
	}
	if !strings.Contains(rec.Body.String(), "budi@cni.net.id(Budi)") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestUserSearchHandler_EmptyQuerySkipsSearch(t *testing.T) {
	dir := &fakeDirectory{enabled: true}
	h := &UserSearchHandler{Directory: dir, Templates: usersTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/api/users/search?q=", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if dir.lastQ != "" {
		t.Error("Search should not be called for an empty query")
	}
}

func TestUserSearchHandler_DirectoryError(t *testing.T) {
	dir := &fakeDirectory{enabled: true, err: assertErr("upstream timeout")}
	h := &UserSearchHandler{Directory: dir, Templates: usersTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/api/users/search?q=budi", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the fragment itself reports the error)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ERR:") {
		t.Errorf("body = %q, want the error branch", rec.Body.String())
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

type fakeLangStore struct {
	lastID   int64
	lastLang string
	err      error
}

func (f *fakeLangStore) SetLanguage(userID int64, lang string) error {
	f.lastID = userID
	f.lastLang = lang
	return f.err
}

func TestProfileLanguageHandler(t *testing.T) {
	ls := &fakeLangStore{}
	h := &ProfileLanguageHandler{Store: ls}

	// GET redirects to /
	req := httptest.NewRequest(http.MethodGet, "/api/profile/language", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Errorf("GET status = %d, loc = %q, want 303 /", rec.Code, rec.Header().Get("Location"))
	}

	// Invalid lang
	req = httptest.NewRequest(http.MethodPost, "/api/profile/language", strings.NewReader("language=fr"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}

	// Valid lang with user context
	u := store.User{ID: 42, Email: "user@example.com"}
	ctx := auth.WithUser(req.Context(), u, store.Session{})
	req = httptest.NewRequest(http.MethodPost, "/api/profile/language", strings.NewReader("language=en")).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://example.com/pools")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", rec.Code)
	}
	if rec.Header().Get("Location") != "https://example.com/pools" {
		t.Errorf("location = %q, want https://example.com/pools", rec.Header().Get("Location"))
	}
	if ls.lastID != 42 || ls.lastLang != "en" {
		t.Errorf("store got id=%d lang=%s, want 42 en", ls.lastID, ls.lastLang)
	}

	// Valid lang zh
	req = httptest.NewRequest(http.MethodPost, "/api/profile/language", strings.NewReader("language=zh")).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if ls.lastLang != "zh" {
		t.Errorf("store got lang=%s, want zh", ls.lastLang)
	}

	// Valid lang ja
	req = httptest.NewRequest(http.MethodPost, "/api/profile/language", strings.NewReader("language=ja")).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if ls.lastLang != "ja" {
		t.Errorf("store got lang=%s, want ja", ls.lastLang)
	}
}

func TestUserUpdateHandler_ResetPassword(t *testing.T) {
	ua := &fakeUserAdmin{}
	au := &fakeAudit{}
	h := &UserUpdateHandler{Store: ua, Audit: au, Templates: usersTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/users/update", strings.NewReader("user_id=2&action=reset_password&new_password=secret123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{ID: 1, Email: "admin@x.id"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if ua.resetID != 2 || ua.resetPW != "secret123" {
		t.Errorf("ResetPassword called with id=%d pw=%s", ua.resetID, ua.resetPW)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "user.reset_password" {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

type fakePWStore struct {
	lastID int64
	oldPW  string
	newPW  string
	err    error
}

func (f *fakePWStore) ChangePassword(userID int64, oldPassword, newPassword string) error {
	f.lastID, f.oldPW, f.newPW = userID, oldPassword, newPassword
	return f.err
}

func TestProfilePasswordHandler(t *testing.T) {
	ps := &fakePWStore{}
	au := &fakeAudit{}
	h := &ProfilePasswordHandler{Store: ps, Audit: au}

	u := store.User{ID: 10, Email: "user@example.com"}
	req := httptest.NewRequest(http.MethodPost, "/api/profile/password", strings.NewReader("old_password=old&new_password=new"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := auth.WithUser(req.Context(), u, store.Session{})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if ps.lastID != 10 || ps.oldPW != "old" || ps.newPW != "new" {
		t.Errorf("store received id=%d old=%s new=%s", ps.lastID, ps.oldPW, ps.newPW)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "user.change_password" {
		t.Errorf("audit entries = %+v", au.entries)
	}
}
