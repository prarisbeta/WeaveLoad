package auth

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/store"
)

type fakeAuthenticator struct {
	user     store.User
	authErr  error
	sess     store.Session
	sessErr  error
	lastUser string
	lastPass string

	recoveryOK  bool
	recoveryErr error
}

func (f *fakeAuthenticator) AuthenticateUser(username, password string) (store.User, error) {
	f.lastUser = username
	f.lastPass = password
	if f.authErr != nil {
		return store.User{}, f.authErr
	}
	return f.user, nil
}

func (f *fakeAuthenticator) VerifyAndUseRecoveryCode(userID int64, code string) (bool, error) {
	return f.recoveryOK, f.recoveryErr
}

func (f *fakeAuthenticator) CreateSession(userID int64, ttl time.Duration) (store.Session, error) {
	if f.sessErr != nil {
		return store.Session{}, f.sessErr
	}
	return f.sess, nil
}

func TestPasswordLoginHandler_GET_RedirectsToLogin(t *testing.T) {
	h := &PasswordLoginHandler{Auth: &fakeAuthenticator{}}
	req := httptest.NewRequest(http.MethodGet, "/auth/login-password", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
}

func TestPasswordLoginHandler_EmptyCredentials_RedirectsWithError(t *testing.T) {
	h := &PasswordLoginHandler{Auth: &fakeAuthenticator{}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login-password", strings.NewReader("username=&password="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Errorf("location = %q, want error parameter", rec.Header().Get("Location"))
	}
}

func TestPasswordLoginHandler_InvalidPassword_RedirectsWithError(t *testing.T) {
	fa := &fakeAuthenticator{authErr: errors.New("invalid password")}
	h := &PasswordLoginHandler{Auth: fa}
	req := httptest.NewRequest(http.MethodPost, "/auth/login-password", strings.NewReader("username=konsolgw&password=wrongpassword"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Errorf("location = %q, want error parameter", rec.Header().Get("Location"))
	}
	if fa.lastUser != "konsolgw" || fa.lastPass != "wrongpassword" {
		t.Errorf("authenticator received user=%q pass=%q", fa.lastUser, fa.lastPass)
	}
}

func TestPasswordLoginHandler_DisabledUser_RedirectsWithError(t *testing.T) {
	fa := &fakeAuthenticator{user: store.User{ID: 1, Email: "konsolgw", Enabled: false}}
	h := &PasswordLoginHandler{Auth: fa}
	req := httptest.NewRequest(http.MethodPost, "/auth/login-password", strings.NewReader("username=konsolgw&password=gwkonsol"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Errorf("location = %q, want error parameter", rec.Header().Get("Location"))
	}
}

func TestPasswordLoginHandler_Success_SetsCookieAndRedirectsHome(t *testing.T) {
	sess := store.Session{ID: "sess-123", UserID: 1, CSRFToken: "csrf-token", ExpiresAt: time.Now().Add(time.Hour)}
	fa := &fakeAuthenticator{user: store.User{ID: 1, Email: "konsolgw", Enabled: true}, sess: sess}
	h := &PasswordLoginHandler{Auth: fa, CookieSecure: false}

	req := httptest.NewRequest(http.MethodPost, "/auth/login-password", strings.NewReader("username=konsolgw&password=gwkonsol"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if rec.Header().Get("Location") != "/" {
		t.Errorf("location = %q, want /", rec.Header().Get("Location"))
	}
	cookies := rec.Result().Cookies()
	var foundSess bool
	for _, c := range cookies {
		if c.Name == SessionCookieName && c.Value == "sess-123" {
			foundSess = true
			break
		}
	}
	if !foundSess {
		t.Errorf("session cookie not set correctly, got cookies: %+v", cookies)
	}
}

func TestPasswordLoginHandler_TOTPEnabledWithoutCode_NeverCreatesSession(t *testing.T) {
	fa := &fakeAuthenticator{
		user: store.User{ID: 1, Email: "konsolgw", Enabled: true, TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP"},
		sess: store.Session{ID: "sess-123"},
	}
	h := &PasswordLoginHandler{Auth: fa}
	req := httptest.NewRequest(http.MethodPost, "/auth/login-password", strings.NewReader("username=konsolgw&password=gwkonsol"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("session cookie set without a 2FA code: %v", rec.Result().Cookies())
	}
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Errorf("status=%d location=%q, want redirect to /login with an error", rec.Code, rec.Header().Get("Location"))
	}
}

// loginPageTemplates mirrors the fields the real login.html reads, so a
// handler that passes a struct missing one (e.g. RequireTOTP) fails here
// instead of silently serving a truncated page.
func loginPageTemplates(t *testing.T) *template.Template {
	t.Helper()
	return template.Must(template.New("login.html").Parse(
		`<form>{{if .RequireTOTP}}code{{else}}user:{{.Username}}{{end}}</form>` +
			`{{if .Error}}ERR={{.Error}}{{end}}{{if not .RequireTOTP}}<a href="/auth/login">sso</a>{{end}}END`))
}

func TestLoginHandler_RendersWholePageIncludingSSOButton(t *testing.T) {
	h := &LoginHandler{Templates: loginPageTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/login?error=boom", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `href="/auth/login"`) || !strings.HasSuffix(body, "END") {
		t.Fatalf("status=%d, page cut short or SSO button missing: %q", rec.Code, body)
	}
	if !strings.Contains(body, "ERR=boom") {
		t.Errorf("error message not shown: %q", body)
	}
}

func TestLoginHandler_TemplateFailureIs500NotATruncatedPage(t *testing.T) {
	broken := template.Must(template.New("login.html").Parse(`<form>{{.NoSuchField}}</form>tail`))
	h := &LoginHandler{Templates: broken}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "<form>") {
		t.Errorf("status=%d body=%q, want 500 and no partial HTML", rec.Code, rec.Body.String())
	}
}
