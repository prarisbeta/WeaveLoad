package auth

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"haproxy-gui/internal/store"
)

// LoginHandler renders the login page (GET /login).
type LoginHandler struct{ Templates *template.Template }

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	errMsg := r.URL.Query().Get("error")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	al := r.Header.Get("Accept-Language")
	lang := "id"
	if len(al) >= 2 && (al[0:2] == "id" || al[0:2] == "en") {
		lang = al[0:2]
	}
	_ = h.Templates.ExecuteTemplate(w, "login.html", struct{ Error, Language string }{Error: errMsg, Language: lang})
}

// BeginLoginHandler starts the OIDC flow (GET /auth/login).
type BeginLoginHandler struct {
	Provider     *Provider
	CookieSecure bool
}

func (h *BeginLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.Provider.BeginLogin(w, r, h.CookieSecure); err != nil {
		http.Redirect(w, r, "/login?error=Gagal+memulai+proses+masuk%2C+coba+lagi", http.StatusFound)
	}
}

// CallbackHandler completes the OIDC flow (GET /auth/callback).
type CallbackHandler struct {
	Provider     *Provider
	Store        *store.Store
	CookieSecure bool
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims, err := h.Provider.HandleCallback(r)
	if err != nil {
		log.Printf("oidc callback failed: %v", err)
		http.Redirect(w, r, "/login?error=Proses+masuk+gagal%2C+coba+lagi", http.StatusFound)
		return
	}
	if _, err := CompleteLogin(w, h.Store, claims, h.CookieSecure); err != nil {
		log.Printf("complete login failed for %s: %v", claims.Email, err)
		http.Redirect(w, r, "/login?error=Akun+ini+nonaktif+atau+tidak+valid", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// LogoutHandler ends the current session (POST /auth/logout).
type LogoutHandler struct {
	Store        *store.Store
	CookieSecure bool
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if sess, ok := SessionFromContext(r.Context()); ok {
		_ = h.Store.DeleteSession(sess.ID)
	}
	ClearSessionCookie(w, h.CookieSecure)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// UserAuthenticator is the subset of store needed for username/password login.
type UserAuthenticator interface {
	AuthenticateUser(usernameOrEmail, password string) (store.User, error)
	CreateSession(userID int64, ttl time.Duration) (store.Session, error)
	VerifyAndUseRecoveryCode(userID int64, code string) (bool, error)
}

// PasswordLoginHandler handles username/password login form submission (POST /auth/login-password).
type PasswordLoginHandler struct {
	Auth         UserAuthenticator
	Templates    *template.Template
	CookieSecure bool
}

func (h *PasswordLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?error=Permintaan+tidak+valid", http.StatusFound)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	totpCode := strings.TrimSpace(r.FormValue("totp_code"))

	al := r.Header.Get("Accept-Language")
	lang := "id"
	if len(al) >= 2 && (al[0:2] == "id" || al[0:2] == "en") {
		lang = al[0:2]
	}

	if username == "" || password == "" {
		h.reject(w, r, http.StatusBadRequest, loginView{Error: "Username dan password wajib diisi", Language: lang})
		return
	}

	u, err := h.Auth.AuthenticateUser(username, password)
	if err != nil {
		log.Printf("password login failed for %s: %v", username, err)
		h.reject(w, r, http.StatusUnauthorized, loginView{Error: "Username atau password salah", Language: lang})
		return
	}
	if !u.Enabled {
		log.Printf("password login attempt for disabled user %s", username)
		h.reject(w, r, http.StatusForbidden, loginView{Error: "Akun ini nonaktif", Language: lang})
		return
	}

	if u.TOTPEnabled {
		// The password is echoed back into the second-step form so the user
		// does not retype it; it never leaves this response.
		again := loginView{Language: lang, Username: username, Password: password, RequireTOTP: true}
		if totpCode == "" {
			// Not an error yet: ask for the code. Without templates there is
			// no form to ask on, so the login must fail rather than continue.
			if h.Templates == nil {
				h.reject(w, r, http.StatusUnauthorized, loginView{Error: "Kode 2FA diperlukan", Language: lang})
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = h.Templates.ExecuteTemplate(w, "login.html", again)
			return
		}
		valid := VerifyTOTPCode(u.TOTPSecret, totpCode, time.Now())
		if !valid {
			var recErr error
			valid, recErr = h.Auth.VerifyAndUseRecoveryCode(u.ID, totpCode)
			if recErr != nil {
				log.Printf("verify recovery code error: %v", recErr)
			}
		}
		if !valid {
			log.Printf("2FA code verification failed for %s", username)
			again.Error = "Kode 2FA / Pemulihan tidak valid"
			h.reject(w, r, http.StatusUnauthorized, again)
			return
		}
	}

	sess, err := h.Auth.CreateSession(u.ID, SessionTTL)
	if err != nil {
		log.Printf("create session failed for %s: %v", username, err)
		http.Redirect(w, r, "/login?error=Gagal+membuat+sesi+login", http.StatusFound)
		return
	}

	SetSessionCookie(w, sess, h.CookieSecure)
	http.Redirect(w, r, "/", http.StatusFound)
}

// loginView is the data login.html renders with.
type loginView struct {
	Error, Language, Username, Password string
	RequireTOTP                         bool
}

// reject answers a failed login: the login page with the given status when
// templates are available, otherwise a redirect back to /login carrying the
// message. Redirecting after WriteHeader would be ignored, so only one of the
// two ever runs.
func (h *PasswordLoginHandler) reject(w http.ResponseWriter, r *http.Request, status int, v loginView) {
	if h.Templates == nil {
		http.Redirect(w, r, "/login?error="+url.QueryEscape(v.Error), http.StatusFound)
		return
	}
	w.WriteHeader(status)
	_ = h.Templates.ExecuteTemplate(w, "login.html", v)
}
