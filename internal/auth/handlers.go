package auth

import (
	"html/template"
	"log"
	"net/http"

	"haproxy-gui/internal/store"
)

// LoginHandler renders the login page (GET /login).
type LoginHandler struct{ Templates *template.Template }

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	errMsg := r.URL.Query().Get("error")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.Templates.ExecuteTemplate(w, "login.html", struct{ Error string }{Error: errMsg})
}

// BeginLoginHandler starts the OIDC flow (GET /auth/login).
type BeginLoginHandler struct {
	Provider     *Provider
	CookieSecure bool
}

func (h *BeginLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.Provider.BeginLogin(w, r, h.CookieSecure); err != nil {
		http.Redirect(w, r, "/login?error=failed+to+start+login", http.StatusFound)
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
		http.Redirect(w, r, "/login?error=login+failed", http.StatusFound)
		return
	}
	if _, err := CompleteLogin(w, h.Store, claims, h.CookieSecure); err != nil {
		log.Printf("complete login failed for %s: %v", claims.Email, err)
		http.Redirect(w, r, "/login?error=account+is+disabled+or+invalid", http.StatusFound)
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
