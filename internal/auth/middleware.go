package auth

import (
	"errors"
	"net/http"
	"time"

	"haproxy-gui/internal/store"
)

// SessionCookieName is the browser cookie holding the opaque session ID.
const SessionCookieName = "haproxygui_session"

// Sessions is the subset of *store.Store this package needs, so tests can
// supply a fake instead of a real database.
type Sessions interface {
	Session(id string) (store.Session, error)
	UserByID(id int64) (store.User, error)
	DeleteSession(id string) error
}

// SetSessionCookie writes sess as an HttpOnly, Secure cookie. secure should
// be false only in local development over plain HTTP.
//
// SameSite=None, not Strict/Lax: this is always set from the OIDC callback
// handler, reached via a cross-site redirect from the IdP (oms.cni.net.id).
// Chrome and Firefox drop a cookie set with SameSite=Strict or Lax when the
// setting response itself arrived through a cross-site redirect chain
// (anti bounce-tracking behavior) — login would 302 to "/" but the session
// would never actually persist. CSRF is enforced separately via
// RequireCSRF's per-session token, so this doesn't weaken that.
func SetSessionCookie(w http.ResponseWriter, sess store.Session, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteNoneMode,
		Expires:  sess.ExpiresAt,
	})
}

// ClearSessionCookie logs the browser out client-side.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   -1,
	})
}

var errNoSessionCookie = errors.New("no session cookie")

// currentSession reads and validates the session cookie from r, disabled
// users included (Enabled is enforced separately so a deactivated account's
// existing session can be reported clearly rather than silently 404ing).
func currentSession(r *http.Request, s Sessions) (store.Session, store.User, error) {
	sessionID := ""
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		sessionID = c.Value
	} else if authHdr := r.Header.Get("Authorization"); len(authHdr) > 7 && authHdr[:7] == "Bearer " {
		sessionID = authHdr[7:]
	}

	if sessionID == "" {
		return store.Session{}, store.User{}, errNoSessionCookie
	}
	sess, err := s.Session(sessionID)
	if err != nil {
		return store.Session{}, store.User{}, err
	}
	u, err := s.UserByID(sess.UserID)
	if err != nil {
		return store.Session{}, store.User{}, err
	}
	return sess, u, nil
}

// RequireAuth rejects requests with no valid session before calling next;
// otherwise it attaches the user/session to the request context. A GET
// request from a normal page navigation (not an htmx fragment request) is
// redirected to /login instead of getting a bare 401, since a browser
// landing on a protected page has nothing useful to do with plain text.
func RequireAuth(s Sessions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, u, err := currentSession(r, s)
			if err != nil {
				if r.Method == http.MethodGet && !isHTMXRequest(r) {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			if !u.Enabled {
				http.Error(w, "account disabled", http.StatusForbidden)
				return
			}
			ctx := WithUser(r.Context(), u, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isHTMXRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// RequireCapability rejects (403) authenticated users whose role doesn't
// grant cap. Must run after RequireAuth in the middleware chain.
func RequireCapability(cap store.Capability) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := UserFromContext(r.Context())
			if !ok {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			if !u.Role.Can(cap) {
				http.Error(w, "insufficient permissions", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireCSRF checks the X-CSRF-Token header against the current session's
// token for state-changing methods. Safe methods (GET/HEAD/OPTIONS) pass
// through unchecked. Must run after RequireAuth.
func RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		sess, ok := SessionFromContext(r.Context())
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			token = r.FormValue("csrf_token")
		}
		if token == "" || !constantTimeEqual(token, sess.CSRFToken) {
			http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// SessionTTL is how long a login stays valid before re-authentication.
const SessionTTL = 30 * time.Minute
