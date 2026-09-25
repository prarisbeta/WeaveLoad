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

// SetSessionCookie writes sess as an HttpOnly, Secure, SameSite=Strict
// cookie. secure should be false only in local development over plain HTTP.
func SetSessionCookie(w http.ResponseWriter, sess store.Session, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
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
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

var errNoSessionCookie = errors.New("no session cookie")

// currentSession reads and validates the session cookie from r, disabled
// users included (Enabled is enforced separately so a deactivated account's
// existing session can be reported clearly rather than silently 404ing).
func currentSession(r *http.Request, s Sessions) (store.Session, store.User, error) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return store.Session{}, store.User{}, errNoSessionCookie
	}
	sess, err := s.Session(c.Value)
	if err != nil {
		return store.Session{}, store.User{}, err
	}
	u, err := s.UserByID(sess.UserID)
	if err != nil {
		return store.Session{}, store.User{}, err
	}
	return sess, u, nil
}

// RequireAuth rejects requests with no valid session (401) before calling
// next; otherwise it attaches the user/session to the request context.
func RequireAuth(s Sessions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, u, err := currentSession(r, s)
			if err != nil {
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

// RequireRole rejects (403) authenticated users whose role doesn't meet
// required. Must run after RequireAuth in the middleware chain.
func RequireRole(required store.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := UserFromContext(r.Context())
			if !ok {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			if !u.Role.Allows(required) {
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
