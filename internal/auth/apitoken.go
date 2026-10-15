package auth

import (
	"context"
	"net/http"
	"strings"

	"haproxy-gui/internal/store"
)

// TokenVerifier checks a long-lived API token (see store.APIToken).
type TokenVerifier interface {
	VerifyAPIToken(plain string) (store.APIToken, error)
}

const ctxAPIToken ctxKey = 100

// APITokenFromContext returns the API token the request authenticated with,
// if it did so by token rather than by browser session.
func APITokenFromContext(ctx context.Context) (store.APIToken, bool) {
	t, ok := ctx.Value(ctxAPIToken).(store.APIToken)
	return t, ok
}

// tokenUser is the identity a token acts as: the read-only Auditor role, so
// a token can read what /api/v1 serves (status, backends, security
// incidents) and nothing that changes state.
func tokenUser(t store.APIToken) store.User {
	return store.User{
		ID:      0,
		Email:   "api-token:" + t.Name,
		Name:    t.Name,
		Role:    store.RoleAuditor,
		Enabled: true,
	}
}

// bearerToken returns the value of an "Authorization: Bearer ..." header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func isAPIToken(s string) bool { return strings.HasPrefix(s, "kgw_") }

func unauthorizedToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="konsol-gateway"`)
	http.Error(w, "invalid or missing API token", http.StatusUnauthorized)
}

func authenticateToken(w http.ResponseWriter, r *http.Request, v TokenVerifier, plain string) (*http.Request, bool) {
	t, err := v.VerifyAPIToken(plain)
	if err != nil {
		unauthorizedToken(w)
		return nil, false
	}
	ctx := WithUser(r.Context(), tokenUser(t), store.Session{})
	ctx = context.WithValue(ctx, ctxAPIToken, t)
	return r.WithContext(ctx), true
}

// RequireAuthOrToken accepts either a "Bearer kgw_..." API token or a normal
// browser session. A token that does not verify is a 401 with a Bearer
// challenge — never a login redirect and never a fall-through to the session
// check, so a script gets a clear answer.
func RequireAuthOrToken(s Sessions, v TokenVerifier) func(http.Handler) http.Handler {
	session := RequireAuth(s)
	return func(next http.Handler) http.Handler {
		withSession := session(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if plain := bearerToken(r); isAPIToken(plain) {
				if r2, ok := authenticateToken(w, r, v, plain); ok {
					next.ServeHTTP(w, r2)
				}
				return
			}
			withSession.ServeHTTP(w, r)
		})
	}
}

// RequireAPIToken accepts only an API token. Browser sessions (cookie or
// session id as bearer) are refused, so an endpoint meant for machine clients
// is never reachable with ambient browser credentials.
func RequireAPIToken(v TokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plain := bearerToken(r)
			if !isAPIToken(plain) {
				unauthorizedToken(w)
				return
			}
			if r2, ok := authenticateToken(w, r, v, plain); ok {
				next.ServeHTTP(w, r2)
			}
		})
	}
}
