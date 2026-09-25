// Package auth handles OIDC login against the OMS CNI SSO provider, session
// cookies, CSRF protection, and role-based access checks. The parts that
// matter for security — session validation, CSRF matching, role checks, and
// turning an identity provider's claims into a local user — are plain
// functions over small interfaces so they're testable without a real IdP.
package auth

import (
	"context"

	"haproxy-gui/internal/store"
)

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxSession
)

// WithUser attaches the authenticated user to ctx.
func WithUser(ctx context.Context, u store.User, sess store.Session) context.Context {
	ctx = context.WithValue(ctx, ctxUser, u)
	return context.WithValue(ctx, ctxSession, sess)
}

// UserFromContext returns the authenticated user, if any.
func UserFromContext(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(ctxUser).(store.User)
	return u, ok
}

// SessionFromContext returns the current session, if any.
func SessionFromContext(ctx context.Context) (store.Session, bool) {
	s, ok := ctx.Value(ctxSession).(store.Session)
	return s, ok
}
