package main

import (
	"embed"
	"html/template"
	"net/http"

	"haproxy-gui/internal/appconfig"
	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/certs"
	"haproxy-gui/internal/cfgfile"
	"haproxy-gui/internal/runtime"
	"haproxy-gui/internal/store"
	"haproxy-gui/internal/web"
)

//go:embed static/*
var staticFS embed.FS

type routeDeps struct {
	templates *template.Template
	store     *store.Store
	runtime   *runtime.Client
	cfgfile   *cfgfile.Store
	certs     *certs.Store
	provider  *auth.Provider
	cfg       appconfig.Config
}

// chain applies middleware in the order given: chain(h, a, b, c) runs
// a(b(c(h))), i.e. the first middleware listed is the outermost.
func chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

func buildRoutes(d routeDeps) http.Handler {
	mux := http.NewServeMux()

	requireAuth := auth.RequireAuth(d.store)
	requireOperator := auth.RequireRole(store.RoleOperator)
	requireAdmin := auth.RequireRole(store.RoleAdmin)
	secure := d.cfg.CookieSecure

	// --- public ---
	mux.Handle("GET /login", &auth.LoginHandler{Templates: d.templates})
	mux.Handle("GET /auth/login", &auth.BeginLoginHandler{Provider: d.provider, CookieSecure: secure})
	mux.Handle("GET /auth/callback", &auth.CallbackHandler{Provider: d.provider, Store: d.store, CookieSecure: secure})
	mux.Handle("POST /auth/logout", chain(&auth.LogoutHandler{Store: d.store, CookieSecure: secure}, requireAuth))
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))

	// --- viewer (read-only) ---
	dashboard := &web.DashboardHandler{Stats: d.runtime, Templates: d.templates}
	mux.Handle("GET /{$}", chain(dashboard, requireAuth))
	mux.Handle("GET /api/dashboard", chain(dashboard, requireAuth))

	auditHandler := &web.AuditHandler{Store: d.store, Templates: d.templates}
	mux.Handle("GET /audit", chain(auditHandler, requireAuth, requireOperator))
	mux.Handle("GET /audit/export", chain(&web.AuditExportHandler{Store: d.store}, requireAuth, requireOperator))

	certsHandler := &web.CertsHandler{Certs: d.certs, Templates: d.templates}
	mux.Handle("GET /certs", chain(certsHandler, requireAuth))

	aclHandler := &web.AclHandler{
		Files: []web.MapFile{
			{Label: "HTTP host routing", Path: "/etc/haproxy/maps/hosts_http.map", HasValue: true},
			{Label: "HTTPS host routing", Path: "/etc/haproxy/maps/hosts_https.map", HasValue: true},
			{Label: "HTTP -> HTTPS redirect list", Path: "/etc/haproxy/maps/https_redirect.lst", HasValue: false},
			{Label: "Stats page allowed IPs", Path: "/etc/haproxy/maps/admin_allow.lst", HasValue: false},
		},
		Runtime:   d.runtime,
		Audit:     d.store,
		Templates: d.templates,
	}
	mux.Handle("GET /acl", chain(aclHandler, requireAuth))

	// --- operator (runtime control) ---
	serverAction := &web.ServerActionHandler{Runtime: d.runtime, Audit: d.store, Refresh: d.runtime, Templates: d.templates}
	mux.Handle("POST /api/servers/action", chain(serverAction, requireAuth, requireOperator, auth.RequireCSRF))
	mux.Handle("POST /api/acl/add", chain(&web.AclAddHandler{AclHandler: aclHandler}, requireAuth, requireOperator, auth.RequireCSRF))
	mux.Handle("POST /api/acl/edit", chain(&web.AclEditHandler{AclHandler: aclHandler}, requireAuth, requireOperator, auth.RequireCSRF))
	mux.Handle("POST /api/acl/delete", chain(&web.AclDeleteHandler{AclHandler: aclHandler}, requireAuth, requireOperator, auth.RequireCSRF))

	// --- admin (config, certs, users) ---
	configHandler := &web.ConfigHandler{Config: d.cfgfile, Audit: d.store, Templates: d.templates}
	mux.Handle("GET /config", chain(configHandler, requireAuth, requireAdmin))
	mux.Handle("POST /api/config/validate", chain(&web.ValidateAction{Config: d.cfgfile, Templates: d.templates}, requireAuth, requireAdmin, auth.RequireCSRF))
	mux.Handle("POST /api/config/apply", chain(&web.SaveApplyAction{Config: d.cfgfile, Audit: d.store, Templates: d.templates}, requireAuth, requireAdmin, auth.RequireCSRF))
	mux.Handle("POST /api/config/rollback", chain(&web.RollbackAction{Config: d.cfgfile, Audit: d.store, Templates: d.templates}, requireAuth, requireAdmin, auth.RequireCSRF))

	mux.Handle("POST /api/certs/upload", chain(&web.CertUploadHandler{
		Stager: d.certs, StagingDir: d.cfg.StagingDir, Audit: d.store, Templates: d.templates,
	}, requireAuth, requireAdmin, auth.RequireCSRF))

	usersHandler := &web.UsersHandler{Store: d.store, Audit: d.store, Templates: d.templates}
	mux.Handle("GET /users", chain(usersHandler, requireAuth, requireAdmin))
	mux.Handle("POST /api/users/update", chain(&web.UserUpdateHandler{Store: d.store, Audit: d.store, Templates: d.templates}, requireAuth, requireAdmin, auth.RequireCSRF))
	mux.Handle("POST /api/users/create", chain(&web.UserCreateHandler{Store: d.store, Audit: d.store, Templates: d.templates}, requireAuth, requireAdmin, auth.RequireCSRF))

	return securityHeaders(mux)
}

// securityHeaders sets a strict, no-CDN Content-Security-Policy and other
// standard hardening headers on every response. htmx is served locally from
// /static, so 'self' is sufficient — no external script/style origins are
// ever needed.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
