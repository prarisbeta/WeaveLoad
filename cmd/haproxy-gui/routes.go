package main

import (
	"embed"
	"html/template"
	"io/fs"
	"log"
	"mime"
	"net/http"

	"haproxy-gui/internal/appconfig"
	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/certs"
	"haproxy-gui/internal/cfgfile"
	"haproxy-gui/internal/omsdir"
	"haproxy-gui/internal/runtime"
	"haproxy-gui/internal/store"
	"haproxy-gui/internal/sysinfo"
	"haproxy-gui/internal/web"
)

//go:embed static/*
var staticFS embed.FS

func init() {
	// Some hosts ship a /etc/mime.types that Go's mime package reads before
	// falling back to its own table, and that file doesn't always map ".js"
	// correctly (seen serving "text/plain" on the CentOS 7 target). Register
	// it explicitly so the static handler never depends on host mime config —
	// otherwise the browser refuses to run the script under our
	// X-Content-Type-Options: nosniff policy.
	mime.AddExtensionType(".js", "text/javascript; charset=utf-8")
}

// staticFiles roots the embedded FS at "static/" — //go:embed keeps that
// prefix on every entry, but the "/static/" URL prefix is stripped before
// the file server ever sees the request, so serving staticFS directly 404s
// on every asset.
func staticFiles() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("static assets: %v", err)
	}
	return sub
}

type routeDeps struct {
	templates *template.Template
	store     *store.Store
	runtime   *runtime.Client
	cfgfile   *cfgfile.Store
	certs     *certs.Store
	provider  *auth.Provider
	dir       *omsdir.Client
	sys       *sysinfo.Sampler
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
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFiles())))

	// --- viewer (read-only) ---
	dashboard := &web.DashboardHandler{Stats: d.runtime, Sys: d.sys, DiskPaths: d.cfg.SysDiskPaths, Templates: d.templates}
	mux.Handle("GET /{$}", chain(dashboard, requireAuth))
	mux.Handle("GET /api/dashboard", chain(dashboard, requireAuth))

	pools := &web.PoolService{Config: d.cfgfile, Stats: d.runtime, Audit: d.store, Templates: d.templates}
	mux.Handle("GET /pools", chain(&web.PoolsHandler{PoolService: pools}, requireAuth))
	mux.Handle("GET /pools/new", chain(&web.PoolNewFormHandler{PoolService: pools}, requireAuth, requireAdmin))
	mux.Handle("GET /pools/{name}", chain(&web.PoolDetailHandler{PoolService: pools}, requireAuth))
	mux.Handle("GET /pools/{name}/members/{member}/edit", chain(&web.PoolMemberEditForm{PoolService: pools}, requireAuth, requireAdmin))
	mux.Handle("GET /nodes", chain(&web.NodesHandler{PoolService: pools}, requireAuth))
	mux.Handle("GET /nodes/add-to-pool", chain(http.HandlerFunc(web.NodeAddRedirect), requireAuth, requireAdmin))

	auditHandler := &web.AuditHandler{Store: d.store, Templates: d.templates}
	mux.Handle("GET /audit", chain(auditHandler, requireAuth, requireOperator))
	mux.Handle("GET /audit/export", chain(&web.AuditExportHandler{Store: d.store}, requireAuth, requireOperator))

	certsHandler := &web.CertsHandler{Certs: d.certs, Templates: d.templates}
	mux.Handle("GET /certs", chain(certsHandler, requireAuth))

	logHandler := &web.LogHandler{Path: d.cfg.LogPath, Templates: d.templates}
	mux.Handle("GET /logs", chain(logHandler, requireAuth, requireOperator))

	aclHandler := &web.AclHandler{
		Files: []web.MapFile{
			{Label: "HTTP host routing", Path: "/etc/haproxy/maps/hosts_http.map", HasValue: true, ValueIsPool: true},
			{Label: "HTTPS host routing", Path: "/etc/haproxy/maps/hosts_https.map", HasValue: true, ValueIsPool: true},
			{Label: "HTTP -> HTTPS redirect list", Path: "/etc/haproxy/maps/https_redirect.lst", HasValue: false},
			{Label: "Stats page allowed IPs", Path: "/etc/haproxy/maps/admin_allow.lst", HasValue: false},
		},
		Runtime:   d.runtime,
		Audit:     d.store,
		Templates: d.templates,
		Config:    d.cfgfile,
	}
	mux.Handle("GET /acl", chain(aclHandler, requireAuth))

	// --- operator (runtime control) ---
	serverAction := &web.ServerActionHandler{Runtime: d.runtime, Audit: d.store, Refresh: d.runtime, Sys: d.sys, DiskPaths: d.cfg.SysDiskPaths, Templates: d.templates}
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

	// Adding/removing pool members rewrites haproxy.cfg and reloads, so it
	// sits with the config editor at admin level; state/weight stay operator.
	mux.Handle("POST /api/pools/{name}/members/preview", chain(&web.PoolMemberPreview{PoolService: pools}, requireAuth, requireAdmin, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/members/add", chain(&web.PoolMemberAdd{PoolService: pools}, requireAuth, requireAdmin, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/members/edit/preview", chain(&web.PoolMemberEditPreview{PoolService: pools}, requireAuth, requireAdmin, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/members/edit/apply", chain(&web.PoolMemberEditApply{PoolService: pools}, requireAuth, requireAdmin, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/members/remove", chain(&web.PoolMemberRemove{PoolService: pools}, requireAuth, requireAdmin, auth.RequireCSRF))
	mux.Handle("POST /api/pools/new/preview", chain(&web.PoolNewPreview{PoolService: pools}, requireAuth, requireAdmin, auth.RequireCSRF))
	mux.Handle("POST /api/pools/new/apply", chain(&web.PoolNewApply{PoolService: pools}, requireAuth, requireAdmin, auth.RequireCSRF))

	mux.Handle("POST /api/certs/upload", chain(&web.CertUploadHandler{
		Stager: d.certs, StagingDir: d.cfg.StagingDir, Audit: d.store, Templates: d.templates,
	}, requireAuth, requireAdmin, auth.RequireCSRF))

	usersHandler := &web.UsersHandler{Store: d.store, Audit: d.store, Templates: d.templates}
	mux.Handle("GET /users", chain(usersHandler, requireAuth, requireAdmin))
	mux.Handle("POST /api/users/update", chain(&web.UserUpdateHandler{Store: d.store, Audit: d.store, Templates: d.templates}, requireAuth, requireAdmin, auth.RequireCSRF))
	mux.Handle("POST /api/users/create", chain(&web.UserCreateHandler{Store: d.store, Audit: d.store, Templates: d.templates}, requireAuth, requireAdmin, auth.RequireCSRF))
	mux.Handle("GET /api/users/search", chain(&web.UserSearchHandler{Directory: d.dir, Templates: d.templates}, requireAuth, requireAdmin))

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
