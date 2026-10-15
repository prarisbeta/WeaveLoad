package main

import (
	"embed"
	"html/template"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"

	"haproxy-gui/internal/ai"
	"haproxy-gui/internal/appconfig"
	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/canary"
	"haproxy-gui/internal/certs"
	"haproxy-gui/internal/cfgfile"
	"haproxy-gui/internal/errorpages"
	"haproxy-gui/internal/fleet"
	"haproxy-gui/internal/license"
	"haproxy-gui/internal/omsdir"
	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/runtime"
	"haproxy-gui/internal/store"
	"haproxy-gui/internal/sysinfo"
	"haproxy-gui/internal/threatintel"
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
	policy    *policy.Engine
	canary    *canary.Watcher
	intel     *threatintel.Service // nil unless feeds or an AbuseIPDB key are configured
	fleetHub  *fleet.Hub
	gate      *license.Gate // nil allows everything (tests, development)
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

	// nil unless KONSOLGW_GEMINI_API_KEY or KONSOLGW_ANTHROPIC_API_KEY is set;
	// the AI handlers then answer from the offline MockProvider.
	aiProvider := ai.FromEnv(os.Getenv)
	if !d.gate.Allows("copilot") {
		aiProvider = nil // the Pro licence includes the live AI providers
	}

	requireAuth := auth.RequireAuth(d.store)
	// requireAPI also accepts a "Bearer kgw_..." API token, for third-party and
	// MCP callers of /api/v1; browser pages keep requireAuth (session only).
	requireAPI := auth.RequireAuthOrToken(d.store, d.store)
	requireRuntimeControl := auth.RequireCapability(store.CapRuntimeControl)
	requireViewLogs := auth.RequireCapability(store.CapViewLogs)
	requireViewQueue := auth.RequireCapability(store.CapViewQueue)
	requireViewAudit := auth.RequireCapability(store.CapViewAudit)
	requireManageConfig := auth.RequireCapability(store.CapManageConfig)
	requireManageUsers := auth.RequireCapability(store.CapManageUsers)
	requireManageSettings := auth.RequireCapability(store.CapManageSettings)
	requireViewSecurity := auth.RequireCapability(store.CapViewSecurity)
	requireManageIncidents := auth.RequireCapability(store.CapManageIncidents)
	secure := d.cfg.CookieSecure

	// --- public ---
	mux.Handle("GET /login", &auth.LoginHandler{Templates: d.templates})
	mux.Handle("POST /auth/login-password", &auth.PasswordLoginHandler{Auth: d.store, Templates: d.templates, CookieSecure: secure})
	mux.Handle("GET /auth/login", &auth.BeginLoginHandler{Provider: d.provider, CookieSecure: secure})
	mux.Handle("GET /auth/callback", &auth.CallbackHandler{Provider: d.provider, Store: d.store, CookieSecure: secure})
	mux.Handle("POST /auth/logout", chain(&auth.LogoutHandler{Store: d.store, CookieSecure: secure}, requireAuth))
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFiles())))

	// --- viewer (read-only) ---
	dashboard := &web.DashboardHandler{Stats: d.runtime, Sys: d.sys, DiskPaths: d.cfg.SysDiskPaths, Templates: d.templates}
	mux.Handle("GET /{$}", chain(dashboard, requireAuth))
	mux.Handle("GET /api/dashboard", chain(dashboard, requireAuth))

	pools := &web.PoolService{Config: d.cfgfile, Stats: d.runtime, Runtime: d.runtime, Audit: d.store, Templates: d.templates}
	mux.Handle("GET /pools", chain(&web.PoolsHandler{PoolService: pools}, requireAuth))
	mux.Handle("GET /pools/new", chain(&web.PoolNewFormHandler{PoolService: pools}, requireAuth, requireManageConfig))
	mux.Handle("GET /pools/{name}", chain(&web.PoolDetailHandler{PoolService: pools}, requireAuth))
	mux.Handle("GET /pools/{name}/members/{member}/edit", chain(&web.PoolMemberEditForm{PoolService: pools}, requireAuth, requireManageConfig))
	mux.Handle("GET /nodes", chain(&web.NodesHandler{PoolService: pools}, requireAuth))
	mux.Handle("GET /nodes/add-to-pool", chain(http.HandlerFunc(web.NodeAddRedirect), requireAuth, requireManageConfig))
	mux.Handle("POST /api/nodes/action", chain(&web.NodeActionHandler{PoolService: pools}, requireAuth, requireRuntimeControl, auth.RequireCSRF))

	auditHandler := &web.AuditHandler{Store: d.store, Templates: d.templates}
	mux.Handle("GET /audit", chain(auditHandler, requireAuth, requireViewAudit))
	mux.Handle("GET /audit/export", chain(&web.AuditExportHandler{Store: d.store}, requireAuth, requireViewAudit))

	certsHandler := &web.CertsHandler{Certs: d.certs, Templates: d.templates}
	mux.Handle("GET /certs", chain(certsHandler, requireAuth))

	logHandler := &web.LogHandler{Path: d.cfg.LogPath, Templates: d.templates}
	mux.Handle("GET /logs", chain(logHandler, requireAuth, requireViewLogs))

	errPagesMgr := errorpages.NewManager("")
	errorPagesHandler := &web.ErrorPagesHandler{Manager: errPagesMgr, Audit: d.store, Templates: d.templates}
	mux.Handle("GET /config/error-pages", chain(errorPagesHandler, requireAuth, requireManageConfig))
	mux.Handle("POST /api/config/error-pages/{code}", chain(&web.ErrorPageSaveAction{Manager: errPagesMgr, Audit: d.store, Templates: d.templates}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("GET /api/config/error-pages/{code}/preview", &web.ErrorPagePreviewHandler{Manager: errPagesMgr})
	mux.Handle("POST /api/config/error-pages/{code}/preview", &web.ErrorPagePreviewHandler{Manager: errPagesMgr})
	mux.Handle("GET /api/config/error-pages/{code}/preset", &web.ErrorPagePresetHandler{})

	queueHandler := &web.QueueHandler{Store: d.store, Runtime: d.runtime, Templates: d.templates}
	mux.Handle("GET /queue", chain(queueHandler, requireAuth, requireViewQueue))
	mux.Handle("POST /api/queue/clear", chain(&web.QueueClearAction{Store: d.store, Audit: d.store}, requireAuth, requireRuntimeControl, auth.RequireCSRF))
	mux.Handle("POST /api/queue/release-ip", chain(&web.QueueReleaseIPAction{Runtime: d.runtime, Audit: d.store}, requireAuth, requireRuntimeControl, auth.RequireCSRF))
	mux.Handle("POST /api/queue/forward-incident", chain(&web.QueueForwardIncidentAction{Store: d.store, Audit: d.store}, requireAuth, requireManageIncidents, auth.RequireCSRF))
	mux.Handle("GET /queue/waiting-room", &web.QueueWaitingRoomHandler{Manager: errPagesMgr})

	securityHandler := &web.SecurityHandler{Store: d.store, Templates: d.templates}
	mux.Handle("GET /security", chain(securityHandler, requireAuth, requireViewSecurity))
	mux.Handle("GET /security/events/{id}", chain(&web.SecurityEventDetail{Store: d.store, Templates: d.templates}, requireAuth, requireViewSecurity))
	ipHandler := &web.SecurityIPHandler{Store: d.store, Templates: d.templates}
	if d.intel != nil { // assigning a nil *Service would make the interface non-nil
		ipHandler.Intel = d.intel
	}
	mux.Handle("GET /security/ip/{ip}", chain(ipHandler, requireAuth, requireViewSecurity))
	mux.Handle("POST /api/security/events/{id}/status", chain(&web.SecurityEventStatusAction{Store: d.store, Audit: d.store}, requireAuth, requireManageIncidents, auth.RequireCSRF))

	// --- incident management & evidence bundle (P7) ---
	mux.Handle("GET /incidents", chain(&web.IncidentsHandler{Store: d.store, Templates: d.templates}, requireAuth, requireViewSecurity))
	mux.Handle("GET /incidents/new", chain(&web.IncidentNewHandler{Store: d.store, Audit: d.store, Templates: d.templates}, requireAuth, requireManageIncidents))
	mux.Handle("POST /incidents/new", chain(&web.IncidentNewHandler{Store: d.store, Audit: d.store, Templates: d.templates}, requireAuth, requireManageIncidents, auth.RequireCSRF))
	mux.Handle("GET /incidents/{id}", chain(&web.IncidentDetailHandler{Store: d.store, Templates: d.templates}, requireAuth, requireViewSecurity))
	mux.Handle("GET /incidents/{id}/export", chain(&web.IncidentExportHandler{Store: d.store}, requireAuth, requireViewSecurity))
	mux.Handle("POST /api/incidents/{id}/status", chain(&web.IncidentStatusAction{Store: d.store, Audit: d.store}, requireAuth, requireManageIncidents, auth.RequireCSRF))
	mux.Handle("POST /api/incidents/{id}/notes", chain(&web.IncidentNoteAction{Store: d.store, Audit: d.store}, requireAuth, requireManageIncidents, auth.RequireCSRF))
	mux.Handle("POST /api/incidents/{id}/link", chain(&web.IncidentLinkAction{Store: d.store, Audit: d.store}, requireAuth, requireManageIncidents, auth.RequireCSRF))
	mux.Handle("POST /api/incidents/{id}/ai-analyze", chain(&web.AIIncidentAnalyzeHandler{Store: d.store, Provider: aiProvider}, requireAuth, requireViewSecurity, auth.RequireCSRF))
	mux.Handle("POST /api/security/events/{id}/ai-analyze", chain(&web.AISecurityAnalyzeHandler{Store: d.store, Provider: aiProvider}, requireAuth, requireViewSecurity, auth.RequireCSRF))

	aclHandler := &web.AclHandler{
		Files: []web.MapFile{
			{Label: "HTTP host routing", Path: "/etc/haproxy/maps/hosts_http.map", HasValue: true, ValueIsPool: true},
			{Label: "HTTPS host routing", Path: "/etc/haproxy/maps/hosts_https.map", HasValue: true, ValueIsPool: true},
			{Label: "HTTP -> HTTPS redirect list", Path: "/etc/haproxy/maps/https_redirect.lst", HasValue: false},
			{Label: "Stats page allowed IPs", Path: "/etc/haproxy/maps/admin_allow.lst", HasValue: false},
			{Label: "Blocklist IP", Path: "/etc/haproxy/maps/blocklist_ip.lst", HasValue: false},
			{Label: "Allowlist IP (Bypass limit & block)", Path: "/etc/haproxy/maps/allowlist_ip.lst", HasValue: false},
			{Label: "Rate Limit Host", Path: "/etc/haproxy/maps/ratelimit_host.map", HasValue: true, ValueIsPool: false},
		},
		Runtime:   d.runtime,
		Audit:     d.store,
		Templates: d.templates,
		Config:    d.cfgfile,
	}
	mux.Handle("GET /acl", chain(aclHandler, requireAuth))

	// --- runtime control (server enable/disable/drain/weight, ACL edits) ---
	serverAction := &web.ServerActionHandler{Runtime: d.runtime, Audit: d.store, Refresh: d.runtime, Sys: d.sys, DiskPaths: d.cfg.SysDiskPaths, Templates: d.templates}
	mux.Handle("POST /api/servers/action", chain(serverAction, requireAuth, requireRuntimeControl, auth.RequireCSRF))
	mux.Handle("POST /api/acl/add", chain(&web.AclAddHandler{AclHandler: aclHandler}, requireAuth, requireRuntimeControl, auth.RequireCSRF))
	mux.Handle("POST /api/acl/edit", chain(&web.AclEditHandler{AclHandler: aclHandler}, requireAuth, requireRuntimeControl, auth.RequireCSRF))
	mux.Handle("POST /api/acl/delete", chain(&web.AclDeleteHandler{AclHandler: aclHandler}, requireAuth, requireRuntimeControl, auth.RequireCSRF))

	// --- manage config (config editor, pools/members, rate limits, certs) ---
	configHandler := &web.ConfigHandler{Config: d.cfgfile, Audit: d.store, Templates: d.templates, Settings: d.store, Tokens: d.store}
	mux.Handle("GET /config", chain(configHandler, requireAuth, requireManageConfig))
	mux.Handle("POST /api/config/validate", chain(&web.ValidateAction{Config: d.cfgfile, Templates: d.templates}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/config/apply", chain(&web.SaveApplyAction{Config: d.cfgfile, Audit: d.store, Templates: d.templates, Canary: d.canary}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/config/rollback", chain(&web.RollbackAction{Config: d.cfgfile, Audit: d.store, Templates: d.templates}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("GET /api/config/backup/download", chain(&web.BackupDownloadAction{Config: d.cfgfile}, requireAuth, requireManageConfig))
	mux.Handle("POST /api/config/backup/delete", chain(&web.BackupDeleteAction{Config: d.cfgfile, Audit: d.store, Templates: d.templates}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/haproxy/restart", chain(&web.RestartServiceAction{Service: d.cfgfile, Audit: d.store, Templates: d.templates}, requireAuth, requireManageConfig, auth.RequireCSRF))

	// Adding/removing pool members rewrites haproxy.cfg and reloads, so it
	// sits with the config editor's capability; state/weight stay under
	// runtime control above.
	mux.Handle("POST /api/pools/{name}/members/preview", chain(&web.PoolMemberPreview{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/members/add", chain(&web.PoolMemberAdd{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/members/edit/preview", chain(&web.PoolMemberEditPreview{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/members/edit/apply", chain(&web.PoolMemberEditApply{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/members/remove", chain(&web.PoolMemberRemove{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/pools/new/preview", chain(&web.PoolNewPreview{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/pools/new/apply", chain(&web.PoolNewApply{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/rate-limit/preview", chain(&web.RateLimitPreview{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/rate-limit/apply", chain(&web.RateLimitApply{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/rate-limit/remove", chain(&web.RateLimitRemove{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/toggle-state", chain(&web.PoolToggleStateAction{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/pools/{name}/delete", chain(&web.PoolDeleteAction{PoolService: pools}, requireAuth, requireManageConfig, auth.RequireCSRF))

	mux.Handle("POST /api/certs/upload", chain(&web.CertUploadHandler{
		Stager: d.certs, StagingDir: d.cfg.StagingDir, Audit: d.store, Templates: d.templates,
	}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/certs/install", chain(&web.CertInstallHandler{
		Installer: d.certs, Audit: d.store, Templates: d.templates,
	}, requireAuth, requireManageConfig, auth.RequireCSRF))
	mux.Handle("POST /api/certs/remove", chain(&web.CertRemoveHandler{
		Remover: d.certs, Audit: d.store, Templates: d.templates,
	}, requireAuth, requireManageConfig, auth.RequireCSRF))

	// --- manage users, manage settings ---
	usersHandler := &web.UsersHandler{Store: d.store, Audit: d.store, Templates: d.templates}
	mux.Handle("GET /users", chain(usersHandler, requireAuth, requireManageUsers))
	mux.Handle("POST /api/users/update", chain(&web.UserUpdateHandler{Store: d.store, Audit: d.store, Templates: d.templates}, requireAuth, requireManageUsers, auth.RequireCSRF))
	mux.Handle("POST /api/users/create", chain(&web.UserCreateHandler{Store: d.store, Audit: d.store, Templates: d.templates}, requireAuth, requireManageUsers, auth.RequireCSRF))
	mux.Handle("GET /api/users/search", chain(&web.UserSearchHandler{Directory: d.dir, Templates: d.templates}, requireAuth, requireManageUsers))

	mux.Handle("POST /api/profile/language", chain(&web.ProfileLanguageHandler{Store: d.store}, requireAuth, auth.RequireCSRF))
	mux.Handle("POST /api/profile/password", chain(&web.ProfilePasswordHandler{Store: d.store, Audit: d.store}, requireAuth, auth.RequireCSRF))
	mux.Handle("POST /api/profile/totp", chain(&web.ProfileTOTPHandler{Store: d.store, Audit: d.store}, requireAuth, auth.RequireCSRF))

	mux.Handle("GET /traffic", chain(&web.TrafficHandler{LogPath: d.cfg.LogPath, Templates: d.templates}, requireAuth))
	mux.Handle("GET /alerts", chain(&web.AlertsHandler{Store: d.store, Templates: d.templates}, requireAuth))
	mux.Handle("POST /api/alerts/{id}/ack", chain(&web.AlertAckHandler{Store: d.store, Audit: d.store}, requireAuth, auth.RequireCSRF))

	// Settings moved into the /config page; old links and bookmarks still work.
	mux.Handle("GET /settings", chain(http.RedirectHandler("/config#settings", http.StatusFound), requireAuth))
	mux.Handle("POST /api/settings/api-tokens", chain(&web.APITokenCreateAction{Store: d.store, Audit: d.store, Templates: d.templates}, requireAuth, requireManageSettings, auth.RequireCSRF))
	mux.Handle("POST /api/settings/api-tokens/revoke", chain(&web.APITokenRevokeAction{Store: d.store, Audit: d.store}, requireAuth, requireManageSettings, auth.RequireCSRF))
	mux.Handle("POST /api/settings/redis/test", chain(&web.RedisTestAction{Templates: d.templates}, requireAuth, requireManageSettings, auth.RequireCSRF))
	mux.Handle("POST /api/settings/redis", chain(&web.RedisSaveAction{Store: d.store, Audit: d.store, Templates: d.templates}, requireAuth, requireManageSettings, auth.RequireCSRF))
	mux.Handle("POST /api/settings/queue-token/generate", chain(&web.QueueTokenGenerateAction{Store: d.store, Audit: d.store, Templates: d.templates}, requireAuth, requireManageSettings, auth.RequireCSRF))

	// --- Observability: Prometheus scrape target and the weekly report ---
	mux.Handle("GET /metrics", chain(&web.MetricsHandler{Store: d.store, Stats: d.runtime, Engine: d.policy}, requireAPI, requireViewSecurity))
	mux.Handle("GET /reports/weekly", chain(&web.WeeklyReportHandler{Store: d.store, Templates: d.templates}, requireAuth, requireViewSecurity))

	// --- AI copilot: read-only tools, answers become Policy Engine proposals ---
	toolbox := &web.CopilotToolbox{Store: d.store, Stats: d.runtime}
	if d.intel != nil {
		toolbox.Intel = d.intel
	}
	mux.Handle("GET /ask", chain(&web.CopilotPageHandler{Templates: d.templates, Enabled: aiProvider != nil}, requireAuth, requireViewSecurity))
	mux.Handle("POST /api/ai/ask", chain(&web.CopilotAskHandler{Provider: aiProvider, Toolbox: toolbox, Engine: d.policy, Audit: d.store, Templates: d.templates}, requireAuth, requireViewSecurity, auth.RequireCSRF))

	// --- Policy Engine: the single gate for automated and proposed changes ---
	requirePolicyView := requireViewSecurity
	mux.Handle("GET /policy", chain(&web.PolicyHandler{Engine: d.policy, Store: d.store, Templates: d.templates, Edition: d.gate.Describe()}, requireAuth, requirePolicyView))

	// --- Fleet: nodes push signed-in reports (shared-secret bearer, own auth) ---
	if d.fleetHub != nil {
		mux.Handle("POST /api/v1/fleet/report", d.fleetHub)
		mux.Handle("GET /fleet", chain(&web.FleetPageHandler{Hub: d.fleetHub, Enabled: d.fleetHub.Token != "", Templates: d.templates}, requireAuth, requireViewSecurity))
	}
	for _, verb := range []string{"approve", "reject", "revert"} {
		mux.Handle("POST /api/policy/{id}/"+verb, chain(&web.PolicyDecisionAction{Engine: d.policy, Verb: verb}, requireAuth, requireRuntimeControl, auth.RequireCSRF))
	}
	mux.Handle("POST /api/policy/kill-switch", chain(&web.PolicyKillSwitchAction{Engine: d.policy}, requireAuth, requireRuntimeControl, auth.RequireCSRF))
	mux.Handle("POST /api/policy/config", chain(&web.PolicyConfigAction{Engine: d.policy}, requireAuth, requireManageSettings, auth.RequireCSRF))
	mux.Handle("GET /api/policy/replay", chain(&web.PolicyReplayHandler{Engine: d.policy, LogPath: d.cfg.LogPath}, requireAuth, requireViewSecurity))
	mux.Handle("POST /api/v1/policy/check", chain(&web.APIV1PolicyCheckHandler{Engine: d.policy}, requireAPI, requireViewSecurity, auth.RequireCSRF))

	// --- HTTP API /api/v1 (C1-4) ---
	mux.Handle("GET /api/v1/status", chain(&web.APIV1StatusHandler{Stats: d.runtime, Sys: d.sys, DiskPaths: d.cfg.SysDiskPaths}, requireAPI))
	mux.Handle("GET /api/v1/backends", chain(&web.APIV1BackendsHandler{Stats: d.runtime, Config: d.cfgfile}, requireAPI))
	mux.Handle("GET /api/v1/servers", chain(&web.APIV1ServersHandler{Stats: d.runtime}, requireAPI))
	mux.Handle("GET /api/v1/nodes", chain(&web.APIV1NodesHandler{Config: d.cfgfile, Stats: d.runtime}, requireAPI))
	mux.Handle("GET /api/v1/incidents", chain(&web.APIV1IncidentsHandler{Store: d.store}, requireAPI, requireViewSecurity))
	mux.Handle("GET /api/v1/incidents/{id}", chain(&web.APIV1IncidentDetailHandler{Store: d.store}, requireAPI, requireViewSecurity))

	mux.Handle("POST /api/v1/proposals", chain(&web.APIV1ProposalHandler{Store: d.store, Audit: d.store, Policy: d.policy}, requireAPI, requireViewSecurity, auth.RequireCSRF))

	// --- MCP over HTTP: remote MCP clients (Claude Code, Cursor, n8n, ...) that
	// take a URL + Authorization header instead of launching konsolgw-mcp. Token
	// only; each tool call re-enters mux so /api/v1 checks apply unchanged. ---
	mcpHandler := web.NewMCPHandler(mux)
	mux.Handle("OPTIONS /mcp", http.HandlerFunc(mcpHandler.Preflight))
	mux.Handle("/mcp", chain(mcpHandler, auth.RequireAPIToken(d.store)))

	// --- external API (own bearer-token auth, not the browser session/CSRF
	// flow above — callers here are the Incident Management module or an
	// external system per the roadmap, not a logged-in browser) ---
	mux.Handle("POST /api/queue/ratelimit-events/consume", &web.QueueConsumeAction{Store: d.store})

	return securityHeaders(mux)
}

// securityHeaders sets a strict, no-CDN Content-Security-Policy and other
// standard hardening headers on every response. htmx is served locally from
// /static, so 'self' is sufficient. frame-ancestors 'self' and SAMEORIGIN allow
// internal sandboxed live preview iframes (such as the error page previewer).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
