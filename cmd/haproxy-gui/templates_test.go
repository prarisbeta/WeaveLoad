package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/certs"
	"haproxy-gui/internal/cfgfile"
	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/store"
	"haproxy-gui/internal/web"
)

// These tests render the pool/node pages through the real embedded
// templates, so a template typo fails "go test" instead of a live page.
// Set PREVIEW_DIR to also write each page out as HTML for a visual check.

type fileConfig struct{ content string }

func (f fileConfig) Active() (string, error) { return f.content, nil }
func (f fileConfig) Validate(string) (cfgfile.ValidateResult, error) {
	return cfgfile.ValidateResult{OK: true, Output: "Configuration file is valid"}, nil
}
func (f fileConfig) SaveDraft(string, string) (string, error) { return "", nil }
func (f fileConfig) Apply(string) (cfgfile.ApplyResult, error) {
	return cfgfile.ApplyResult{OK: true}, nil
}

// Real backups carry an int64 Size (os.FileInfo.Size); the page used to fail
// as soon as one existed, which an empty fixture never exercised.
func (f fileConfig) ListBackups() ([]cfgfile.Backup, error) {
	return []cfgfile.Backup{
		{Name: "haproxy.cfg.bak-1792045394840025288", Size: 26897, ModTime: time.Now(), IsEncrypted: true},
		{Name: "haproxy.cfg.bak-1790000000000000000", Size: 0, ModTime: time.Now()},
	}, nil
}
func (f fileConfig) GetBackupPath(name string) (string, error) { return "", nil }
func (f fileConfig) ReadBackup(name string) (string, error)    { return f.content, nil }
func (f fileConfig) DeleteBackup(name string) error            { return nil }

type noopExecutor struct{}

func (noopExecutor) BlockIP(string) error      { return nil }
func (noopExecutor) UnblockIP(string) error    { return nil }
func (noopExecutor) Drain(_, _ string) error   { return nil }
func (noopExecutor) Undrain(_, _ string) error { return nil }

type fixedSettings struct{ redis store.RedisSettings }

func (f fixedSettings) GetRedisSettings() (store.RedisSettings, error) { return f.redis, nil }
func (f fixedSettings) SetRedisSettings(store.RedisSettings) error     { return nil }
func (f fixedSettings) GetQueueAPIToken() (string, error)              { return "", nil }
func (f fixedSettings) SetQueueAPIToken(string) error                  { return nil }

// fixedTokens serves one active and one revoked API token so the Settings
// section and the one-time result partial render with the real templates.
type fixedTokens struct{}

func (fixedTokens) ListAPITokens() ([]store.APIToken, error) {
	return []store.APIToken{
		{ID: 2, Name: "n8n-prod", Prefix: "kgw_abcd", CreatedBy: "admin@cni.net.id", CreatedAt: time.Now()},
		{ID: 1, Name: "old-test", Prefix: "kgw_zzzz", CreatedAt: time.Now(), Revoked: true},
	}, nil
}

func (fixedTokens) CreateAPIToken(name, by string) (string, store.APIToken, error) {
	return "kgw_plaintextplaintextplaintext", store.APIToken{ID: 3, Name: name, Prefix: "kgw_plai"}, nil
}

func (fixedTokens) RevokeAPIToken(int64) error { return nil }

type noopAudit struct{}

func (noopAudit) Record(store.AuditEntry) error { return nil }

// fixedCerts serves one installed and one staged certificate, and a canned
// install outcome, so the SSL page and its result partial render for real.
type fixedCerts struct{}

func (fixedCerts) List() ([]certs.Info, error) {
	return []certs.Info{{FileName: "live.pem", CommonName: "live.cni.net.id", NotAfter: time.Now().Add(90 * 24 * time.Hour)}}, nil
}

func (fixedCerts) ListStaged() ([]certs.Info, error) {
	return []certs.Info{{FileName: "palapacloud.id.pem", CommonName: "*.palapacloud.id", NotAfter: time.Now().Add(90 * 24 * time.Hour)}}, nil
}

func (fixedCerts) Remove(string) (certs.InstallResult, error) {
	return certs.InstallResult{OK: true, Output: "removed"}, nil
}

func (fixedCerts) RemoveStaged(string) error { return nil }

func (fixedCerts) Install(string) (certs.InstallResult, error) {
	return certs.InstallResult{OK: true, Output: "installed"}, nil
}

type fixedSecurity struct{}

func (fixedSecurity) ListSecurityEvents(store.SecurityFilter) ([]store.SecurityEvent, int, error) {
	return []store.SecurityEvent{{
		ID: 1, Rule: "brute_force", Severity: "high", SubjectType: "ip", Subject: "10.0.0.9",
		Count: 12, Status: "open", Evidence: map[string]any{"login_failures": 12},
	}}, 1, nil
}
func (fixedSecurity) GetSecurityEvent(id int64) (store.SecurityEvent, error) {
	return store.SecurityEvent{
		ID: 1, Rule: "brute_force", Severity: "high", SubjectType: "ip", Subject: "10.0.0.9",
		Count: 12, Status: "open", Evidence: map[string]any{"login_failures": 12},
	}, nil
}
func (fixedSecurity) SetSecurityEventStatus(int64, string, string) error { return nil }
func (fixedSecurity) GetIPRisk(ip string) (store.IPRisk, error) {
	return store.IPRisk{IP: ip, Score: 42, State: "suspicious"}, nil
}
func (fixedSecurity) ListTopRisk(n int) ([]store.IPRisk, error) {
	return []store.IPRisk{{IP: "10.0.0.9", Score: 42, State: "suspicious"}}, nil
}
func (fixedSecurity) CreateIncident(store.Incident, []int64) (int64, error) { return 1, nil }
func (fixedSecurity) GetIncident(id int64) (store.Incident, []store.SecurityEvent, []store.IncidentNote, error) {
	return store.Incident{ID: 1, Title: "Serangan Brute Force", Severity: "high", Status: "open", Owner: "admin@cni.net.id"},
		[]store.SecurityEvent{{ID: 1, Rule: "brute_force", Severity: "high", Subject: "10.0.0.9", Count: 12}},
		[]store.IncidentNote{{ID: 1, IncidentID: 1, Author: "admin@cni.net.id", Content: "Analisis awal berjalan"}},
		nil
}
func (fixedSecurity) ListIncidents(store.IncidentFilter) ([]store.Incident, int, error) {
	return []store.Incident{{ID: 1, Title: "Serangan Brute Force", Severity: "high", Status: "open", Owner: "admin@cni.net.id"}}, 1, nil
}
func (fixedSecurity) UpdateIncidentStatus(int64, string, string, string, string) error { return nil }
func (fixedSecurity) AddIncidentNote(int64, string, string) (int64, error)             { return 1, nil }
func (fixedSecurity) LinkEventsToIncident(int64, []int64) error                        { return nil }
func (fixedSecurity) UnlinkEventFromIncident(int64) error                              { return nil }
func (fixedSecurity) CorrelateCandidateEvents(string, string, int) ([]store.SecurityEvent, error) {
	return nil, nil
}

type fixedStats string

func (s fixedStats) ShowStat() (string, error) { return string(s), nil }

const previewStats = `# pxname,svname,status,weight,check_status,last_chk,scur
https_oms,node01,UP,1,L7OK,HTTP status check returned code 200,42
https_oms,node02,DRAIN,1,L7OK,HTTP status check returned code 200,3
https_oms,BACKEND,UP,,,,45
http_oms,node1,UP,1,L7OK,,5
http_oms,node2,UP,1,L7OK,,4
http_oms,node3,DOWN,1,L4CON,Connection refused,0
http_oms,BACKEND,UP,,,,9
`

func realTemplates(t *testing.T) *template.Template {
	t.Helper()
	tpl, err := template.New("").Funcs(web.TemplateFuncs()).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}

func TestPoolPagesRenderWithRealTemplates(t *testing.T) {
	cfgBytes, err := os.ReadFile(filepath.Join("..", "..", "tuning", "haproxy.cfg"))
	if err != nil {
		t.Skip("tuning/haproxy.cfg not available:", err)
	}
	svc := &web.PoolService{
		Config:    fileConfig{string(cfgBytes)},
		Stats:     fixedStats(previewStats),
		Templates: realTemplates(t),
	}

	ps, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })
	pe := &policy.Engine{Repo: ps, Exec: noopExecutor{}, Audit: ps}
	if _, _, err := pe.Submit(policy.Action{Type: policy.BlockIP, Target: "9.9.9.9", Reason: "SQLi burst", Source: "auto:threat_intel"}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /policy", &web.PolicyHandler{Engine: pe, Store: ps, Templates: realTemplates(t)})
	mux.Handle("GET /pools", &web.PoolsHandler{PoolService: svc})
	mux.Handle("GET /pools/new", &web.PoolNewFormHandler{PoolService: svc})
	mux.Handle("GET /pools/{name}", &web.PoolDetailHandler{PoolService: svc})
	mux.Handle("GET /pools/{name}/members/{member}/edit", &web.PoolMemberEditForm{PoolService: svc})
	mux.Handle("GET /nodes", &web.NodesHandler{PoolService: svc})
	mux.Handle("POST /api/pools/{name}/members/preview", &web.PoolMemberPreview{PoolService: svc})
	mux.Handle("POST /api/pools/{name}/members/edit/preview", &web.PoolMemberEditPreview{PoolService: svc})
	mux.Handle("POST /api/pools/new/preview", &web.PoolNewPreview{PoolService: svc})
	mux.Handle("GET /config", &web.ConfigHandler{Config: fileConfig{string(cfgBytes)}, Templates: realTemplates(t), Settings: fixedSettings{redis: store.RedisSettings{Host: "10.0.0.5", Port: "6379"}}, Tokens: fixedTokens{}})
	mux.Handle("POST /api/settings/api-tokens", &web.APITokenCreateAction{Store: fixedTokens{}, Audit: noopAudit{}, Templates: realTemplates(t)})
	mux.Handle("GET /login", &auth.LoginHandler{Templates: realTemplates(t)})
	mux.Handle("GET /certs", &web.CertsHandler{Certs: fixedCerts{}, Templates: realTemplates(t)})
	mux.Handle("POST /api/certs/remove", &web.CertRemoveHandler{Remover: fixedCerts{}, Audit: noopAudit{}, Templates: realTemplates(t)})
	mux.Handle("POST /api/certs/install", &web.CertInstallHandler{Installer: fixedCerts{}, Audit: noopAudit{}, Templates: realTemplates(t)})
	mux.Handle("GET /queue", &web.QueueHandler{Store: fixedSettings{}, Templates: realTemplates(t)})
	mux.Handle("GET /security", &web.SecurityHandler{Store: fixedSecurity{}, Templates: realTemplates(t)})
	mux.Handle("GET /security/events/{id}", &web.SecurityEventDetail{Store: fixedSecurity{}, Templates: realTemplates(t)})
	mux.Handle("GET /security/ip/{ip}", &web.SecurityIPHandler{Store: fixedSecurity{}, Templates: realTemplates(t)})
	mux.Handle("GET /incidents", &web.IncidentsHandler{Store: fixedSecurity{}, Templates: realTemplates(t)})
	mux.Handle("GET /incidents/new", &web.IncidentNewHandler{Store: fixedSecurity{}, Templates: realTemplates(t)})
	mux.Handle("GET /incidents/{id}", &web.IncidentDetailHandler{Store: fixedSecurity{}, Templates: realTemplates(t)})

	pages := []struct {
		file, method, target string
		form                 url.Values
		want                 string
	}{
		{"pools.html", http.MethodGet, "/pools", nil, "https_oms"},
		{"pool_detail.html", http.MethodGet, "/pools/https_oms?node=192.168.200.120", nil, "Tambah anggota"},
		{"nodes.html", http.MethodGet, "/nodes", nil, "192.168.200.108"},
		{"preview.html", http.MethodPost, "/api/pools/https_oms/members/preview",
			url.Values{"name": {"node03"}, "host": {"192.168.200.120"}, "port": {"443"}, "clone_from": {"node01"}},
			"server node03 192.168.200.120:443"},
		{"pool_new.html", http.MethodGet, "/pools/new", nil, "Buat Pool Baru"},
		{"pool_new_preview.html", http.MethodPost, "/api/pools/new/preview",
			url.Values{"pool_name": {"http_wizardtest"}, "name": {"n1"}, "host": {"10.0.0.9"}, "port": {"80"}},
			"backend http_wizardtest"},
		{"pool_edit_form.html", http.MethodGet, "/pools/https_oms/members/node01/edit", nil, "Ubah anggota"},
		{"pool_edit_preview.html", http.MethodPost, "/api/pools/https_oms/members/edit/preview",
			url.Values{"current_name": {"node01"}, "name": {"node01"}, "host": {"192.168.200.108"}, "port": {"443"}, "weight": {"50"}},
			"weight 50"},
		{"config.html", http.MethodGet, "/config", nil, "Restart layanan HAProxy"},
		{"config_settings_redis", http.MethodGet, "/config", nil, "10.0.0.5"},
		{"config_settings_tokens", http.MethodGet, "/config", nil, "n8n-prod"},
		{"config_settings_anchor", http.MethodGet, "/config", nil, `id="settings"`},
		{"config_still_has_editor", http.MethodGet, "/config", nil, "Restart layanan HAProxy"},
		{"config_lists_backups", http.MethodGet, "/config", nil, "haproxy.cfg.bak-1792045394840025288"},
		{"config_backup_size", http.MethodGet, "/config", nil, "26.3 KiB"},
		{"config_settings_mcp_url", http.MethodGet, "/config", nil, "/mcp"},
		{"config_api_tokens_in_mcp_panel", http.MethodGet, "/config", nil, `id="api-tokens"`},
		{"policy.html", http.MethodGet, "/policy", nil, "Kill switch"},
		{"policy_pending_action", http.MethodGet, "/policy", nil, "9.9.9.9"},
		{"policy_modes", http.MethodGet, "/policy", nil, `name="mode_block_ip"`},
		{"api_token_result.html", http.MethodPost, "/api/settings/api-tokens", url.Values{"name": {"claude-code"}}, "kgw_plaintextplaintextplaintext"},
		{"login.html", http.MethodGet, "/login", nil, `href="/auth/login"`},
		{"certs.html", http.MethodGet, "/certs", nil, "palapacloud.id.pem"},
		{"certs_remove_live", http.MethodGet, "/certs", nil, "/api/certs/remove"},
		{"cert_remove_result.html", http.MethodPost, "/api/certs/remove", url.Values{"filename": {"old.pem"}, "scope": {"live"}}, "Berhasil diterapkan."},
		{"cert_remove_staged_result.html", http.MethodPost, "/api/certs/remove", url.Values{"filename": {"palapacloud.id.pem"}, "scope": {"staged"}}, "Berhasil diterapkan."},
		{"cert_install_result.html", http.MethodPost, "/api/certs/install", url.Values{"filename": {"palapacloud.id.pem"}}, "Berhasil diterapkan."},
		{"queue.html", http.MethodGet, "/queue", nil, "belum dikonfigurasi"},
		{"security.html", http.MethodGet, "/security", nil, "10.0.0.9"},
		{"security_event.html", http.MethodGet, "/security/events/1", nil, "brute_force"},
		{"security_ip.html", http.MethodGet, "/security/ip/10.0.0.9", nil, "10.0.0.9"},
		{"incidents.html", http.MethodGet, "/incidents", nil, "Serangan Brute Force"},
		{"incident_new.html", http.MethodGet, "/incidents/new", nil, "Buat Insiden Baru"},
		{"incident_detail.html", http.MethodGet, "/incidents/1", nil, "Serangan Brute Force"},
	}
	for _, p := range pages {
		var req *http.Request
		if p.form != nil {
			req = httptest.NewRequest(p.method, p.target, strings.NewReader(p.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req = httptest.NewRequest(p.method, p.target, nil)
		}
		req = req.WithContext(auth.WithUser(req.Context(),
			store.User{Email: "admin@cni.net.id", Role: store.RolePlatformAdmin}, store.Session{CSRFToken: "t"}))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, p.want) {
			t.Errorf("%s: code=%d, want %q in body:\n%s", p.target, rec.Code, p.want, body)
		}
		if dir := os.Getenv("PREVIEW_DIR"); dir != "" {
			_ = os.MkdirAll(dir, 0o755)
			_ = os.WriteFile(filepath.Join(dir, p.file), []byte(body), 0o644)
		}
	}
}
