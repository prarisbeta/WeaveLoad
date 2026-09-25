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

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/cfgfile"
	"haproxy-gui/internal/store"
	"haproxy-gui/internal/sysinfo"
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
func (f fileConfig) ListBackups() ([]cfgfile.Backup, error) { return nil, nil }

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
	tpl, err := template.New("").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"bytes": sysinfo.FormatBytes,
	}).ParseFS(templatesFS, "templates/*.html")
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

	mux := http.NewServeMux()
	mux.Handle("GET /pools", &web.PoolsHandler{PoolService: svc})
	mux.Handle("GET /pools/new", &web.PoolNewFormHandler{PoolService: svc})
	mux.Handle("GET /pools/{name}", &web.PoolDetailHandler{PoolService: svc})
	mux.Handle("GET /pools/{name}/members/{member}/edit", &web.PoolMemberEditForm{PoolService: svc})
	mux.Handle("GET /nodes", &web.NodesHandler{PoolService: svc})
	mux.Handle("POST /api/pools/{name}/members/preview", &web.PoolMemberPreview{PoolService: svc})
	mux.Handle("POST /api/pools/{name}/members/edit/preview", &web.PoolMemberEditPreview{PoolService: svc})
	mux.Handle("POST /api/pools/new/preview", &web.PoolNewPreview{PoolService: svc})

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
			store.User{Email: "admin@cni.net.id", Role: store.RoleAdmin}, store.Session{CSRFToken: "t"}))
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
