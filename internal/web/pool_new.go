package web

import (
	"net/http"
	"strings"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/haproxycfg"
)

// PoolNewFormHandler renders the "create a new pool" wizard — three
// numbered steps on one page (name/method, health check, first member),
// each with a short explanation, so someone who has never edited
// haproxy.cfg by hand can still stand up a working backend.
type PoolNewFormHandler struct{ *PoolService }

func (h *PoolNewFormHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, h.Templates, "pool_new.html", struct{ Chrome }{NewChrome(r, "pools")})
}

func poolSpecFromForm(r *http.Request) haproxycfg.PoolSpec {
	spec := haproxycfg.PoolSpec{
		Name:            strings.TrimSpace(r.FormValue("pool_name")),
		Profile:         strings.TrimSpace(r.FormValue("profile")),
		Balance:         strings.TrimSpace(r.FormValue("balance")),
		HealthCheckType: strings.TrimSpace(r.FormValue("health_check_type")),
		HealthCheckPath: strings.TrimSpace(r.FormValue("health_check_path")),
		HealthCheckUser: strings.TrimSpace(r.FormValue("health_check_user")),
		HealthCheckHost: strings.TrimSpace(r.FormValue("health_check_host")),
		Mode:            strings.TrimSpace(r.FormValue("mode")),
		ListenPort:      strings.TrimSpace(r.FormValue("listen_port")),
		TimeoutClient:   strings.TrimSpace(r.FormValue("timeout_client")),
		TimeoutServer:   strings.TrimSpace(r.FormValue("timeout_server")),
		ForwardFor:      r.FormValue("forwardfor") == "1" || r.FormValue("forwardfor") == "true",
		TrustCloudflare: r.FormValue("trust_cloudflare") == "1" || r.FormValue("trust_cloudflare") == "true",
		CookieSticky:    r.FormValue("cookie_sticky") == "1" || r.FormValue("cookie_sticky") == "true",
		Domain:          strings.TrimSpace(r.FormValue("domain")),
	}

	names := r.Form["member_name"]
	if len(names) == 0 {
		names = r.Form["member_name[]"]
	}
	hosts := r.Form["member_host"]
	if len(hosts) == 0 {
		hosts = r.Form["member_host[]"]
	}
	ports := r.Form["member_port"]
	if len(ports) == 0 {
		ports = r.Form["member_port[]"]
	}
	weights := r.Form["member_weight"]
	if len(weights) == 0 {
		weights = r.Form["member_weight[]"]
	}
	maxconns := r.Form["member_maxconn"]
	if len(maxconns) == 0 {
		maxconns = r.Form["member_maxconn[]"]
	}
	backups := r.Form["member_backup"]
	if len(backups) == 0 {
		backups = r.Form["member_backup[]"]
	}

	if len(names) > 0 {
		for i := range names {
			n := strings.TrimSpace(names[i])
			h := ""
			if i < len(hosts) {
				h = strings.TrimSpace(hosts[i])
			}
			p := ""
			if i < len(ports) {
				p = strings.TrimSpace(ports[i])
			}
			w := ""
			if i < len(weights) {
				w = strings.TrimSpace(weights[i])
			}
			mc := ""
			if i < len(maxconns) {
				mc = strings.TrimSpace(maxconns[i])
			}
			bk := false
			if i < len(backups) {
				bk = backups[i] == "1" || backups[i] == "true"
			}
			if n != "" && h != "" {
				spec.Members = append(spec.Members, haproxycfg.MemberSpec{
					Name: n, Host: h, Port: p, Weight: w, Maxconn: mc, Backup: bk,
				})
			}
		}
	}

	// Fallback to legacy single member form fields
	if len(spec.Members) == 0 {
		legacyName := strings.TrimSpace(r.FormValue("name"))
		legacyHost := strings.TrimSpace(r.FormValue("host"))
		if legacyName != "" && legacyHost != "" {
			spec.Member = haproxycfg.MemberSpec{
				Name:    legacyName,
				Host:    legacyHost,
				Port:    strings.TrimSpace(r.FormValue("port")),
				Weight:  strings.TrimSpace(r.FormValue("weight")),
				Maxconn: strings.TrimSpace(r.FormValue("maxconn")),
				Backup:  r.FormValue("backup") == "1" || r.FormValue("backup") == "true",
			}
			spec.Members = append(spec.Members, spec.Member)
		}
	} else {
		spec.Member = spec.Members[0]
	}

	return spec
}

type poolNewPreviewData struct {
	Spec       haproxycfg.PoolSpec
	Block      string
	Validation poolResult
	CSRFToken  string
}

// PoolNewPreview builds the new backend section and runs "haproxy -c" on
// the result, changing nothing yet — same preview-then-confirm pattern as
// every other config change in this app.
type PoolNewPreview struct{ *PoolService }

func (h *PoolNewPreview) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	spec := poolSpecFromForm(r)

	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updated, block, err := haproxycfg.AddPool(content, spec)
	if err != nil {
		renderTemplate(w, h.Templates, "pool_result.html", poolResult{Message: err.Error()})
		return
	}
	v, err := h.Config.Validate(updated)
	if err != nil {
		http.Error(w, "Validator tidak bisa dijalankan: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sess, _ := auth.SessionFromContext(r.Context())
	renderTemplate(w, h.Templates, "pool_new_preview.html", poolNewPreviewData{
		Spec: spec, Block: block, CSRFToken: sess.CSRFToken,
		Validation: poolResult{OK: v.OK, Output: v.Output},
	})
}

// PoolNewApply creates the new pool through the same validate-stage-apply-
// audit pipeline as every other config change, then hands back a link to
// the new pool's own page.
type PoolNewApply struct{ *PoolService }

func (h *PoolNewApply) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	spec := poolSpecFromForm(r)

	h.mu.Lock()
	defer h.mu.Unlock()

	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updated, block, err := haproxycfg.AddPool(content, spec)
	if err != nil {
		renderTemplate(w, h.Templates, "pool_result.html", poolResult{Message: err.Error()})
		return
	}

	okMsg := "Pool " + spec.Name + " dibuat dan HAProxy dimuat ulang. Buka /pools/" + spec.Name + " untuk mengelolanya."
	if spec.Domain != "" {
		_ = appendLine("/etc/haproxy/maps/hosts_http.map", spec.Domain+" "+spec.Name)
		_ = appendLine("/etc/haproxy/maps/hosts_https.map", spec.Domain+" "+spec.Name)
		okMsg = "Pool " + spec.Name + " dibuat dan domain " + spec.Domain + " otomatis diarahkan ke pool ini."
	}

	h.applyChange(w, r, "pool.create", spec.Name, block, updated, okMsg)
}
