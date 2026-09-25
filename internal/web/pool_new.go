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
	return haproxycfg.PoolSpec{
		Name:            strings.TrimSpace(r.FormValue("pool_name")),
		Balance:         strings.TrimSpace(r.FormValue("balance")),
		HealthCheckPath: strings.TrimSpace(r.FormValue("health_check_path")),
		Member: haproxycfg.MemberSpec{
			Name:    strings.TrimSpace(r.FormValue("name")),
			Host:    strings.TrimSpace(r.FormValue("host")),
			Port:    strings.TrimSpace(r.FormValue("port")),
			Weight:  strings.TrimSpace(r.FormValue("weight")),
			Maxconn: strings.TrimSpace(r.FormValue("maxconn")),
		},
	}
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
	h.applyChange(w, r, "pool.create", spec.Name, block,
		updated, "Pool "+spec.Name+" dibuat dan HAProxy dimuat ulang. Buka /pools/"+spec.Name+" untuk mengelolanya, atau atur rute domain ke pool ini di halaman Aturan & Rute.")
}
