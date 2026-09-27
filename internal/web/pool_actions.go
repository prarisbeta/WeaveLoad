package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/haproxycfg"
	"haproxy-gui/internal/stats"
	"haproxy-gui/internal/store"
)

// memberChangedEvent is sent as an HX-Trigger header after any change to a
// pool member, so the pool page re-fetches its members table immediately
// instead of waiting for the next poll.
const memberChangedEvent = "memberChanged"

// poolResult is the fragment every pool action answers with. Actions reply
// 200 even when refusing, because htmx only swaps successful responses and
// the operator needs to see why nothing happened.
type poolResult struct {
	OK      bool
	Message string
	Output  string
}

type poolPreviewData struct {
	Pool       string
	Line       string
	Validation poolResult
	Spec       haproxycfg.MemberSpec
	CSRFToken  string
	// Action picks which endpoint the confirm button submits to: "add" (the
	// default, zero value) or "edit". CurrentName is only set for "edit" —
	// the member's name before this edit, since Spec.Name may rename it.
	Action      string
	CurrentName string
}

// PoolMemberPreview builds the server line a new member would get and runs
// "haproxy -c" on the resulting config, changing nothing. The response
// shows the exact line and, if valid, a button that submits the same
// fields to PoolMemberAdd.
type PoolMemberPreview struct{ *PoolService }

func (h *PoolMemberPreview) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	pool := r.PathValue("name")
	spec := memberSpecFromForm(r)

	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updated, line, err := haproxycfg.AddMember(content, pool, spec)
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
	renderTemplate(w, h.Templates, "pool_preview.html", poolPreviewData{
		Pool: pool, Line: line, Spec: spec, CSRFToken: sess.CSRFToken,
		Validation: poolResult{OK: v.OK, Output: v.Output},
	})
}

// PoolMemberAdd adds one member: edits haproxy.cfg, validates, and applies
// through the same root helper (backup, reload, auto-rollback) as the
// config editor. Wire behind auth.RequireCapability(store.CapManageConfig).
type PoolMemberAdd struct{ *PoolService }

func (h *PoolMemberAdd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	pool := r.PathValue("name")
	spec := memberSpecFromForm(r)

	h.mu.Lock()
	defer h.mu.Unlock()

	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updated, line, err := haproxycfg.AddMember(content, pool, spec)
	if err != nil {
		renderTemplate(w, h.Templates, "pool_result.html", poolResult{Message: err.Error()})
		return
	}
	h.applyChange(w, r, "pool.member.add", pool+"/"+spec.Name, line, updated,
		"Anggota "+spec.Name+" ditambahkan ke "+pool+" dan HAProxy dimuat ulang.")
}

// poolEditFormData prefills the edit form with a member's current settings.
type poolEditFormData struct {
	Pool      string
	Member    haproxycfg.Member
	CSRFToken string
}

// PoolMemberEditForm returns the pre-filled "edit member" form fragment for
// one existing member, loaded into the pool page in place when its "Edit"
// button is clicked.
type PoolMemberEditForm struct{ *PoolService }

func (h *PoolMemberEditForm) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pool := r.PathValue("name")
	member := r.PathValue("member")

	cfg, _, _, err := h.load()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	p, ok := cfg.Pool(pool)
	if !ok {
		http.Error(w, "Kelompok server tidak ditemukan", http.StatusNotFound)
		return
	}
	for _, m := range p.Members {
		if m.Name != member {
			continue
		}
		sess, _ := auth.SessionFromContext(r.Context())
		renderTemplate(w, h.Templates, "pool_edit_form.html", poolEditFormData{
			Pool: pool, Member: m, CSRFToken: sess.CSRFToken,
		})
		return
	}
	http.Error(w, "Anggota tidak ditemukan", http.StatusNotFound)
}

// PoolMemberEditPreview builds the replacement server line for an existing
// member and runs "haproxy -c" on the result, changing nothing yet — same
// preview-then-confirm pattern as adding a member.
type PoolMemberEditPreview struct{ *PoolService }

func (h *PoolMemberEditPreview) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	pool := r.PathValue("name")
	currentName := strings.TrimSpace(r.FormValue("current_name"))
	spec := memberSpecFromForm(r)

	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updated, line, err := haproxycfg.EditMember(content, pool, currentName, spec)
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
	renderTemplate(w, h.Templates, "pool_preview.html", poolPreviewData{
		Pool: pool, Line: line, Spec: spec, CSRFToken: sess.CSRFToken,
		Action: "edit", CurrentName: currentName,
		Validation: poolResult{OK: v.OK, Output: v.Output},
	})
}

// PoolMemberEditApply applies an edit built by PoolMemberEditPreview through
// the same validate-stage-apply-audit pipeline as every other config change.
type PoolMemberEditApply struct{ *PoolService }

func (h *PoolMemberEditApply) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	pool := r.PathValue("name")
	currentName := strings.TrimSpace(r.FormValue("current_name"))
	spec := memberSpecFromForm(r)

	h.mu.Lock()
	defer h.mu.Unlock()

	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updated, line, err := haproxycfg.EditMember(content, pool, currentName, spec)
	if err != nil {
		renderTemplate(w, h.Templates, "pool_result.html", poolResult{Message: err.Error()})
		return
	}
	msg := "Pengaturan " + currentName + " diperbarui"
	if spec.Name != currentName {
		msg += " (nama baru: " + spec.Name + ")"
	}
	msg += " di " + pool + " dan HAProxy dimuat ulang."
	h.applyChange(w, r, "pool.member.edit", pool+"/"+currentName, line, updated, msg)
}

// PoolMemberRemove removes one member, but only once it's been taken out
// of service (MAINT, or DRAIN with no sessions left) — the F5 habit of
// "disable, wait, then delete", enforced so a click can't cut live users.
type PoolMemberRemove struct{ *PoolService }

func (h *PoolMemberRemove) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	pool := r.PathValue("name")
	member := strings.TrimSpace(r.FormValue("server"))

	h.mu.Lock()
	defer h.mu.Unlock()

	if msg := h.removalBlocker(pool, member); msg != "" {
		renderTemplate(w, h.Templates, "pool_result.html", poolResult{Message: msg})
		return
	}
	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updated, line, err := haproxycfg.RemoveMember(content, pool, member)
	if err != nil {
		renderTemplate(w, h.Templates, "pool_result.html", poolResult{Message: err.Error()})
		return
	}
	h.applyChange(w, r, "pool.member.remove", pool+"/"+member, line, updated,
		"Anggota "+member+" dihapus dari "+pool+" dan HAProxy dimuat ulang.")
}

// removalBlocker returns why member can't be removed yet, or "" if it can.
func (h *PoolMemberRemove) removalBlocker(pool, member string) string {
	raw, err := h.Stats.ShowStat()
	if err != nil {
		return "Status live tidak bisa dibaca, penghapusan dibatalkan demi keamanan: " + err.Error()
	}
	snap, err := stats.Parse(raw)
	if err != nil {
		return "Status live tidak bisa dibaca, penghapusan dibatalkan demi keamanan: " + err.Error()
	}
	b, _ := snap.Backend(pool)
	for _, srv := range b.Servers {
		if srv.Name != member {
			continue
		}
		switch {
		case strings.HasPrefix(srv.Status, "MAINT"):
			return ""
		case strings.HasPrefix(srv.Status, "DRAIN") && srv.Sessions == 0:
			return ""
		case strings.HasPrefix(srv.Status, "DRAIN"):
			return member + " masih melayani koneksi. Tunggu sampai koneksinya 0, lalu hapus lagi."
		default:
			return "Nonaktifkan atau kosongkan " + member + " dulu sebelum menghapusnya, agar pengguna yang sedang terhubung tidak terputus."
		}
	}
	// Not in live stats (e.g. added to the file but never loaded): nothing to cut.
	return ""
}

func rateLimitSpecFromForm(r *http.Request) haproxycfg.RateLimitSpec {
	rps, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("rps")))
	action := strings.TrimSpace(r.FormValue("action"))
	if action == "" {
		action = "deny"
	}
	ignoreCF := r.FormValue("ignore_cf") == "1" || r.FormValue("ignore_cf") == "true"
	return haproxycfg.RateLimitSpec{RPS: rps, Action: action, IgnoreCloudflare: ignoreCF}
}

type rateLimitPreviewData struct {
	Pool       string
	Block      string
	Validation poolResult
	Spec       haproxycfg.RateLimitSpec
	CSRFToken  string
}

// RateLimitPreview builds the per-IP rate-limit block for a pool and runs
// "haproxy -c" on the result, changing nothing yet — same preview-then-
// confirm pattern as every other config-mutating action here.
type RateLimitPreview struct{ *PoolService }

func (h *RateLimitPreview) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	pool := r.PathValue("name")
	spec := rateLimitSpecFromForm(r)

	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updated, block, err := haproxycfg.SetRateLimit(content, pool, spec)
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
	renderTemplate(w, h.Templates, "rate_limit_preview.html", rateLimitPreviewData{
		Pool: pool, Block: block, Spec: spec, CSRFToken: sess.CSRFToken,
		Validation: poolResult{OK: v.OK, Output: v.Output},
	})
}

// RateLimitApply adds or replaces a pool's rate-limit block through the same
// validate-stage-apply-audit pipeline as every other config change.
type RateLimitApply struct{ *PoolService }

func (h *RateLimitApply) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	pool := r.PathValue("name")
	spec := rateLimitSpecFromForm(r)

	h.mu.Lock()
	defer h.mu.Unlock()

	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updated, block, err := haproxycfg.SetRateLimit(content, pool, spec)
	if err != nil {
		renderTemplate(w, h.Templates, "pool_result.html", poolResult{Message: err.Error()})
		return
	}
	h.applyChange(w, r, "pool.rate_limit.set", pool, block, updated,
		fmt.Sprintf("Batas laju %s (%d permintaan/detik per alamat IP) diterapkan di %s dan HAProxy dimuat ulang.", spec.Action, spec.RPS, pool))
}

// RateLimitRemove turns off a pool's rate limit — applied directly (no
// preview) since removal has nothing left to preview, matching how member
// removal itself works.
type RateLimitRemove struct{ *PoolService }

func (h *RateLimitRemove) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pool := r.PathValue("name")

	h.mu.Lock()
	defer h.mu.Unlock()

	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updated, err := haproxycfg.RemoveRateLimit(content, pool)
	if err != nil {
		renderTemplate(w, h.Templates, "pool_result.html", poolResult{Message: err.Error()})
		return
	}
	h.applyChange(w, r, "pool.rate_limit.remove", pool, "rate limit removed", updated,
		"Batas laju di "+pool+" dinonaktifkan dan HAProxy dimuat ulang.")
}

// applyChange validates, stages and applies updated as the new haproxy.cfg,
// recording the outcome either way, and renders the result fragment.
func (s *PoolService) applyChange(w http.ResponseWriter, r *http.Request, action, target, line, updated, okMsg string) {
	u, _ := auth.UserFromContext(r.Context())
	record := func(detail string) error {
		return s.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: clientIP(r),
			Action: action, Target: target, Detail: detail,
		})
	}

	v, err := s.Config.Validate(updated)
	if err != nil {
		http.Error(w, "Validator tidak bisa dijalankan: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !v.OK {
		_ = record("rejected: failed haproxy -c: " + line)
		renderTemplate(w, s.Templates, "pool_result.html", poolResult{
			Message: "Konfigurasi hasil perubahan tidak valid, tidak diterapkan.", Output: v.Output,
		})
		return
	}

	draft, err := s.Config.SaveDraft(u.Email, updated)
	if err != nil {
		http.Error(w, "Draf tidak bisa disimpan: "+err.Error(), http.StatusInternalServerError)
		return
	}
	res, err := s.Config.Apply(draft)
	if err != nil {
		http.Error(w, "Helper penerapan tidak bisa dijalankan: "+err.Error(), http.StatusInternalServerError)
		return
	}

	detail := "applied: " + line
	if !res.OK {
		detail = "apply helper failed (auto rollback expected): " + line
	}
	if err := record(detail); err != nil {
		http.Error(w, "Perubahan mungkin sudah diterapkan tetapi gagal dicatat di riwayat: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !res.OK {
		renderTemplate(w, s.Templates, "pool_result.html", poolResult{
			Message: "Penerapan gagal, konfigurasi dikembalikan otomatis ke versi sebelumnya.", Output: res.Output,
		})
		return
	}
	w.Header().Set("HX-Trigger", memberChangedEvent)
	renderTemplate(w, s.Templates, "pool_result.html", poolResult{OK: true, Message: okMsg, Output: res.Output})
}

// PoolToggleStateAction enables or disables an entire pool.
type PoolToggleStateAction struct{ *PoolService }

func (h *PoolToggleStateAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	pool := r.PathValue("name")
	disabledStr := r.FormValue("disabled")
	disabled := disabledStr == "true" || disabledStr == "1"

	h.mu.Lock()
	defer h.mu.Unlock()

	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}

	updated, err := haproxycfg.SetPoolDisabled(content, pool, disabled)
	if err != nil {
		renderTemplate(w, h.Templates, "pool_result.html", poolResult{Message: err.Error()})
		return
	}

	actionName := "pool.enable"
	actionDesc := fmt.Sprintf("Kelompok %s diaktifkan kembali.", pool)
	if disabled {
		actionName = "pool.disable"
		actionDesc = fmt.Sprintf("Kelompok %s dinonaktifkan.", pool)
	}

	h.applyChange(w, r, actionName, pool, actionDesc, updated, actionDesc)
}

// PoolDeleteAction deletes an entire pool and cleans up domain mappings.
type PoolDeleteAction struct{ *PoolService }

func (h *PoolDeleteAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pool := r.PathValue("name")

	h.mu.Lock()
	defer h.mu.Unlock()

	content, err := h.Config.Active()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}

	updated, err := haproxycfg.DeletePool(content, pool)
	if err != nil {
		renderTemplate(w, h.Templates, "pool_result.html", poolResult{Message: err.Error()})
		return
	}

	actionDesc := fmt.Sprintf("Kelompok %s berhasil dihapus dari konfigurasi.", pool)
	h.applyChange(w, r, "pool.delete", pool, "deleted pool "+pool, updated, actionDesc)
}


