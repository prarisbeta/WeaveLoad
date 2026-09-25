package web

import (
	"net/http"
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
// config editor. Wire behind auth.RequireRole(store.RoleAdmin).
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
