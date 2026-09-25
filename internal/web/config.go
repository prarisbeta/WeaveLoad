package web

import (
	"html/template"
	"net/http"
	"strings"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/cfgfile"
	"haproxy-gui/internal/store"
)

// ConfigStore is the subset of *cfgfile.Store the config editor needs.
type ConfigStore interface {
	Active() (string, error)
	Validate(content string) (cfgfile.ValidateResult, error)
	SaveDraft(author, content string) (string, error)
	Apply(stagedPath string) (cfgfile.ApplyResult, error)
	ListBackups() ([]cfgfile.Backup, error)
}

// ConfigHandler serves the config editor page and its actions
// (view/validate/save/apply). Apply must be wired behind
// auth.RequireRole(store.RoleAdmin) — this is the most powerful action in
// the whole app, since it changes what HAProxy actually does.
type ConfigHandler struct {
	Config    ConfigStore
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *ConfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	active, err := h.Config.Active()
	if err != nil {
		http.Error(w, "failed to read active config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	backups, _ := h.Config.ListBackups()

	renderTemplate(w, h.Templates, "config.html", struct {
		Active  string
		Backups []cfgfile.Backup
	}{Active: active, Backups: backups})
}

// ValidateAction handles "Validate" clicks: runs haproxy -c against the
// submitted draft and reports pass/fail without changing anything on disk
// beyond a throwaway temp file (cfgfile.Validate's responsibility).
type ValidateAction struct {
	Config    ConfigStore
	Templates *template.Template
}

func (h *ValidateAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	content := r.FormValue("content")
	if strings.TrimSpace(content) == "" {
		http.Error(w, "content must not be empty", http.StatusBadRequest)
		return
	}

	res, err := h.Config.Validate(content)
	if err != nil {
		http.Error(w, "failed to run validator: "+err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, h.Templates, "validate_result.html", res)
}

// SaveApplyAction handles "Save & Apply": validates, stages, and — only if
// validation passed — applies the draft via the root helper, recording the
// outcome (success or failure) in the audit log either way.
type SaveApplyAction struct {
	Config    ConfigStore
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *SaveApplyAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	content := r.FormValue("content")
	if strings.TrimSpace(content) == "" {
		http.Error(w, "content must not be empty", http.StatusBadRequest)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	ip := clientIP(r)

	validation, err := h.Config.Validate(content)
	if err != nil {
		http.Error(w, "failed to run validator: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !validation.OK {
		_ = h.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: ip,
			Action: "config.apply", Detail: "rejected: failed haproxy -c: " + validation.Output,
		})
		renderTemplate(w, h.Templates, "validate_result.html", validation)
		return
	}

	draftPath, err := h.Config.SaveDraft(u.Email, content)
	if err != nil {
		http.Error(w, "failed to stage draft: "+err.Error(), http.StatusInternalServerError)
		return
	}

	res, err := h.Config.Apply(draftPath)
	if err != nil {
		http.Error(w, "failed to run apply helper: "+err.Error(), http.StatusInternalServerError)
		return
	}

	auditDetail := "applied"
	if !res.OK {
		auditDetail = "apply helper failed (auto rollback expected): " + res.Output
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: ip,
		Action: "config.apply", Target: draftPath, Detail: auditDetail,
	}); err != nil {
		http.Error(w, "config apply outcome could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !res.OK {
		http.Error(w, "apply failed, HAProxy config was rolled back: "+res.Output, http.StatusBadGateway)
		return
	}
	renderTemplate(w, h.Templates, "apply_result.html", res)
}

// RollbackAction restores one of the timestamped backups cfgfile.Store
// tracks, going through the exact same validate-then-apply path as any
// other config change (a backup is just a draft that happens to be old).
type RollbackAction struct {
	Config    ConfigStore
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *RollbackAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	path := r.FormValue("backup_path")
	if path == "" {
		http.Error(w, "backup_path is required", http.StatusBadRequest)
		return
	}

	backups, err := h.Config.ListBackups()
	if err != nil {
		http.Error(w, "failed to list backups: "+err.Error(), http.StatusInternalServerError)
		return
	}
	found := false
	for _, b := range backups {
		if b.Path == path {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "unknown backup path", http.StatusBadRequest)
		return
	}

	res, err := h.Config.Apply(path)
	if err != nil {
		http.Error(w, "failed to run apply helper: "+err.Error(), http.StatusInternalServerError)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	detail := "rolled back"
	if !res.OK {
		detail = "rollback failed: " + res.Output
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "config.rollback", Target: path, Detail: detail,
	}); err != nil {
		http.Error(w, "rollback outcome could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !res.OK {
		http.Error(w, res.Output, http.StatusBadGateway)
		return
	}
	renderTemplate(w, h.Templates, "apply_result.html", res)
}
