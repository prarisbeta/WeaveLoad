package web

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
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
	GetBackupPath(name string) (string, error)
	ReadBackup(name string) (string, error)
	DeleteBackup(name string) error
}

// ServiceRestarter is the subset of *cfgfile.Store the "restart HAProxy"
// action needs — kept separate from ConfigStore since it's a different,
// more disruptive action (drops in-flight connections) than anything else
// on the config page.
type ServiceRestarter interface {
	Restart() (cfgfile.ApplyResult, error)
}

// ConfigHandler serves the config editor page and its actions
// (view/validate/save/apply). Apply must be wired behind
// auth.RequireCapability(store.CapManageConfig) — this is the most powerful action in
// the whole app, since it changes what HAProxy actually does.
type ConfigHandler struct {
	Config    ConfigStore
	Audit     AuditRecorder
	Templates *template.Template
	// Settings and Tokens, when set, add the settings sections (Redis queue,
	// queue token, API tokens) to this page for users who hold manage_settings.
	Settings SettingsStore
	Tokens   APITokenStore
}

func (h *ConfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	active, err := h.Config.Active()
	if err != nil {
		http.Error(w, "failed to read active config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	backups, _ := h.Config.ListBackups()
	settings, err := loadSettingsData(r, h.Settings, h.Tokens)
	if err != nil {
		http.Error(w, "failed to load settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, h.Templates, "config.html", struct {
		Chrome
		SettingsData
		Active  string
		Backups []cfgfile.Backup
	}{Chrome: NewChrome(r, "config"), SettingsData: settings, Active: active, Backups: backups})
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
	renderTemplate(w, h.Templates, "validate_result.html", newResultView(r, res.OK, res.Output))
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
		renderTemplate(w, h.Templates, "validate_result.html", newResultView(r, validation.OK, validation.Output))
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

	// Trigger auto-encryption on newly generated backups
	_, _ = h.Config.ListBackups()

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
		http.Error(w, "Penerapan gagal, konfigurasi dikembalikan otomatis ke versi sebelumnya: "+res.Output, http.StatusBadGateway)
		return
	}
	renderTemplate(w, h.Templates, "apply_result.html", newResultView(r, res.OK, res.Output))
}

// RollbackAction restores one of the timestamped backups cfgfile.Store
// tracks, staging it cleanly and applying it via the root helper.
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
	name := r.FormValue("name")
	if name == "" {
		name = r.FormValue("backup_path")
	}
	name = filepath.Base(name)
	if name == "" || name == "." {
		http.Error(w, "backup name is required", http.StatusBadRequest)
		return
	}

	content, err := h.Config.ReadBackup(name)
	if err != nil {
		http.Error(w, "failed to read/decrypt backup file: "+err.Error(), http.StatusBadRequest)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	draftPath, err := h.Config.SaveDraft("rollback-"+u.Email, content)
	if err != nil {
		http.Error(w, "failed to stage rollback draft: "+err.Error(), http.StatusInternalServerError)
		return
	}

	res, err := h.Config.Apply(draftPath)
	if err != nil {
		http.Error(w, "failed to run apply helper: "+err.Error(), http.StatusInternalServerError)
		return
	}

	detail := "rolled back"
	if !res.OK {
		detail = "rollback failed: " + res.Output
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "config.rollback", Target: name, Detail: detail,
	}); err != nil {
		http.Error(w, "rollback outcome could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !res.OK {
		http.Error(w, res.Output, http.StatusBadGateway)
		return
	}
	renderTemplate(w, h.Templates, "apply_result.html", newResultView(r, res.OK, res.Output))
}

// BackupDownloadAction streams a decrypted backup file as an attachment download.
type BackupDownloadAction struct {
	Config ConfigStore
}

func (h *BackupDownloadAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = r.URL.Query().Get("file")
	}
	name = filepath.Base(name)
	if name == "" || name == "." {
		http.Error(w, "backup name is required", http.StatusBadRequest)
		return
	}

	content, err := h.Config.ReadBackup(name)
	if err != nil {
		http.Error(w, "failed to read/decrypt backup file: "+err.Error(), http.StatusNotFound)
		return
	}

	dlName := name
	if !strings.HasSuffix(dlName, ".cfg") {
		dlName += ".cfg"
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, dlName))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(content))
}

// BackupDeleteAction removes a backup file and returns the refreshed backup list HTML.
type BackupDeleteAction struct {
	Config    ConfigStore
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *BackupDeleteAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		name = r.FormValue("backup_path")
	}
	name = filepath.Base(name)
	if name == "" || name == "." {
		http.Error(w, "backup name is required", http.StatusBadRequest)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	ip := clientIP(r)

	if err := h.Config.DeleteBackup(name); err != nil {
		_ = h.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: ip,
			Action: "config.backup.delete", Target: name, Detail: "failed: " + err.Error(),
		})
		http.Error(w, "failed to delete backup: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: ip,
		Action: "config.backup.delete", Target: name, Detail: "deleted backup file",
	})

	backups, _ := h.Config.ListBackups()
	renderTemplate(w, h.Templates, "config_backups.html", struct {
		Chrome
		Backups []cfgfile.Backup
	}{Chrome: NewChrome(r, "config"), Backups: backups})
}

// RestartServiceAction restarts the haproxy systemd service directly —
// unlike apply/rollback, which reload, this briefly drops in-flight
// connections. Meant for cases a reload alone can't fix (a wedged worker,
// config applied outside the GUI). Always audit-logged, success or failure.
type RestartServiceAction struct {
	Service   ServiceRestarter
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *RestartServiceAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFromContext(r.Context())

	res, err := h.Service.Restart()
	if err != nil {
		http.Error(w, "failed to run restart helper: "+err.Error(), http.StatusInternalServerError)
		return
	}

	detail := "restarted"
	if !res.OK {
		detail = "restart failed: " + res.Output
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "haproxy.restart", Detail: detail,
	}); err != nil {
		http.Error(w, "restart outcome could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !res.OK {
		http.Error(w, res.Output, http.StatusBadGateway)
		return
	}
	renderTemplate(w, h.Templates, "apply_result.html", newResultView(r, res.OK, res.Output))
}
