package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/omsdir"
	"haproxy-gui/internal/store"
)

// UserAdmin is the subset of *store.Store the user management page needs.
// Every method here should only ever be reachable behind
// auth.RequireCapability(store.CapManageUsers).
type UserAdmin interface {
	ListUsers() ([]store.User, error)
	SetRole(userID int64, role store.Role) error
	SetEnabled(userID int64, enabled bool) error
	CreateUser(email, name string, role store.Role) (store.User, error)
	DeleteUser(userID int64) error
	ResetPassword(userID int64, newPassword string) error
}

// UsersHandler lists accounts and lets an admin change roles / enable-
// disable accounts. It refuses to let an admin demote or disable their own
// account, since that could lock every admin out with no recovery path
// short of the break-glass local account.
type UsersHandler struct {
	Store     UserAdmin
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *UsersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	users, err := h.Store.ListUsers()
	if err != nil {
		http.Error(w, "failed to list users: "+err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, h.Templates, "users.html", struct {
		Chrome
		Users []store.User
	}{Chrome: NewChrome(r, "users"), Users: users})
}

// UserUpdateHandler applies a role change or enable/disable toggle to one
// user, submitted as a single form action.
type UserUpdateHandler struct {
	Store     UserAdmin
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *UserUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	actor, _ := auth.UserFromContext(r.Context())
	action := r.FormValue("action")

	var actionErr error
	var auditAction, auditDetail string

	switch action {
	case "set_role":
		role := store.Role(r.FormValue("role"))
		if actor.ID == id && !role.Can(store.CapManageUsers) {
			http.Error(w, "Anda tidak bisa mengubah peran akun sendiri menjadi peran tanpa akses manajemen pengguna. Hal itu akan mengunci Anda sendiri.", http.StatusForbidden)
			return
		}
		actionErr = h.Store.SetRole(id, role)
		auditAction, auditDetail = "user.set_role", "role="+string(role)
	case "enable":
		actionErr = h.Store.SetEnabled(id, true)
		auditAction = "user.enable"
	case "disable":
		if actor.ID == id {
			http.Error(w, "Anda tidak bisa menonaktifkan akun sendiri.", http.StatusForbidden)
			return
		}
		actionErr = h.Store.SetEnabled(id, false)
		auditAction = "user.disable"
	case "delete":
		if actor.ID == id {
			http.Error(w, "Anda tidak bisa menghapus akun sendiri.", http.StatusForbidden)
			return
		}
		actionErr = h.Store.DeleteUser(id)
		auditAction = "user.delete"
	case "reset_password":
		newPassword := r.FormValue("new_password")
		if strings.TrimSpace(newPassword) == "" {
			http.Error(w, "Kata sandi baru tidak boleh kosong", http.StatusBadRequest)
			return
		}
		actionErr = h.Store.ResetPassword(id, newPassword)
		auditAction = "user.reset_password"
	default:
		http.Error(w, "unknown action: "+action, http.StatusBadRequest)
		return
	}

	status := "ok"
	if actionErr != nil {
		status = "error: " + actionErr.Error()
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: actor.Email, RemoteIP: clientIP(r),
		Action: auditAction, Target: strconv.FormatInt(id, 10),
		Detail: auditDetail + " result=" + status,
	}); err != nil {
		http.Error(w, "change may have applied but failed to audit-log: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if actionErr != nil {
		http.Error(w, actionErr.Error(), http.StatusBadRequest)
		return
	}

	users, err := h.Store.ListUsers()
	if err != nil {
		http.Error(w, "updated, but failed to reload user list: "+err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, h.Templates, "users_table.html", struct {
		Chrome
		Users []store.User
	}{Chrome: NewChrome(r, "users"), Users: users})
}

// DirectorySearcher is the subset of *omsdir.Client the search box needs.
type DirectorySearcher interface {
	Enabled() bool
	Search(query string) ([]omsdir.User, error)
}

// UserSearchHandler looks up candidates in the OMS CNI SSO directory as an
// admin types, so a user can be pre-registered by picking them from a
// search result instead of typing their email by hand. Directory may be
// nil or report Enabled()==false (no client credentials configured), in
// which case the fragment just says so — manual entry always still works.
type UserSearchHandler struct {
	Directory DirectorySearcher
	Templates *template.Template
}

func (h *UserSearchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	data := struct {
		Chrome
		Query   string
		Enabled bool
		Results []omsdir.User
		Error   string
	}{
		Chrome:  NewChrome(r, "users"),
		Query:   query,
		Enabled: h.Directory != nil && h.Directory.Enabled(),
	}

	if data.Enabled && query != "" {
		results, err := h.Directory.Search(query)
		if err != nil {
			data.Error = "Pencarian ke direktori SSO gagal: " + err.Error()
		} else {
			data.Results = results
		}
	}
	renderTemplate(w, h.Templates, "user_search_results.html", data)
}

// UserCreateHandler pre-registers an account by email — for granting an
// Operator or Admin role to someone from the OMS CNI SSO directory before
// they've ever logged in, instead of waiting for their first login to land
// them as Viewer and promoting them afterwards (previously the only way to
// do that up front was editing the database by hand).
type UserCreateHandler struct {
	Store     UserAdmin
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *UserCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	name := strings.TrimSpace(r.FormValue("name"))
	role := store.Role(r.FormValue("role"))

	if !strings.Contains(email, "@") {
		http.Error(w, "Masukkan alamat email yang valid dari akun SSO OMS CNI (harus mengandung @).", http.StatusBadRequest)
		return
	}
	if !role.Valid() {
		http.Error(w, "Peran tidak dikenali.", http.StatusBadRequest)
		return
	}

	actor, _ := auth.UserFromContext(r.Context())
	_, err := h.Store.CreateUser(email, name, role)

	status := "ok"
	if err != nil {
		status = "error: " + err.Error()
	}
	if auditErr := h.Audit.Record(store.AuditEntry{
		UserEmail: actor.Email, RemoteIP: clientIP(r),
		Action: "user.create", Target: email,
		Detail: "role=" + string(role) + " result=" + status,
	}); auditErr != nil {
		http.Error(w, "pengguna mungkin sudah ditambahkan, tapi gagal dicatat ke riwayat aktivitas: "+auditErr.Error(), http.StatusInternalServerError)
		return
	}

	if err != nil {
		if errors.Is(err, store.ErrEmailTaken) {
			http.Error(w, "Email ini sudah terdaftar sebagai pengguna.", http.StatusConflict)
			return
		}
		http.Error(w, "Gagal menambahkan pengguna: "+err.Error(), http.StatusBadRequest)
		return
	}

	users, err := h.Store.ListUsers()
	if err != nil {
		http.Error(w, "pengguna ditambahkan, tapi daftar gagal dimuat ulang: "+err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, h.Templates, "users_table.html", struct {
		Chrome
		Users []store.User
	}{Chrome: NewChrome(r, "users"), Users: users})
}

// ProfileLanguageStore is the subset of store needed to set user language
type ProfileLanguageStore interface {
	SetLanguage(userID int64, lang string) error
}

// ProfileLanguageHandler allows users to change their own language preference
type ProfileLanguageHandler struct {
	Store ProfileLanguageStore
}

func (h *ProfileLanguageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	lang := strings.TrimSpace(r.FormValue("language"))
	if lang != "id" && lang != "en" && lang != "zh" && lang != "ja" {
		http.Error(w, "invalid language", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "gateway_lang",
		Value:    lang,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(365 * 24 * time.Hour),
	})

	u, ok := auth.UserFromContext(r.Context())
	if ok && u.ID != 0 {
		_ = h.Store.SetLanguage(u.ID, lang)
	}

	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref == "" || strings.Contains(ref, "/api/profile/language") {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// ProfilePasswordStore is the subset of store needed for a user to change their password.
type ProfilePasswordStore interface {
	ChangePassword(userID int64, oldPassword, newPassword string) error
}

// ProfilePasswordHandler handles user password changes (POST /api/profile/password).
type ProfilePasswordHandler struct {
	Store ProfilePasswordStore
	Audit AuditRecorder
}

func (h *ProfilePasswordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	u, ok := auth.UserFromContext(r.Context())
	if !ok || u.ID == 0 {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	oldPass := r.FormValue("old_password")
	newPass := r.FormValue("new_password")

	if strings.TrimSpace(newPass) == "" {
		http.Error(w, "Kata sandi baru tidak boleh kosong", http.StatusBadRequest)
		return
	}

	if err := h.Store.ChangePassword(u.ID, oldPass, newPass); err != nil {
		http.Error(w, "Gagal mengubah kata sandi: "+err.Error(), http.StatusBadRequest)
		return
	}

	if h.Audit != nil {
		_ = h.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: clientIP(r),
			Action: "user.change_password", Target: strconv.FormatInt(u.ID, 10),
			Detail: "result=ok",
		})
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Kata sandi berhasil diperbarui"))
}

// ProfileTOTPStore is the subset of store needed for 2FA TOTP setup.
type ProfileTOTPStore interface {
	SetTOTP(userID int64, secret string, recoveryCodes []string) error
	SetTOTPEnabled(userID int64, enabled bool) error
}

// ProfileTOTPHandler handles 2FA TOTP setup, enable, and disable actions (POST /api/profile/totp).
type ProfileTOTPHandler struct {
	Store ProfileTOTPStore
	Audit AuditRecorder
}

func (h *ProfileTOTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	u, ok := auth.UserFromContext(r.Context())
	if !ok || u.ID == 0 {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	action := r.FormValue("action")
	switch action {
	case "setup":
		secret, err := auth.GenerateTOTPSecret()
		if err != nil {
			http.Error(w, "failed to generate TOTP secret", http.StatusInternalServerError)
			return
		}
		codes, err := auth.GenerateRecoveryCodes()
		if err != nil {
			http.Error(w, "failed to generate recovery codes", http.StatusInternalServerError)
			return
		}
		if err := h.Store.SetTOTP(u.ID, secret, codes); err != nil {
			http.Error(w, "failed to save TOTP setup: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secret":         secret,
			"recovery_codes": codes,
			"otpauth_url":    fmt.Sprintf("otpauth://totp/KonsolGateway:%s?secret=%s&issuer=KonsolGateway", u.Email, secret),
		})
	case "enable":
		code := strings.TrimSpace(r.FormValue("code"))
		if !auth.VerifyTOTPCode(u.TOTPSecret, code, time.Now()) {
			http.Error(w, "Kode 2FA tidak valid. Pastikan waktu di perangkat Anda sesuai.", http.StatusBadRequest)
			return
		}
		if err := h.Store.SetTOTPEnabled(u.ID, true); err != nil {
			http.Error(w, "Gagal mengaktifkan 2FA: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if h.Audit != nil {
			_ = h.Audit.Record(store.AuditEntry{
				UserEmail: u.Email, RemoteIP: clientIP(r),
				Action: "user.totp_enable", Target: strconv.FormatInt(u.ID, 10),
				Detail: "result=ok",
			})
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Autentikasi 2FA berhasil diaktifkan"))
	case "disable":
		if err := h.Store.SetTOTPEnabled(u.ID, false); err != nil {
			http.Error(w, "Gagal menonaktifkan 2FA: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if h.Audit != nil {
			_ = h.Audit.Record(store.AuditEntry{
				UserEmail: u.Email, RemoteIP: clientIP(r),
				Action: "user.totp_disable", Target: strconv.FormatInt(u.ID, 10),
				Detail: "result=ok",
			})
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Autentikasi 2FA dinonaktifkan"))
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}
