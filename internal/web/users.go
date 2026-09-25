package web

import (
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/store"
)

// UserAdmin is the subset of *store.Store the user management page needs.
// Every method here should only ever be reachable behind
// auth.RequireRole(store.RoleAdmin).
type UserAdmin interface {
	ListUsers() ([]store.User, error)
	SetRole(userID int64, role store.Role) error
	SetEnabled(userID int64, enabled bool) error
	CreateUser(email, name string, role store.Role) (store.User, error)
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
		if actor.ID == id && role != store.RoleAdmin {
			http.Error(w, "you cannot demote your own account", http.StatusForbidden)
			return
		}
		actionErr = h.Store.SetRole(id, role)
		auditAction, auditDetail = "user.set_role", "role="+string(role)
	case "enable":
		actionErr = h.Store.SetEnabled(id, true)
		auditAction = "user.enable"
	case "disable":
		if actor.ID == id {
			http.Error(w, "you cannot disable your own account", http.StatusForbidden)
			return
		}
		actionErr = h.Store.SetEnabled(id, false)
		auditAction = "user.disable"
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
	switch role {
	case store.RoleViewer, store.RoleOperator, store.RoleAdmin:
	default:
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
