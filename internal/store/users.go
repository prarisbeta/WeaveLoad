package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// Role is a user's job function, which grants a fixed set of Capabilities
// (see rolePermissions) — not a rank in a hierarchy. A SOC Analyst and an
// SRE are both "more privileged than Viewer" in different, non-overlapping
// ways (e.g. the SOC Analyst can see security events an SRE can't, but
// can't touch HAProxy config an SRE can) — see docs/roadmap's RBAC section.
type Role string

const (
	RoleSuperAdmin    Role = "super_admin"
	RolePlatformAdmin Role = "platform_admin"
	RoleNOCOperator   Role = "noc_operator"
	RoleSOCAnalyst    Role = "soc_analyst"
	RoleSRE           Role = "sre"
	RoleSecurityAdmin Role = "security_admin"
	RoleAuditor       Role = "auditor"
	RoleViewer        Role = "viewer"
)

// Capability is one specific thing a role may be permitted to do. Handlers
// and templates check a capability directly (Role.Can) instead of comparing
// roles against each other.
type Capability string

const (
	CapRuntimeControl Capability = "runtime_control" // enable/disable/drain/weight servers, edit ACL/map entries
	CapViewLogs       Capability = "view_logs"
	CapViewQueue      Capability = "view_queue"
	CapViewAudit      Capability = "view_audit"
	CapManageConfig   Capability = "manage_config" // config editor, pool/member add-edit-remove, rate limits, cert upload
	CapManageUsers    Capability = "manage_users"
	CapManageSettings Capability = "manage_settings" // Redis connection, queue API token

	// Reserved for modules not yet built (Security Engine, Incident
	// Management — see the HAIProxy roadmap): no route checks these yet,
	// but the role table below already grants them so wiring up those
	// modules later doesn't require touching every role's permission set
	// again.
	CapViewSecurity    Capability = "view_security"
	CapManageIncidents Capability = "manage_incidents"
)

var allCapabilities = []Capability{
	CapRuntimeControl, CapViewLogs, CapViewQueue, CapViewAudit,
	CapManageConfig, CapManageUsers, CapManageSettings,
	CapViewSecurity, CapManageIncidents,
}

// rolePermissions is the whole RBAC model: what each of the 8 roles can do.
// Super Admin and Platform Admin both get every capability for now — the
// MVP has no org/tenant-scoped settings that would distinguish "owns the
// whole platform" from "administers one deployment" yet.
var rolePermissions = map[Role][]Capability{
	RoleSuperAdmin:    allCapabilities,
	RolePlatformAdmin: allCapabilities,
	RoleNOCOperator:   {CapRuntimeControl, CapViewLogs, CapViewQueue},
	RoleSOCAnalyst:    {CapViewQueue, CapViewAudit, CapViewSecurity, CapManageIncidents},
	RoleSRE:           {CapRuntimeControl, CapManageConfig, CapViewLogs, CapViewQueue},
	RoleSecurityAdmin: {CapRuntimeControl, CapManageConfig, CapViewLogs, CapViewQueue, CapViewAudit, CapViewSecurity, CapManageIncidents, CapManageSettings},
	RoleAuditor:       {CapViewLogs, CapViewQueue, CapViewAudit, CapViewSecurity},
	RoleViewer:        {},
}

// Can reports whether this role grants c. An unrecognized role (shouldn't
// happen — SetRole/CreateUser validate against Valid()) grants nothing.
func (r Role) Can(c Capability) bool {
	for _, have := range rolePermissions[r] {
		if have == c {
			return true
		}
	}
	return false
}

// Valid reports whether r is one of the 8 recognized roles.
func (r Role) Valid() bool {
	_, ok := rolePermissions[r]
	return ok
}

// User is one haproxy-gui account.
type User struct {
	ID         int64
	Email      string
	Name       string
	Role       Role
	SSOSubject string
	Enabled    bool
	Language   string
}

var ErrNotFound = errors.New("not found")

// UpsertSSOUser creates a user on first SSO login, or updates their name if
// it changed, without ever downgrading a role an admin has set. Brand new
// users start as Viewer — an admin must promote them.
func (s *Store) UpsertSSOUser(email, name, subject string) (User, error) {
	email = normalizeEmail(email)
	if email == "" {
		return User{}, fmt.Errorf("email is required")
	}

	u, err := s.UserByEmail(email)
	if err == nil {
		if _, execErr := s.db.Exec(
			`UPDATE users SET name = ?, sso_subject = ? WHERE id = ?`,
			name, subject, u.ID,
		); execErr != nil {
			return User{}, fmt.Errorf("update user: %w", execErr)
		}
		u.Name = name
		u.SSOSubject = subject
		return u, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return User{}, err
	}

	res, err := s.db.Exec(
		`INSERT INTO users (email, name, role, sso_subject, enabled, language) VALUES (?, ?, ?, ?, 1, 'id')`,
		email, name, RoleViewer, subject,
	)
	if err != nil {
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Email: email, Name: name, Role: RoleViewer, SSOSubject: subject, Enabled: true, Language: "id"}, nil
}

// ErrEmailTaken is returned by CreateUser when the email is already
// registered (whether from a prior SSO login or a prior CreateUser call).
var ErrEmailTaken = errors.New("email already registered")

// CreateUser pre-registers an account with a chosen role, before that
// person has ever logged in — so an admin can grant Operator/Admin access
// up front instead of waiting for a first SSO login to land them as Viewer
// and promoting them after the fact. sso_subject is left empty; the first
// real SSO login fills it in via UpsertSSOUser, which matches by email and
// never resets a role that's already set.
func (s *Store) CreateUser(email, name string, role Role) (User, error) {
	email = normalizeEmail(email)
	if email == "" {
		return User{}, fmt.Errorf("email is required")
	}
	if !role.Valid() {
		return User{}, fmt.Errorf("invalid role: %q", role)
	}

	if _, err := s.UserByEmail(email); err == nil {
		return User{}, ErrEmailTaken
	} else if !errors.Is(err, ErrNotFound) {
		return User{}, err
	}

	res, err := s.db.Exec(
		`INSERT INTO users (email, name, role, enabled, language) VALUES (?, ?, ?, 1, 'id')`,
		email, name, role,
	)
	if err != nil {
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Email: email, Name: name, Role: role, Enabled: true, Language: "id"}, nil
}

// UserByEmail looks up a user, returning ErrNotFound if none exists.
func (s *Store) UserByEmail(email string) (User, error) {
	row := s.db.QueryRow(
		`SELECT id, email, name, role, COALESCE(sso_subject,''), enabled, language FROM users WHERE email = ?`,
		normalizeEmail(email),
	)
	return scanUser(row)
}

// UserByID looks up a user by primary key.
func (s *Store) UserByID(id int64) (User, error) {
	row := s.db.QueryRow(
		`SELECT id, email, name, role, COALESCE(sso_subject,''), enabled, language FROM users WHERE id = ?`, id,
	)
	return scanUser(row)
}

func scanUser(row *sql.Row) (User, error) {
	var u User
	var role string
	var enabled int
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &role, &u.SSOSubject, &enabled, &u.Language); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("scan user: %w", err)
	}
	u.Role = Role(role)
	u.Enabled = enabled != 0
	return u, nil
}

// SetRole changes a user's role. Only callers who have already checked the
// acting user is an Admin should call this.
func (s *Store) SetRole(userID int64, role Role) error {
	if !role.Valid() {
		return fmt.Errorf("invalid role: %q", role)
	}
	_, err := s.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, role, userID)
	return err
}

// SetEnabled enables or disables a user's account. A disabled account's
// existing sessions still resolve to a user (so RequireAuth can report 403
// with a clear reason) but can no longer create new ones via login.
func (s *Store) SetEnabled(userID int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE users SET enabled = ? WHERE id = ?`, v, userID)
	return err
}

// SetLanguage updates a user's preferred language.
func (s *Store) SetLanguage(userID int64, lang string) error {
	_, err := s.db.Exec(`UPDATE users SET language = ? WHERE id = ?`, lang, userID)
	return err
}

// ListUsers returns all users ordered by email.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT id, email, name, role, COALESCE(sso_subject,''), enabled, language FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		var role string
		var enabled int
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &role, &u.SSOSubject, &enabled, &u.Language); err != nil {
			return nil, err
		}
		u.Role = Role(role)
		u.Enabled = enabled != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

func normalizeEmail(e string) string {
	// Emails are case-insensitive per RFC 5321 in practice; store lowercase
	// so "Admin@x" and "admin@x" are the same account.
	b := []byte(e)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
