package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
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
	ID                int64
	Email             string
	Name              string
	Role              Role
	SSOSubject        string
	Enabled           bool
	Language          string
	TOTPSecret        string
	TOTPEnabled       bool
	TOTPRecoveryCodes string
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
		`SELECT id, email, name, role, COALESCE(sso_subject,''), enabled, language, COALESCE(totp_secret,''), totp_enabled, COALESCE(totp_recovery_codes,'') FROM users WHERE email = ?`,
		normalizeEmail(email),
	)
	return scanUser(row)
}

// UserByID looks up a user by primary key.
func (s *Store) UserByID(id int64) (User, error) {
	row := s.db.QueryRow(
		`SELECT id, email, name, role, COALESCE(sso_subject,''), enabled, language, COALESCE(totp_secret,''), totp_enabled, COALESCE(totp_recovery_codes,'') FROM users WHERE id = ?`, id,
	)
	return scanUser(row)
}

func scanUser(row *sql.Row) (User, error) {
	var u User
	var role string
	var enabled, totpEnabled int
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &role, &u.SSOSubject, &enabled, &u.Language, &u.TOTPSecret, &totpEnabled, &u.TOTPRecoveryCodes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("scan user: %w", err)
	}
	u.Role = Role(role)
	u.Enabled = enabled != 0
	u.TOTPEnabled = totpEnabled != 0
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
	rows, err := s.db.Query(`SELECT id, email, name, role, COALESCE(sso_subject,''), enabled, language, COALESCE(totp_secret,''), totp_enabled, COALESCE(totp_recovery_codes,'') FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		var role string
		var enabled, totpEnabled int
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &role, &u.SSOSubject, &enabled, &u.Language, &u.TOTPSecret, &totpEnabled, &u.TOTPRecoveryCodes); err != nil {
			return nil, err
		}
		u.Role = Role(role)
		u.Enabled = enabled != 0
		u.TOTPEnabled = totpEnabled != 0
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

// DeleteUser deletes a user account and any associated active sessions.
func (s *Store) DeleteUser(userID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete user sessions: %w", err)
	}

	res, err := tx.Exec(`DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}

	return tx.Commit()
}

// AuthenticateUser verifies username/email and password against password_hash.
func (s *Store) AuthenticateUser(usernameOrEmail, password string) (User, error) {
	row := s.db.QueryRow(
		`SELECT id, email, name, role, COALESCE(sso_subject,''), COALESCE(password_hash,''), enabled, language FROM users WHERE email = ?`,
		normalizeEmail(usernameOrEmail),
	)
	var u User
	var role, hash string
	var enabled int
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &role, &u.SSOSubject, &hash, &enabled, &u.Language); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("scan user: %w", err)
	}
	u.Role = Role(role)
	u.Enabled = enabled != 0
	if hash == "" {
		return User{}, fmt.Errorf("no password set for user")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return User{}, fmt.Errorf("invalid password")
	}
	return u, nil
}

// EnsureDefaultUser creates or updates a local account with a password hash and role.
func (s *Store) EnsureDefaultUser(email, name, password string, role Role) error {
	email = normalizeEmail(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}
	if !role.Valid() {
		return fmt.Errorf("invalid role: %q", role)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	u, err := s.UserByEmail(email)
	if err == nil {
		_, execErr := s.db.Exec(
			`UPDATE users SET name = ?, password_hash = ?, role = ? WHERE id = ?`,
			name, string(hash), role, u.ID,
		)
		return execErr
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}

	_, err = s.db.Exec(
		`INSERT INTO users (email, name, role, password_hash, enabled, language) VALUES (?, ?, ?, ?, 1, 'id')`,
		email, name, role, string(hash),
	)
	return err
}

// ResetPassword sets a user's password without checking the old password (for admins).
func (s *Store) ResetPassword(userID int64, newPassword string) error {
	if strings.TrimSpace(newPassword) == "" {
		return fmt.Errorf("password cannot be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	res, err := s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, string(hash), userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ChangePassword updates a user's password after verifying their old password.
func (s *Store) ChangePassword(userID int64, oldPassword, newPassword string) error {
	if strings.TrimSpace(newPassword) == "" {
		return fmt.Errorf("new password cannot be empty")
	}
	u, err := s.UserByID(userID)
	if err != nil {
		return err
	}
	var hash string
	row := s.db.QueryRow(`SELECT COALESCE(password_hash,'') FROM users WHERE id = ?`, u.ID)
	if err := row.Scan(&hash); err != nil {
		return err
	}
	if hash == "" {
		return fmt.Errorf("user has no password set")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(oldPassword)); err != nil {
		return fmt.Errorf("invalid old password")
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, string(newHash), userID)
	return err
}

// SetTOTP stores a user's TOTP secret and recovery codes (comma-separated).
func (s *Store) SetTOTP(userID int64, secret string, recoveryCodes []string) error {
	codesStr := strings.Join(recoveryCodes, ",")
	_, err := s.db.Exec(`UPDATE users SET totp_secret = ?, totp_recovery_codes = ? WHERE id = ?`, secret, codesStr, userID)
	return err
}

// SetTOTPEnabled enables or disables TOTP 2FA for a user.
func (s *Store) SetTOTPEnabled(userID int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE users SET totp_enabled = ? WHERE id = ?`, v, userID)
	return err
}

// VerifyAndUseRecoveryCode checks if code is in the user's recovery codes and consumes it if found.
func (s *Store) VerifyAndUseRecoveryCode(userID int64, code string) (bool, error) {
	u, err := s.UserByID(userID)
	if err != nil {
		return false, err
	}
	if u.TOTPRecoveryCodes == "" {
		return false, nil
	}
	codes := strings.Split(u.TOTPRecoveryCodes, ",")
	code = strings.ToUpper(strings.TrimSpace(code))
	foundIndex := -1
	for i, c := range codes {
		if strings.TrimSpace(c) == code {
			foundIndex = i
			break
		}
	}
	if foundIndex == -1 {
		return false, nil
	}

	// Remove used code
	updatedCodes := append(codes[:foundIndex], codes[foundIndex+1:]...)
	_, err = s.db.Exec(`UPDATE users SET totp_recovery_codes = ? WHERE id = ?`, strings.Join(updatedCodes, ","), userID)
	return true, err
}

// bootstrapEmail is the local account created on first start so a fresh
// install can be logged into before any SSO user exists.
const bootstrapEmail = "konsolgw"

// EnsureBootstrapAdmin creates the local super-admin account if it does not
// exist yet, and does nothing if it does: a password the operator changed is
// never reset by a restart. An empty password makes it generate a random one,
// returned so the caller can show it once; "" is returned when nothing was
// generated (account already there, or the password was supplied).
func (s *Store) EnsureBootstrapAdmin(password string) (generated string, err error) {
	if _, err := s.UserByEmail(bootstrapEmail); err == nil {
		return "", nil
	} else if !errors.Is(err, ErrNotFound) {
		return "", err
	}

	if password == "" {
		buf := make([]byte, 15)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("generate bootstrap password: %w", err)
		}
		password = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
		generated = password
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO users (email, name, role, password_hash, enabled, language) VALUES (?, ?, ?, ?, 1, 'id')`,
		bootstrapEmail, "Konsol GW Admin", RoleSuperAdmin, string(hash),
	); err != nil {
		return "", err
	}
	return generated, nil
}
