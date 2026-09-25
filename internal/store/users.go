package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// Role is a user's permission level. Higher roles include lower ones'
// capabilities: Admin > Operator > Viewer.
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Allows reports whether this role meets or exceeds the required role.
func (r Role) Allows(required Role) bool {
	rank := map[Role]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}
	return rank[r] >= rank[required]
}

// User is one haproxy-gui account.
type User struct {
	ID         int64
	Email      string
	Name       string
	Role       Role
	SSOSubject string
	Enabled    bool
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
		`INSERT INTO users (email, name, role, sso_subject, enabled) VALUES (?, ?, ?, ?, 1)`,
		email, name, RoleViewer, subject,
	)
	if err != nil {
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Email: email, Name: name, Role: RoleViewer, SSOSubject: subject, Enabled: true}, nil
}

// UserByEmail looks up a user, returning ErrNotFound if none exists.
func (s *Store) UserByEmail(email string) (User, error) {
	row := s.db.QueryRow(
		`SELECT id, email, name, role, COALESCE(sso_subject,''), enabled FROM users WHERE email = ?`,
		normalizeEmail(email),
	)
	return scanUser(row)
}

// UserByID looks up a user by primary key.
func (s *Store) UserByID(id int64) (User, error) {
	row := s.db.QueryRow(
		`SELECT id, email, name, role, COALESCE(sso_subject,''), enabled FROM users WHERE id = ?`, id,
	)
	return scanUser(row)
}

func scanUser(row *sql.Row) (User, error) {
	var u User
	var role string
	var enabled int
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &role, &u.SSOSubject, &enabled); err != nil {
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
	switch role {
	case RoleViewer, RoleOperator, RoleAdmin:
	default:
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

// ListUsers returns all users ordered by email.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT id, email, name, role, COALESCE(sso_subject,''), enabled FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		var role string
		var enabled int
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &role, &u.SSOSubject, &enabled); err != nil {
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
