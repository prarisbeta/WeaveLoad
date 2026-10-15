package store

import (
	"database/sql"
	"testing"
	"time"
)

func newTestDB(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestMigrateRoles_UpgradesOldSchemaAndRemapsRoles simulates a database
// created before the 8-role RBAC model (CHECK IN ('viewer','operator',
// 'admin')) and checks migrateRoles both remaps every existing user's role
// correctly and is safe to run again afterwards (Open calls it on every
// startup, not just once).
func TestMigrateRoles_UpgradesOldSchemaAndRemapsRoles(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	const oldSchema = `CREATE TABLE users (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		email         TEXT NOT NULL UNIQUE,
		name          TEXT NOT NULL DEFAULT '',
		role          TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer','operator','admin')),
		sso_subject   TEXT,
		password_hash TEXT,
		enabled       INTEGER NOT NULL DEFAULT 1,
		created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`
	if _, err := db.Exec(oldSchema); err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (email, name, role) VALUES
		('a@x.id', 'A', 'admin'), ('b@x.id', 'B', 'operator'), ('c@x.id', 'C', 'viewer')`); err != nil {
		t.Fatalf("seed old rows: %v", err)
	}

	s := &Store{db: db}
	if err := s.migrateRoles(); err != nil {
		t.Fatalf("migrateRoles: %v", err)
	}
	if err := s.migrateTOTP(); err != nil {
		t.Fatalf("migrateTOTP: %v", err)
	}

	cases := []struct {
		email string
		want  Role
	}{
		{"a@x.id", RolePlatformAdmin},
		{"b@x.id", RoleNOCOperator},
		{"c@x.id", RoleViewer},
	}
	for _, c := range cases {
		u, err := s.UserByEmail(c.email)
		if err != nil {
			t.Fatalf("UserByEmail(%q): %v", c.email, err)
		}
		if u.Role != c.want {
			t.Errorf("%s role after migration = %q, want %q", c.email, u.Role, c.want)
		}
	}

	// Idempotent: a second run (as happens on every subsequent process
	// startup via Open -> migrate -> migrateRoles) must not error or
	// re-touch already-migrated rows.
	if err := s.migrateRoles(); err != nil {
		t.Fatalf("second migrateRoles call: %v", err)
	}
	if u, err := s.UserByEmail("a@x.id"); err != nil || u.Role != RolePlatformAdmin {
		t.Errorf("role changed on second migration: %+v, err=%v", u, err)
	}

	// New role values must now actually be insertable — proves the CHECK
	// constraint itself was rebuilt, not just the copied data remapped.
	if _, err := s.CreateUser("d@x.id", "D", RoleSOCAnalyst); err != nil {
		t.Errorf("CreateUser with a new-model role after migration: %v", err)
	}
}

func TestUpsertSSOUser_CreatesViewerByDefault(t *testing.T) {
	s := newTestDB(t)
	u, err := s.UpsertSSOUser("Budi@Example.com", "Budi Santoso", "sub-123")
	if err != nil {
		t.Fatalf("UpsertSSOUser: %v", err)
	}
	if u.Email != "budi@example.com" {
		t.Errorf("email = %q, want lowercased", u.Email)
	}
	if u.Role != RoleViewer {
		t.Errorf("role = %q, want viewer", u.Role)
	}
	if !u.Enabled {
		t.Error("new user should be enabled by default")
	}
}

func TestUpsertSSOUser_SecondLoginDoesNotDowngradeRole(t *testing.T) {
	s := newTestDB(t)
	u, err := s.UpsertSSOUser("admin@example.com", "Admin", "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole(u.ID, RolePlatformAdmin); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	again, err := s.UpsertSSOUser("admin@example.com", "Admin Renamed", "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if again.Role != RolePlatformAdmin {
		t.Errorf("role after re-login = %q, want platform_admin (must not be reset)", again.Role)
	}
	if again.Name != "Admin Renamed" {
		t.Errorf("name = %q, want updated name", again.Name)
	}
}

func TestUserByEmail_NotFound(t *testing.T) {
	s := newTestDB(t)
	if _, err := s.UserByEmail("nobody@example.com"); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestRole_Can(t *testing.T) {
	cases := []struct {
		role Role
		cap  Capability
		want bool
	}{
		{RolePlatformAdmin, CapManageUsers, true},
		{RolePlatformAdmin, CapViewSecurity, true}, // admins get every capability, including reserved ones
		{RoleViewer, CapManageUsers, false},
		{RoleViewer, CapRuntimeControl, false},
		{RoleNOCOperator, CapRuntimeControl, true},
		{RoleNOCOperator, CapManageConfig, false}, // NOC Operator can't edit HAProxy config
		{RoleSOCAnalyst, CapViewSecurity, true},
		{RoleSOCAnalyst, CapManageConfig, false}, // per the PRD: SOC Analyst never gets HAProxy config access
		{Role("not_a_real_role"), CapManageUsers, false},
	}
	for _, c := range cases {
		if got := c.role.Can(c.cap); got != c.want {
			t.Errorf("%s.Can(%s) = %v, want %v", c.role, c.cap, got, c.want)
		}
	}
}

func TestRole_Valid(t *testing.T) {
	for _, r := range []Role{RoleSuperAdmin, RolePlatformAdmin, RoleNOCOperator, RoleSOCAnalyst, RoleSRE, RoleSecurityAdmin, RoleAuditor, RoleViewer} {
		if !r.Valid() {
			t.Errorf("%s.Valid() = false, want true", r)
		}
	}
	if Role("bogus").Valid() {
		t.Error(`Role("bogus").Valid() = true, want false`)
	}
}

func TestSession_RoundTrip(t *testing.T) {
	s := newTestDB(t)
	u, _ := s.UpsertSSOUser("user@example.com", "User", "sub")

	sess, err := s.CreateSession(u.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.CSRFToken == "" || sess.ID == "" {
		t.Fatal("expected non-empty session ID and CSRF token")
	}

	got, err := s.Session(sess.ID)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if got.UserID != u.ID || got.CSRFToken != sess.CSRFToken {
		t.Errorf("got %+v, want matching %+v", got, sess)
	}
}

func TestSession_ExpiredIsNotFound(t *testing.T) {
	s := newTestDB(t)
	u, _ := s.UpsertSSOUser("user@example.com", "User", "sub")

	sess, err := s.CreateSession(u.ID, -time.Second) // already expired
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(sess.ID); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound for expired session", err)
	}
}

func TestSession_UnknownIDIsNotFound(t *testing.T) {
	s := newTestDB(t)
	if _, err := s.Session("does-not-exist"); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleteSession_LogsOut(t *testing.T) {
	s := newTestDB(t)
	u, _ := s.UpsertSSOUser("user@example.com", "User", "sub")
	sess, _ := s.CreateSession(u.ID, time.Hour)

	if err := s.DeleteSession(sess.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := s.Session(sess.ID); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound after delete", err)
	}
}

func TestRecord_RequiresUserEmailAndAction(t *testing.T) {
	s := newTestDB(t)
	if err := s.Record(AuditEntry{Action: "x"}); err == nil {
		t.Error("expected error for missing user email")
	}
	if err := s.Record(AuditEntry{UserEmail: "x@example.com"}); err == nil {
		t.Error("expected error for missing action")
	}
}

func TestListAudit_NewestFirstAndFiltered(t *testing.T) {
	s := newTestDB(t)
	must := func(e AuditEntry) {
		t.Helper()
		if err := s.Record(e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	must(AuditEntry{UserEmail: "a@example.com", Action: "server.drain", Target: "http_oms/node1"})
	must(AuditEntry{UserEmail: "b@example.com", Action: "config.apply", Target: "haproxy.cfg"})
	must(AuditEntry{UserEmail: "a@example.com", Action: "server.ready", Target: "http_oms/node1"})

	all, err := s.ListAudit(AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("entries = %d, want 3", len(all))
	}
	if all[0].Action != "server.ready" {
		t.Errorf("newest entry action = %q, want server.ready (most recent first)", all[0].Action)
	}

	onlyA, err := s.ListAudit(AuditFilter{UserEmail: "A@Example.com"})
	if err != nil {
		t.Fatalf("ListAudit filtered: %v", err)
	}
	if len(onlyA) != 2 {
		t.Errorf("entries for a@example.com = %d, want 2", len(onlyA))
	}
}

func TestCreateUser_PreRegistersWithChosenRole(t *testing.T) {
	s := newTestDB(t)
	u, err := s.CreateUser("Baru@Example.com", "Baru", RoleNOCOperator)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Email != "baru@example.com" {
		t.Errorf("email = %q, want lowercased", u.Email)
	}
	if u.Role != RoleNOCOperator {
		t.Errorf("role = %q, want operator", u.Role)
	}
	if !u.Enabled {
		t.Error("pre-registered user should be enabled by default")
	}
}

func TestCreateUser_RejectsDuplicateEmail(t *testing.T) {
	s := newTestDB(t)
	if _, err := s.CreateUser("dup@example.com", "A", RoleViewer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("Dup@Example.com", "B", RolePlatformAdmin); err != ErrEmailTaken {
		t.Errorf("err = %v, want ErrEmailTaken", err)
	}
}

func TestCreateUser_RejectsUnknownRole(t *testing.T) {
	s := newTestDB(t)
	if _, err := s.CreateUser("x@example.com", "X", "superuser"); err == nil {
		t.Error("expected error for invalid role")
	}
}

func TestCreateUser_FirstSSOLoginKeepsPreAssignedRole(t *testing.T) {
	s := newTestDB(t)
	pre, err := s.CreateUser("future-admin@example.com", "Future Admin", RolePlatformAdmin)
	if err != nil {
		t.Fatal(err)
	}

	loggedIn, err := s.UpsertSSOUser("future-admin@example.com", "Future Admin", "sub-xyz")
	if err != nil {
		t.Fatal(err)
	}
	if loggedIn.ID != pre.ID {
		t.Errorf("SSO login should match the pre-registered row, got a different ID")
	}
	if loggedIn.Role != RolePlatformAdmin {
		t.Errorf("role after first login = %q, want admin (pre-assigned role must survive)", loggedIn.Role)
	}
	if loggedIn.SSOSubject != "sub-xyz" {
		t.Errorf("sso_subject = %q, want it filled in by the first real login", loggedIn.SSOSubject)
	}
}

func TestSetRole_RejectsUnknownRole(t *testing.T) {
	s := newTestDB(t)
	u, _ := s.UpsertSSOUser("user@example.com", "User", "sub")
	if err := s.SetRole(u.ID, "superuser"); err == nil {
		t.Error("expected error for invalid role")
	}
}

func TestRecordAndPruneAudit(t *testing.T) {
	s := newTestDB(t)
	if err := s.Record(AuditEntry{
		UserEmail: "alice@example.com",
		RemoteIP:  "127.0.0.1",
		Action:    "server.ready",
		Target:    "web/node1",
		Detail:    "test",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	entries, err := s.ListAudit(AuditFilter{})
	if err != nil || len(entries) != 1 {
		t.Fatalf("ListAudit: err=%v len=%d", err, len(entries))
	}

	// Insert an old entry manually
	oldTS := time.Now().UTC().Add(-40 * 24 * time.Hour).Format("2006-01-02T15:04:05.000Z")
	if _, err := s.db.Exec(`INSERT INTO audit_log (ts, user_email, remote_ip, action, target, detail) VALUES (?, 'bob@example.com', '127.0.0.1', 'server.drain', 'web/node2', 'old')`, oldTS); err != nil {
		t.Fatalf("insert old audit: %v", err)
	}

	pruned, err := s.PruneAudit(30 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("PruneAudit: %v", err)
	}
	if pruned != 1 {
		t.Errorf("pruned = %d, want 1", pruned)
	}

	remaining, _ := s.ListAudit(AuditFilter{})
	if len(remaining) != 1 || remaining[0].UserEmail != "alice@example.com" {
		t.Errorf("remaining = %+v, want only alice's recent audit", remaining)
	}
}

func TestEnsureDefaultUser_And_AuthenticateUser(t *testing.T) {
	t.Setenv("KONSOLGW_BOOTSTRAP_PASSWORD", "gwkonsol")
	s := newTestDB(t)

	// konsolgw user is seeded by Open automatically
	u, err := s.AuthenticateUser("konsolgw", "gwkonsol")
	if err != nil {
		t.Fatalf("AuthenticateUser konsolgw failed: %v", err)
	}
	if u.Email != "konsolgw" || u.Role != RoleSuperAdmin {
		t.Errorf("u = %+v, want email=konsolgw role=super_admin", u)
	}

	// Wrong password fails
	if _, err := s.AuthenticateUser("konsolgw", "wrongpass"); err == nil {
		t.Error("expected error for wrong password")
	}

	// Unknown user fails
	if _, err := s.AuthenticateUser("nonexistent", "gwkonsol"); err == nil {
		t.Error("expected error for non-existent user")
	}
}

func TestDeleteUser(t *testing.T) {
	s := newTestDB(t)

	u, err := s.CreateUser("todelete@example.com", "To Delete", RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	sess, err := s.CreateSession(u.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	// User should no longer exist
	if _, err := s.UserByID(u.ID); err != ErrNotFound {
		t.Errorf("UserByID after delete = %v, want ErrNotFound", err)
	}

	// Session should be deleted as well
	if _, err := s.Session(sess.ID); err != ErrNotFound {
		t.Errorf("Session after user delete = %v, want ErrNotFound", err)
	}
}

func TestResetPassword_And_ChangePassword(t *testing.T) {
	s := newTestDB(t)

	u, err := s.CreateUser("userpw@example.com", "User PW", RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// ResetPassword sets new password without checking old
	if err := s.ResetPassword(u.ID, "newsecret123"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Login with new secret succeeds
	if _, err := s.AuthenticateUser("userpw@example.com", "newsecret123"); err != nil {
		t.Fatalf("AuthenticateUser after ResetPassword: %v", err)
	}

	// ChangePassword with correct old password succeeds
	if err := s.ChangePassword(u.ID, "newsecret123", "updatedsecret456"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Old password no longer works
	if _, err := s.AuthenticateUser("userpw@example.com", "newsecret123"); err == nil {
		t.Error("expected authentication failure for old password")
	}

	// New updated password works
	if _, err := s.AuthenticateUser("userpw@example.com", "updatedsecret456"); err != nil {
		t.Fatalf("AuthenticateUser with updated password: %v", err)
	}

	// ChangePassword with wrong old password fails
	if err := s.ChangePassword(u.ID, "wrongold", "anotherpw"); err == nil {
		t.Error("expected error for wrong old password")
	}
}

func TestEnsureBootstrapAdmin_UsesGivenPassword(t *testing.T) {
	t.Setenv("KONSOLGW_BOOTSTRAP_PASSWORD", "from-env-123")
	s := newTestDB(t)

	u, err := s.AuthenticateUser("konsolgw", "from-env-123")
	if err != nil {
		t.Fatalf("login with env password: %v", err)
	}
	if u.Role != RoleSuperAdmin {
		t.Errorf("role = %q, want super_admin", u.Role)
	}
	if _, err := s.AuthenticateUser("konsolgw", "gwkonsol"); err == nil {
		t.Error("the old hardcoded password must not work")
	}
}

func TestEnsureBootstrapAdmin_GeneratesPasswordWhenUnset(t *testing.T) {
	t.Setenv("KONSOLGW_BOOTSTRAP_PASSWORD", "")
	s := newTestDB(t)

	// Already created by Open with a random password nobody was told; a
	// second call must report nothing generated and leave it alone.
	gen, err := s.EnsureBootstrapAdmin("")
	if err != nil || gen != "" {
		t.Fatalf("second call = %q, %v; want no new password", gen, err)
	}
	if _, err := s.AuthenticateUser("konsolgw", "gwkonsol"); err == nil {
		t.Error("the old hardcoded password must not work")
	}
}

func TestEnsureBootstrapAdmin_NeverOverwritesExistingPassword(t *testing.T) {
	t.Setenv("KONSOLGW_BOOTSTRAP_PASSWORD", "first-password-1")
	s := newTestDB(t)
	if err := s.ResetPassword(mustUserID(t, s, "konsolgw"), "changed-by-admin-9"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.EnsureBootstrapAdmin("first-password-1"); err != nil {
		t.Fatalf("EnsureBootstrapAdmin: %v", err)
	}
	if _, err := s.AuthenticateUser("konsolgw", "changed-by-admin-9"); err != nil {
		t.Errorf("restart reset the admin's password: %v", err)
	}
}

func TestEnsureBootstrapAdmin_GeneratedPasswordWorks(t *testing.T) {
	t.Setenv("KONSOLGW_BOOTSTRAP_PASSWORD", "")
	s := &Store{}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	s.db = db
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}

	gen, err := s.EnsureBootstrapAdmin("")
	if err != nil || len(gen) < 16 {
		t.Fatalf("generated = %q, %v; want a password of at least 16 chars", gen, err)
	}
	if _, err := s.AuthenticateUser("konsolgw", gen); err != nil {
		t.Errorf("login with the generated password: %v", err)
	}
}

func mustUserID(t *testing.T, s *Store, email string) int64 {
	t.Helper()
	u, err := s.UserByEmail(email)
	if err != nil {
		t.Fatalf("UserByEmail(%q): %v", email, err)
	}
	return u.ID
}
