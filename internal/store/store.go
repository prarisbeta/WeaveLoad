// Package store persists haproxy-gui's own state — users, sessions, and the
// audit log — in a small SQLite database. It never touches HAProxy itself;
// see internal/runtime and internal/cfgfile for that.
package store

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database holding users, sessions and audit entries.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path and applies schema
// migrations. Use ":memory:" in tests for a throwaway database.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// SQLite handles one writer at a time; this app is small enough that a
	// single connection avoids "database is locked" errors entirely.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	generated, err := s.EnsureBootstrapAdmin(os.Getenv("KONSOLGW_BOOTSTRAP_PASSWORD"))
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("ensure bootstrap admin: %w", err)
	}
	if generated != "" {
		// Shown once: it is not stored anywhere in plain text. Set
		// KONSOLGW_BOOTSTRAP_PASSWORD to choose it instead.
		log.Printf("created local admin %q with generated password %s - change it after the first login", bootstrapEmail, generated)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// usersRoleCheck is shared between the fresh-install schema below and
// migrateRoles' rebuild of an existing (pre-8-role) users table, so the two
// can never drift apart.
const usersRoleCheck = `'super_admin','platform_admin','noc_operator','soc_analyst','sre','security_admin','auditor','viewer'`

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	email         TEXT NOT NULL UNIQUE,
	name          TEXT NOT NULL DEFAULT '',
	role          TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN (` + usersRoleCheck + `)),
	sso_subject   TEXT,
	password_hash TEXT,
	enabled       INTEGER NOT NULL DEFAULT 1,
	language      TEXT NOT NULL DEFAULT 'id',
	created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS sessions (
	id         TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id),
	csrf_token TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
	expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
	user_email TEXT NOT NULL,
	remote_ip  TEXT NOT NULL DEFAULT '',
	action     TEXT NOT NULL,
	target     TEXT NOT NULL DEFAULT '',
	detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);

CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

-- rule, severity and status are validated in Go, not with a CHECK
-- constraint — see migrateRoles above for why an enum-like CHECK column is
-- painful to extend later in SQLite.
CREATE TABLE IF NOT EXISTS security_events (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	fingerprint  TEXT NOT NULL UNIQUE,
	rule         TEXT NOT NULL,
	severity     TEXT NOT NULL,
	subject_type TEXT NOT NULL,
	subject      TEXT NOT NULL,
	pool         TEXT NOT NULL DEFAULT '',
	first_seen   TEXT NOT NULL,
	last_seen    TEXT NOT NULL,
	count        INTEGER NOT NULL DEFAULT 1,
	evidence     TEXT NOT NULL DEFAULT '{}',
	status       TEXT NOT NULL DEFAULT 'open',
	incident_id  INTEGER,
	acked_by     TEXT NOT NULL DEFAULT '',
	acked_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_secev_last ON security_events(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_secev_subject ON security_events(subject_type, subject);
CREATE INDEX IF NOT EXISTS idx_secev_incident ON security_events(incident_id);

CREATE TABLE IF NOT EXISTS ip_risk (
	ip              TEXT PRIMARY KEY,
	score           REAL NOT NULL,
	state           TEXT NOT NULL,
	first_seen      TEXT NOT NULL,
	last_seen       TEXT NOT NULL,
	detections_24h  INTEGER NOT NULL DEFAULT 0,
	state_override  TEXT,
	override_by     TEXT NOT NULL DEFAULT '',
	override_reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS incidents (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	title       TEXT NOT NULL,
	severity    TEXT NOT NULL DEFAULT 'medium',
	status      TEXT NOT NULL DEFAULT 'open',
	owner       TEXT NOT NULL DEFAULT '',
	summary     TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
	updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
	resolved_at TEXT,
	resolved_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at DESC);

CREATE TABLE IF NOT EXISTS incident_notes (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
	author      TEXT NOT NULL,
	content     TEXT NOT NULL,
	created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_incident_notes_inc ON incident_notes(incident_id, created_at ASC);

CREATE TABLE IF NOT EXISTS alerts (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	rule        TEXT NOT NULL,
	severity    TEXT NOT NULL DEFAULT 'medium',
	subject     TEXT NOT NULL,
	message     TEXT NOT NULL,
	status      TEXT NOT NULL DEFAULT 'active',
	created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
	acked_at    TEXT,
	acked_by    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at DESC);

CREATE TABLE IF NOT EXISTS api_tokens (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL,
	prefix       TEXT NOT NULL,
	token_hash   TEXT NOT NULL UNIQUE,
	created_by   TEXT NOT NULL DEFAULT '',
	created_at   TEXT NOT NULL,
	last_used_at TEXT,
	revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS policy_actions (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	created_at  TEXT NOT NULL,
	type        TEXT NOT NULL,
	target      TEXT NOT NULL,
	ttl_seconds INTEGER NOT NULL DEFAULT 0,
	reason      TEXT NOT NULL DEFAULT '',
	evidence    TEXT NOT NULL DEFAULT '',
	source      TEXT NOT NULL DEFAULT '',
	confidence  REAL NOT NULL DEFAULT 0,
	status      TEXT NOT NULL,
	decided_by  TEXT NOT NULL DEFAULT '',
	decided_at  TEXT,
	executed_at TEXT,
	expires_at  TEXT,
	result      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_policy_status ON policy_actions(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_policy_target ON policy_actions(type, target);

CREATE TABLE IF NOT EXISTS traffic_baseline (
	backend TEXT NOT NULL,
	metric  TEXT NOT NULL,
	slot    INTEGER NOT NULL,
	mean    REAL NOT NULL,
	var     REAL NOT NULL,
	n       INTEGER NOT NULL,
	PRIMARY KEY (backend, metric, slot)
);

CREATE TABLE IF NOT EXISTS ip_intel (
	ip          TEXT PRIMARY KEY,
	abuse_score INTEGER NOT NULL DEFAULT -1,
	reports     INTEGER NOT NULL DEFAULT 0,
	country     TEXT NOT NULL DEFAULT '',
	isp         TEXT NOT NULL DEFAULT '',
	checked_at  TEXT NOT NULL
);
`

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	if err := s.migrateRoles(); err != nil {
		return err
	}
	if err := s.migrateLanguage(); err != nil {
		return err
	}
	return s.migrateTOTP()
}

func (s *Store) migrateTOTP() error {
	var hasTOTP bool
	rows, err := s.db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return fmt.Errorf("inspect users columns for totp: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "totp_secret" {
			hasTOTP = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if !hasTOTP {
		if _, err := s.db.Exec(`ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add totp_secret column: %w", err)
		}
		if _, err := s.db.Exec(`ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add totp_enabled column: %w", err)
		}
		if _, err := s.db.Exec(`ALTER TABLE users ADD COLUMN totp_recovery_codes TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add totp_recovery_codes column: %w", err)
		}
	}
	return nil
}

// migrateRoles upgrades a users table created before the 8-role RBAC model
// (CHECK IN ('viewer','operator','admin')) to the current one, mapping the
// old 3 roles onto their closest new equivalent so nobody's access silently
// changes on upgrade: admin -> platform_admin (keeps every capability),
// operator -> noc_operator (kept the runtime-control capability operator
// had), viewer -> viewer (unchanged name and meaning).
//
// SQLite can't ALTER a CHECK constraint in place, so this rebuilds the
// table: rename it aside, create it fresh with the new constraint, copy
// rows across with the role remapped, drop the old copy. Idempotent — it
// inspects the table's own CREATE SQL and does nothing once it already
// contains the new constraint's roles.
func (s *Store) migrateRoles() error {
	var createSQL string
	err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'`).Scan(&createSQL)
	if err != nil {
		return fmt.Errorf("inspect users table: %w", err)
	}
	if strings.Contains(createSQL, "platform_admin") {
		return nil // already on the 8-role schema
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin role migration: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`ALTER TABLE users RENAME TO users_pre_rbac_migration`); err != nil {
		return fmt.Errorf("rename old users table: %w", err)
	}
	if _, err := tx.Exec(`CREATE TABLE users (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		email         TEXT NOT NULL UNIQUE,
		name          TEXT NOT NULL DEFAULT '',
		role          TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN (` + usersRoleCheck + `)),
		sso_subject   TEXT,
		password_hash TEXT,
		enabled       INTEGER NOT NULL DEFAULT 1,
		language      TEXT NOT NULL DEFAULT 'id',
		created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`); err != nil {
		return fmt.Errorf("recreate users table: %w", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO users (id, email, name, role, sso_subject, password_hash, enabled, language, created_at)
		SELECT id, email, name,
			CASE role WHEN 'admin' THEN 'platform_admin' WHEN 'operator' THEN 'noc_operator' ELSE role END,
			sso_subject, password_hash, enabled, 'id', created_at
		FROM users_pre_rbac_migration`); err != nil {
		return fmt.Errorf("copy users to migrated table: %w", err)
	}
	if _, err := tx.Exec(`DROP TABLE users_pre_rbac_migration`); err != nil {
		return fmt.Errorf("drop old users table: %w", err)
	}
	return tx.Commit()
}

func (s *Store) migrateLanguage() error {
	// Add language column if it doesn't exist
	var hasLanguage bool
	rows, err := s.db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return fmt.Errorf("inspect users columns: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "language" {
			hasLanguage = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if !hasLanguage {
		if _, err := s.db.Exec(`ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT 'id'`); err != nil {
			return fmt.Errorf("add language column: %w", err)
		}
	}
	return nil
}
