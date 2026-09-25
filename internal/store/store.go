// Package store persists haproxy-gui's own state — users, sessions, and the
// audit log — in a small SQLite database. It never touches HAProxy itself;
// see internal/runtime and internal/cfgfile for that.
package store

import (
	"database/sql"
	"fmt"

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
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	email         TEXT NOT NULL UNIQUE,
	name          TEXT NOT NULL DEFAULT '',
	role          TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer','operator','admin')),
	sso_subject   TEXT,
	password_hash TEXT,
	enabled       INTEGER NOT NULL DEFAULT 1,
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
`

func (s *Store) migrate() error {
	_, err := s.db.Exec(schema)
	return err
}
