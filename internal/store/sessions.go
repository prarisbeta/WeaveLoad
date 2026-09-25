package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Session is one logged-in browser session. ID is the opaque cookie value;
// CSRFToken must be echoed back on every state-changing request.
type Session struct {
	ID        string
	UserID    int64
	CSRFToken string
	ExpiresAt time.Time
}

// randomToken returns a URL-safe-ish random hex string of the given byte length.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CreateSession starts a new session for userID, valid for ttl.
func (s *Store) CreateSession(userID int64, ttl time.Duration) (Session, error) {
	id, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	expires := time.Now().Add(ttl).UTC()

	_, err = s.db.Exec(
		`INSERT INTO sessions (id, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)`,
		id, userID, csrf, expires.Format(time.RFC3339Nano),
	)
	if err != nil {
		return Session{}, fmt.Errorf("insert session: %w", err)
	}
	return Session{ID: id, UserID: userID, CSRFToken: csrf, ExpiresAt: expires}, nil
}

// Session looks up a session by ID, rejecting it if expired. An expired
// session is treated the same as a missing one (ErrNotFound) so callers
// can't distinguish "never existed" from "timed out" — nothing useful to
// an attacker either way, and it keeps the caller-facing logic to one case.
func (s *Store) Session(id string) (Session, error) {
	row := s.db.QueryRow(
		`SELECT id, user_id, csrf_token, expires_at FROM sessions WHERE id = ?`, id,
	)
	var sess Session
	var expiresStr string
	if err := row.Scan(&sess.ID, &sess.UserID, &sess.CSRFToken, &expiresStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, ErrNotFound
		}
		return Session{}, fmt.Errorf("scan session: %w", err)
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresStr)
	if err != nil {
		return Session{}, fmt.Errorf("parse expires_at: %w", err)
	}
	sess.ExpiresAt = expires
	if time.Now().After(expires) {
		_ = s.DeleteSession(id)
		return Session{}, ErrNotFound
	}
	return sess, nil
}

// DeleteSession logs a session out immediately (used by logout, and by
// Session itself to clean up expired rows lazily).
func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// PruneExpiredSessions removes all sessions past their expiry. Safe to call
// periodically; not required for correctness since Session() also lazily
// deletes on read, but keeps the table from growing unbounded on an
// instance nobody logs out of cleanly.
func (s *Store) PruneExpiredSessions() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
