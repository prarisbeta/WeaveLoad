package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// APIToken is a long-lived, read-only credential for third-party callers of
// /api/v1 and /mcp (MCP clients, n8n, scripts). Only a SHA-256 hash is
// stored; the plaintext is shown once at creation.
type APIToken struct {
	ID         int64
	Name       string
	Prefix     string // first 8 characters of the token, to recognise it in the list
	CreatedBy  string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero if never used
	Revoked    bool
}

const apiTokenPrefix = "kgw_"

func hashAPIToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// CreateAPIToken makes a new token and returns its plaintext, which cannot be
// recovered later.
func (s *Store) CreateAPIToken(name, createdBy string) (string, APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", APIToken{}, errors.New("token name is required")
	}
	if len(name) > 80 {
		return "", APIToken{}, errors.New("token name is too long (max 80 characters)")
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", APIToken{}, fmt.Errorf("generate token: %w", err)
	}
	plain := apiTokenPrefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
	now := time.Now().UTC()
	res, err := s.db.Exec(
		`INSERT INTO api_tokens (name, prefix, token_hash, created_by, created_at) VALUES (?, ?, ?, ?, ?)`,
		name, plain[:8], hashAPIToken(plain), createdBy, now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return "", APIToken{}, fmt.Errorf("insert api token: %w", err)
	}
	id, _ := res.LastInsertId()
	return plain, APIToken{ID: id, Name: name, Prefix: plain[:8], CreatedBy: createdBy, CreatedAt: now}, nil
}

// VerifyAPIToken returns the token matching plain, or ErrNotFound for an
// unknown, malformed or revoked one (callers must not distinguish those).
func (s *Store) VerifyAPIToken(plain string) (APIToken, error) {
	if !strings.HasPrefix(plain, apiTokenPrefix) || len(plain) < 20 {
		return APIToken{}, ErrNotFound
	}
	var t APIToken
	var created, lastUsed string
	var revoked int
	err := s.db.QueryRow(
		`SELECT id, name, prefix, created_by, created_at, COALESCE(last_used_at,''), revoked FROM api_tokens WHERE token_hash = ?`,
		hashAPIToken(plain),
	).Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedBy, &created, &lastUsed, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return APIToken{}, ErrNotFound
	}
	if err != nil {
		return APIToken{}, fmt.Errorf("lookup api token: %w", err)
	}
	if revoked != 0 {
		return APIToken{}, ErrNotFound
	}
	t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	t.LastUsedAt, _ = time.Parse(time.RFC3339Nano, lastUsed)

	// Best effort, and at most once a minute so a chatty client does not turn
	// every call into a database write.
	if t.LastUsedAt.IsZero() || time.Since(t.LastUsedAt) > time.Minute {
		now := time.Now().UTC()
		if _, err := s.db.Exec(`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now.Format(time.RFC3339Nano), t.ID); err == nil {
			t.LastUsedAt = now
		}
	}
	return t, nil
}

// RevokeAPIToken disables a token immediately. The row stays for the audit
// trail.
func (s *Store) RevokeAPIToken(id int64) error {
	res, err := s.db.Exec(`UPDATE api_tokens SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("revoke api token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAPITokens returns every token, newest first.
func (s *Store) ListAPITokens() ([]APIToken, error) {
	rows, err := s.db.Query(`SELECT id, name, prefix, created_by, created_at, COALESCE(last_used_at,''), revoked FROM api_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var created, lastUsed string
		var revoked int
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedBy, &created, &lastUsed, &revoked); err != nil {
			return nil, err
		}
		t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		t.LastUsedAt, _ = time.Parse(time.RFC3339Nano, lastUsed)
		t.Revoked = revoked != 0
		out = append(out, t)
	}
	return out, rows.Err()
}
