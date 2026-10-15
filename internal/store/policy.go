package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PolicyAction is one action the Policy Engine considered: proposed, run,
// shadowed (logged but not run), rejected or expired.
type PolicyAction struct {
	ID         int64
	CreatedAt  time.Time
	Type       string // block_ip | drain_server
	Target     string // an IP, or "backend/server"
	TTLSeconds int
	Reason     string
	Evidence   string
	Source     string // e.g. "auto:threat_intel", "api:<token name>", "ui:<email>"
	Confidence float64
	// Status: pending | shadow | executed | failed | rejected | expired
	Status     string
	DecidedBy  string
	DecidedAt  *time.Time
	ExecutedAt *time.Time
	ExpiresAt  *time.Time
	Result     string
}

const policyCols = `id, created_at, type, target, ttl_seconds, reason, evidence, source, confidence, status, decided_by, decided_at, executed_at, expires_at, result`

func fmtT(t time.Time) string { return t.UTC().Format(timeLayout) }

func fmtTP(t *time.Time) any {
	if t == nil {
		return nil
	}
	return fmtT(*t)
}

// CreatePolicyAction inserts a and returns its new ID.
func (s *Store) CreatePolicyAction(a PolicyAction) (int64, error) {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	res, err := s.db.Exec(`INSERT INTO policy_actions
		(created_at, type, target, ttl_seconds, reason, evidence, source, confidence, status, decided_by, decided_at, executed_at, expires_at, result)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		fmtT(a.CreatedAt), a.Type, a.Target, a.TTLSeconds, a.Reason, a.Evidence, a.Source, a.Confidence,
		a.Status, a.DecidedBy, fmtTP(a.DecidedAt), fmtTP(a.ExecutedAt), fmtTP(a.ExpiresAt), a.Result)
	if err != nil {
		return 0, fmt.Errorf("insert policy action: %w", err)
	}
	return res.LastInsertId()
}

// UpdatePolicyAction persists the mutable fields of a (status, decision,
// execution and expiry times, result).
func (s *Store) UpdatePolicyAction(a PolicyAction) error {
	_, err := s.db.Exec(`UPDATE policy_actions SET status=?, decided_by=?, decided_at=?, executed_at=?, expires_at=?, result=? WHERE id=?`,
		a.Status, a.DecidedBy, fmtTP(a.DecidedAt), fmtTP(a.ExecutedAt), fmtTP(a.ExpiresAt), a.Result, a.ID)
	if err != nil {
		return fmt.Errorf("update policy action: %w", err)
	}
	return nil
}

func scanPolicy(r rowScanner) (PolicyAction, error) {
	var a PolicyAction
	var created string
	var decided, executed, expires sql.NullString
	if err := r.Scan(&a.ID, &created, &a.Type, &a.Target, &a.TTLSeconds, &a.Reason, &a.Evidence, &a.Source,
		&a.Confidence, &a.Status, &a.DecidedBy, &decided, &executed, &expires, &a.Result); err != nil {
		return PolicyAction{}, err
	}
	a.CreatedAt, _ = time.Parse(timeLayout, created)
	parse := func(ns sql.NullString) *time.Time {
		if !ns.Valid || ns.String == "" {
			return nil
		}
		t, err := time.Parse(timeLayout, ns.String)
		if err != nil {
			return nil
		}
		return &t
	}
	a.DecidedAt, a.ExecutedAt, a.ExpiresAt = parse(decided), parse(executed), parse(expires)
	return a, nil
}

// GetPolicyAction returns one action, or ErrNotFound.
func (s *Store) GetPolicyAction(id int64) (PolicyAction, error) {
	a, err := scanPolicy(s.db.QueryRow(`SELECT `+policyCols+` FROM policy_actions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyAction{}, ErrNotFound
	}
	return a, err
}

// ListPolicyActions returns actions newest first, optionally only those with
// the given status. limit <= 0 means 100.
func (s *Store) ListPolicyActions(status string, limit int) ([]PolicyAction, error) {
	if limit <= 0 {
		limit = 100
	}
	q := `SELECT ` + policyCols + ` FROM policy_actions`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("list policy actions: %w", err)
	}
	defer rows.Close()
	var out []PolicyAction
	for rows.Next() {
		a, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan policy action: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountPolicyActionsSince counts actions of typ created at or after since
// whose status is one of statuses.
func (s *Store) CountPolicyActionsSince(typ string, statuses []string, since time.Time) (int, error) {
	if len(statuses) == 0 {
		return 0, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(statuses)), ",")
	args := []any{typ, fmtT(since)}
	for _, st := range statuses {
		args = append(args, st)
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM policy_actions WHERE type = ? AND created_at >= ? AND status IN (`+ph+`)`, args...).Scan(&n)
	return n, err
}

// HasOpenPolicyAction reports whether typ/target is already waiting for a
// decision or currently in force.
func (s *Store) HasOpenPolicyAction(typ, target string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM policy_actions WHERE type = ? AND target = ? AND status IN ('pending','executed')`, typ, target).Scan(&n)
	return n > 0, err
}

// ListExpiredPolicyActions returns executed actions whose expiry has passed.
func (s *Store) ListExpiredPolicyActions(now time.Time) ([]PolicyAction, error) {
	all, err := s.ListPolicyActions("executed", 1000)
	if err != nil {
		return nil, err
	}
	var out []PolicyAction
	for _, a := range all {
		if a.ExpiresAt != nil && !a.ExpiresAt.After(now) {
			out = append(out, a)
		}
	}
	return out, nil
}

// PrunePolicyActions deletes finished actions (anything but pending or
// executed) created before olderThan.
func (s *Store) PrunePolicyActions(olderThan time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM policy_actions WHERE status NOT IN ('pending','executed') AND created_at < ?`, fmtT(olderThan))
	if err != nil {
		return 0, fmt.Errorf("prune policy actions: %w", err)
	}
	return res.RowsAffected()
}
