package store

import (
	"fmt"
	"time"
)

// AuditEntry is one recorded action for the audit log. Every runtime
// control, config apply, cert change and user-role change goes through
// Record so there is a single, append-only trail of who did what.
type AuditEntry struct {
	ID        int64
	Timestamp time.Time
	UserEmail string
	RemoteIP  string
	Action    string
	Target    string
	Detail    string
}

// Record appends one audit entry. It never fails silently: a caller that
// can't record an audit entry should treat the underlying action as
// unverified and surface the error, not proceed as if it were logged.
func (s *Store) Record(e AuditEntry) error {
	if e.UserEmail == "" {
		return fmt.Errorf("audit entry requires a user email")
	}
	if e.Action == "" {
		return fmt.Errorf("audit entry requires an action")
	}
	_, err := s.db.Exec(
		`INSERT INTO audit_log (user_email, remote_ip, action, target, detail) VALUES (?, ?, ?, ?, ?)`,
		normalizeEmail(e.UserEmail), e.RemoteIP, e.Action, e.Target, e.Detail,
	)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// AuditFilter narrows ListAudit's results. Zero values mean "no filter".
type AuditFilter struct {
	UserEmail string
	Action    string
	Limit     int // 0 means a default cap of 200
}

// ListAudit returns matching entries, newest first.
func (s *Store) ListAudit(f AuditFilter) ([]AuditEntry, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	query := `SELECT id, ts, user_email, remote_ip, action, target, detail FROM audit_log WHERE 1=1`
	var args []any
	if f.UserEmail != "" {
		query += ` AND user_email = ?`
		args = append(args, normalizeEmail(f.UserEmail))
	}
	if f.Action != "" {
		query += ` AND action = ?`
		args = append(args, f.Action)
	}
	query += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.UserEmail, &e.RemoteIP, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		e.Timestamp, _ = time.Parse("2006-01-02T15:04:05.000Z", ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneAudit removes audit entries older than the given duration (e.g. 30 days).
// Returns the number of pruned rows.
func (s *Store) PruneAudit(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan).Format("2006-01-02T15:04:05.000Z")
	res, err := s.db.Exec(`DELETE FROM audit_log WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune audit log: %w", err)
	}
	return res.RowsAffected()
}
