package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SecurityEvent is a persisted detection from the internal/security engine.
// Rule, Severity, SubjectType and Status are free-form strings validated by
// the caller (internal/security defines the valid values for the first
// three) rather than a SQLite CHECK constraint — see migrateRoles in
// store.go for why that constraint style doesn't age well.
type SecurityEvent struct {
	ID          int64
	Fingerprint string
	Rule        string
	Severity    string
	SubjectType string
	Subject     string
	Pool        string
	FirstSeen   time.Time
	LastSeen    time.Time
	Count       int
	Evidence    map[string]any
	Status      string // open | acknowledged | dismissed | escalated
	IncidentID  *int64
	AckedBy     string
	AckedAt     *time.Time
}

// IPRisk is the persisted risk profile for one IP.
type IPRisk struct {
	IP             string
	Score          float64
	State          string
	FirstSeen      time.Time
	LastSeen       time.Time
	Detections24h  int
	StateOverride  string
	OverrideBy     string
	OverrideReason string
}

const timeLayout = "2006-01-02T15:04:05.999999999Z07:00"

// UpsertSecurityEvent inserts a new event, or — when an event with the same
// Fingerprint already exists — replaces its LastSeen, Count, Severity and
// Evidence with ev's (the caller, internal/security, always computes these
// as running totals over the detection's window, so the latest value is
// simply the current truth). Returns the row id and whether a new row was
// created.
func (s *Store) UpsertSecurityEvent(ev SecurityEvent) (id int64, created bool, err error) {
	evidence, err := json.Marshal(ev.Evidence)
	if err != nil {
		return 0, false, fmt.Errorf("marshal evidence: %w", err)
	}
	if ev.Status == "" {
		ev.Status = "open"
	}

	// SQLite's UPSERT reports one row affected whether it inserted or
	// updated, so existence has to be checked explicitly rather than read
	// off the Exec result.
	var existingID int64
	existed := true
	if err := s.db.QueryRow(`SELECT id FROM security_events WHERE fingerprint = ?`, ev.Fingerprint).Scan(&existingID); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, false, fmt.Errorf("look up existing event: %w", err)
		}
		existed = false
	}

	res, err := s.db.Exec(`
		INSERT INTO security_events (fingerprint, rule, severity, subject_type, subject, pool, first_seen, last_seen, count, evidence, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(fingerprint) DO UPDATE SET
			last_seen = excluded.last_seen,
			count     = excluded.count,
			severity  = excluded.severity,
			evidence  = excluded.evidence
	`,
		ev.Fingerprint, ev.Rule, ev.Severity, ev.SubjectType, ev.Subject, ev.Pool,
		ev.FirstSeen.UTC().Format(timeLayout), ev.LastSeen.UTC().Format(timeLayout), ev.Count, string(evidence), ev.Status,
	)
	if err != nil {
		return 0, false, fmt.Errorf("upsert security event: %w", err)
	}
	if existed {
		return existingID, false, nil
	}
	insertedID, err := res.LastInsertId()
	if err != nil {
		return 0, false, fmt.Errorf("get inserted event id: %w", err)
	}
	return insertedID, true, nil
}

// SecurityFilter narrows ListSecurityEvents. Zero values mean "no filter" on
// that field.
type SecurityFilter struct {
	Rule     string
	Severity string
	Status   string
	Subject  string
	Since    time.Time
	Limit    int
	Offset   int
}

// ListSecurityEvents returns events matching filter, newest first, along
// with the total count ignoring Limit/Offset (for pagination).
func (s *Store) ListSecurityEvents(f SecurityFilter) ([]SecurityEvent, int, error) {
	var where []string
	var args []any
	if f.Rule != "" {
		where = append(where, "rule = ?")
		args = append(args, f.Rule)
	}
	if f.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, f.Severity)
	}
	if f.Status != "" {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	}
	if f.Subject != "" {
		where = append(where, "subject = ?")
		args = append(args, f.Subject)
	}
	if !f.Since.IsZero() {
		where = append(where, "last_seen >= ?")
		args = append(args, f.Since.UTC().Format(timeLayout))
	}
	clause := ""
	if len(where) > 0 {
		clause = "WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM security_events `+clause, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count security events: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, fingerprint, rule, severity, subject_type, subject, pool, first_seen, last_seen, count, evidence, status, incident_id, acked_by, acked_at
		FROM security_events ` + clause + ` ORDER BY last_seen DESC LIMIT ? OFFSET ?`
	rows, err := s.db.Query(query, append(append([]any{}, args...), limit, f.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list security events: %w", err)
	}
	defer rows.Close()

	var out []SecurityEvent
	for rows.Next() {
		ev, err := scanSecurityEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, ev)
	}
	return out, total, rows.Err()
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanSecurityEvent(row rowScanner) (SecurityEvent, error) {
	var ev SecurityEvent
	var firstSeen, lastSeen, evidence string
	var incidentID sql.NullInt64
	var ackedAt sql.NullString
	if err := row.Scan(&ev.ID, &ev.Fingerprint, &ev.Rule, &ev.Severity, &ev.SubjectType, &ev.Subject, &ev.Pool,
		&firstSeen, &lastSeen, &ev.Count, &evidence, &ev.Status, &incidentID, &ev.AckedBy, &ackedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SecurityEvent{}, ErrNotFound
		}
		return SecurityEvent{}, fmt.Errorf("scan security event: %w", err)
	}
	ev.FirstSeen, _ = time.Parse(timeLayout, firstSeen)
	ev.LastSeen, _ = time.Parse(timeLayout, lastSeen)
	_ = json.Unmarshal([]byte(evidence), &ev.Evidence)
	if incidentID.Valid {
		ev.IncidentID = &incidentID.Int64
	}
	if ackedAt.Valid {
		t, _ := time.Parse(timeLayout, ackedAt.String)
		ev.AckedAt = &t
	}
	return ev, nil
}

// GetSecurityEvent looks up one event by id.
func (s *Store) GetSecurityEvent(id int64) (SecurityEvent, error) {
	row := s.db.QueryRow(`SELECT id, fingerprint, rule, severity, subject_type, subject, pool, first_seen, last_seen, count, evidence, status, incident_id, acked_by, acked_at
		FROM security_events WHERE id = ?`, id)
	return scanSecurityEvent(row)
}

// SetSecurityEventStatus updates an event's status (ack/dismiss/escalate)
// and, for a non-empty actor, records who acknowledged it and when.
func (s *Store) SetSecurityEventStatus(id int64, status, actor string) error {
	res, err := s.db.Exec(
		`UPDATE security_events SET status = ?, acked_by = ?, acked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`,
		status, actor, id,
	)
	if err != nil {
		return fmt.Errorf("set security event status: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertIPRisk replaces the persisted risk profile for one IP.
func (s *Store) UpsertIPRisk(r IPRisk) error {
	_, err := s.db.Exec(`
		INSERT INTO ip_risk (ip, score, state, first_seen, last_seen, detections_24h, state_override, override_by, override_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			score          = excluded.score,
			state          = excluded.state,
			last_seen      = excluded.last_seen,
			detections_24h = excluded.detections_24h
	`,
		r.IP, r.Score, r.State, r.FirstSeen.UTC().Format(timeLayout), r.LastSeen.UTC().Format(timeLayout),
		r.Detections24h, nullIfEmpty(r.StateOverride), r.OverrideBy, r.OverrideReason,
	)
	if err != nil {
		return fmt.Errorf("upsert ip risk: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// GetIPRisk looks up the persisted risk profile for one IP.
func (s *Store) GetIPRisk(ip string) (IPRisk, error) {
	row := s.db.QueryRow(`SELECT ip, score, state, first_seen, last_seen, detections_24h, COALESCE(state_override,''), override_by, override_reason
		FROM ip_risk WHERE ip = ?`, ip)
	var r IPRisk
	var firstSeen, lastSeen string
	if err := row.Scan(&r.IP, &r.Score, &r.State, &firstSeen, &lastSeen, &r.Detections24h, &r.StateOverride, &r.OverrideBy, &r.OverrideReason); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IPRisk{}, ErrNotFound
		}
		return IPRisk{}, fmt.Errorf("scan ip risk: %w", err)
	}
	r.FirstSeen, _ = time.Parse(timeLayout, firstSeen)
	r.LastSeen, _ = time.Parse(timeLayout, lastSeen)
	return r, nil
}

// ListTopRisk returns the n highest-scored IPs, highest first.
func (s *Store) ListTopRisk(n int) ([]IPRisk, error) {
	if n <= 0 {
		n = 20
	}
	rows, err := s.db.Query(`SELECT ip, score, state, first_seen, last_seen, detections_24h, COALESCE(state_override,''), override_by, override_reason
		FROM ip_risk ORDER BY score DESC LIMIT ?`, n)
	if err != nil {
		return nil, fmt.Errorf("list top risk: %w", err)
	}
	defer rows.Close()

	var out []IPRisk
	for rows.Next() {
		var r IPRisk
		var firstSeen, lastSeen string
		if err := rows.Scan(&r.IP, &r.Score, &r.State, &firstSeen, &lastSeen, &r.Detections24h, &r.StateOverride, &r.OverrideBy, &r.OverrideReason); err != nil {
			return nil, fmt.Errorf("scan ip risk: %w", err)
		}
		r.FirstSeen, _ = time.Parse(timeLayout, firstSeen)
		r.LastSeen, _ = time.Parse(timeLayout, lastSeen)
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneSecurityEvents deletes dismissed events last seen before olderThan,
// so the table doesn't grow forever. Open/acknowledged/escalated events are
// kept regardless of age.
func (s *Store) PruneSecurityEvents(olderThan time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM security_events WHERE status = 'dismissed' AND last_seen < ?`,
		olderThan.UTC().Format(timeLayout))
	if err != nil {
		return 0, fmt.Errorf("prune security events: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
