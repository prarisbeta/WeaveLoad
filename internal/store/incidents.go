package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Incident represents a tracked security or operational incident correlated
// across one or more SecurityEvents.
type Incident struct {
	ID         int64      `json:"id"`
	Title      string     `json:"title"`
	Severity   string     `json:"severity"` // critical | high | medium | low
	Status     string     `json:"status"`   // open | investigating | mitigated | resolved
	Owner      string     `json:"owner"`
	Summary    string     `json:"summary"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy string     `json:"resolved_by,omitempty"`
	EventCount int        `json:"event_count,omitempty"`
}

// IncidentNote is an operator log or investigation entry within an incident.
type IncidentNote struct {
	ID         int64     `json:"id"`
	IncidentID int64     `json:"incident_id"`
	Author     string    `json:"author"`
	Content    string    `json:"content"`
	CreatedAt  time.Time `json:"created_at"`
}

// IncidentFilter defines query parameters for listing incidents.
type IncidentFilter struct {
	Status   string
	Severity string
	Owner    string
	Query    string
	Limit    int
	Offset   int
}

// EvidenceBundle bundles all incident data, linked security events, and
// operator notes for export / forensic audit.
type EvidenceBundle struct {
	Incident   Incident        `json:"incident"`
	Events     []SecurityEvent `json:"events"`
	Notes      []IncidentNote  `json:"notes"`
	ExportedAt time.Time       `json:"exported_at"`
	ExportedBy string          `json:"exported_by"`
}

// CreateIncident inserts a new incident, optionally links initial event IDs,
// and sets their status to escalated.
func (s *Store) CreateIncident(inc Incident, eventIDs []int64) (int64, error) {
	if strings.TrimSpace(inc.Title) == "" {
		return 0, errors.New("incident title is required")
	}
	if inc.Severity == "" {
		inc.Severity = "medium"
	}
	if inc.Status == "" {
		inc.Status = "open"
	}
	now := time.Now().UTC()
	if inc.CreatedAt.IsZero() {
		inc.CreatedAt = now
	}
	inc.UpdatedAt = now

	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		INSERT INTO incidents (title, severity, status, owner, summary, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, inc.Title, inc.Severity, inc.Status, inc.Owner, inc.Summary,
		inc.CreatedAt.Format(timeLayout), inc.UpdatedAt.Format(timeLayout))
	if err != nil {
		return 0, fmt.Errorf("insert incident: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last insert id: %w", err)
	}

	if len(eventIDs) > 0 {
		for _, evID := range eventIDs {
			if _, err := tx.Exec(`
				UPDATE security_events
				SET incident_id = ?, status = 'escalated'
				WHERE id = ?
			`, id, evID); err != nil {
				return 0, fmt.Errorf("link event %d: %w", evID, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}
	return id, nil
}

// GetIncident loads an incident, its linked security events, and its notes.
func (s *Store) GetIncident(id int64) (Incident, []SecurityEvent, []IncidentNote, error) {
	var inc Incident
	var createdStr, updatedStr string
	var resolvedStr sql.NullString

	err := s.db.QueryRow(`
		SELECT id, title, severity, status, owner, summary, created_at, updated_at, resolved_at, resolved_by
		FROM incidents
		WHERE id = ?
	`, id).Scan(&inc.ID, &inc.Title, &inc.Severity, &inc.Status, &inc.Owner, &inc.Summary,
		&createdStr, &updatedStr, &resolvedStr, &inc.ResolvedBy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return inc, nil, nil, fmt.Errorf("incident %d not found: %w", id, sql.ErrNoRows)
		}
		return inc, nil, nil, fmt.Errorf("get incident: %w", err)
	}

	inc.CreatedAt, _ = time.Parse(timeLayout, createdStr)
	inc.UpdatedAt, _ = time.Parse(timeLayout, updatedStr)
	if resolvedStr.Valid && resolvedStr.String != "" {
		t, err := time.Parse(timeLayout, resolvedStr.String)
		if err == nil {
			inc.ResolvedAt = &t
		}
	}

	// Load linked events
	events, err := s.getLinkedEvents(id)
	if err != nil {
		return inc, nil, nil, fmt.Errorf("get linked events: %w", err)
	}
	inc.EventCount = len(events)

	// Load notes
	notes, err := s.getIncidentNotes(id)
	if err != nil {
		return inc, nil, nil, fmt.Errorf("get incident notes: %w", err)
	}

	return inc, events, notes, nil
}

func (s *Store) getLinkedEvents(incidentID int64) ([]SecurityEvent, error) {
	rows, err := s.db.Query(`
		SELECT id, fingerprint, rule, severity, subject_type, subject, pool, first_seen, last_seen, count, evidence, status, incident_id, acked_by, acked_at
		FROM security_events
		WHERE incident_id = ?
		ORDER BY last_seen DESC
	`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		var ev SecurityEvent
		var firstSeenStr, lastSeenStr string
		var ackedAtStr sql.NullString
		var evidenceStr string
		var incID sql.NullInt64

		if err := rows.Scan(
			&ev.ID, &ev.Fingerprint, &ev.Rule, &ev.Severity, &ev.SubjectType, &ev.Subject, &ev.Pool,
			&firstSeenStr, &lastSeenStr, &ev.Count, &evidenceStr, &ev.Status, &incID, &ev.AckedBy, &ackedAtStr,
		); err != nil {
			return nil, err
		}
		ev.FirstSeen, _ = time.Parse(timeLayout, firstSeenStr)
		ev.LastSeen, _ = time.Parse(timeLayout, lastSeenStr)
		if incID.Valid {
			v := incID.Int64
			ev.IncidentID = &v
		}
		if ackedAtStr.Valid && ackedAtStr.String != "" {
			t, _ := time.Parse(timeLayout, ackedAtStr.String)
			ev.AckedAt = &t
		}
		_ = json.Unmarshal([]byte(evidenceStr), &ev.Evidence)
		events = append(events, ev)
	}
	return events, rows.Err()
}

func (s *Store) getIncidentNotes(incidentID int64) ([]IncidentNote, error) {
	rows, err := s.db.Query(`
		SELECT id, incident_id, author, content, created_at
		FROM incident_notes
		WHERE incident_id = ?
		ORDER BY created_at ASC
	`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []IncidentNote
	for rows.Next() {
		var n IncidentNote
		var createdStr string
		if err := rows.Scan(&n.ID, &n.IncidentID, &n.Author, &n.Content, &createdStr); err != nil {
			return nil, err
		}
		n.CreatedAt, _ = time.Parse(timeLayout, createdStr)
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

// ListIncidents returns matching incidents and total count.
func (s *Store) ListIncidents(f IncidentFilter) ([]Incident, int, error) {
	var where []string
	var args []any

	if f.Status != "" {
		where = append(where, "i.status = ?")
		args = append(args, f.Status)
	}
	if f.Severity != "" {
		where = append(where, "i.severity = ?")
		args = append(args, f.Severity)
	}
	if f.Owner != "" {
		where = append(where, "i.owner = ?")
		args = append(args, f.Owner)
	}
	if f.Query != "" {
		where = append(where, "(i.title LIKE ? OR i.summary LIKE ?)")
		q := "%" + f.Query + "%"
		args = append(args, q, q)
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM incidents i %s`, whereClause)
	var total int
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count incidents: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	queryArgs := append(args, limit, offset)
	selectQuery := fmt.Sprintf(`
		SELECT i.id, i.title, i.severity, i.status, i.owner, i.summary, i.created_at, i.updated_at, i.resolved_at, i.resolved_by,
		       (SELECT COUNT(*) FROM security_events se WHERE se.incident_id = i.id) AS event_count
		FROM incidents i
		%s
		ORDER BY CASE i.status WHEN 'open' THEN 1 WHEN 'investigating' THEN 2 WHEN 'mitigated' THEN 3 ELSE 4 END, i.updated_at DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	rows, err := s.db.Query(selectQuery, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()

	var incidents []Incident
	for rows.Next() {
		var inc Incident
		var createdStr, updatedStr string
		var resolvedStr sql.NullString

		if err := rows.Scan(
			&inc.ID, &inc.Title, &inc.Severity, &inc.Status, &inc.Owner, &inc.Summary,
			&createdStr, &updatedStr, &resolvedStr, &inc.ResolvedBy, &inc.EventCount,
		); err != nil {
			return nil, 0, err
		}
		inc.CreatedAt, _ = time.Parse(timeLayout, createdStr)
		inc.UpdatedAt, _ = time.Parse(timeLayout, updatedStr)
		if resolvedStr.Valid && resolvedStr.String != "" {
			t, _ := time.Parse(timeLayout, resolvedStr.String)
			inc.ResolvedAt = &t
		}
		incidents = append(incidents, inc)
	}

	return incidents, total, rows.Err()
}

// UpdateIncidentStatus updates the status, owner, summary, and resolution details.
func (s *Store) UpdateIncidentStatus(id int64, status, owner, summary, resolvedBy string) error {
	now := time.Now().UTC()
	var resolvedAt *string
	if status == "resolved" {
		t := now.Format(timeLayout)
		resolvedAt = &t
	}

	res, err := s.db.Exec(`
		UPDATE incidents
		SET status = ?,
		    owner = CASE WHEN ? != '' THEN ? ELSE owner END,
		    summary = CASE WHEN ? != '' THEN ? ELSE summary END,
		    updated_at = ?,
		    resolved_at = CASE WHEN ? = 'resolved' THEN ? ELSE resolved_at END,
		    resolved_by = CASE WHEN ? = 'resolved' AND ? != '' THEN ? ELSE resolved_by END
		WHERE id = ?
	`, status, owner, owner, summary, summary, now.Format(timeLayout), status, resolvedAt, status, resolvedBy, resolvedBy, id)
	if err != nil {
		return fmt.Errorf("update incident status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("incident %d not found: %w", id, sql.ErrNoRows)
	}
	return nil
}

// AddIncidentNote adds an investigation note to an incident and updates incident's updated_at.
func (s *Store) AddIncidentNote(incidentID int64, author, content string) (int64, error) {
	if strings.TrimSpace(content) == "" {
		return 0, errors.New("note content cannot be empty")
	}
	now := time.Now().UTC()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		INSERT INTO incident_notes (incident_id, author, content, created_at)
		VALUES (?, ?, ?, ?)
	`, incidentID, author, content, now.Format(timeLayout))
	if err != nil {
		return 0, fmt.Errorf("insert note: %w", err)
	}

	noteID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	if _, err := tx.Exec(`UPDATE incidents SET updated_at = ? WHERE id = ?`, now.Format(timeLayout), incidentID); err != nil {
		return 0, fmt.Errorf("touch incident: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return noteID, nil
}

// LinkEventsToIncident links one or more security events to an incident.
func (s *Store) LinkEventsToIncident(incidentID int64, eventIDs []int64) error {
	if len(eventIDs) == 0 {
		return nil
	}
	now := time.Now().UTC()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, evID := range eventIDs {
		if _, err := tx.Exec(`
			UPDATE security_events
			SET incident_id = ?, status = 'escalated'
			WHERE id = ?
		`, incidentID, evID); err != nil {
			return fmt.Errorf("link event %d: %w", evID, err)
		}
	}

	if _, err := tx.Exec(`UPDATE incidents SET updated_at = ? WHERE id = ?`, now.Format(timeLayout), incidentID); err != nil {
		return fmt.Errorf("touch incident: %w", err)
	}

	return tx.Commit()
}

// UnlinkEventFromIncident removes the incident association from a security event.
func (s *Store) UnlinkEventFromIncident(eventID int64) error {
	res, err := s.db.Exec(`
		UPDATE security_events
		SET incident_id = NULL
		WHERE id = ?
	`, eventID)
	if err != nil {
		return fmt.Errorf("unlink event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("event %d not found: %w", eventID, sql.ErrNoRows)
	}
	return nil
}

// CorrelateCandidateEvents finds unlinked or open security events sharing subject or pool.
func (s *Store) CorrelateCandidateEvents(subject, pool string, limit int) ([]SecurityEvent, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	rows, err := s.db.Query(`
		SELECT id, fingerprint, rule, severity, subject_type, subject, pool, first_seen, last_seen, count, evidence, status, incident_id, acked_by, acked_at
		FROM security_events
		WHERE incident_id IS NULL AND (subject = ? OR (pool != '' AND pool = ?))
		ORDER BY last_seen DESC
		LIMIT ?
	`, subject, pool, limit)
	if err != nil {
		return nil, fmt.Errorf("correlate candidate events: %w", err)
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		var ev SecurityEvent
		var firstSeenStr, lastSeenStr string
		var ackedAtStr sql.NullString
		var evidenceStr string
		var incID sql.NullInt64

		if err := rows.Scan(
			&ev.ID, &ev.Fingerprint, &ev.Rule, &ev.Severity, &ev.SubjectType, &ev.Subject, &ev.Pool,
			&firstSeenStr, &lastSeenStr, &ev.Count, &evidenceStr, &ev.Status, &incID, &ev.AckedBy, &ackedAtStr,
		); err != nil {
			return nil, err
		}
		ev.FirstSeen, _ = time.Parse(timeLayout, firstSeenStr)
		ev.LastSeen, _ = time.Parse(timeLayout, lastSeenStr)
		if ackedAtStr.Valid && ackedAtStr.String != "" {
			t, _ := time.Parse(timeLayout, ackedAtStr.String)
			ev.AckedAt = &t
		}
		_ = json.Unmarshal([]byte(evidenceStr), &ev.Evidence)
		events = append(events, ev)
	}
	return events, rows.Err()
}
