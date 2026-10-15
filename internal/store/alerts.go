package store

import (
	"errors"
	"fmt"
	"time"
)

type Alert struct {
	ID        int64
	Rule      string
	Severity  string
	Subject   string
	Message   string
	Status    string // active, acked, resolved
	CreatedAt time.Time
	AckedAt   *time.Time
	AckedBy   string
}

func (s *Store) CreateAlert(rule, severity, subject, message string) (Alert, error) {
	res, err := s.db.Exec(
		`INSERT INTO alerts (rule, severity, subject, message, status) VALUES (?, ?, ?, ?, 'active')`,
		rule, severity, subject, message,
	)
	if err != nil {
		return Alert{}, fmt.Errorf("insert alert: %w", err)
	}
	id, _ := res.LastInsertId()
	return Alert{
		ID:        id,
		Rule:      rule,
		Severity:  severity,
		Subject:   subject,
		Message:   message,
		Status:    "active",
		CreatedAt: time.Now(),
	}, nil
}

func (s *Store) ListAlerts() ([]Alert, error) {
	rows, err := s.db.Query(`SELECT id, rule, severity, subject, message, status, created_at, COALESCE(acked_at,''), COALESCE(acked_by,'') FROM alerts ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Alert
	for rows.Next() {
		var a Alert
		var createdStr, ackedStr string
		if err := rows.Scan(&a.ID, &a.Rule, &a.Severity, &a.Subject, &a.Message, &a.Status, &createdStr, &ackedStr, &a.AckedBy); err != nil {
			return nil, err
		}
		a.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		if ackedStr != "" {
			t, _ := time.Parse(time.RFC3339, ackedStr)
			a.AckedAt = &t
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

func (s *Store) AckAlert(id int64, userEmail string) error {
	nowStr := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`UPDATE alerts SET status = 'acked', acked_at = ?, acked_by = ? WHERE id = ?`, nowStr, userEmail, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("alert not found")
	}
	return nil
}
