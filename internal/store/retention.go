package store

import (
	"fmt"
	"time"
)

// alertTimeLayout is the format the alerts table's created_at default
// (strftime '%Y-%m-%dT%H:%M:%fZ') produces, so cutoffs compare correctly as text.
const alertTimeLayout = "2006-01-02T15:04:05.000Z"

// PruneStaleSecurityEvents deletes events last seen before olderThan that no
// incident references, whatever their status. Events attached to an incident
// are evidence and are kept; so is everything recent.
func (s *Store) PruneStaleSecurityEvents(olderThan time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM security_events WHERE incident_id IS NULL AND last_seen < ?`,
		olderThan.UTC().Format(timeLayout))
	if err != nil {
		return 0, fmt.Errorf("prune stale security events: %w", err)
	}
	return res.RowsAffected()
}

// PruneIPRisk deletes risk profiles not seen since olderThan. A profile an
// operator overrode by hand is kept: that decision should not expire silently.
func (s *Store) PruneIPRisk(olderThan time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM ip_risk WHERE last_seen < ? AND (state_override IS NULL OR state_override = '')`,
		olderThan.UTC().Format(timeLayout))
	if err != nil {
		return 0, fmt.Errorf("prune ip risk: %w", err)
	}
	return res.RowsAffected()
}

// PruneAlerts deletes alerts created before olderThan that someone already
// acknowledged or resolved. Active alerts are never pruned.
func (s *Store) PruneAlerts(olderThan time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM alerts WHERE status <> 'active' AND created_at < ?`,
		olderThan.UTC().Format(alertTimeLayout))
	if err != nil {
		return 0, fmt.Errorf("prune alerts: %w", err)
	}
	return res.RowsAffected()
}
