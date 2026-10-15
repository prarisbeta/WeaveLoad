package store

import (
	"fmt"
	"time"
)

// UpsertFleetNode stores the latest report payload from a node.
func (s *Store) UpsertFleetNode(name string, payload []byte, receivedAt time.Time) error {
	_, err := s.db.Exec(`INSERT INTO fleet_nodes (name, payload, received_at) VALUES (?,?,?)
		ON CONFLICT(name) DO UPDATE SET payload=excluded.payload, received_at=excluded.received_at`,
		name, string(payload), fmtT(receivedAt))
	if err != nil {
		return fmt.Errorf("upsert fleet node: %w", err)
	}
	return nil
}

// ListFleetNodes returns each node's latest payload and receive time.
func (s *Store) ListFleetNodes() (map[string][]byte, map[string]time.Time, error) {
	rows, err := s.db.Query(`SELECT name, payload, received_at FROM fleet_nodes`)
	if err != nil {
		return nil, nil, fmt.Errorf("list fleet nodes: %w", err)
	}
	defer rows.Close()
	payloads, times := map[string][]byte{}, map[string]time.Time{}
	for rows.Next() {
		var name, payload, at string
		if err := rows.Scan(&name, &payload, &at); err != nil {
			return nil, nil, err
		}
		payloads[name] = []byte(payload)
		times[name], _ = time.Parse(timeLayout, at)
	}
	return payloads, times, rows.Err()
}

// PruneFleetNodes forgets nodes that have not reported since olderThan.
func (s *Store) PruneFleetNodes(olderThan time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM fleet_nodes WHERE received_at < ?`, fmtT(olderThan))
	if err != nil {
		return 0, fmt.Errorf("prune fleet nodes: %w", err)
	}
	return res.RowsAffected()
}
