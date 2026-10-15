package store

import "fmt"

// CountPolicyActionsByStatus returns how many policy actions are in each status.
func (s *Store) CountPolicyActionsByStatus() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT status, COUNT(*) FROM policy_actions GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("count policy actions: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}
