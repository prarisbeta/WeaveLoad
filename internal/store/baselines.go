package store

import (
	"fmt"

	"haproxy-gui/internal/anomaly"
)

// LoadBaselines returns every learned traffic baseline.
func (s *Store) LoadBaselines() (map[anomaly.Key]anomaly.Stat, error) {
	rows, err := s.db.Query(`SELECT backend, metric, slot, mean, var, n FROM traffic_baseline`)
	if err != nil {
		return nil, fmt.Errorf("load baselines: %w", err)
	}
	defer rows.Close()
	out := map[anomaly.Key]anomaly.Stat{}
	for rows.Next() {
		var k anomaly.Key
		var metric string
		var st anomaly.Stat
		if err := rows.Scan(&k.Backend, &metric, &k.Slot, &st.Mean, &st.Var, &st.N); err != nil {
			return nil, fmt.Errorf("scan baseline: %w", err)
		}
		k.Metric = anomaly.Metric(metric)
		out[k] = st
	}
	return out, rows.Err()
}

// SaveBaseline upserts one learned baseline.
func (s *Store) SaveBaseline(k anomaly.Key, st anomaly.Stat) error {
	_, err := s.db.Exec(`INSERT INTO traffic_baseline (backend, metric, slot, mean, var, n) VALUES (?,?,?,?,?,?)
		ON CONFLICT(backend, metric, slot) DO UPDATE SET mean=excluded.mean, var=excluded.var, n=excluded.n`,
		k.Backend, string(k.Metric), k.Slot, st.Mean, st.Var, st.N)
	if err != nil {
		return fmt.Errorf("save baseline: %w", err)
	}
	return nil
}
