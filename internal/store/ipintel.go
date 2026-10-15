package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// IPIntel is a cached live reputation lookup for one IP.
type IPIntel struct {
	IP         string
	AbuseScore int
	Reports    int
	Country    string
	ISP        string
	CheckedAt  time.Time
}

// GetIPIntel returns the cached lookup for ip, or ErrNotFound.
func (s *Store) GetIPIntel(ip string) (IPIntel, error) {
	var in IPIntel
	var checked string
	err := s.db.QueryRow(`SELECT ip, abuse_score, reports, country, isp, checked_at FROM ip_intel WHERE ip = ?`, ip).
		Scan(&in.IP, &in.AbuseScore, &in.Reports, &in.Country, &in.ISP, &checked)
	if errors.Is(err, sql.ErrNoRows) {
		return IPIntel{}, ErrNotFound
	}
	if err != nil {
		return IPIntel{}, fmt.Errorf("get ip intel: %w", err)
	}
	in.CheckedAt, _ = time.Parse(timeLayout, checked)
	return in, nil
}

// UpsertIPIntel stores or refreshes the cached lookup for in.IP.
func (s *Store) UpsertIPIntel(in IPIntel) error {
	_, err := s.db.Exec(`INSERT INTO ip_intel (ip, abuse_score, reports, country, isp, checked_at) VALUES (?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET abuse_score=excluded.abuse_score, reports=excluded.reports,
		country=excluded.country, isp=excluded.isp, checked_at=excluded.checked_at`,
		in.IP, in.AbuseScore, in.Reports, in.Country, in.ISP, fmtT(in.CheckedAt))
	if err != nil {
		return fmt.Errorf("upsert ip intel: %w", err)
	}
	return nil
}

// PruneIPIntel deletes cached lookups older than olderThan.
func (s *Store) PruneIPIntel(olderThan time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM ip_intel WHERE checked_at < ?`, fmtT(olderThan))
	if err != nil {
		return 0, fmt.Errorf("prune ip intel: %w", err)
	}
	return res.RowsAffected()
}
