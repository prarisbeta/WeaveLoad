package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// GetSetting returns the raw string stored under key, or ErrNotFound if
// nothing has been saved under it yet.
func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("query setting %q: %w", key, err)
	}
	return v, nil
}

// SetSetting upserts key's value.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	return nil
}

// RedisSettings is the queue backend connection the Settings page manages.
// Persisted as one JSON blob under a single settings key so adding a field
// later never needs a schema migration.
type RedisSettings struct {
	Host     string
	Port     string
	Password string
	DB       int
	TLS      bool
}

const redisSettingsKey = "redis"

// GetRedisSettings returns the saved Redis connection, or a zero value if
// nothing has been saved yet (not an error — the feature is opt-in).
func (s *Store) GetRedisSettings() (RedisSettings, error) {
	raw, err := s.GetSetting(redisSettingsKey)
	if errors.Is(err, ErrNotFound) {
		return RedisSettings{}, nil
	}
	if err != nil {
		return RedisSettings{}, err
	}
	var rs RedisSettings
	if err := json.Unmarshal([]byte(raw), &rs); err != nil {
		return RedisSettings{}, fmt.Errorf("decode redis settings: %w", err)
	}
	return rs, nil
}

// SetRedisSettings saves the Redis connection settings, replacing whatever
// was saved before.
func (s *Store) SetRedisSettings(rs RedisSettings) error {
	b, err := json.Marshal(rs)
	if err != nil {
		return fmt.Errorf("encode redis settings: %w", err)
	}
	return s.SetSetting(redisSettingsKey, string(b))
}

const queueAPITokenKey = "queue_api_token"

// GetQueueAPIToken returns the bearer token external systems (or the
// Incident Management module) must present to the queue consumption API, or
// "" if none has been generated yet — the endpoint treats that as "not
// configured" and refuses every request.
func (s *Store) GetQueueAPIToken() (string, error) {
	token, err := s.GetSetting(queueAPITokenKey)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	return token, err
}

// SetQueueAPIToken saves the queue consumption API's bearer token.
func (s *Store) SetQueueAPIToken(token string) error {
	return s.SetSetting(queueAPITokenKey, token)
}
