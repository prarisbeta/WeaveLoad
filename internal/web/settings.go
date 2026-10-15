package web

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/redisping"
	"haproxy-gui/internal/store"
)

// SettingsStore is the subset of *store.Store the Settings page (and the
// queue viewer/consumption API, which share its Redis connection and API
// token) needs.
type SettingsStore interface {
	GetRedisSettings() (store.RedisSettings, error)
	SetRedisSettings(store.RedisSettings) error
	GetQueueAPIToken() (string, error)
	SetQueueAPIToken(string) error
}

// SettingsData is what the settings sections of the /config page render: the
// Redis queue connection, the queue consumption token, and the API tokens for
// third-party apps and MCP. They used to be a separate /settings page.
type SettingsData struct {
	ShowSettings  bool // the viewer holds manage_settings and the stores are wired
	Redis         store.RedisSettings
	QueueTokenSet bool
	ShowAPITokens bool
	APITokens     []store.APIToken
	MCPURL        string
	APIURL        string
}

// loadSettingsData gathers the settings sections for r's user. It returns the
// zero value (ShowSettings false) for a user without manage_settings, so the
// section simply is not rendered for them; the POST actions enforce the
// capability on their own.
func loadSettingsData(r *http.Request, ss SettingsStore, tokens APITokenStore) (SettingsData, error) {
	u, _ := auth.UserFromContext(r.Context())
	if ss == nil || !u.Role.Can(store.CapManageSettings) {
		return SettingsData{}, nil
	}
	rs, err := ss.GetRedisSettings()
	if err != nil {
		return SettingsData{}, fmt.Errorf("load settings: %w", err)
	}
	queueToken, err := ss.GetQueueAPIToken()
	if err != nil {
		return SettingsData{}, fmt.Errorf("load settings: %w", err)
	}
	d := SettingsData{
		ShowSettings:  true,
		Redis:         rs,
		QueueTokenSet: queueToken != "",
		MCPURL:        publicURL(r) + "/mcp",
		APIURL:        publicURL(r) + "/api/v1",
	}
	if tokens != nil {
		if d.APITokens, err = tokens.ListAPITokens(); err != nil {
			return SettingsData{}, fmt.Errorf("load API tokens: %w", err)
		}
		d.ShowAPITokens = true
	}
	return d, nil
}

func redisSettingsFromForm(r *http.Request) store.RedisSettings {
	db, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("db")))
	return store.RedisSettings{
		Host:     strings.TrimSpace(r.FormValue("host")),
		Port:     strings.TrimSpace(r.FormValue("port")),
		Password: r.FormValue("password"),
		DB:       db,
		TLS:      r.FormValue("tls") == "1",
	}
}

// RedisTestAction dials the submitted (not necessarily saved) connection
// settings and reports whether PING round-trips, without persisting
// anything — lets an admin check credentials before committing to them.
type RedisTestAction struct {
	Templates *template.Template
}

func (h *RedisTestAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	rs := redisSettingsFromForm(r)
	if rs.Host == "" || rs.Port == "" {
		http.Error(w, "host dan port wajib diisi", http.StatusBadRequest)
		return
	}

	err := redisping.Ping(redisping.Options{
		Host: rs.Host, Port: rs.Port, Password: rs.Password, DB: rs.DB, TLS: rs.TLS,
		Timeout: 5 * time.Second,
	})
	renderTemplate(w, h.Templates, "redis_test_result.html", redisTestResult{
		OK:      err == nil,
		Message: redisTestMessage(err),
	})
}

type redisTestResult struct {
	OK      bool
	Message string
}

func redisTestMessage(err error) string {
	if err == nil {
		return "Berhasil terhubung: Redis membalas PING."
	}
	return "Gagal terhubung: " + err.Error()
}

// RedisSaveAction persists the submitted Redis connection settings.
type RedisSaveAction struct {
	Store     SettingsStore
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *RedisSaveAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	rs := redisSettingsFromForm(r)
	if rs.Host == "" || rs.Port == "" {
		http.Error(w, "host dan port wajib diisi", http.StatusBadRequest)
		return
	}
	if err := h.Store.SetRedisSettings(rs); err != nil {
		http.Error(w, "failed to save settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "settings.redis.save",
		Detail: fmt.Sprintf("host=%s port=%s db=%d tls=%v", rs.Host, rs.Port, rs.DB, rs.TLS),
	}); err != nil {
		http.Error(w, "settings saved but could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, h.Templates, "redis_test_result.html", redisTestResult{
		OK: true, Message: "Pengaturan Redis disimpan.",
	})
}
