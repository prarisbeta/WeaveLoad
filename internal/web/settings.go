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

// SettingsHandler renders the Settings page — currently just the Redis
// queue connection, admin-only like every other app-level configuration.
type SettingsHandler struct {
	Store     SettingsStore
	Templates *template.Template
}

func (h *SettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rs, err := h.Store.GetRedisSettings()
	if err != nil {
		http.Error(w, "failed to load settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	token, err := h.Store.GetQueueAPIToken()
	if err != nil {
		http.Error(w, "failed to load settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, h.Templates, "settings.html", struct {
		Chrome
		Redis         store.RedisSettings
		QueueTokenSet bool
	}{Chrome: NewChrome(r, "settings"), Redis: rs, QueueTokenSet: token != ""})
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
