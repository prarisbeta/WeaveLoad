package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/errorpages"
	"haproxy-gui/internal/ratelimitqueue"
	"haproxy-gui/internal/redisping"
	"haproxy-gui/internal/store"
)

// maxQueueViewLines caps how many of the newest backlog entries the viewer
// page fetches and renders.
const maxQueueViewLines = 200

// QueueTableClearer represents the runtime ability to clear stick-table entries.
type QueueTableClearer interface {
	ClearTable(table, key string) error
}

// QueueIncidentStore represents the incident storage capability needed for forwarding queue events.
type QueueIncidentStore interface {
	CreateIncident(inc store.Incident, eventIDs []int64) (int64, error)
}

// QueueHandler renders the Antrean (queue) page: enterprise queue control,
// rate-limit events backlog in Redis, and waiting room status.
type QueueHandler struct {
	Store     SettingsStore
	Runtime   QueueTableClearer
	Templates *template.Template
}

type queueEventView struct {
	ratelimitqueue.Event
	RawJSON string
}

func (h *QueueHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rs, err := h.Store.GetRedisSettings()
	if err != nil {
		http.Error(w, "failed to load settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if rs.Host == "" {
		renderTemplate(w, h.Templates, "queue.html", struct {
			Chrome
			Configured bool
			Total      int64
			Shown      int
			Events     []queueEventView
		}{
			Chrome:     NewChrome(r, "queue"),
			Configured: false,
		})
		return
	}

	opts := redisping.Options{Host: rs.Host, Port: rs.Port, Password: rs.Password, DB: rs.DB, TLS: rs.TLS}
	total, err := redisping.LLen(opts, ratelimitqueue.QueueKey)
	if err != nil {
		http.Error(w, "Tidak bisa terhubung ke Redis: "+err.Error(), http.StatusBadGateway)
		return
	}
	raw, err := redisping.LRange(opts, ratelimitqueue.QueueKey, -maxQueueViewLines, -1)
	if err != nil {
		http.Error(w, "Gagal membaca antrean dari Redis: "+err.Error(), http.StatusBadGateway)
		return
	}

	// LRANGE returns oldest-of-the-window first (list order); show newest first.
	events := make([]queueEventView, len(raw))
	for i, line := range raw {
		v := queueEventView{RawJSON: line}
		_ = json.Unmarshal([]byte(line), &v.Event) // best-effort; RawJSON is the fallback
		events[len(raw)-1-i] = v
	}

	renderTemplate(w, h.Templates, "queue.html", struct {
		Chrome
		Configured bool
		Total      int64
		Shown      int
		Events     []queueEventView
	}{
		Chrome:     NewChrome(r, "queue"),
		Configured: true,
		Total:      total,
		Shown:      len(events),
		Events:     events,
	})
}

// QueueClearAction clears all rate-limit events from the Redis queue.
type QueueClearAction struct {
	Store SettingsStore
	Audit AuditRecorder
}

func (h *QueueClearAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rs, err := h.Store.GetRedisSettings()
	if err != nil {
		http.Error(w, "failed to load settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if rs.Host == "" {
		http.Error(w, "Redis belum dikonfigurasi", http.StatusBadRequest)
		return
	}

	opts := redisping.Options{Host: rs.Host, Port: rs.Port, Password: rs.Password, DB: rs.DB, TLS: rs.TLS}
	if err := redisping.Del(opts, ratelimitqueue.QueueKey); err != nil {
		http.Error(w, "Gagal mengosongkan antrean: "+err.Error(), http.StatusBadGateway)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	_ = h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email,
		RemoteIP:  clientIP(r),
		Action:    "queue.clear",
		Detail:    "Cleared all events from Redis ratelimit queue",
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "Antrean kejadian rate-limit berhasil dikosongkan.",
	})
}

// QueueReleaseIPAction resets rate-limit counters for an IP in HAProxy stick-table.
type QueueReleaseIPAction struct {
	Runtime QueueTableClearer
	Audit   AuditRecorder
}

func (h *QueueReleaseIPAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	pool := strings.TrimSpace(r.FormValue("pool"))
	ip := strings.TrimSpace(r.FormValue("ip"))

	if pool == "" || ip == "" {
		http.Error(w, "pool dan IP harus diisi", http.StatusBadRequest)
		return
	}

	if h.Runtime != nil {
		if err := h.Runtime.ClearTable(pool, ip); err != nil {
			http.Error(w, "Gagal melepaskan IP dari stick-table: "+err.Error(), http.StatusBadGateway)
			return
		}
	}

	u, _ := auth.UserFromContext(r.Context())
	_ = h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email,
		RemoteIP:  clientIP(r),
		Action:    "queue.release_ip",
		Target:    fmt.Sprintf("%s/%s", pool, ip),
		Detail:    fmt.Sprintf("Released rate-limit for IP %s on pool %s", ip, pool),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": fmt.Sprintf("IP %s berhasil dilepaskan dari batas laju kelompok %s.", ip, pool),
	})
}

// QueueForwardIncidentAction creates a new incident ticket from a queue rate-limit event.
type QueueForwardIncidentAction struct {
	Store QueueIncidentStore
	Audit AuditRecorder
}

func (h *QueueForwardIncidentAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	ip := strings.TrimSpace(r.FormValue("ip"))
	pool := strings.TrimSpace(r.FormValue("pool"))
	severity := strings.TrimSpace(r.FormValue("severity"))
	if severity == "" {
		severity = "medium"
	}
	summary := strings.TrimSpace(r.FormValue("summary"))
	if summary == "" {
		summary = fmt.Sprintf("Lonjakan antrean trafik terdeteksi pada pool %s dari IP %s yang memicu pembatasan laju (Rate Limit).", pool, ip)
	}

	u, _ := auth.UserFromContext(r.Context())
	inc := store.Incident{
		Title:     fmt.Sprintf("[Antrean Rate Limit] Lonjakan Trafik: IP %s (%s)", ip, pool),
		Severity:  severity,
		Status:    "open",
		Owner:     u.Email,
		Summary:   summary,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := h.Store.CreateIncident(inc, nil)
	if err != nil {
		http.Error(w, "Gagal membuat insiden: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email,
		RemoteIP:  clientIP(r),
		Action:    "incident.create_from_queue",
		Target:    fmt.Sprintf("incident:%d", id),
		Detail:    fmt.Sprintf("Created incident #%d from queue event IP %s pool %s", id, ip, pool),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":          true,
		"incident_id": id,
		"message":     fmt.Sprintf("Insiden #%d berhasil dibuat.", id),
	})
}

// QueueWaitingRoomHandler serves the standalone interactive waiting room demo page.
type QueueWaitingRoomHandler struct {
	Manager *errorpages.Manager
}

func (h *QueueWaitingRoomHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	page, err := h.Manager.Get(429)
	if err != nil {
		page.HTMLBody = errorpages.ExtractHTMLBody(errorpages.GetPreset(429))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page.HTMLBody))
}

// defaultQueueConsumeLimit and maxQueueConsumeLimit bound the "limit" query param on the consumption API.
const (
	defaultQueueConsumeLimit = 50
	maxQueueConsumeLimit     = 500
)

// QueueConsumeAction drains events from the head of the Redis list for downstream consumers.
type QueueConsumeAction struct {
	Store SettingsStore
}

func (h *QueueConsumeAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, err := h.Store.GetQueueAPIToken()
	if err != nil {
		http.Error(w, "failed to load settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if token == "" {
		http.Error(w, "queue consumption API is not configured: generate a token on the Settings page first", http.StatusServiceUnavailable)
		return
	}
	if !validBearerToken(r, token) {
		http.Error(w, "invalid or missing bearer token", http.StatusUnauthorized)
		return
	}

	rs, err := h.Store.GetRedisSettings()
	if err != nil {
		http.Error(w, "failed to load settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if rs.Host == "" {
		http.Error(w, "queue is not configured: no Redis connection saved on the Settings page", http.StatusServiceUnavailable)
		return
	}

	limit := defaultQueueConsumeLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			http.Error(w, "invalid limit parameter", http.StatusBadRequest)
			return
		}
		limit = n
	}
	if limit > maxQueueConsumeLimit {
		limit = maxQueueConsumeLimit
	}

	opts := redisping.Options{Host: rs.Host, Port: rs.Port, Password: rs.Password, DB: rs.DB, TLS: rs.TLS}
	raw, err := redisping.PopN(opts, ratelimitqueue.QueueKey, limit)
	if err != nil {
		http.Error(w, "failed to pop events from Redis: "+err.Error(), http.StatusBadGateway)
		return
	}

	events := make([]ratelimitqueue.Event, 0, len(raw))
	for _, line := range raw {
		var ev ratelimitqueue.Event
		if json.Unmarshal([]byte(line), &ev) == nil {
			events = append(events, ev)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Count  int                    `json:"count"`
		Events []ratelimitqueue.Event `json:"events"`
	}{Count: len(events), Events: events})
}

func validBearerToken(r *http.Request, want string) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == r.Header.Get("Authorization") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// QueueTokenGenerateAction creates (or replaces) the queue consumption API's bearer token.
type QueueTokenGenerateAction struct {
	Store     SettingsStore
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *QueueTokenGenerateAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, err := generateToken()
	if err != nil {
		http.Error(w, "failed to generate token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.Store.SetQueueAPIToken(token); err != nil {
		http.Error(w, "failed to save token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "settings.queue_token.generate",
	}); err != nil {
		http.Error(w, "token saved but could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, h.Templates, "queue_token_result.html", struct{ Token string }{Token: token})
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
