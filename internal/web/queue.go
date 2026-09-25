package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/ratelimitqueue"
	"haproxy-gui/internal/redisping"
	"haproxy-gui/internal/store"
)

// maxQueueViewLines caps how many of the newest backlog entries the viewer
// page fetches and renders — the list itself is unbounded (nothing trims
// it), so without a cap a large backlog would make LRANGE and the page both
// slow.
const maxQueueViewLines = 200

// QueueHandler renders the Antrean (queue) page: a read-only peek at the
// rate-limit events backlog in Redis (see internal/ratelimitqueue and
// main.pushRateLimitEventsPeriodically). It only ever LRANGEs — actually
// draining the queue is the consumption API's job (QueueConsumeAction),
// for whatever downstream system (Incident Management, or an external
// consumer) is meant to process events exactly once.
type QueueHandler struct {
	Store     SettingsStore
	Templates *template.Template
}

type queueEventView struct {
	ratelimitqueue.Event
	// RawJSON is the raw queue line as stored in Redis, shown as a fallback
	// when it doesn't parse as an Event — named distinctly from the embedded
	// Event.Raw (the original HAProxy access-log line) so the template can
	// tell the two apart instead of one silently shadowing the other.
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
		}{Chrome: NewChrome(r, "queue"), Configured: false})
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

// defaultQueueConsumeLimit and maxQueueConsumeLimit bound the "limit" query
// param on the consumption API — no default would let one call drain the
// entire backlog, and no cap would let a misbehaving consumer request an
// unreasonably large batch.
const (
	defaultQueueConsumeLimit = 50
	maxQueueConsumeLimit     = 500
)

// QueueConsumeAction is the API a downstream consumer (the future Incident
// Management module, or an external system per the roadmap) polls to drain
// the rate-limit events queue exactly once per event: each call pops up to
// "limit" events off the head of the Redis list and returns them, removing
// them from the queue. It authenticates via a bearer token from the
// Settings page instead of the normal session/CSRF flow, since callers here
// are not browsers with a logged-in session.
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

// validBearerToken reports whether r carries "Authorization: Bearer <want>",
// comparing in constant time so response timing can't be used to guess the
// token a character at a time.
func validBearerToken(r *http.Request, want string) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == r.Header.Get("Authorization") { // prefix wasn't present
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// QueueTokenGenerateAction creates (or replaces) the queue consumption
// API's bearer token, shown once on the Settings page for the admin to copy
// into whatever external system or Incident Management config needs it —
// same pattern as the Redis password field already on that page.
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

// generateToken returns a random 32-byte value hex-encoded, used as the
// queue consumption API's bearer token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
