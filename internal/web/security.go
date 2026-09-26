package web

import (
	"html/template"
	"net"
	"net/http"
	"strconv"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/store"
)

// SecurityStore is the subset of *store.Store the security pages need.
type SecurityStore interface {
	ListSecurityEvents(store.SecurityFilter) ([]store.SecurityEvent, int, error)
	GetSecurityEvent(id int64) (store.SecurityEvent, error)
	SetSecurityEventStatus(id int64, status, actor string) error
	GetIPRisk(ip string) (store.IPRisk, error)
	ListTopRisk(n int) ([]store.IPRisk, error)
}

// securityEventsPageSize bounds how many rows one page of the events list
// shows, so a busy deployment's event table stays fast to render.
const securityEventsPageSize = 50

// validRules/validSeverities/validStatuses are the only values the filter
// form on the security page may submit — anything else is rejected with a
// 400 rather than silently passed through to SQL.
var validSecurityRules = map[string]bool{
	"": true, "brute_force": true, "rate_anomaly": true, "path_scan": true,
	"sensitive_probe": true, "http_abuse": true, "backend_abuse": true, "rate_limited": true,
}
var validSecuritySeverities = map[string]bool{"": true, "low": true, "medium": true, "high": true, "critical": true}
var validSecurityStatuses = map[string]bool{"": true, "open": true, "acknowledged": true, "dismissed": true, "escalated": true}

// SecurityHandler renders the security events list with optional filters,
// alongside a "top risk IPs" sidebar. Gated by CapViewSecurity in routes.go.
type SecurityHandler struct {
	Store     SecurityStore
	Templates *template.Template
}

func (h *SecurityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rule, severity, status := q.Get("rule"), q.Get("severity"), q.Get("status")
	if !validSecurityRules[rule] || !validSecuritySeverities[severity] || !validSecurityStatuses[status] {
		http.Error(w, "invalid filter value", http.StatusBadRequest)
		return
	}
	subject := q.Get("ip")
	if subject != "" && net.ParseIP(subject) == nil {
		http.Error(w, "invalid ip filter", http.StatusBadRequest)
		return
	}
	page := 1
	if v := q.Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	since := sinceFromQuery(q.Get("since"))

	events, total, err := h.Store.ListSecurityEvents(store.SecurityFilter{
		Rule: rule, Severity: severity, Status: status, Subject: subject,
		Since: since, Limit: securityEventsPageSize, Offset: (page - 1) * securityEventsPageSize,
	})
	if err != nil {
		http.Error(w, "failed to load security events: "+err.Error(), http.StatusInternalServerError)
		return
	}
	topRisk, err := h.Store.ListTopRisk(10)
	if err != nil {
		http.Error(w, "failed to load risk profiles: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Chrome
		Events            []store.SecurityEvent
		TopRisk           []store.IPRisk
		Total             int
		Page              int
		PageSize          int
		Rule, Severity    string
		Status, IP, Since string
	}{
		Chrome: NewChrome(r, "security"), Events: events, TopRisk: topRisk,
		Total: total, Page: page, PageSize: securityEventsPageSize,
		Rule: rule, Severity: severity, Status: status, IP: subject, Since: q.Get("since"),
	}

	name := "security.html"
	if r.Header.Get("HX-Request") == "true" {
		name = "security_table.html"
	}
	renderTemplate(w, h.Templates, name, data)
}

func sinceFromQuery(v string) time.Time {
	switch v {
	case "1h":
		return time.Now().Add(-time.Hour)
	case "24h", "":
		return time.Now().Add(-24 * time.Hour)
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour)
	default:
		return time.Now().Add(-24 * time.Hour)
	}
}

// SecurityEventDetail renders one event: its evidence, and the risk profile
// of its subject when the subject is an IP.
type SecurityEventDetail struct {
	Store     SecurityStore
	Templates *template.Template
}

func (h *SecurityEventDetail) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid event id", http.StatusBadRequest)
		return
	}
	ev, err := h.Store.GetSecurityEvent(id)
	if err != nil {
		if err == store.ErrNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to load event: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var risk store.IPRisk
	if ev.SubjectType == "ip" {
		risk, _ = h.Store.GetIPRisk(ev.Subject) // best-effort; zero value renders as "unknown"
	}

	renderTemplate(w, h.Templates, "security_event.html", struct {
		Chrome
		Event store.SecurityEvent
		Risk  store.IPRisk
	}{Chrome: NewChrome(r, "security"), Event: ev, Risk: risk})
}

// SecurityIPHandler renders one IP's risk profile plus every event
// recorded against it.
type SecurityIPHandler struct {
	Store     SecurityStore
	Templates *template.Template
}

func (h *SecurityIPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if net.ParseIP(ip) == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	risk, err := h.Store.GetIPRisk(ip)
	if err != nil && err != store.ErrNotFound {
		http.Error(w, "failed to load risk profile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	events, total, err := h.Store.ListSecurityEvents(store.SecurityFilter{Subject: ip, Limit: 200})
	if err != nil {
		http.Error(w, "failed to load events: "+err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, h.Templates, "security_ip.html", struct {
		Chrome
		IP     string
		Risk   store.IPRisk
		Events []store.SecurityEvent
		Total  int
	}{Chrome: NewChrome(r, "security"), IP: ip, Risk: risk, Events: events, Total: total})
}

// securityStatusActions are the only transitions the API accepts.
var securityStatusActions = map[string]bool{"acknowledged": true, "dismissed": true, "escalated": true}

// SecurityEventStatusAction acknowledges, dismisses or escalates one event.
// Gated by CapManageIncidents in routes.go, since triaging a detection is
// the Incident Management capability, not merely viewing security data.
type SecurityEventStatusAction struct {
	Store SecurityStore
	Audit AuditRecorder
}

func (h *SecurityEventStatusAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid event id", http.StatusBadRequest)
		return
	}
	status := r.FormValue("status")
	if !securityStatusActions[status] {
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	if err := h.Store.SetSecurityEventStatus(id, status, u.Email); err != nil {
		if err == store.ErrNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to update event: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "security.event." + status, Target: strconv.FormatInt(id, 10),
	}); err != nil {
		http.Error(w, "status updated but could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
