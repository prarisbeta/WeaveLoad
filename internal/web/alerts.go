package web

import (
	"html/template"
	"net/http"
	"strconv"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/store"
)

// AlertLister is the subset of store needed to list and acknowledge alerts.
type AlertLister interface {
	ListAlerts() ([]store.Alert, error)
	AckAlert(id int64, userEmail string) error
}

// AlertsHandler renders the /alerts page.
type AlertsHandler struct {
	Store     AlertLister
	Templates *template.Template
}

func (h *AlertsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	alerts, err := h.Store.ListAlerts()
	if err != nil {
		http.Error(w, "failed to list alerts: "+err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, h.Templates, "alerts.html", struct {
		Chrome
		Alerts []store.Alert
	}{
		Chrome: NewChrome(r, "alerts"),
		Alerts: alerts,
	})
}

// AlertAckHandler acknowledges an alert (POST /api/alerts/{id}/ack).
type AlertAckHandler struct {
	Store AlertLister
	Audit AuditRecorder
}

func (h *AlertAckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/alerts", http.StatusSeeOther)
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid alert id", http.StatusBadRequest)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	if err := h.Store.AckAlert(id, u.Email); err != nil {
		http.Error(w, "failed to ack alert: "+err.Error(), http.StatusBadRequest)
		return
	}

	if h.Audit != nil {
		_ = h.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: clientIP(r),
			Action: "alert.ack", Target: strconv.FormatInt(id, 10),
			Detail: "status=acked",
		})
	}

	http.Redirect(w, r, "/alerts", http.StatusSeeOther)
}
