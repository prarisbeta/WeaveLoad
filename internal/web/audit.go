package web

import (
	"html/template"
	"net/http"

	"haproxy-gui/internal/store"
)

// AuditLister is the subset of *store.Store the audit page needs.
type AuditLister interface {
	ListAudit(store.AuditFilter) ([]store.AuditEntry, error)
}

// AuditHandler renders the audit log, optionally filtered by user or action
// via query parameters (?user=...&action=...).
type AuditHandler struct {
	Store     AuditLister
	Templates *template.Template
}

func (h *AuditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	entries, err := h.Store.ListAudit(store.AuditFilter{
		UserEmail: q.Get("user"),
		Action:    q.Get("action"),
	})
	if err != nil {
		http.Error(w, "failed to load audit log: "+err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, h.Templates, "audit.html", struct {
		Entries []store.AuditEntry
	}{Entries: entries})
}
