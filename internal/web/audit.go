package web

import (
	"encoding/csv"
	"fmt"
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
	filter := store.AuditFilter{UserEmail: q.Get("user"), Action: q.Get("action")}
	entries, err := h.Store.ListAudit(filter)
	if err != nil {
		http.Error(w, "Riwayat aktivitas gagal dimuat: "+err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, h.Templates, "audit.html", struct {
		Chrome
		Entries []store.AuditEntry
		Filter  store.AuditFilter
	}{Chrome: NewChrome(r, "audit"), Entries: entries, Filter: filter})
}

// AuditExportHandler streams the same (optionally filtered) entries as a
// downloadable CSV file, for record-keeping outside the app.
type AuditExportHandler struct {
	Store AuditLister
}

func (h *AuditExportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	entries, err := h.Store.ListAudit(store.AuditFilter{UserEmail: q.Get("user"), Action: q.Get("action"), Limit: 5000})
	if err != nil {
		http.Error(w, "Riwayat aktivitas gagal dimuat: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="riwayat-aktivitas.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"waktu", "pengguna", "ip", "aksi", "target", "detail"})
	for _, e := range entries {
		_ = cw.Write([]string{
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.UserEmail, e.RemoteIP, e.Action, e.Target, e.Detail,
		})
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		http.Error(w, fmt.Sprintf("failed to write CSV: %v", err), http.StatusInternalServerError)
	}
}
