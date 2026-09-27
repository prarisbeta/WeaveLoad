package web

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/store"
)

// IncidentStore defines store operations required by incident pages.
type IncidentStore interface {
	CreateIncident(inc store.Incident, eventIDs []int64) (int64, error)
	GetIncident(id int64) (store.Incident, []store.SecurityEvent, []store.IncidentNote, error)
	ListIncidents(filter store.IncidentFilter) ([]store.Incident, int, error)
	UpdateIncidentStatus(id int64, status, owner, summary, resolvedBy string) error
	AddIncidentNote(incidentID int64, author, content string) (int64, error)
	LinkEventsToIncident(incidentID int64, eventIDs []int64) error
	UnlinkEventFromIncident(eventID int64) error
	CorrelateCandidateEvents(subject, pool string, limit int) ([]store.SecurityEvent, error)
	GetSecurityEvent(id int64) (store.SecurityEvent, error)
}

const incidentsPageSize = 50

var validIncidentSeverities = map[string]bool{"": true, "low": true, "medium": true, "high": true, "critical": true}
var validIncidentStatuses = map[string]bool{"": true, "open": true, "investigating": true, "mitigated": true, "resolved": true}

// IncidentsHandler renders the list of incidents with status filters and stats.
type IncidentsHandler struct {
	Store     IncidentStore
	Templates *template.Template
}

func (h *IncidentsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status, severity, search := q.Get("status"), q.Get("severity"), q.Get("q")
	if !validIncidentStatuses[status] || !validIncidentSeverities[severity] {
		http.Error(w, "invalid filter parameter", http.StatusBadRequest)
		return
	}

	page := 1
	if v := q.Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}

	incidents, total, err := h.Store.ListIncidents(store.IncidentFilter{
		Status:   status,
		Severity: severity,
		Query:    search,
		Limit:    incidentsPageSize,
		Offset:   (page - 1) * incidentsPageSize,
	})
	if err != nil {
		http.Error(w, "failed to list incidents: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Calculate counts per status for filter tabs
	var openCount, investigatingCount, mitigatedCount, resolvedCount int
	allIncidents, _, _ := h.Store.ListIncidents(store.IncidentFilter{Limit: 500})
	for _, inc := range allIncidents {
		switch inc.Status {
		case "open":
			openCount++
		case "investigating":
			investigatingCount++
		case "mitigated":
			mitigatedCount++
		case "resolved":
			resolvedCount++
		}
	}

	u, _ := auth.UserFromContext(r.Context())
	canManage := u.Role.Can(store.CapManageIncidents)

	data := struct {
		Chrome
		Incidents          []store.Incident
		Total              int
		Page               int
		PageSize           int
		Status             string
		Severity           string
		Search             string
		OpenCount          int
		InvestigatingCount int
		MitigatedCount     int
		ResolvedCount      int
		CanManage          bool
	}{
		Chrome:             NewChrome(r, "incidents"),
		Incidents:          incidents,
		Total:              total,
		Page:               page,
		PageSize:           incidentsPageSize,
		Status:             status,
		Severity:           severity,
		Search:             search,
		OpenCount:          openCount,
		InvestigatingCount: investigatingCount,
		MitigatedCount:     mitigatedCount,
		ResolvedCount:      resolvedCount,
		CanManage:          canManage,
	}

	renderTemplate(w, h.Templates, "incidents.html", data)
}

// IncidentNewHandler handles GET for form rendering and POST for creation.
type IncidentNewHandler struct {
	Store     IncidentStore
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *IncidentNewHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFromContext(r.Context())
	if !u.Role.Can(store.CapManageIncidents) {
		http.Error(w, "forbidden: missing manage_incidents capability", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		title := strings.TrimSpace(r.FormValue("title"))
		severity := strings.TrimSpace(r.FormValue("severity"))
		owner := strings.TrimSpace(r.FormValue("owner"))
		if owner == "" {
			owner = u.Email
		}
		summary := strings.TrimSpace(r.FormValue("summary"))
		initialNote := strings.TrimSpace(r.FormValue("initial_note"))

		var eventIDs []int64
		if evStr := r.FormValue("event_id"); evStr != "" {
			if id, err := strconv.ParseInt(evStr, 10, 64); err == nil {
				eventIDs = append(eventIDs, id)
			}
		}

		if title == "" {
			http.Error(w, "title is required", http.StatusBadRequest)
			return
		}

		incID, err := h.Store.CreateIncident(store.Incident{
			Title:    title,
			Severity: severity,
			Status:   "open",
			Owner:    owner,
			Summary:  summary,
		}, eventIDs)
		if err != nil {
			http.Error(w, "failed to create incident: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if initialNote != "" {
			_, _ = h.Store.AddIncidentNote(incID, u.Email, initialNote)
		}

		if h.Audit != nil {
			_ = h.Audit.Record(store.AuditEntry{
				UserEmail: u.Email,
				RemoteIP:  clientIP(r),
				Action:    "incident.create",
				Target:    fmt.Sprintf("incident #%d", incID),
				Detail:    fmt.Sprintf("created incident %q with severity %s", title, severity),
			})
		}

		http.Redirect(w, r, fmt.Sprintf("/incidents/%d", incID), http.StatusSeeOther)
		return
	}

	// GET - render form
	var prefillEvent *store.SecurityEvent
	if evStr := r.URL.Query().Get("event_id"); evStr != "" {
		if id, err := strconv.ParseInt(evStr, 10, 64); err == nil {
			if ev, err := h.Store.GetSecurityEvent(id); err == nil {
				prefillEvent = &ev
			}
		}
	}

	data := struct {
		Chrome
		PrefillEvent *store.SecurityEvent
		DefaultOwner string
	}{
		Chrome:       NewChrome(r, "incidents"),
		PrefillEvent: prefillEvent,
		DefaultOwner: u.Email,
	}

	renderTemplate(w, h.Templates, "incident_new.html", data)
}

// IncidentDetailHandler renders incident timeline, linked events, notes, and candidate events.
type IncidentDetailHandler struct {
	Store     IncidentStore
	Templates *template.Template
}

func (h *IncidentDetailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}

	inc, events, notes, err := h.Store.GetIncident(id)
	if err != nil {
		http.Error(w, "incident not found: "+err.Error(), http.StatusNotFound)
		return
	}

	// Correlate candidate events
	var candidates []store.SecurityEvent
	var subjects []string
	for _, ev := range events {
		if ev.Subject != "" {
			subjects = append(subjects, ev.Subject)
		}
	}
	if len(subjects) > 0 {
		candidates, _ = h.Store.CorrelateCandidateEvents(subjects[0], "", 10)
	}

	u, _ := auth.UserFromContext(r.Context())
	canManage := u.Role.Can(store.CapManageIncidents)

	data := struct {
		Chrome
		Incident   store.Incident
		Events     []store.SecurityEvent
		Notes      []store.IncidentNote
		Candidates []store.SecurityEvent
		CanManage  bool
	}{
		Chrome:     NewChrome(r, "incidents"),
		Incident:   inc,
		Events:     events,
		Notes:      notes,
		Candidates: candidates,
		CanManage:  canManage,
	}

	renderTemplate(w, h.Templates, "incident_detail.html", data)
}

// IncidentStatusAction handles status updates (open/investigating/mitigated/resolved).
type IncidentStatusAction struct {
	Store IncidentStore
	Audit AuditRecorder
}

func (h *IncidentStatusAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFromContext(r.Context())
	if !u.Role.Can(store.CapManageIncidents) {
		http.Error(w, "forbidden: missing manage_incidents capability", http.StatusForbidden)
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	status := strings.TrimSpace(r.FormValue("status"))
	if !validIncidentStatuses[status] || status == "" {
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}

	owner := strings.TrimSpace(r.FormValue("owner"))
	summary := strings.TrimSpace(r.FormValue("summary"))
	note := strings.TrimSpace(r.FormValue("note"))
	resolvedBy := ""
	if status == "resolved" {
		resolvedBy = u.Email
	}

	if err := h.Store.UpdateIncidentStatus(id, status, owner, summary, resolvedBy); err != nil {
		http.Error(w, "failed to update status: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if note != "" {
		_, _ = h.Store.AddIncidentNote(id, u.Email, fmt.Sprintf("[Status: %s] %s", status, note))
	} else {
		_, _ = h.Store.AddIncidentNote(id, u.Email, fmt.Sprintf("Status diubah menjadi %s", status))
	}

	if h.Audit != nil {
		_ = h.Audit.Record(store.AuditEntry{
			UserEmail: u.Email,
			RemoteIP:  clientIP(r),
			Action:    "incident.status",
			Target:    fmt.Sprintf("incident #%d", id),
			Detail:    fmt.Sprintf("status -> %s (owner: %s)", status, owner),
		})
	}

	http.Redirect(w, r, fmt.Sprintf("/incidents/%d", id), http.StatusSeeOther)
}

// IncidentNoteAction adds an investigation note to an incident.
type IncidentNoteAction struct {
	Store IncidentStore
	Audit AuditRecorder
}

func (h *IncidentNoteAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFromContext(r.Context())
	if !u.Role.Can(store.CapManageIncidents) {
		http.Error(w, "forbidden: missing manage_incidents capability", http.StatusForbidden)
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	content := strings.TrimSpace(r.FormValue("content"))
	if content == "" {
		http.Error(w, "note content cannot be empty", http.StatusBadRequest)
		return
	}

	if _, err := h.Store.AddIncidentNote(id, u.Email, content); err != nil {
		http.Error(w, "failed to add note: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.Audit != nil {
		_ = h.Audit.Record(store.AuditEntry{
			UserEmail: u.Email,
			RemoteIP:  clientIP(r),
			Action:    "incident.note",
			Target:    fmt.Sprintf("incident #%d", id),
			Detail:    "added investigation note",
		})
	}

	http.Redirect(w, r, fmt.Sprintf("/incidents/%d", id), http.StatusSeeOther)
}

// IncidentLinkAction links or unlinks security events from an incident.
type IncidentLinkAction struct {
	Store IncidentStore
	Audit AuditRecorder
}

func (h *IncidentLinkAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFromContext(r.Context())
	if !u.Role.Can(store.CapManageIncidents) {
		http.Error(w, "forbidden: missing manage_incidents capability", http.StatusForbidden)
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action") // link | unlink
	eventIDStr := r.FormValue("event_id")
	evID, err := strconv.ParseInt(eventIDStr, 10, 64)
	if err != nil || evID <= 0 {
		http.Error(w, "invalid event id", http.StatusBadRequest)
		return
	}

	if action == "unlink" {
		if err := h.Store.UnlinkEventFromIncident(evID); err != nil {
			http.Error(w, "failed to unlink event: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := h.Store.LinkEventsToIncident(id, []int64{evID}); err != nil {
			http.Error(w, "failed to link event: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if h.Audit != nil {
		_ = h.Audit.Record(store.AuditEntry{
			UserEmail: u.Email,
			RemoteIP:  clientIP(r),
			Action:    "incident." + action,
			Target:    fmt.Sprintf("incident #%d", id),
			Detail:    fmt.Sprintf("%s event #%d", action, evID),
		})
	}

	http.Redirect(w, r, fmt.Sprintf("/incidents/%d", id), http.StatusSeeOther)
}

// IncidentExportHandler generates Evidence Bundle in JSON or CSV format (P7-2).
type IncidentExportHandler struct {
	Store IncidentStore
}

func (h *IncidentExportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}

	inc, events, notes, err := h.Store.GetIncident(id)
	if err != nil {
		http.Error(w, "incident not found: "+err.Error(), http.StatusNotFound)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	format := r.URL.Query().Get("format")

	if format == "csv" {
		var buf bytes.Buffer
		cw := csv.NewWriter(&buf)

		// Incident Header
		_ = cw.Write([]string{"SECTION", "ID", "TITLE/RULE", "SEVERITY/STATUS", "OWNER/AUTHOR", "SUMMARY/CONTENT", "TIMESTAMP"})
		_ = cw.Write([]string{
			"INCIDENT",
			strconv.FormatInt(inc.ID, 10),
			inc.Title,
			inc.Severity + "/" + inc.Status,
			inc.Owner,
			inc.Summary,
			inc.CreatedAt.Format(time.RFC3339),
		})

		// Linked Events
		for _, ev := range events {
			evBytes, _ := json.Marshal(ev.Evidence)
			_ = cw.Write([]string{
				"EVENT",
				strconv.FormatInt(ev.ID, 10),
				ev.Rule,
				ev.Severity + "/" + ev.Status,
				ev.SubjectType + ":" + ev.Subject,
				string(evBytes),
				ev.LastSeen.Format(time.RFC3339),
			})
		}

		// Notes
		for _, note := range notes {
			_ = cw.Write([]string{
				"NOTE",
				strconv.FormatInt(note.ID, 10),
				"Investigation Note",
				"-",
				note.Author,
				note.Content,
				note.CreatedAt.Format(time.RFC3339),
			})
		}

		cw.Flush()
		filename := fmt.Sprintf("evidence_bundle_incident_%d_%s.csv", id, time.Now().Format("20060102_150405"))
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
		return
	}

	// JSON Evidence Bundle (Default)
	bundle := store.EvidenceBundle{
		Incident:   inc,
		Events:     events,
		Notes:      notes,
		ExportedAt: time.Now().UTC(),
		ExportedBy: u.Email,
	}

	filename := fmt.Sprintf("evidence_bundle_incident_%d_%s.json", id, time.Now().Format("20060102_150405"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(bundle)
}
