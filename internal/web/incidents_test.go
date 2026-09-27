package web

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/store"
)

type fakeIncidentStore struct {
	incidents map[int64]store.Incident
	events    map[int64]store.SecurityEvent
	notes     map[int64][]store.IncidentNote
	nextIncID int64
	nextNote  int64
}

func newFakeIncidentStore() *fakeIncidentStore {
	return &fakeIncidentStore{
		incidents: make(map[int64]store.Incident),
		events:    make(map[int64]store.SecurityEvent),
		notes:     make(map[int64][]store.IncidentNote),
		nextIncID: 1,
		nextNote:  1,
	}
}

func (f *fakeIncidentStore) CreateIncident(inc store.Incident, eventIDs []int64) (int64, error) {
	id := f.nextIncID
	f.nextIncID++
	inc.ID = id
	inc.CreatedAt = time.Now()
	inc.UpdatedAt = time.Now()
	f.incidents[id] = inc

	for _, evID := range eventIDs {
		if ev, ok := f.events[evID]; ok {
			ev.IncidentID = &id
			ev.Status = "escalated"
			f.events[evID] = ev
		}
	}
	return id, nil
}

func (f *fakeIncidentStore) GetIncident(id int64) (store.Incident, []store.SecurityEvent, []store.IncidentNote, error) {
	inc, ok := f.incidents[id]
	if !ok {
		return inc, nil, nil, http.ErrMissingFile
	}
	var evs []store.SecurityEvent
	for _, ev := range f.events {
		if ev.IncidentID != nil && *ev.IncidentID == id {
			evs = append(evs, ev)
		}
	}
	inc.EventCount = len(evs)
	return inc, evs, f.notes[id], nil
}

func (f *fakeIncidentStore) ListIncidents(filter store.IncidentFilter) ([]store.Incident, int, error) {
	var list []store.Incident
	for _, inc := range f.incidents {
		if filter.Status != "" && inc.Status != filter.Status {
			continue
		}
		list = append(list, inc)
	}
	return list, len(list), nil
}

func (f *fakeIncidentStore) UpdateIncidentStatus(id int64, status, owner, summary, resolvedBy string) error {
	inc, ok := f.incidents[id]
	if !ok {
		return http.ErrMissingFile
	}
	inc.Status = status
	if owner != "" {
		inc.Owner = owner
	}
	if summary != "" {
		inc.Summary = summary
	}
	if status == "resolved" {
		now := time.Now()
		inc.ResolvedAt = &now
		inc.ResolvedBy = resolvedBy
	}
	f.incidents[id] = inc
	return nil
}

func (f *fakeIncidentStore) AddIncidentNote(incidentID int64, author, content string) (int64, error) {
	id := f.nextNote
	f.nextNote++
	note := store.IncidentNote{
		ID:         id,
		IncidentID: incidentID,
		Author:     author,
		Content:    content,
		CreatedAt:  time.Now(),
	}
	f.notes[incidentID] = append(f.notes[incidentID], note)
	return id, nil
}

func (f *fakeIncidentStore) LinkEventsToIncident(incidentID int64, eventIDs []int64) error {
	for _, evID := range eventIDs {
		if ev, ok := f.events[evID]; ok {
			ev.IncidentID = &incidentID
			f.events[evID] = ev
		}
	}
	return nil
}

func (f *fakeIncidentStore) UnlinkEventFromIncident(eventID int64) error {
	if ev, ok := f.events[eventID]; ok {
		ev.IncidentID = nil
		f.events[eventID] = ev
	}
	return nil
}

func (f *fakeIncidentStore) CorrelateCandidateEvents(subject, pool string, limit int) ([]store.SecurityEvent, error) {
	var candidates []store.SecurityEvent
	for _, ev := range f.events {
		if ev.IncidentID == nil && (ev.Subject == subject || (pool != "" && ev.Pool == pool)) {
			candidates = append(candidates, ev)
		}
	}
	return candidates, nil
}

func (f *fakeIncidentStore) GetSecurityEvent(id int64) (store.SecurityEvent, error) {
	ev, ok := f.events[id]
	if !ok {
		return ev, http.ErrMissingFile
	}
	return ev, nil
}

func incidentTemplates(t *testing.T) *template.Template {
	t.Helper()
	return mustParse(t, `
{{define "incidents.html"}}INCIDENTS total={{.Total}} open={{.OpenCount}} {{range .Incidents}}({{.ID}}:{{.Title}}:{{.Status}}){{end}}{{end}}
{{define "incident_new.html"}}NEWINCIDENT prefill={{if .PrefillEvent}}{{.PrefillEvent.ID}}{{else}}none{{end}}{{end}}
{{define "incident_detail.html"}}DETAIL {{.Incident.ID}} status={{.Incident.Status}} events={{len .Events}} notes={{len .Notes}}{{end}}
`)
}

func TestIncidentsHandler_RendersList(t *testing.T) {
	st := newFakeIncidentStore()
	_, _ = st.CreateIncident(store.Incident{Title: "Inc 1", Status: "open"}, nil)
	_, _ = st.CreateIncident(store.Incident{Title: "Inc 2", Status: "resolved"}, nil)

	h := &IncidentsHandler{Store: st, Templates: incidentTemplates(t)}

	req := httptest.NewRequest(http.MethodGet, "/incidents", nil)
	req = withUser(req, store.User{Email: "admin@example.com", Role: store.RoleSecurityAdmin})
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "total=2") || !strings.Contains(body, "Inc 1") {
		t.Errorf("body=%s", body)
	}
}

func TestIncidentNewHandler_CreatesIncidentAndAudits(t *testing.T) {
	st := newFakeIncidentStore()
	st.events[10] = store.SecurityEvent{ID: 10, Subject: "10.0.0.9", Rule: "brute_force"}
	audit := &fakeAudit{}

	h := &IncidentNewHandler{Store: st, Audit: audit, Templates: incidentTemplates(t)}

	// 1. GET form
	reqGet := httptest.NewRequest(http.MethodGet, "/incidents/new?event_id=10", nil)
	reqGet = withUser(reqGet, store.User{Email: "admin@example.com", Role: store.RoleSecurityAdmin})
	recGet := httptest.NewRecorder()
	h.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK || !strings.Contains(recGet.Body.String(), "prefill=10") {
		t.Errorf("get form body=%s", recGet.Body.String())
	}

	// 2. POST create
	form := url.Values{
		"title":        {"DDoS Attempt"},
		"severity":     {"high"},
		"summary":      {"High request rate detected"},
		"event_id":     {"10"},
		"initial_note": {"Assigned to NOC"},
	}
	reqPost := httptest.NewRequest(http.MethodPost, "/incidents/new", strings.NewReader(form.Encode()))
	reqPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqPost = withUser(reqPost, store.User{Email: "admin@example.com", Role: store.RoleSecurityAdmin})
	recPost := httptest.NewRecorder()

	h.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusSeeOther {
		t.Fatalf("post code=%d want 303", recPost.Code)
	}

	if len(st.incidents) != 1 {
		t.Fatalf("incidents count=%d want 1", len(st.incidents))
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "incident.create" {
		t.Errorf("audit=%+v", audit.entries)
	}
}

func TestIncidentActions_StatusAndNotes(t *testing.T) {
	st := newFakeIncidentStore()
	incID, _ := st.CreateIncident(store.Incident{Title: "Port Scan", Status: "open"}, nil)
	audit := &fakeAudit{}

	statusHandler := &IncidentStatusAction{Store: st, Audit: audit}
	noteHandler := &IncidentNoteAction{Store: st, Audit: audit}

	// 1. Add Note
	noteForm := url.Values{"content": {"Checked firewall logs"}}
	reqNote := httptest.NewRequest(http.MethodPost, "/api/incidents/1/notes", strings.NewReader(noteForm.Encode()))
	reqNote.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqNote.SetPathValue("id", "1")
	reqNote = withUser(reqNote, store.User{Email: "admin@example.com", Role: store.RoleSecurityAdmin})
	recNote := httptest.NewRecorder()
	noteHandler.ServeHTTP(recNote, reqNote)
	if recNote.Code != http.StatusSeeOther {
		t.Fatalf("note code=%d want 303", recNote.Code)
	}

	// 2. Update status to resolved
	statusForm := url.Values{"status": {"resolved"}, "note": {"Mitigated via block"}}
	reqStatus := httptest.NewRequest(http.MethodPost, "/api/incidents/1/status", strings.NewReader(statusForm.Encode()))
	reqStatus.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqStatus.SetPathValue("id", "1")
	reqStatus = withUser(reqStatus, store.User{Email: "admin@example.com", Role: store.RoleSecurityAdmin})
	recStatus := httptest.NewRecorder()
	statusHandler.ServeHTTP(recStatus, reqStatus)
	if recStatus.Code != http.StatusSeeOther {
		t.Fatalf("status code=%d want 303", recStatus.Code)
	}

	inc, _, notes, _ := st.GetIncident(incID)
	if inc.Status != "resolved" {
		t.Errorf("status=%s want resolved", inc.Status)
	}
	if len(notes) < 2 {
		t.Errorf("notes len=%d want >=2", len(notes))
	}
}

func TestIncidentExportHandler_JSONAndCSV(t *testing.T) {
	st := newFakeIncidentStore()
	incID, _ := st.CreateIncident(store.Incident{Title: "Sensitive Probe", Status: "investigating"}, nil)
	_, _ = st.AddIncidentNote(incID, "analyst@example.com", "Analyzed suspicious IPs")

	h := &IncidentExportHandler{Store: st}

	// 1. Export JSON
	reqJSON := httptest.NewRequest(http.MethodGet, "/incidents/1/export?format=json", nil)
	reqJSON.SetPathValue("id", "1")
	reqJSON = withUser(reqJSON, store.User{Email: "admin@example.com", Role: store.RoleSecurityAdmin})
	recJSON := httptest.NewRecorder()
	h.ServeHTTP(recJSON, reqJSON)

	if recJSON.Code != http.StatusOK {
		t.Fatalf("json code=%d want 200", recJSON.Code)
	}
	var bundle store.EvidenceBundle
	if err := json.NewDecoder(recJSON.Body).Decode(&bundle); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if bundle.Incident.Title != "Sensitive Probe" || len(bundle.Notes) != 1 {
		t.Errorf("bundle=%+v", bundle)
	}

	// 2. Export CSV
	reqCSV := httptest.NewRequest(http.MethodGet, "/incidents/1/export?format=csv", nil)
	reqCSV.SetPathValue("id", "1")
	reqCSV = withUser(reqCSV, store.User{Email: "admin@example.com", Role: store.RoleSecurityAdmin})
	recCSV := httptest.NewRecorder()
	h.ServeHTTP(recCSV, reqCSV)

	if recCSV.Code != http.StatusOK {
		t.Fatalf("csv code=%d want 200", recCSV.Code)
	}
	csvBody := recCSV.Body.String()
	if !strings.Contains(csvBody, "Sensitive Probe") || !strings.Contains(csvBody, "Analyzed suspicious IPs") {
		t.Errorf("csvBody=%s", csvBody)
	}
}
