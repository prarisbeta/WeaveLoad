package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"haproxy-gui/internal/ai"
	"haproxy-gui/internal/store"
)

// AIIncidentAnalyzeHandler handles POST /api/incidents/{id}/ai-analyze.
type AIIncidentAnalyzeHandler struct {
	Store    *store.Store
	Provider ai.Provider // nil -> offline MockProvider
}

func (h *AIIncidentAnalyzeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/incidents", http.StatusSeeOther)
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}

	inc, _, _, err := h.Store.GetIncident(id)
	if err != nil {
		http.Error(w, "incident not found", http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	summaryData := fmt.Sprintf("Title: %s, Summary: %s, Status: %s, Severity: %s", inc.Title, inc.Summary, inc.Status, inc.Severity)
	res, err := ai.InvestigateData(ctx, h.Provider, "Incident #"+idStr, summaryData)
	if err != nil {
		http.Error(w, "AI analysis failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(res))
}

// AISecurityAnalyzeHandler handles POST /api/security/events/{id}/ai-analyze.
type AISecurityAnalyzeHandler struct {
	Store    *store.Store
	Provider ai.Provider // nil -> offline MockProvider
}

func (h *AISecurityAnalyzeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/security", http.StatusSeeOther)
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid event id", http.StatusBadRequest)
		return
	}

	ev, err := h.Store.GetSecurityEvent(id)
	if err != nil {
		http.Error(w, "security event not found", http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	dataStr := fmt.Sprintf("Rule: %s, Subject: %s (%s), Severity: %s, Evidence: %s", ev.Rule, ev.Subject, ev.SubjectType, ev.Severity, evidenceJSON(ev.Evidence))
	res, err := ai.InvestigateData(ctx, h.Provider, "Security Event #"+idStr, dataStr)
	if err != nil {
		http.Error(w, "AI analysis failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(res))
}

func evidenceJSON(evidence map[string]any) string {
	b, err := json.Marshal(evidence)
	if err != nil {
		return "{}"
	}
	return string(b)
}
