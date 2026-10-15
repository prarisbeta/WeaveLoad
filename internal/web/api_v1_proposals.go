package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/store"
)

// ProposalStore is the subset of *store.Store a proposal needs: it lands as
// an active alert that an operator acknowledges, nothing more.
type ProposalStore interface {
	CreateAlert(rule, severity, subject, message string) (store.Alert, error)
}

const (
	maxProposalField = 2000
	maxProposalBody  = 16 << 10
)

// APIV1ProposalHandler handles POST /api/v1/proposals, behind the MCP
// propose_action tool. A proposal is a note for a human: it is shown on the
// Alerts page and executes nothing.
type APIV1ProposalHandler struct {
	Store ProposalStore
	Audit AuditRecorder
	// Policy, when set, also receives a proposal that names a typed action.
	Policy PolicyEngine
}

func (h *APIV1ProposalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason     string `json:"reason"`
		Evidence   string `json:"evidence"`
		Action     string `json:"action"`      // optional: block_ip | drain_server
		Target     string `json:"target"`      // IP, or "backend/server"
		TTLSeconds int    `json:"ttl_seconds"` // optional; the policy default applies when 0
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxProposalBody)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "body must be JSON with reason and evidence"})
		return
	}
	in.Reason, in.Evidence = strings.TrimSpace(in.Reason), strings.TrimSpace(in.Evidence)
	if in.Reason == "" || in.Evidence == "" {
		writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "reason and evidence are required"})
		return
	}
	if len(in.Reason) > maxProposalField || len(in.Evidence) > maxProposalField {
		writeAPIJSON(w, http.StatusRequestEntityTooLarge, APIResponse{Error: fmt.Sprintf("reason and evidence are limited to %d characters each", maxProposalField)})
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	alert, err := h.Store.CreateAlert("ai_proposal", "medium", u.Email, in.Reason+"\n\nEvidence: "+in.Evidence)
	if err != nil {
		writeAPIJSON(w, http.StatusInternalServerError, APIResponse{Error: "failed to record proposal"})
		return
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "proposal.create", Target: fmt.Sprintf("alert:%d", alert.ID), Detail: in.Reason,
	}); err != nil {
		writeAPIJSON(w, http.StatusInternalServerError, APIResponse{Error: "proposal recorded but could not be audit-logged"})
		return
	}
	data := map[string]any{"id": alert.ID, "status": "active"}
	if in.Action != "" {
		pd, ok := h.submitAction(r, u.Email, in.Action, in.Target, in.TTLSeconds, in.Reason, in.Evidence)
		data["policy"] = pd
		if !ok {
			data["policy_note"] = "the proposal is recorded as an alert, but the Policy Engine refused the action"
		}
	}
	writeAPIJSON(w, http.StatusCreated, APIResponse{Success: true, Data: data})
}

// submitAction hands a typed action to the Policy Engine. API callers and the
// AI are capped at "propose": whatever the configured mode is, the action
// waits for a human.
func (h *APIV1ProposalHandler) submitAction(r *http.Request, email, action, target string, ttlSeconds int, reason, evidence string) (map[string]any, bool) {
	if h.Policy == nil {
		return map[string]any{"allowed": false, "reasons": []string{"policy engine is not enabled"}}, false
	}
	source := "api:" + email
	if t, ok := auth.APITokenFromContext(r.Context()); ok {
		source = "api:" + t.Name
	}
	rec, d, err := h.Policy.Submit(policy.Action{
		Type: policy.ActionType(action), Target: target, TTL: time.Duration(ttlSeconds) * time.Second,
		Reason: reason, Evidence: evidence, Source: source, MaxMode: policy.ModePropose,
	})
	out := map[string]any{"allowed": d.Allowed, "mode": d.Mode, "reasons": d.Reasons}
	if err != nil {
		out["error"] = "failed to record the action"
		return out, false
	}
	if d.Allowed {
		out["action_id"], out["status"] = rec.ID, rec.Status
	}
	return out, d.Allowed
}
