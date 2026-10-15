package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"haproxy-gui/internal/auth"
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
}

func (h *APIV1ProposalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason   string `json:"reason"`
		Evidence string `json:"evidence"`
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
	writeAPIJSON(w, http.StatusCreated, APIResponse{Success: true, Data: map[string]any{"id": alert.ID, "status": "active"}})
}
