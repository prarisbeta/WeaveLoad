package web

import (
	"encoding/json"
	"net/http"
	"time"

	"haproxy-gui/internal/policy"
)

// APIV1PolicyCheckHandler handles POST /api/v1/policy/check, behind the MCP
// policy_check_action tool: a dry run that says what the Policy Engine would
// do with an action, without recording or running anything.
type APIV1PolicyCheckHandler struct {
	Engine PolicyEngine
}

func (h *APIV1PolicyCheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action     string `json:"action"`
		Target     string `json:"target"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxProposalBody)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "body must be JSON with action and target"})
		return
	}
	if in.Action == "" || in.Target == "" {
		writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "action and target are required"})
		return
	}
	d := h.Engine.Check(policy.Action{
		Type: policy.ActionType(in.Action), Target: in.Target,
		TTL: time.Duration(in.TTLSeconds) * time.Second, MaxMode: policy.ModePropose,
	})
	writeAPIJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]any{
		"allowed": d.Allowed, "mode": d.Mode, "reasons": d.Reasons,
	}})
}
