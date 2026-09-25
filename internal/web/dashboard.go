// Package web wires HTTP handlers for the dashboard, runtime controls, the
// config editor, certificate management, and the audit log. Handlers are
// kept thin: parse the request, call into runtime/stats/cfgfile/store, log
// to the audit trail, render.
package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/runtime"
	"haproxy-gui/internal/stats"
	"haproxy-gui/internal/store"
)

// StatsSource is the subset of *runtime.Client the dashboard needs.
type StatsSource interface {
	ShowStat() (string, error)
}

// AuditRecorder is the subset of *store.Store the handlers need for logging.
type AuditRecorder interface {
	Record(store.AuditEntry) error
}

// DashboardHandler renders the live frontend/backend/server table.
type DashboardHandler struct {
	Stats     StatsSource
	Templates *template.Template
}

func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, err := h.Stats.ShowStat()
	if err != nil {
		http.Error(w, "failed to reach haproxy runtime socket: "+err.Error(), http.StatusBadGateway)
		return
	}
	snap, err := stats.Parse(raw)
	if err != nil {
		http.Error(w, "failed to parse haproxy stats: "+err.Error(), http.StatusInternalServerError)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	sess, _ := auth.SessionFromContext(r.Context())
	data := struct {
		Snapshot   stats.Snapshot
		User       store.User
		CanOperate bool
		CSRFToken  string
	}{Snapshot: snap, User: u, CanOperate: u.Role.Allows(store.RoleOperator), CSRFToken: sess.CSRFToken}

	if isHTMXRequest(r) {
		renderTemplate(w, h.Templates, "dashboard_table.html", data)
		return
	}
	renderTemplate(w, h.Templates, "dashboard.html", data)
}

func isHTMXRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

func renderTemplate(w http.ResponseWriter, t *template.Template, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// ServerControl is the subset of *runtime.Client the runtime-control
// handler needs.
type ServerControl interface {
	SetServerState(backend, server string, state runtime.ServerState) error
	SetServerWeight(backend, server, weight string) error
}

// ServerActionHandler enables/disables/drains a server, or changes its
// weight, and records the action in the audit log. Wiring this behind
// auth.RequireRole(store.RoleOperator) is the caller's responsibility.
type ServerActionHandler struct {
	Runtime   ServerControl
	Audit     AuditRecorder
	Templates *template.Template
	// Refresh re-fetches stats for the fragment re-render after a
	// successful action, so the dashboard row updates without a full
	// page reload. Same signature as DashboardHandler's dependency.
	Refresh StatsSource
}

type serverActionRequest struct {
	Backend string `json:"backend"`
	Server  string `json:"server"`
	Action  string `json:"action"` // "ready" | "drain" | "maint" | "weight"
	Weight  string `json:"weight"` // only for action=weight
}

func (h *ServerActionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req serverActionRequest
	if err := parseRequest(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !runtime.ValidName(req.Backend) || !runtime.ValidName(req.Server) {
		http.Error(w, "invalid backend or server name", http.StatusBadRequest)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	target := req.Backend + "/" + req.Server

	var actionErr error
	var auditAction, auditDetail string

	switch req.Action {
	case "ready", "drain", "maint":
		actionErr = h.Runtime.SetServerState(req.Backend, req.Server, runtime.ServerState(req.Action))
		auditAction = "server." + req.Action
	case "weight":
		actionErr = h.Runtime.SetServerWeight(req.Backend, req.Server, req.Weight)
		auditAction = "server.weight"
		auditDetail = "weight=" + req.Weight
	default:
		http.Error(w, "unknown action: "+req.Action, http.StatusBadRequest)
		return
	}

	status := "ok"
	if actionErr != nil {
		status = "error: " + actionErr.Error()
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email,
		RemoteIP:  clientIP(r),
		Action:    auditAction,
		Target:    target,
		Detail:    strings.TrimSpace(auditDetail + " result=" + status),
	}); err != nil {
		// Audit failure must not be silently swallowed: the operator needs
		// to know the action's effect on HAProxy may be unrecorded.
		http.Error(w, "action may have applied but failed to audit-log: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if actionErr != nil {
		http.Error(w, actionErr.Error(), http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func parseRequest(r *http.Request, out *serverActionRequest) error {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(out); err != nil {
			return fmt.Errorf("invalid JSON body: %w", err)
		}
		return nil
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("invalid form body: %w", err)
	}
	out.Backend = r.FormValue("backend")
	out.Server = r.FormValue("server")
	out.Action = r.FormValue("action")
	out.Weight = r.FormValue("weight")
	return nil
}

// clientIP extracts the request's remote address without the port, for the
// audit log. It intentionally does not trust X-Forwarded-For, since this
// app is meant to sit directly behind HAProxy on localhost or a private
// network, not behind an arbitrary untrusted proxy chain.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
