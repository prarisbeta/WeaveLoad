package web

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sync"
	"time"

	"haproxy-gui/internal/ai"
	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/store"
)

// CopilotStore is what the copilot's tools read.
type CopilotStore interface {
	ListSecurityEvents(store.SecurityFilter) ([]store.SecurityEvent, int, error)
	GetIPRisk(ip string) (store.IPRisk, error)
	ListTopRisk(n int) ([]store.IPRisk, error)
	ListIncidents(store.IncidentFilter) ([]store.Incident, int, error)
	ListPolicyActions(status string, limit int) ([]store.PolicyAction, error)
}

// CopilotToolbox gives the AI read-only views of the gateway. Nothing here
// writes, and every result is bounded.
type CopilotToolbox struct {
	Store CopilotStore
	Stats StatsSource // optional
	Intel IntelPeeker // optional
}

func (t *CopilotToolbox) Tools() []ai.Tool {
	return []ai.Tool{
		{Name: "top_risk_ips", Description: "IP dengan skor risiko tertinggi. Args: n (1-20, default 10)"},
		{Name: "security_events", Description: "Kejadian keamanan terbaru. Args: rule (opsional), severity (opsional), limit (1-30, default 15). Aturan: brute_force, rate_anomaly, path_scan, sensitive_probe, http_abuse, backend_abuse, rate_limited, threat_intel, known_bad_ip, traffic_anomaly"},
		{Name: "ip_profile", Description: "Profil satu IP: skor risiko, kejadian terakhir, data threat intel. Args: ip"},
		{Name: "open_incidents", Description: "Insiden yang belum selesai. Tanpa args"},
		{Name: "backends", Description: "Status backend dan server (UP/DOWN/DRAIN, sesi). Tanpa args"},
		{Name: "policy_actions", Description: "Aksi Policy Engine terbaru (pending/executed/...). Args: status (opsional)"},
	}
}

func (t *CopilotToolbox) Call(ctx context.Context, name string, args map[string]any) (string, error) {
	switch name {
	case "top_risk_ips":
		rows, err := t.Store.ListTopRisk(clampInt(args["n"], 10, 1, 20))
		return toJSON(rows, err)
	case "security_events":
		str := func(k string) string { v, _ := args[k].(string); return v }
		evs, total, err := t.Store.ListSecurityEvents(store.SecurityFilter{
			Rule: str("rule"), Severity: str("severity"), Limit: clampInt(args["limit"], 15, 1, 30),
		})
		if err != nil {
			return "", err
		}
		return toJSON(map[string]any{"total": total, "events": evs}, nil)
	case "ip_profile":
		ip, _ := args["ip"].(string)
		if net.ParseIP(ip) == nil {
			return "", fmt.Errorf("ip tidak valid")
		}
		out := map[string]any{"ip": ip}
		if risk, err := t.Store.GetIPRisk(ip); err == nil {
			out["risk"] = risk
		}
		if evs, _, err := t.Store.ListSecurityEvents(store.SecurityFilter{Subject: ip, Limit: 10}); err == nil {
			out["events"] = evs
		}
		if t.Intel != nil {
			out["intel"] = t.Intel.Peek(ip)
		}
		return toJSON(out, nil)
	case "open_incidents":
		var all []store.Incident
		for _, st := range []string{"open", "investigating"} {
			list, _, err := t.Store.ListIncidents(store.IncidentFilter{Status: st, Limit: 10})
			if err != nil {
				return "", err
			}
			all = append(all, list...)
		}
		return toJSON(all, nil)
	case "backends":
		snap, err := parseAPISnapshot(t.Stats)
		if err != nil {
			return "", fmt.Errorf("status live tidak tersedia: %w", err)
		}
		return toJSON(snap.Backends, nil)
	case "policy_actions":
		st, _ := args["status"].(string)
		list, err := t.Store.ListPolicyActions(st, 15)
		return toJSON(list, err)
	}
	return "", fmt.Errorf("tool tidak dikenal: %s", name)
}

func toJSON(v any, err error) (string, error) {
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func clampInt(v any, def, lo, hi int) int {
	n := def
	if f, ok := v.(float64); ok {
		n = int(f)
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// askLimiter caps AI questions per user per hour, which bounds the cost of
// the copilot no matter who is clicking.
type askLimiter struct {
	mu    sync.Mutex
	asked map[string][]time.Time
	max   int
}

func (l *askLimiter) allow(user string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.asked == nil {
		l.asked = map[string][]time.Time{}
	}
	cutoff := now.Add(-time.Hour)
	kept := l.asked[user][:0]
	for _, ts := range l.asked[user] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= l.max {
		l.asked[user] = kept
		return false
	}
	l.asked[user] = append(kept, now)
	return true
}

// CopilotPageHandler renders GET /ask.
type CopilotPageHandler struct {
	Templates *template.Template
	Enabled   bool // an AI provider is configured
}

func (h *CopilotPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, h.Templates, "ask.html", struct {
		Chrome
		Enabled bool
	}{Chrome: NewChrome(r, "ask"), Enabled: h.Enabled})
}

// CopilotAskHandler handles POST /api/ai/ask. The model's recommendations
// become Policy Engine proposals (never above "propose") for users who may
// decide on them; everyone with security access sees the analysis.
type CopilotAskHandler struct {
	Provider  ai.Provider
	Toolbox   ai.Toolbox
	Engine    PolicyEngine // optional
	Audit     AuditRecorder
	Templates *template.Template

	// MaxPerHour limits questions per user; 0 means 20.
	MaxPerHour int
	limiter    askLimiter
	// Now defaults to time.Now; overridable for tests.
	Now func() time.Time
}

type askRecView struct {
	policy.Action
	Note string
}

func (h *CopilotAskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	u, _ := auth.UserFromContext(r.Context())
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	if h.limiter.max == 0 {
		h.limiter.max = h.MaxPerHour
		if h.limiter.max == 0 {
			h.limiter.max = 20
		}
	}
	if !h.limiter.allow(u.Email, now) {
		h.render(w, r, nil, nil, "Batas pertanyaan per jam tercapai. Coba lagi nanti.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	question := r.FormValue("question")
	ans, err := ai.Ask(ctx, h.Provider, h.Toolbox, question)
	_ = h.Audit.Record(store.AuditEntry{UserEmail: u.Email, RemoteIP: clientIP(r), Action: "ai.ask", Detail: truncate(question, 200)})
	if err != nil {
		h.render(w, r, nil, nil, "Gagal: "+err.Error())
		return
	}

	canDecide := u.Role.Can(store.CapRuntimeControl)
	var recs []askRecView
	for _, rec := range ans.Recommendations {
		v := askRecView{Action: policy.Action{
			Type: policy.ActionType(rec.Action), Target: rec.Target, Reason: rec.Reason, Confidence: rec.Confidence,
		}}
		switch {
		case h.Engine == nil || !canDecide:
			v.Note = "usulan (tidak dikirim ke Policy Engine)"
		default:
			v.Source = "ai:copilot"
			v.MaxMode = policy.ModePropose
			v.Evidence = "Pertanyaan: " + truncate(question, 200)
			_, d, err := h.Engine.Submit(v.Action)
			switch {
			case err != nil:
				v.Note = "gagal dicatat"
			case d.Allowed:
				v.Note = "dikirim ke Policy Engine, menunggu persetujuan"
			default:
				v.Note = "ditolak Policy Engine: " + joinReasons(d.Reasons)
			}
		}
		recs = append(recs, v)
	}
	h.render(w, r, &ans, recs, "")
}

func (h *CopilotAskHandler) render(w http.ResponseWriter, r *http.Request, ans *ai.Answer, recs []askRecView, errMsg string) {
	renderTemplate(w, h.Templates, "ask_result.html", struct {
		Chrome
		Answer *ai.Answer
		Recs   []askRecView
		Error  string
	}{Chrome: NewChrome(r, "ask"), Answer: ans, Recs: recs, Error: errMsg})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func joinReasons(rs []string) string {
	out := ""
	for i, r := range rs {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}
