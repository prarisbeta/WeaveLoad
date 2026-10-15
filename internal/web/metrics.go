package web

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"haproxy-gui/internal/store"
)

// MetricsStore is what the Prometheus endpoint reads.
type MetricsStore interface {
	ListSecurityEvents(store.SecurityFilter) ([]store.SecurityEvent, int, error)
	ListTopRisk(n int) ([]store.IPRisk, error)
	ListIncidents(store.IncidentFilter) ([]store.Incident, int, error)
	CountPolicyActionsByStatus() (map[string]int, error)
}

// MetricsHandler serves GET /metrics in the Prometheus text format. It is
// behind the same authentication as /api/v1, so Prometheus scrapes it with
// "authorization: bearer kgw_..." using an API token.
type MetricsHandler struct {
	Store  MetricsStore
	Stats  StatsSource  // optional
	Engine PolicyEngine // optional, for the kill-switch gauge
}

func (h *MetricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	gauge := func(name, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}

	gauge("konsolgw_security_events_open", "Open security events by severity.")
	for _, sev := range []string{"low", "medium", "high", "critical"} {
		_, total, err := h.Store.ListSecurityEvents(store.SecurityFilter{Severity: sev, Status: "open", Limit: 1})
		if err == nil {
			fmt.Fprintf(&b, "konsolgw_security_events_open{severity=%q} %d\n", sev, total)
		}
	}

	if risks, err := h.Store.ListTopRisk(500); err == nil {
		high := 0
		for _, rk := range risks {
			if rk.State == "high_risk" {
				high++
			}
		}
		gauge("konsolgw_ips_high_risk", "IPs currently in the high_risk state.")
		fmt.Fprintf(&b, "konsolgw_ips_high_risk %d\n", high)
	}

	if _, total, err := h.Store.ListIncidents(store.IncidentFilter{Status: "open", Limit: 1}); err == nil {
		gauge("konsolgw_incidents_open", "Incidents in the open state.")
		fmt.Fprintf(&b, "konsolgw_incidents_open %d\n", total)
	}

	if counts, err := h.Store.CountPolicyActionsByStatus(); err == nil {
		gauge("konsolgw_policy_actions", "Policy Engine actions by status.")
		statuses := make([]string, 0, len(counts))
		for st := range counts {
			statuses = append(statuses, st)
		}
		sort.Strings(statuses)
		for _, st := range statuses {
			fmt.Fprintf(&b, "konsolgw_policy_actions{status=%q} %d\n", st, counts[st])
		}
	}

	if h.Engine != nil {
		gauge("konsolgw_policy_kill_switch", "1 when the Policy Engine kill switch is on.")
		v := 0
		if h.Engine.Config().KillSwitch {
			v = 1
		}
		fmt.Fprintf(&b, "konsolgw_policy_kill_switch %d\n", v)
	}

	if h.Stats != nil {
		gauge("konsolgw_haproxy_up", "1 when the HAProxy runtime socket answers.")
		snap, err := parseAPISnapshot(h.Stats)
		if err != nil {
			b.WriteString("konsolgw_haproxy_up 0\n")
		} else {
			b.WriteString("konsolgw_haproxy_up 1\n")
			gauge("konsolgw_backend_servers", "Servers per backend by health.")
			for _, be := range snap.Backends {
				up, down := 0, 0
				for _, sv := range be.Servers {
					switch {
					case sv.Up():
						up++
					case sv.Down():
						down++
					}
				}
				fmt.Fprintf(&b, "konsolgw_backend_servers{backend=%q,state=\"up\"} %d\n", be.Name, up)
				fmt.Fprintf(&b, "konsolgw_backend_servers{backend=%q,state=\"down\"} %d\n", be.Name, down)
			}
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
