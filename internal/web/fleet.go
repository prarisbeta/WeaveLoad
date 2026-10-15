package web

import (
	"html/template"
	"net/http"
	"time"

	"haproxy-gui/internal/fleet"
)

// FleetLister lists the nodes that report to this gateway.
type FleetLister interface {
	List() ([]fleet.Node, error)
}

// FleetPageHandler renders GET /fleet: every node's health at a glance.
type FleetPageHandler struct {
	Hub       FleetLister
	Enabled   bool // KONSOLGW_FLEET_TOKEN is set on this gateway
	Templates *template.Template
	Now       func() time.Time
}

func (h *FleetPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	var nodes []fleet.Node
	if h.Enabled {
		var err error
		if nodes, err = h.Hub.List(); err != nil {
			http.Error(w, "failed to list nodes: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	type row struct {
		fleet.Node
		Stale, Down bool
		Age         time.Duration
	}
	rows := make([]row, 0, len(nodes))
	var down, stale int
	for _, n := range nodes {
		rw := row{Node: n, Stale: n.Stale(now), Down: n.Down(), Age: now.Sub(n.ReceivedAt).Round(time.Second)}
		if rw.Stale {
			stale++
		} else if rw.Down {
			down++
		}
		rows = append(rows, rw)
	}
	renderTemplate(w, h.Templates, "fleet.html", struct {
		Chrome
		Enabled bool
		Rows    []row
		Total   int
		Down    int
		Stale   int
	}{Chrome: NewChrome(r, "fleet"), Enabled: h.Enabled, Rows: rows, Total: len(rows), Down: down, Stale: stale})
}
