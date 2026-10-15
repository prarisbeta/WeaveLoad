package web

import (
	"net/http"
	"sort"

	"haproxy-gui/internal/haproxycfg"
)

type sessionServer struct {
	Pool     string `json:"pool"`
	Server   string `json:"server"`
	Port     string `json:"port,omitempty"`
	Status   string `json:"status"`
	Backup   bool   `json:"backup,omitempty"`
	Sessions int    `json:"active_sessions"`
}

type sessionNode struct {
	Host     string          `json:"host"`
	Sessions int             `json:"active_sessions"`
	Servers  []sessionServer `json:"servers"`
}

// APIV1SessionsHandler handles GET /api/v1/sessions: live active sessions per
// node (host), with the pool/server rows behind each number, busiest first.
// A node that serves several pools sums the sessions of all of them. It is what
// the MCP tool get_active_sessions reads.
type APIV1SessionsHandler struct {
	Config ConfigStore
	Stats  StatsSource
}

func (h *APIV1SessionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	content, err := h.Config.Active()
	if err != nil {
		writeAPIJSON(w, http.StatusInternalServerError, APIResponse{Error: "Konfigurasi tidak bisa dibaca: " + err.Error()})
		return
	}
	snap, err := parseAPISnapshot(h.Stats)
	if err != nil {
		writeAPIJSON(w, http.StatusServiceUnavailable, APIResponse{Error: "live stats are not available: " + err.Error()})
		return
	}

	nodes := []sessionNode{}
	total := 0
	for _, n := range haproxycfg.Parse(content).Nodes() {
		node := sessionNode{Host: n.Host, Servers: []sessionServer{}}
		for _, u := range n.Uses {
			row := sessionServer{Pool: u.Pool, Server: u.Server, Port: u.Port, Backup: u.Backup, Status: "UNKNOWN"}
			if b, ok := snap.Backend(u.Pool); ok {
				for _, srv := range b.Servers {
					if srv.Name == u.Server {
						row.Status, row.Sessions = srv.Status, srv.Sessions
					}
				}
			}
			node.Sessions += row.Sessions
			node.Servers = append(node.Servers, row)
		}
		sort.SliceStable(node.Servers, func(i, j int) bool { return node.Servers[i].Sessions > node.Servers[j].Sessions })
		total += node.Sessions
		nodes = append(nodes, node)
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Sessions != nodes[j].Sessions {
			return nodes[i].Sessions > nodes[j].Sessions
		}
		return nodes[i].Host < nodes[j].Host
	})

	writeAPIJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    nodes,
		Meta:    map[string]any{"nodes": len(nodes), "total_active_sessions": total},
	})
}
