package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"haproxy-gui/internal/haproxycfg"
	"haproxy-gui/internal/stats"
	"haproxy-gui/internal/store"
	"haproxy-gui/internal/sysinfo"
)

// APIResponse is the standard JSON envelope for all /api/v1 endpoints per C1-4.
type APIResponse struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
	Meta    any    `json:"meta,omitempty"`
}

func writeAPIJSON(w http.ResponseWriter, status int, resp APIResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func parseAPISnapshot(s StatsSource) (stats.Snapshot, error) {
	if s == nil {
		return stats.Snapshot{}, fmt.Errorf("stats source nil")
	}
	raw, err := s.ShowStat()
	if err != nil {
		return stats.Snapshot{}, err
	}
	return stats.Parse(raw)
}

// APIV1StatusHandler handles GET /api/v1/status
type APIV1StatusHandler struct {
	Stats     StatsSource
	Sys       SysSampler
	DiskPaths []string
}

func (h *APIV1StatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	snap, snapErr := parseAPISnapshot(h.Stats)
	var sysInfo *sysinfo.Snapshot
	if h.Sys != nil {
		paths := h.DiskPaths
		if len(paths) == 0 {
			paths = []string{"/"}
		}
		info := h.Sys.Read(paths)
		sysInfo = &info
	}

	liveOK := snapErr == nil
	data := map[string]any{
		"live":      liveOK,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	if snapErr != nil {
		data["live_error"] = snapErr.Error()
	} else {
		summary := snap.Summary()
		data["summary"] = summary
		data["frontends_total"] = len(snap.Frontends)
		data["backends_total"] = len(snap.Backends)
		data["total_sessions"] = summary.Sessions
	}
	if sysInfo != nil {
		data["system"] = sysInfo
	}

	writeAPIJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
		Meta: map[string]any{
			"version": "v1",
		},
	})
}

// APIV1BackendsHandler handles GET /api/v1/backends
type APIV1BackendsHandler struct {
	Stats  StatsSource
	Config ConfigStore
}

func (h *APIV1BackendsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	snap, snapErr := parseAPISnapshot(h.Stats)
	if snapErr != nil {
		writeAPIJSON(w, http.StatusServiceUnavailable, APIResponse{
			Success: false,
			Error:   "Stats live tidak tersedia: " + snapErr.Error(),
		})
		return
	}

	var backends []map[string]any
	for _, b := range snap.Backends {
		upCount := 0
		downCount := 0
		totalSessions := 0
		for _, s := range b.Servers {
			totalSessions += s.Sessions
			if s.Up() {
				upCount++
			} else if s.Down() {
				downCount++
			}
		}
		backends = append(backends, map[string]any{
			"name":         b.Name,
			"status":       b.Status,
			"servers":      len(b.Servers),
			"servers_up":   upCount,
			"servers_down": downCount,
			"sessions":     totalSessions,
		})
	}

	writeAPIJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    backends,
		Meta: map[string]any{
			"total": len(backends),
		},
	})
}

// APIV1ServersHandler handles GET /api/v1/servers
type APIV1ServersHandler struct {
	Stats StatsSource
}

func (h *APIV1ServersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	snap, snapErr := parseAPISnapshot(h.Stats)
	if snapErr != nil {
		writeAPIJSON(w, http.StatusServiceUnavailable, APIResponse{
			Success: false,
			Error:   "Stats live tidak tersedia: " + snapErr.Error(),
		})
		return
	}

	var servers []map[string]any
	for _, b := range snap.Backends {
		for _, s := range b.Servers {
			servers = append(servers, map[string]any{
				"backend":      b.Name,
				"server":       s.Name,
				"status":       s.Status,
				"is_ready":     s.IsReady(),
				"is_draining":  s.IsDraining(),
				"is_maint":     s.IsMaint(),
				"weight":       s.Weight,
				"sessions":     s.Sessions,
				"check_status": s.CheckStatus,
				"last_check":   s.LastCheck,
			})
		}
	}

	writeAPIJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    servers,
		Meta: map[string]any{
			"total": len(servers),
		},
	})
}

// APIV1NodesHandler handles GET /api/v1/nodes
type APIV1NodesHandler struct {
	Config ConfigStore
	Stats  StatsSource
}

func (h *APIV1NodesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	content, err := h.Config.Active()
	if err != nil {
		writeAPIJSON(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Konfigurasi tidak bisa dibaca: " + err.Error(),
		})
		return
	}
	cfg := haproxycfg.Parse(content)
	snap, _ := parseAPISnapshot(h.Stats)

	var nodes []map[string]any
	for _, n := range cfg.Nodes() {
		upCount := 0
		var uses []map[string]any
		for _, u := range n.Uses {
			status := "UNKNOWN"
			if b, ok := snap.Backend(u.Pool); ok {
				for _, srv := range b.Servers {
					if srv.Name == u.Server {
						status = srv.Status
						if srv.Up() {
							upCount++
						}
					}
				}
			}
			uses = append(uses, map[string]any{
				"pool":   u.Pool,
				"server": u.Server,
				"port":   u.Port,
				"backup": u.Backup,
				"status": status,
			})
		}
		nodes = append(nodes, map[string]any{
			"host":       n.Host,
			"total_uses": len(n.Uses),
			"up_uses":    upCount,
			"uses":       uses,
		})
	}

	writeAPIJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    nodes,
		Meta: map[string]any{
			"total": len(nodes),
		},
	})
}

// APIV1IncidentsHandler handles GET /api/v1/incidents
type APIV1IncidentsHandler struct {
	Store IncidentStore
}

func (h *APIV1IncidentsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	severity := q.Get("severity")
	search := q.Get("q")

	incidents, total, err := h.Store.ListIncidents(store.IncidentFilter{
		Status:   status,
		Severity: severity,
		Query:    search,
		Limit:    100,
	})
	if err != nil {
		writeAPIJSON(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Gagal membaca insiden: " + err.Error(),
		})
		return
	}

	writeAPIJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    incidents,
		Meta: map[string]any{
			"total": total,
		},
	})
}

// APIV1IncidentDetailHandler handles GET /api/v1/incidents/{id}
type APIV1IncidentDetailHandler struct {
	Store IncidentStore
}

func (h *APIV1IncidentDetailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeAPIJSON(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "ID insiden tidak valid",
		})
		return
	}

	inc, events, notes, err := h.Store.GetIncident(id)
	if err != nil {
		writeAPIJSON(w, http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Insiden tidak ditemukan: " + err.Error(),
		})
		return
	}

	writeAPIJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]any{
			"incident": inc,
			"events":   events,
			"notes":    notes,
		},
	})
}
