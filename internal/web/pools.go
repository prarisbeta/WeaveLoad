package web

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/haproxycfg"
	"haproxy-gui/internal/runtime"
	"haproxy-gui/internal/stats"
	"haproxy-gui/internal/store"
)

// PoolService holds what every pool/node page and action needs. One shared
// instance is wired into all the handlers below so its mutex serialises
// every read-modify-apply cycle on haproxy.cfg made through this page.
type PoolService struct {
	Config    ConfigStore
	Stats     StatsSource
	Audit     AuditRecorder
	Templates *template.Template

	mu sync.Mutex
}

// memberView joins one config server line with its live runtime state.
type memberView struct {
	haproxycfg.Member
	Live    stats.Server
	HasLive bool
}

// poolView is one pool as the list and detail pages render it.
type poolView struct {
	haproxycfg.Pool
	LiveStatus string
	Members    []memberView
	Up         int
	Down       int
	Sessions   int
}

// load reads the active config and live stats and joins them. A stats
// failure is not fatal — the pages still render from config alone, with
// the error shown — because the config file is the source of truth here.
func (s *PoolService) load() (haproxycfg.Config, stats.Snapshot, string, error) {
	content, err := s.Config.Active()
	if err != nil {
		return haproxycfg.Config{}, stats.Snapshot{}, "", err
	}
	cfg := haproxycfg.Parse(content)

	var snap stats.Snapshot
	statsErr := ""
	if raw, err := s.Stats.ShowStat(); err != nil {
		statsErr = "Status live tidak tersedia: " + err.Error()
	} else if snap, err = stats.Parse(raw); err != nil {
		statsErr = "Status live tidak bisa dibaca: " + err.Error()
	}
	return cfg, snap, statsErr, nil
}

func joinPool(p haproxycfg.Pool, snap stats.Snapshot) poolView {
	v := poolView{Pool: p}
	live, hasLive := snap.Backend(p.Name)
	v.LiveStatus = live.Status
	for _, m := range p.Members {
		mv := memberView{Member: m}
		for _, srv := range live.Servers {
			if srv.Name == m.Name {
				mv.Live, mv.HasLive = srv, hasLive
				break
			}
		}
		if mv.HasLive {
			v.Sessions += mv.Live.Sessions
			if mv.Live.Up() {
				v.Up++
			} else if mv.Live.Down() {
				v.Down++
			}
		}
		v.Members = append(v.Members, mv)
	}
	return v
}

// PoolsHandler lists every pool with member counts and live health.
type PoolsHandler struct{ *PoolService }

func (h *PoolsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg, snap, statsErr, err := h.load()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	pools := make([]poolView, 0, len(cfg.Pools))
	for _, p := range cfg.Pools {
		if len(p.Members) == 0 && p.Kind == "listen" {
			continue // e.g. the stats page: a listen section with no servers isn't a pool
		}
		pools = append(pools, joinPool(p, snap))
	}
	renderTemplate(w, h.Templates, "pools.html", struct {
		Chrome
		Pools    []poolView
		StatsErr string
		CanAdmin bool
	}{NewChrome(r, "pools"), pools, statsErr, userIsAdmin(r)})
}

type poolDetailData struct {
	Chrome
	Pool       poolView
	StatsErr   string
	CanOperate bool
	CanAdmin   bool
	KnownHosts []string
	Suggested  string
	// Prefill is the node address passed from the Nodes page ("?node=").
	Prefill string
}

// PoolDetailHandler shows one pool's members and, for admins, the form to
// add a member. An htmx request returns only the members table, which the
// page polls and also re-fetches after any member change.
type PoolDetailHandler struct{ *PoolService }

func (h *PoolDetailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg, snap, statsErr, err := h.load()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	p, ok := cfg.Pool(r.PathValue("name"))
	if !ok {
		http.Error(w, "Kelompok server tidak ditemukan", http.StatusNotFound)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	var hosts []string
	for _, n := range cfg.Nodes() {
		hosts = append(hosts, n.Host)
	}
	data := poolDetailData{
		Chrome:     NewChrome(r, "pools"),
		Pool:       joinPool(p, snap),
		StatsErr:   statsErr,
		CanOperate: u.Role.Can(store.CapRuntimeControl),
		CanAdmin:   u.Role.Can(store.CapManageConfig),
		KnownHosts: hosts,
		Suggested:  p.SuggestName(),
		Prefill:    r.URL.Query().Get("node"),
	}
	if isHTMXRequest(r) {
		renderTemplate(w, h.Templates, "pool_members.html", data)
		return
	}
	renderTemplate(w, h.Templates, "pool_detail.html", data)
}

// NodesHandler lists every backend host and the pools it serves.
type NodesHandler struct{ *PoolService }

type nodeView struct {
	haproxycfg.Node
	Uses  []nodeUseView
	Up    int
	Total int
}

type nodeUseView struct {
	haproxycfg.NodeUse
	Live    stats.Server
	HasLive bool
}

func (h *NodesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg, snap, statsErr, err := h.load()
	if err != nil {
		http.Error(w, "Konfigurasi tidak bisa dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var nodes []nodeView
	for _, n := range cfg.Nodes() {
		nv := nodeView{Node: n, Total: len(n.Uses)}
		for _, use := range n.Uses {
			uv := nodeUseView{NodeUse: use}
			if b, ok := snap.Backend(use.Pool); ok {
				for _, srv := range b.Servers {
					if srv.Name == use.Server {
						uv.Live, uv.HasLive = srv, true
						if srv.Up() {
							nv.Up++
						}
					}
				}
			}
			nv.Uses = append(nv.Uses, uv)
		}
		nodes = append(nodes, nv)
	}
	var poolNames []string
	for _, p := range cfg.Pools {
		if len(p.Members) > 0 || p.Kind == "backend" {
			poolNames = append(poolNames, p.Name)
		}
	}
	renderTemplate(w, h.Templates, "nodes.html", struct {
		Chrome
		Nodes    []nodeView
		Pools    []string
		StatsErr string
		CanAdmin bool
	}{NewChrome(r, "nodes"), nodes, poolNames, statsErr, userIsAdmin(r)})
}

func userIsAdmin(r *http.Request) bool {
	u, _ := auth.UserFromContext(r.Context())
	return u.Role.Can(store.CapManageConfig)
}

// NodeAddRedirect sends the Nodes page's "add to pool" form to the chosen
// pool's page with the node prefilled. It exists only because an HTML form
// can't put a select's value into the URL path by itself.
func NodeAddRedirect(w http.ResponseWriter, r *http.Request) {
	pool := r.URL.Query().Get("pool")
	node := r.URL.Query().Get("node")
	if !runtime.ValidName(pool) {
		http.Error(w, "kelompok tidak valid", http.StatusBadRequest)
		return
	}
	target := "/pools/" + pool
	if node != "" {
		target += "?node=" + url.QueryEscape(node)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func memberSpecFromForm(r *http.Request) haproxycfg.MemberSpec {
	return haproxycfg.MemberSpec{
		Name:      strings.TrimSpace(r.FormValue("name")),
		Host:      strings.TrimSpace(r.FormValue("host")),
		Port:      strings.TrimSpace(r.FormValue("port")),
		Weight:    strings.TrimSpace(r.FormValue("weight")),
		Maxconn:   strings.TrimSpace(r.FormValue("maxconn")),
		Backup:    r.FormValue("backup") != "",
		Disabled:  r.FormValue("disabled") != "",
		CloneFrom: strings.TrimSpace(r.FormValue("clone_from")),
	}
}
