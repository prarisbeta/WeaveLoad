package web

import (
	"net/http"
	"strconv"
	"time"

	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/traffic"
)

const (
	defaultTrafficLines = 1000
	minTrafficLines     = 100
	maxTrafficLines     = 5000
)

type trafficItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type trafficBackend struct {
	Name     string  `json:"name"`
	AvgMs    float64 `json:"avg_ms"`
	Requests int     `json:"requests"`
}

// trafficView is the JSON shape of GET /api/v1/traffic.
type trafficView struct {
	SampleLines     int              `json:"sample_lines"`
	From            string           `json:"from,omitempty"`
	To              string           `json:"to,omitempty"`
	TotalRequests   int              `json:"total_requests"`
	Errors5xx       int              `json:"errors_5xx"`
	ErrorRatio      float64          `json:"error_ratio"`
	AvgLatencyMs    float64          `json:"avg_latency_ms"`
	TopSources      []trafficItem    `json:"top_sources"`
	TopPaths        []trafficItem    `json:"top_paths"`
	TopHosts        []trafficItem    `json:"top_hosts"`
	SlowestBackends []trafficBackend `json:"slowest_backends"`
}

func trafficItems(in []traffic.ItemStat) []trafficItem {
	out := make([]trafficItem, 0, len(in))
	for _, i := range in {
		out = append(out, trafficItem{Name: i.Name, Count: i.Count})
	}
	return out
}

// APIV1TrafficHandler handles GET /api/v1/traffic?lines=N: the same summary
// the /traffic page shows (top sources, paths and hosts, 5xx share, backend
// latency), computed over the newest N access-log lines. It is what the MCP
// tool get_traffic_summary reads.
type APIV1TrafficHandler struct {
	LogPath string
}

func (h *APIV1TrafficHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := defaultTrafficLines
	if v := r.URL.Query().Get("lines"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed <= 0 {
			writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "lines must be a positive integer"})
			return
		}
		n = parsed
	}
	if n < minTrafficLines {
		n = minTrafficLines
	}
	if n > maxTrafficLines {
		n = maxTrafficLines
	}

	lines, err := haproxylog.TailRecent(h.LogPath, n)
	if err != nil {
		writeAPIJSON(w, http.StatusServiceUnavailable, APIResponse{Error: "access log is not readable: " + err.Error()})
		return
	}
	s := traffic.AggregateLines(lines)

	view := trafficView{
		SampleLines:   len(lines),
		TotalRequests: s.TotalRequests,
		Errors5xx:     s.Total5xx,
		AvgLatencyMs:  s.AvgLatencyMs,
		TopSources:    trafficItems(s.TopSources),
		TopPaths:      trafficItems(s.TopPaths),
		TopHosts:      trafficItems(s.TopHosts),
	}
	if s.TotalRequests > 0 {
		view.ErrorRatio = float64(s.Total5xx) / float64(s.TotalRequests)
	}
	view.SlowestBackends = make([]trafficBackend, 0, len(s.SlowerBackends))
	for _, b := range s.SlowerBackends {
		view.SlowestBackends = append(view.SlowestBackends, trafficBackend{Name: b.Name, AvgMs: b.AvgMs, Requests: b.Requests})
	}
	if len(lines) > 0 {
		if t := lines[0].Time; !t.IsZero() {
			view.From = t.UTC().Format(time.RFC3339)
		}
		if t := lines[len(lines)-1].Time; !t.IsZero() {
			view.To = t.UTC().Format(time.RFC3339)
		}
	}
	writeAPIJSON(w, http.StatusOK, APIResponse{Success: true, Data: view})
}
