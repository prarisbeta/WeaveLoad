package web

import (
	"net"
	"net/http"
	"strconv"
	"time"

	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/store"
	"haproxy-gui/internal/traffic"
)

const (
	defaultSeriesMinutes = 60
	maxSeriesMinutes     = 360
	seriesLogLines       = 50000

	defaultErrorLines = 2000
	maxErrorLines     = 5000
	maxErrorLimit     = 25
)

// atoiParam reads an optional positive integer query parameter.
func atoiParam(r *http.Request, name string, def int) (int, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// APIV1TrafficSeriesHandler handles GET /api/v1/traffic/timeseries: requests,
// 4xx, 5xx and latency per time slice, so a spike or an outage can be placed in
// time. Query: minutes (1-360, default 60), step (minutes per slice; default 1,
// or 5 for windows over two hours), backend (optional).
type APIV1TrafficSeriesHandler struct {
	LogPath string
	Now     func() time.Time
}

func (h *APIV1TrafficSeriesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	minutes, ok := atoiParam(r, "minutes", defaultSeriesMinutes)
	if !ok {
		writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "minutes must be a positive integer"})
		return
	}
	if minutes > maxSeriesMinutes {
		minutes = maxSeriesMinutes
	}
	defStep := 1
	if minutes > 120 {
		defStep = 5
	}
	step, ok := atoiParam(r, "step", defStep)
	if !ok {
		writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "step must be a positive integer"})
		return
	}
	if step > minutes {
		step = minutes
	}

	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	lines, err := haproxylog.Read(h.LogPath, haproxylog.Filter{Date: now, Limit: seriesLogLines})
	if err != nil {
		writeAPIJSON(w, http.StatusServiceUnavailable, APIResponse{Error: "access log is not readable: " + err.Error()})
		return
	}
	backend := r.URL.Query().Get("backend")
	series := traffic.Timeseries(lines, now, time.Duration(minutes)*time.Minute, time.Duration(step)*time.Minute, backend)
	writeAPIJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    series,
		Meta:    map[string]any{"minutes": minutes, "step_minutes": step, "backend": backend, "buckets": len(series)},
	})
}

// APIV1TrafficErrorsHandler handles GET /api/v1/traffic/errors: the paths and
// client IPs behind 4xx/5xx responses in the newest log lines. Query: lines
// (100-5000, default 2000), class (4xx, 5xx or all), limit (1-25, default 10).
type APIV1TrafficErrorsHandler struct {
	LogPath string
}

func (h *APIV1TrafficErrorsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n, ok := atoiParam(r, "lines", defaultErrorLines)
	limit, ok2 := atoiParam(r, "limit", 10)
	if !ok || !ok2 {
		writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "lines and limit must be positive integers"})
		return
	}
	if n < minTrafficLines {
		n = minTrafficLines
	}
	if n > maxErrorLines {
		n = maxErrorLines
	}
	if limit > maxErrorLimit {
		limit = maxErrorLimit
	}
	class := r.URL.Query().Get("class")
	switch class {
	case "", "all":
		class = "all"
	case "4xx", "5xx":
	default:
		writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "class must be 4xx, 5xx or all"})
		return
	}

	lines, err := haproxylog.TailRecent(h.LogPath, n)
	if err != nil {
		writeAPIJSON(w, http.StatusServiceUnavailable, APIResponse{Error: "access log is not readable: " + err.Error()})
		return
	}
	paths, ips := traffic.TopErrors(lines, class, limit)
	writeAPIJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]any{"paths": paths, "ips": ips},
		Meta:    map[string]any{"sample_lines": len(lines), "class": class},
	})
}

// IPProfileStore is what the IP profile reads.
type IPProfileStore interface {
	GetIPRisk(ip string) (store.IPRisk, error)
	ListSecurityEvents(store.SecurityFilter) ([]store.SecurityEvent, int, error)
}

// APIV1IPProfileHandler handles GET /api/v1/security/ip/{ip}: everything the
// gateway knows about one client: risk score, recent detections, threat intel
// when configured, and its recent request pattern from the access log.
type APIV1IPProfileHandler struct {
	Store   IPProfileStore
	Intel   IntelPeeker // optional
	LogPath string      // optional
}

func (h *APIV1IPProfileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if net.ParseIP(ip) == nil {
		writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "a valid IP address is required"})
		return
	}
	out := map[string]any{"ip": ip}
	if risk, err := h.Store.GetIPRisk(ip); err == nil {
		out["risk"] = risk
	}
	events, total, err := h.Store.ListSecurityEvents(store.SecurityFilter{Subject: ip, Limit: 10})
	if err != nil {
		writeAPIJSON(w, http.StatusInternalServerError, APIResponse{Error: "failed to read security events: " + err.Error()})
		return
	}
	out["events"] = events
	out["events_total"] = total
	if h.Intel != nil {
		out["intel"] = h.Intel.Peek(ip)
	}
	if h.LogPath != "" {
		if lines, err := haproxylog.TailRecent(h.LogPath, maxErrorLines); err == nil {
			out["traffic"] = ipTraffic(lines, ip)
		}
	}
	writeAPIJSON(w, http.StatusOK, APIResponse{Success: true, Data: out})
}

// ipTraffic summarises one client's requests among the given log lines.
func ipTraffic(lines []haproxylog.Line, ip string) map[string]any {
	statuses := map[string]int{}
	paths := map[string]int{}
	var mine []haproxylog.Line
	for _, l := range lines {
		if l.ClientIP != ip {
			continue
		}
		mine = append(mine, l)
		statuses[strconv.Itoa(l.StatusCode/100)+"xx"]++
		if l.Path != "" {
			paths[l.Path]++
		}
	}
	s := traffic.AggregateLines(mine)
	return map[string]any{
		"sample_lines": len(lines),
		"requests":     len(mine),
		"by_status":    statuses,
		"top_paths":    trafficItems(s.TopPaths),
	}
}
