package traffic

import (
	"sort"
	"time"

	"haproxy-gui/internal/haproxylog"
)

// Bucket is one time slice of the request series.
type Bucket struct {
	Start        time.Time `json:"start"`
	Requests     int       `json:"requests"`
	Errors4xx    int       `json:"errors_4xx"`
	Errors5xx    int       `json:"errors_5xx"`
	AvgLatencyMs float64   `json:"avg_latency_ms"`
}

// Timeseries buckets the lines that fall in the window ending at now into
// consecutive slices of step, oldest first. Empty slices are kept as zero rows:
// a quiet minute in the middle of an outage is exactly what the reader needs to
// see. A non-empty backend limits the series to that backend.
func Timeseries(lines []haproxylog.Line, now time.Time, window, step time.Duration, backend string) []Bucket {
	if step <= 0 || window < step {
		return nil
	}
	n := int(window / step)
	last := now.Truncate(step)
	first := last.Add(-time.Duration(n-1) * step)

	buckets := make([]Bucket, n)
	latSum := make([]float64, n)
	latN := make([]int, n)
	for i := range buckets {
		buckets[i].Start = first.Add(time.Duration(i) * step)
	}
	for _, l := range lines {
		if l.Time.IsZero() || (backend != "" && l.Backend != backend) {
			continue
		}
		i := int(l.Time.Truncate(step).Sub(first) / step)
		if l.Time.Before(first) || i < 0 || i >= n {
			continue
		}
		b := &buckets[i]
		b.Requests++
		switch {
		case l.StatusCode >= 500 && l.StatusCode < 600:
			b.Errors5xx++
		case l.StatusCode >= 400 && l.StatusCode < 500:
			b.Errors4xx++
		}
		if l.Tr >= 0 {
			latSum[i] += float64(l.Tr)
			latN[i]++
		}
	}
	for i := range buckets {
		if latN[i] > 0 {
			buckets[i].AvgLatencyMs = latSum[i] / float64(latN[i])
		}
	}
	return buckets
}

// ErrorPath is one path that answered with an error status.
type ErrorPath struct {
	Path       string `json:"path"`
	Status     int    `json:"status"`
	Count      int    `json:"count"`
	Backend    string `json:"backend,omitempty"`
	TopIP      string `json:"top_ip,omitempty"`
	TopIPCount int    `json:"top_ip_count,omitempty"`
}

// ErrorIP is a client that caused many error responses.
type ErrorIP struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

type errKey struct {
	path   string
	status int
}

type errAgg struct {
	count   int
	backend string
	ips     map[string]int
}

// TopErrors ranks the paths and client IPs behind error responses. class is
// "4xx", "5xx", or anything else for both. Paths come without their query
// string (the log reader strips it), so tokens passed in URLs are not exposed.
func TopErrors(lines []haproxylog.Line, class string, limit int) ([]ErrorPath, []ErrorIP) {
	if limit <= 0 {
		limit = 10
	}
	paths := map[errKey]*errAgg{}
	ips := map[string]int{}
	for _, l := range lines {
		s := l.StatusCode
		is4, is5 := s >= 400 && s < 500, s >= 500 && s < 600
		if !is4 && !is5 || (class == "4xx" && !is4) || (class == "5xx" && !is5) {
			continue
		}
		path := l.Path
		if path == "" {
			path = "-"
		}
		k := errKey{path, s}
		a := paths[k]
		if a == nil {
			a = &errAgg{ips: map[string]int{}}
			paths[k] = a
		}
		a.count++
		if l.Backend != "" {
			a.backend = l.Backend
		}
		if l.ClientIP != "" {
			a.ips[l.ClientIP]++
			ips[l.ClientIP]++
		}
	}

	outPaths := make([]ErrorPath, 0, len(paths))
	for k, a := range paths {
		ep := ErrorPath{Path: k.path, Status: k.status, Count: a.count, Backend: a.backend}
		for ip, c := range a.ips {
			if c > ep.TopIPCount || (c == ep.TopIPCount && ip < ep.TopIP) {
				ep.TopIP, ep.TopIPCount = ip, c
			}
		}
		outPaths = append(outPaths, ep)
	}
	sort.Slice(outPaths, func(i, j int) bool {
		if outPaths[i].Count != outPaths[j].Count {
			return outPaths[i].Count > outPaths[j].Count
		}
		if outPaths[i].Path != outPaths[j].Path {
			return outPaths[i].Path < outPaths[j].Path
		}
		return outPaths[i].Status < outPaths[j].Status
	})
	if len(outPaths) > limit {
		outPaths = outPaths[:limit]
	}

	outIPs := make([]ErrorIP, 0, len(ips))
	for ip, c := range ips {
		outIPs = append(outIPs, ErrorIP{IP: ip, Count: c})
	}
	sort.Slice(outIPs, func(i, j int) bool {
		if outIPs[i].Count != outIPs[j].Count {
			return outIPs[i].Count > outIPs[j].Count
		}
		return outIPs[i].IP < outIPs[j].IP
	})
	if len(outIPs) > limit {
		outIPs = outIPs[:limit]
	}
	return outPaths, outIPs
}
