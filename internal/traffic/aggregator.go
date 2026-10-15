package traffic

import (
	"sort"

	"haproxy-gui/internal/haproxylog"
)

// ItemStat represents a item frequency or metric.
type ItemStat struct {
	Name  string
	Count int
}

// BackendLatency represents backend average latency.
type BackendLatency struct {
	Name     string
	AvgMs    float64
	Requests int
}

// Summary collects aggregated log metrics.
type Summary struct {
	TopSources     []ItemStat
	TopPaths       []ItemStat
	TopHosts       []ItemStat
	SlowerBackends []BackendLatency
	TotalRequests  int
	Total5xx       int
	AvgLatencyMs   float64
}

// AggregateLines computes summary statistics from a slice of log lines.
func AggregateLines(lines []haproxylog.Line) Summary {
	sourcesMap := map[string]int{}
	pathsMap := map[string]int{}
	hostsMap := map[string]int{}
	backendMs := map[string]float64{}
	backendReq := map[string]int{}

	totalReq := len(lines)
	total5xx := 0
	sumLatency := 0.0

	for _, l := range lines {
		if l.ClientIP != "" {
			sourcesMap[l.ClientIP]++
		}
		if l.Path != "" {
			pathsMap[l.Path]++
		}
		if l.Host != "" {
			hostsMap[l.Host]++
		}
		if l.StatusCode >= 500 && l.StatusCode < 600 {
			total5xx++
		}
		if l.Backend != "" && l.Tr >= 0 {
			backendMs[l.Backend] += float64(l.Tr)
			backendReq[l.Backend]++
		}
		if l.Tr >= 0 {
			sumLatency += float64(l.Tr)
		}
	}

	avgLat := 0.0
	if totalReq > 0 {
		avgLat = sumLatency / float64(totalReq)
	}

	s := Summary{
		TopSources:    topN(sourcesMap, 10),
		TopPaths:      topN(pathsMap, 10),
		TopHosts:      topN(hostsMap, 10),
		TotalRequests: totalReq,
		Total5xx:      total5xx,
		AvgLatencyMs:  avgLat,
	}

	var backends []BackendLatency
	for b, ms := range backendMs {
		reqs := backendReq[b]
		if reqs > 0 {
			backends = append(backends, BackendLatency{
				Name:     b,
				AvgMs:    ms / float64(reqs),
				Requests: reqs,
			})
		}
	}
	sort.Slice(backends, func(i, j int) bool {
		return backends[i].AvgMs > backends[j].AvgMs
	})
	if len(backends) > 10 {
		backends = backends[:10]
	}
	s.SlowerBackends = backends

	return s
}

func topN(m map[string]int, n int) []ItemStat {
	var list []ItemStat
	for k, v := range m {
		list = append(list, ItemStat{Name: k, Count: v})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Count > list[j].Count
	})
	if len(list) > n {
		list = list[:n]
	}
	return list
}
