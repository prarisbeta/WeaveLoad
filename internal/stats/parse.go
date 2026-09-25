// Package stats parses the CSV body of HAProxy's Runtime API "show stat"
// command into a structured tree: frontends, backends and their servers.
package stats

import (
	"encoding/csv"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Row is one line of "show stat", keyed by column name so field order
// changes across HAProxy versions don't silently misalign values.
type Row struct {
	Proxy       string // pxname
	Name        string // svname: "FRONTEND", "BACKEND", or a server name
	Status      string // UP, DOWN, MAINT, DRAIN, no check, ...
	Weight      int
	CheckStatus string // check_status: L7OK, L7STS, ...
	LastChk     string // last_chk: human-readable reason
	Sessions    int    // scur
	Type        int    // 0=frontend,1=backend,2=server,3=listener
}

// Server is one backend member.
type Server struct {
	Backend     string
	Name        string
	Status      string
	Weight      int
	CheckStatus string
	LastCheck   string
	Sessions    int
}

// Up reports whether HAProxy currently considers this server healthy
// (including servers with no health check configured, which always read "no check").
func (s Server) Up() bool {
	return s.Status == "UP" || s.Status == "no check"
}

// Down reports the states an operator should treat as "needs attention":
// actually failing checks, not deliberate MAINT/DRAIN.
func (s Server) Down() bool {
	return strings.HasPrefix(s.Status, "DOWN")
}

// Backend is one backend section with its member servers.
type Backend struct {
	Name    string
	Status  string // aggregate BACKEND row status
	Servers []Server
}

// Frontend is one frontend section.
type Frontend struct {
	Name   string
	Status string
}

// Snapshot is the full parsed state of one "show stat" call.
type Snapshot struct {
	Frontends []Frontend
	Backends  []Backend
}

// Parse reads the raw CSV body (header line starts with "# ") and returns
// a Snapshot. Unknown/extra columns are ignored; required columns missing
// from the header is an error, since that means the format changed.
func Parse(csvBody string) (Snapshot, error) {
	body := strings.TrimPrefix(strings.TrimSpace(csvBody), "# ")
	r := csv.NewReader(strings.NewReader(body))
	r.FieldsPerRecord = -1

	records, err := r.ReadAll()
	if err != nil {
		return Snapshot{}, fmt.Errorf("parse show stat csv: %w", err)
	}
	if len(records) == 0 {
		return Snapshot{}, fmt.Errorf("empty show stat output")
	}

	header := records[0]
	col := make(map[string]int, len(header))
	for i, name := range header {
		col[strings.TrimSpace(name)] = i
	}

	required := []string{"pxname", "svname", "status", "weight", "check_status", "last_chk", "scur"}
	for _, c := range required {
		if _, ok := col[c]; !ok {
			return Snapshot{}, fmt.Errorf("show stat missing expected column %q", c)
		}
	}

	get := func(rec []string, name string) string {
		i := col[name]
		if i >= len(rec) {
			return ""
		}
		return rec[i]
	}
	getInt := func(rec []string, name string) int {
		n, _ := strconv.Atoi(get(rec, name))
		return n
	}

	var snap Snapshot
	backendIdx := map[string]int{}

	for _, rec := range records[1:] {
		if len(rec) == 0 {
			continue
		}
		px := get(rec, "pxname")
		sv := get(rec, "svname")

		switch sv {
		case "FRONTEND":
			snap.Frontends = append(snap.Frontends, Frontend{
				Name:   px,
				Status: get(rec, "status"),
			})
		case "BACKEND":
			i, ok := backendIdx[px]
			if !ok {
				i = len(snap.Backends)
				snap.Backends = append(snap.Backends, Backend{Name: px})
				backendIdx[px] = i
			}
			snap.Backends[i].Status = get(rec, "status")
		default:
			i, ok := backendIdx[px]
			if !ok {
				i = len(snap.Backends)
				snap.Backends = append(snap.Backends, Backend{Name: px})
				backendIdx[px] = i
			}
			snap.Backends[i].Servers = append(snap.Backends[i].Servers, Server{
				Backend:     px,
				Name:        sv,
				Status:      get(rec, "status"),
				Weight:      getInt(rec, "weight"),
				CheckStatus: get(rec, "check_status"),
				LastCheck:   get(rec, "last_chk"),
				Sessions:    getInt(rec, "scur"),
			})
		}
	}

	return snap, nil
}

// Summary aggregates a Snapshot into the counts an overview page needs, so
// callers don't re-walk Frontends/Backends/Servers themselves.
type Summary struct {
	FrontendsUp    int
	FrontendsTotal int
	BackendsUp     int
	BackendsTotal  int
	ServersDown    int
	ServersTotal   int
	Sessions       int
}

// Healthy reports whether every frontend and backend is up and no server is
// down (ignoring servers deliberately in MAINT/DRAIN).
func (s Summary) Healthy() bool {
	return s.FrontendsUp == s.FrontendsTotal && s.BackendsUp == s.BackendsTotal && s.ServersDown == 0
}

// Summary computes aggregate counts across the whole snapshot.
func (s Snapshot) Summary() Summary {
	var sum Summary
	sum.FrontendsTotal = len(s.Frontends)
	for _, f := range s.Frontends {
		if f.Status == "OPEN" {
			sum.FrontendsUp++
		}
	}
	sum.BackendsTotal = len(s.Backends)
	for _, b := range s.Backends {
		if b.Status == "UP" {
			sum.BackendsUp++
		}
		for _, srv := range b.Servers {
			sum.ServersTotal++
			sum.Sessions += srv.Sessions
			if srv.Down() {
				sum.ServersDown++
			}
		}
	}
	return sum
}

// ChartBar is one bar in a connections chart: a name, its raw active-session
// count, and how full the bar should be (0-100) relative to the largest
// value among its siblings in the same chart.
type ChartBar struct {
	Name     string
	Sessions int
	Percent  int
}

// TotalSessions sums this backend's servers' active session counts.
func (b Backend) TotalSessions() int {
	total := 0
	for _, s := range b.Servers {
		total += s.Sessions
	}
	return total
}

// pieColors cycles through a fixed, colorblind-considerate palette so
// PieSlice never needs a template-side color decision (Go's html/template
// has no arithmetic to compute a palette index itself).
var pieColors = []string{"#0e7c86", "#2563eb", "#f59e0b", "#dc2626", "#7c3aed", "#059669", "#db2777", "#4b5563"}

// PieSlice is one wedge of a connections pie chart: StartPct/EndPct are
// pre-computed cumulative percentages (0-100) suitable for a single CSS
// conic-gradient stop list, so the template only ever prints numbers it
// didn't have to compute itself.
type PieSlice struct {
	Name     string
	Sessions int
	Percent  float64
	StartPct float64
	EndPct   float64
	Color    string
}

// maxPieSlices caps how many backends get their own wedge — beyond this,
// a long tail of small backends turns the pie into unreadable confetti, and
// there are exactly this many colors in pieColors to draw from.
const maxPieSlices = 8

// ConnectionsPie returns one slice per backend, comparing each one's share
// of total active connections across the whole system ("keseluruhan"). Only
// the maxPieSlices busiest backends get a wedge; the rest are folded into a
// single "Lainnya" slice so the wedges still add up to the true total.
func (s Snapshot) ConnectionsPie() []PieSlice {
	total := 0
	for _, b := range s.Backends {
		total += b.TotalSessions()
	}

	ranked := make([]Backend, len(s.Backends))
	copy(ranked, s.Backends)
	sort.SliceStable(ranked, func(i, j int) bool {
		return ranked[i].TotalSessions() > ranked[j].TotalSessions()
	})

	shown := ranked
	var others int
	if len(ranked) > maxPieSlices {
		shown = ranked[:maxPieSlices]
		for _, b := range ranked[maxPieSlices:] {
			others += b.TotalSessions()
		}
	}

	slices := make([]PieSlice, 0, len(shown)+1)
	acc := 0.0
	addSlice := func(name string, sessions int, colorIdx int) {
		pct := 0.0
		if total > 0 {
			pct = math.Round(float64(sessions)*10000/float64(total)) / 100 // 2 decimal places
		}
		slices = append(slices, PieSlice{
			Name: name, Sessions: sessions, Percent: pct,
			StartPct: acc, EndPct: acc + pct,
			Color: pieColors[colorIdx%len(pieColors)],
		})
		acc += pct
	}
	for i, b := range shown {
		addSlice(b.Name, b.TotalSessions(), i)
	}
	if others > 0 {
		addSlice("Lainnya", others, len(pieColors)-1)
	}
	// Floating-point rounding can leave the last slice a hair short of
	// 100%; stretch it so the gradient has no unpainted sliver at the seam.
	if len(slices) > 0 && slices[len(slices)-1].EndPct < 100 {
		slices[len(slices)-1].EndPct = 100
	}
	return slices
}

// ConnectionsByServer returns one bar per server in this backend, comparing
// how connections are distributed within the group ("per kelompok").
func (b Backend) ConnectionsByServer() []ChartBar {
	bars := make([]ChartBar, len(b.Servers))
	max := 0
	for i, srv := range b.Servers {
		bars[i] = ChartBar{Name: srv.Name, Sessions: srv.Sessions}
		if bars[i].Sessions > max {
			max = bars[i].Sessions
		}
	}
	fillPercents(bars, max)
	return bars
}

func fillPercents(bars []ChartBar, max int) {
	for i := range bars {
		if max <= 0 {
			bars[i].Percent = 0
			continue
		}
		bars[i].Percent = bars[i].Sessions * 100 / max
	}
}

// Backend looks up one backend by name.
func (s Snapshot) Backend(name string) (Backend, bool) {
	for _, b := range s.Backends {
		if b.Name == name {
			return b, true
		}
	}
	return Backend{}, false
}
