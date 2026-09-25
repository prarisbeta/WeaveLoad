// Package stats parses the CSV body of HAProxy's Runtime API "show stat"
// command into a structured tree: frontends, backends and their servers.
package stats

import (
	"encoding/csv"
	"fmt"
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

// Backend looks up one backend by name.
func (s Snapshot) Backend(name string) (Backend, bool) {
	for _, b := range s.Backends {
		if b.Name == name {
			return b, true
		}
	}
	return Backend{}, false
}
