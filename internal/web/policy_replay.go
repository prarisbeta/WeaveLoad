package web

import (
	"net/http"
	"sort"
	"time"

	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/security"
)

// maxReplayLines bounds how much of one day's log a replay loads.
const maxReplayLines = 200000

// PolicyReplayHandler handles GET /api/policy/replay?date=YYYY-MM-DD: it runs
// that day's access log through the detectors in a sandbox and reports which
// IPs the policy would act on right now, with the verdict the current
// configuration would give. Nothing is recorded or executed.
type PolicyReplayHandler struct {
	Engine  PolicyEngine
	LogPath string
}

type replayRow struct {
	IP      string   `json:"ip"`
	Hits    int      `json:"hits"`
	Threats []string `json:"threats"`
	MITRE   []string `json:"mitre"`
	Mode    string   `json:"mode"`
	Allowed bool     `json:"allowed"`
	Reasons []string `json:"reasons,omitempty"`
}

func (h *PolicyReplayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	day := time.Now()
	if v := r.URL.Query().Get("date"); v != "" {
		d, err := time.ParseInLocation("2006-01-02", v, time.Local)
		if err != nil {
			writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "date must be YYYY-MM-DD"})
			return
		}
		day = d
	}
	lines, err := haproxylog.Read(h.LogPath, haproxylog.Filter{Date: day, Limit: maxReplayLines})
	if err != nil {
		writeAPIJSON(w, http.StatusInternalServerError, APIResponse{Error: "cannot read the access log: " + err.Error()})
		return
	}

	dets := security.Replay(lines, security.DefaultThresholds())
	rows := h.wouldBlock(dets)
	writeAPIJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]any{
		"date": day.Format("2006-01-02"), "lines": len(lines), "detections": len(dets), "would_block": rows,
	}})
}

// wouldBlock lists the IPs a critical threat-intel detection targets, with the
// policy's current dry-run verdict for each.
func (h *PolicyReplayHandler) wouldBlock(dets []security.Detection) []replayRow {
	byIP := map[string]*replayRow{}
	for _, d := range dets {
		if d.Rule != security.RuleThreatIntel || d.Severity != security.SeverityCritical || d.SubjectType != security.SubjectIP {
			continue
		}
		row := byIP[d.Subject]
		if row == nil {
			row = &replayRow{IP: d.Subject}
			byIP[d.Subject] = row
		}
		if d.Count > row.Hits {
			row.Hits = d.Count
		}
		row.Threats = toStrings(d.Evidence["threats"])
		row.MITRE = toStrings(d.Evidence["mitre"])
	}
	rows := make([]replayRow, 0, len(byIP))
	for ip, row := range byIP {
		dec := h.Engine.Check(policy.Action{Type: policy.BlockIP, Target: ip})
		row.Mode, row.Allowed, row.Reasons = string(dec.Mode), dec.Allowed, dec.Reasons
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].IP < rows[j].IP })
	return rows
}

func toStrings(v any) []string {
	s, _ := v.([]string)
	return s
}
