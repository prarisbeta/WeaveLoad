package web

import (
	"html/template"
	"net/http"
	"sort"
	"time"

	"haproxy-gui/internal/store"
)

// ReportStore is what the weekly report reads.
type ReportStore interface {
	ListSecurityEvents(store.SecurityFilter) ([]store.SecurityEvent, int, error)
	ListTopRisk(n int) ([]store.IPRisk, error)
	ListIncidents(store.IncidentFilter) ([]store.Incident, int, error)
	ListPolicyActions(status string, limit int) ([]store.PolicyAction, error)
}

// WeeklyReportHandler renders GET /reports/weekly: a printable summary of
// the last seven days (browser "print to PDF" produces the PDF).
type WeeklyReportHandler struct {
	Store     ReportStore
	Templates *template.Template
	// Now defaults to time.Now; overridable for tests.
	Now func() time.Time
}

// ReportCount is a labelled tally.
type ReportCount struct {
	Label string
	Count int
}

// WeeklyReport is the data behind the page.
type WeeklyReport struct {
	From, To      time.Time
	Events        int
	ByRule        []ReportCount
	BySeverity    []ReportCount
	MITRE         []ReportCount
	TopIPs        []store.IPRisk
	PolicyByState []ReportCount
	PolicyTotal   int
	Resolved      int
	MTTR          time.Duration // mean time from creation to resolution
	StillOpen     int
}

const reportEventCap = 5000

func (h *WeeklyReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	rep, err := BuildWeeklyReport(h.Store, now)
	if err != nil {
		http.Error(w, "failed to build the report: "+err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, h.Templates, "report_weekly.html", struct {
		Chrome
		Report WeeklyReport
	}{Chrome: NewChrome(r, "security"), Report: rep})
}

// BuildWeeklyReport aggregates the seven days ending at now.
func BuildWeeklyReport(s ReportStore, now time.Time) (WeeklyReport, error) {
	rep := WeeklyReport{From: now.AddDate(0, 0, -7), To: now}

	events, total, err := s.ListSecurityEvents(store.SecurityFilter{Since: rep.From, Limit: reportEventCap})
	if err != nil {
		return rep, err
	}
	rep.Events = total
	byRule, bySev, mitre := map[string]int{}, map[string]int{}, map[string]int{}
	for _, e := range events {
		byRule[e.Rule]++
		bySev[e.Severity]++
		if ts, ok := e.Evidence["mitre"].([]any); ok {
			for _, t := range ts {
				if id, ok := t.(string); ok {
					mitre[id]++
				}
			}
		}
	}
	rep.ByRule, rep.BySeverity, rep.MITRE = ranked(byRule), ranked(bySev), ranked(mitre)

	if rep.TopIPs, err = s.ListTopRisk(10); err != nil {
		return rep, err
	}

	actions, err := s.ListPolicyActions("", 1000)
	if err != nil {
		return rep, err
	}
	byState := map[string]int{}
	for _, a := range actions {
		if a.CreatedAt.Before(rep.From) {
			continue
		}
		byState[a.Status]++
		rep.PolicyTotal++
	}
	rep.PolicyByState = ranked(byState)

	incidents, _, err := s.ListIncidents(store.IncidentFilter{Limit: 500})
	if err != nil {
		return rep, err
	}
	var sum time.Duration
	for _, inc := range incidents {
		if inc.ResolvedAt == nil {
			if inc.Status != "false_positive" {
				rep.StillOpen++
			}
			continue
		}
		if inc.ResolvedAt.Before(rep.From) {
			continue
		}
		rep.Resolved++
		sum += inc.ResolvedAt.Sub(inc.CreatedAt)
	}
	if rep.Resolved > 0 {
		rep.MTTR = sum / time.Duration(rep.Resolved)
	}
	return rep, nil
}

func ranked(m map[string]int) []ReportCount {
	out := make([]ReportCount, 0, len(m))
	for k, v := range m {
		out = append(out, ReportCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Label < out[j].Label
	})
	return out
}
