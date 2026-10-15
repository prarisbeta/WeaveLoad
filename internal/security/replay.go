package security

import (
	"sort"
	"time"

	"haproxy-gui/internal/haproxylog"
)

// Replay feeds historical log lines through a fresh Engine, one simulated
// minute at a time, and returns every Detection it would have raised. It
// touches no store and no network, so it is safe to run against production
// logs to answer "what would the detectors and the policy have done?".
// Lines without a timestamp are skipped.
func Replay(lines []haproxylog.Line, thr Thresholds) []Detection {
	timed := make([]haproxylog.Line, 0, len(lines))
	for _, l := range lines {
		if !l.Time.IsZero() {
			timed = append(timed, l)
		}
	}
	sort.SliceStable(timed, func(i, j int) bool { return timed[i].Time.Before(timed[j].Time) })

	e := NewEngine(thr)
	var out []Detection
	for i := 0; i < len(timed); {
		minute := timed[i].Time.Truncate(time.Minute)
		j := i
		for j < len(timed) && timed[j].Time.Truncate(time.Minute).Equal(minute) {
			j++
		}
		out = append(out, e.Ingest(timed[i:j], minute.Add(59*time.Second))...)
		i = j
	}
	return out
}
