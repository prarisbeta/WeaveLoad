// Package anomaly learns what normal traffic looks like for each backend at
// each hour of the week, and flags 5-minute windows that deviate sharply: a
// spike, a collapse, or a jump in response time. A flat moving average
// cannot do this, because Monday 09:00 and Sunday 03:00 are different
// "normals"; keeping one baseline per (backend, metric, hour-of-week) can.
package anomaly

import (
	"fmt"
	"math"
	"sort"
	"time"

	"haproxy-gui/internal/haproxylog"
)

// BucketSize is the width of one measurement window.
const BucketSize = 5 * time.Minute

// Metric names a measured quantity.
type Metric string

const (
	MetricRequests Metric = "requests" // requests per bucket
	MetricLatency  Metric = "latency"  // mean response time (Tr, ms) per bucket
)

// Config tunes the detector.
type Config struct {
	// MinSamples is how many buckets a slot must have seen before it can
	// raise anything: before that the baseline is still being learned.
	MinSamples int
	// Alpha is the EWMA weight of a new observation once a slot is warm.
	Alpha float64
	// Z is the z-score a bucket must reach, in either direction.
	Z float64
	// MinRatio additionally requires observed/expected to be at least this
	// (or at most its inverse for a drop), so tiny absolute wobbles on a
	// very steady series do not fire.
	MinRatio float64
	// MinRequests is the floor for the request metric: a quiet backend whose
	// traffic goes from 3 to 12 requests is not an incident.
	MinRequests float64
	// MinLatencySamples is how many timed requests a bucket needs for its
	// mean response time to be trusted.
	MinLatencySamples int
	// MinLatencyMillis is the floor for a latency alert.
	MinLatencyMillis float64
}

// DefaultConfig learns for about two weeks, then alerts at 4 sigma and 3x.
func DefaultConfig() Config {
	return Config{
		MinSamples: 24, Alpha: 0.1, Z: 4, MinRatio: 3,
		MinRequests: 200, MinLatencySamples: 30, MinLatencyMillis: 300,
	}
}

// Stat is the learned baseline for one (backend, metric, slot).
type Stat struct {
	Mean, Var float64
	N         int
}

// Key identifies a baseline.
type Key struct {
	Backend string
	Metric  Metric
	Slot    int // hour of week, 0..167, Monday 00:00 = 0
}

// Persistence stores baselines so learning survives a restart.
type Persistence interface {
	LoadBaselines() (map[Key]Stat, error)
	SaveBaseline(Key, Stat) error
}

// Anomaly is one finding.
type Anomaly struct {
	Backend   string
	Metric    Metric
	Direction string // "spike" or "drop"
	Observed  float64
	Expected  float64
	Z         float64
	Severity  string // "medium" or "high"
	Bucket    time.Time
}

// Fingerprint is stable for one backend, metric and bucket.
func (a Anomaly) Fingerprint() string {
	return fmt.Sprintf("traffic_anomaly|%s|%s|%d", a.Backend, a.Metric, a.Bucket.Unix())
}

type agg struct {
	req     int
	trSum   float64
	trCount int
}

// Tracker accumulates log lines into buckets and judges each bucket once it
// has closed. It is not safe for concurrent use; the security runner drives
// it from one goroutine.
type Tracker struct {
	Cfg   Config
	Store Persistence // optional

	stats   map[Key]Stat
	buckets map[string]map[int64]*agg // backend -> bucket start (unix) -> totals
	loaded  bool
	born    time.Time // first Ingest call; see the partial-bucket rule in Ingest
}

// NewTracker returns a Tracker using cfg, loading saved baselines if p is set.
func NewTracker(cfg Config, p Persistence) *Tracker {
	return &Tracker{Cfg: cfg, Store: p, stats: map[Key]Stat{}, buckets: map[string]map[int64]*agg{}}
}

func (t *Tracker) load() {
	if t.loaded {
		return
	}
	t.loaded = true
	if t.Store == nil {
		return
	}
	if saved, err := t.Store.LoadBaselines(); err == nil {
		for k, v := range saved {
			t.stats[k] = v
		}
	}
}

// Slot is the hour-of-week index for ts (Monday 00:00 is 0).
func Slot(ts time.Time) int {
	wd := (int(ts.Weekday()) + 6) % 7
	return wd*24 + ts.Hour()
}

// Ingest adds lines to their buckets and returns anomalies for every bucket
// that ended at or before now. Lines without a timestamp, backend or parsed
// status are ignored.
func (t *Tracker) Ingest(lines []haproxylog.Line, now time.Time) []Anomaly {
	t.load()
	if t.born.IsZero() {
		t.born = now
	}
	for _, l := range lines {
		if l.Backend == "" || l.Time.IsZero() || l.StatusCode <= 0 {
			continue
		}
		start := l.Time.Truncate(BucketSize).Unix()
		bm := t.buckets[l.Backend]
		if bm == nil {
			bm = map[int64]*agg{}
			t.buckets[l.Backend] = bm
		}
		a := bm[start]
		if a == nil {
			a = &agg{}
			bm[start] = a
		}
		a.req++
		if l.Tr >= 0 {
			a.trSum += float64(l.Tr)
			a.trCount++
		}
	}

	var out []Anomaly
	for backend, bm := range t.buckets {
		var starts []int64
		for s := range bm {
			if time.Unix(s, 0).Add(BucketSize).Before(now) || time.Unix(s, 0).Add(BucketSize).Equal(now) {
				starts = append(starts, s)
			}
		}
		sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
		for _, s := range starts {
			start := time.Unix(s, 0)
			// The bucket that was already running when the tracker started only
			// holds the tail of its traffic; judging it would look like a drop.
			partial := start.Before(t.born) && start.Add(BucketSize).After(t.born)
			if !partial {
				out = append(out, t.judge(backend, start, bm[s])...)
			}
			delete(bm, s)
		}
		if len(bm) == 0 {
			delete(t.buckets, backend)
		}
	}
	return out
}

func (t *Tracker) judge(backend string, start time.Time, a *agg) []Anomaly {
	slot := Slot(start)
	var out []Anomaly

	if an, ok := t.score(Key{backend, MetricRequests, slot}, float64(a.req), start, t.Cfg.MinRequests, true); ok {
		out = append(out, an)
	}
	if a.trCount >= t.Cfg.MinLatencySamples {
		mean := a.trSum / float64(a.trCount)
		if an, ok := t.score(Key{backend, MetricLatency, slot}, mean, start, t.Cfg.MinLatencyMillis, false); ok {
			out = append(out, an)
		}
	}
	return out
}

// score compares x with the baseline for k, then folds x into the baseline.
// A value that raised an anomaly is clamped before it is learned, so one
// attack cannot teach the detector that attacks are normal. dropsToo selects
// whether a collapse (not just a spike) is reported.
func (t *Tracker) score(k Key, x float64, bucket time.Time, floor float64, dropsToo bool) (Anomaly, bool) {
	st := t.stats[k]
	var found Anomaly
	fired := false

	if st.N >= t.Cfg.MinSamples {
		std := math.Sqrt(st.Var)
		// A perfectly steady series has zero variance; a small floor keeps
		// the z-score finite without letting tiny wobbles fire (MinRatio and
		// the absolute floors do that job).
		if min := 0.05 * st.Mean; std < min {
			std = min
		}
		if std < 1 {
			std = 1
		}
		z := (x - st.Mean) / std
		switch {
		case z >= t.Cfg.Z && x >= floor && st.Mean > 0 && x/st.Mean >= t.Cfg.MinRatio:
			sev := "medium"
			if z >= 2*t.Cfg.Z || x/st.Mean >= 10 {
				sev = "high"
			}
			found, fired = Anomaly{Backend: k.Backend, Metric: k.Metric, Direction: "spike", Observed: x, Expected: st.Mean, Z: z, Severity: sev, Bucket: bucket}, true
		case dropsToo && z <= -t.Cfg.Z && st.Mean >= floor && x <= st.Mean/t.Cfg.MinRatio:
			found, fired = Anomaly{Backend: k.Backend, Metric: k.Metric, Direction: "drop", Observed: x, Expected: st.Mean, Z: z, Severity: "high", Bucket: bucket}, true
		}
		if fired {
			// Learn the clamped value, not the outlier itself.
			if x > st.Mean+3*std {
				x = st.Mean + 3*std
			} else if x < st.Mean-3*std {
				x = st.Mean - 3*std
			}
		}
	}

	t.learn(k, st, x)
	return found, fired
}

func (t *Tracker) learn(k Key, st Stat, x float64) {
	st.N++
	a := t.Cfg.Alpha
	if st.N <= 10 {
		a = 1 / float64(st.N) // plain running mean while the slot is young
	}
	delta := x - st.Mean
	st.Mean += a * delta
	st.Var = (1 - a) * (st.Var + a*delta*delta)
	t.stats[k] = st
	if t.Store != nil {
		_ = t.Store.SaveBaseline(k, st)
	}
}
