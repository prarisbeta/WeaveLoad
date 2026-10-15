package anomaly

import (
	"testing"
	"time"

	"haproxy-gui/internal/haproxylog"
)

// Monday 2026-10-05 09:00 local; every "week" below is the same slot a week later.
var mondayNine = time.Date(2026, 10, 5, 9, 0, 0, 0, time.Local)

func bucketLines(backend string, at time.Time, n int, trMs int) []haproxylog.Line {
	out := make([]haproxylog.Line, n)
	for i := range out {
		out[i] = haproxylog.Line{Backend: backend, Time: at.Add(time.Duration(i%250) * time.Second), StatusCode: 200, Tr: trMs}
	}
	return out
}

func testConfig() Config {
	c := DefaultConfig()
	c.MinSamples = 6
	c.MinRequests = 100
	return c
}

// learn feeds `weeks` same-slot buckets of about `req` requests (+/- 5%).
func learn(t *testing.T, tr *Tracker, backend string, weeks, req, trMs int) time.Time {
	t.Helper()
	var at time.Time
	for w := 0; w < weeks; w++ {
		at = mondayNine.AddDate(0, 0, 7*w)
		n := req + (w%3-1)*req/20
		tr.Ingest(bucketLines(backend, at, n, trMs), at.Add(BucketSize))
	}
	return at
}

func TestSlot(t *testing.T) {
	if got := Slot(mondayNine); got != 9 {
		t.Errorf("Monday 09:00 = slot %d, want 9", got)
	}
	if got := Slot(time.Date(2026, 10, 11, 23, 30, 0, 0, time.Local)); got != 6*24+23 { // Sunday
		t.Errorf("Sunday 23:30 = slot %d", got)
	}
}

func TestSpikeAfterWarmup(t *testing.T) {
	tr := NewTracker(testConfig(), nil)
	last := learn(t, tr, "web", 10, 1000, 40)

	next := last.AddDate(0, 0, 7)
	got := tr.Ingest(bucketLines("web", next, 6000, 40), next.Add(BucketSize))
	if len(got) != 1 || got[0].Metric != MetricRequests || got[0].Direction != "spike" {
		t.Fatalf("got %+v, want one request spike", got)
	}
	if got[0].Observed != 6000 || got[0].Expected < 900 || got[0].Expected > 1100 {
		t.Errorf("observed/expected = %v/%v", got[0].Observed, got[0].Expected)
	}
}

func TestDropIsHigh(t *testing.T) {
	tr := NewTracker(testConfig(), nil)
	last := learn(t, tr, "web", 10, 1000, 40)
	next := last.AddDate(0, 0, 7)
	got := tr.Ingest(bucketLines("web", next, 50, 40), next.Add(BucketSize))
	if len(got) != 1 || got[0].Direction != "drop" || got[0].Severity != "high" {
		t.Fatalf("got %+v, want a high drop", got)
	}
}

func TestLatencySpike(t *testing.T) {
	tr := NewTracker(testConfig(), nil)
	last := learn(t, tr, "web", 10, 1000, 50)
	next := last.AddDate(0, 0, 7)
	got := tr.Ingest(bucketLines("web", next, 1000, 900), next.Add(BucketSize))
	if len(got) != 1 || got[0].Metric != MetricLatency || got[0].Direction != "spike" {
		t.Fatalf("got %+v, want a latency spike", got)
	}
}

func TestNormalVariationAndColdStartStaySilent(t *testing.T) {
	tr := NewTracker(testConfig(), nil)
	// Still learning: even a huge bucket must not alert.
	cold := mondayNine
	if got := tr.Ingest(bucketLines("web", cold, 9000, 40), cold.Add(BucketSize)); len(got) != 0 {
		t.Errorf("cold start alerted: %+v", got)
	}
	last := learn(t, tr, "api", 10, 1000, 40)
	next := last.AddDate(0, 0, 7)
	if got := tr.Ingest(bucketLines("api", next, 1100, 45), next.Add(BucketSize)); len(got) != 0 {
		t.Errorf("a 10%% wobble alerted: %+v", got)
	}
}

func TestDifferentHoursHaveDifferentNormals(t *testing.T) {
	tr := NewTracker(testConfig(), nil)
	learn(t, tr, "web", 10, 1000, 40) // Monday 09:00 busy
	// The same traffic volume is normal at 09:00 but a spike at 03:00, where the backend is quiet.
	for w := 0; w < 10; w++ {
		at := mondayNine.Add(-6*time.Hour).AddDate(0, 0, 7*w)
		tr.Ingest(bucketLines("web", at, 150, 40), at.Add(BucketSize))
	}
	night := mondayNine.Add(-6*time.Hour).AddDate(0, 0, 70)
	got := tr.Ingest(bucketLines("web", night, 1000, 40), night.Add(BucketSize))
	if len(got) != 1 || got[0].Direction != "spike" {
		t.Errorf("1000 requests at 03:00 should be a spike against a 150 baseline: %+v", got)
	}
}

func TestOutlierDoesNotPoisonTheBaseline(t *testing.T) {
	tr := NewTracker(testConfig(), nil)
	last := learn(t, tr, "web", 10, 1000, 40)
	next := last.AddDate(0, 0, 7)
	tr.Ingest(bucketLines("web", next, 20000, 40), next.Add(BucketSize))

	st := tr.stats[Key{"web", MetricRequests, Slot(next)}]
	if st.Mean > 2000 {
		t.Errorf("baseline mean jumped to %.0f after one attack bucket", st.Mean)
	}
	again := next.AddDate(0, 0, 7)
	if got := tr.Ingest(bucketLines("web", again, 20000, 40), again.Add(BucketSize)); len(got) != 1 {
		t.Errorf("the same attack a week later must still alert: %+v", got)
	}
}

func TestOpenBucketIsNotJudgedYet(t *testing.T) {
	tr := NewTracker(testConfig(), nil)
	last := learn(t, tr, "web", 10, 1000, 40)
	next := last.AddDate(0, 0, 7)
	if got := tr.Ingest(bucketLines("web", next, 6000, 40), next.Add(time.Minute)); len(got) != 0 {
		t.Errorf("a bucket still open was judged: %+v", got)
	}
	if got := tr.Ingest(nil, next.Add(BucketSize)); len(got) != 1 {
		t.Errorf("the closed bucket must be judged on the next call: %+v", got)
	}
}

func TestBucketRunningAtStartupIsNotJudged(t *testing.T) {
	ms := &memStore{m: map[Key]Stat{}}
	last := learn(t, NewTracker(testConfig(), ms), "web", 10, 1000, 40)

	// A restart in the middle of a bucket: only its tail is seen, which would
	// look like a collapse from 1000 to 40 requests.
	restarted := NewTracker(testConfig(), ms)
	next := last.AddDate(0, 0, 7)
	if got := restarted.Ingest(bucketLines("web", next.Add(4*time.Minute), 40, 40), next.Add(4*time.Minute+30*time.Second)); len(got) != 0 {
		t.Fatalf("early call: %+v", got)
	}
	if got := restarted.Ingest(nil, next.Add(BucketSize)); len(got) != 0 {
		t.Errorf("the partial first bucket produced a false drop: %+v", got)
	}
	before := ms.m[Key{"web", MetricRequests, Slot(next)}].N
	if before != 10 {
		t.Errorf("the partial bucket was learned (n=%d, want 10)", before)
	}
}

func TestIgnoresUnusableLines(t *testing.T) {
	tr := NewTracker(testConfig(), nil)
	lines := []haproxylog.Line{
		{Backend: "", Time: mondayNine, StatusCode: 200},
		{Backend: "web", StatusCode: 200},
		{Backend: "web", Time: mondayNine, StatusCode: 0},
	}
	tr.Ingest(lines, mondayNine.Add(time.Hour))
	if len(tr.stats) != 0 {
		t.Errorf("unusable lines produced baselines: %+v", tr.stats)
	}
}

type memStore struct{ m map[Key]Stat }

func (s *memStore) LoadBaselines() (map[Key]Stat, error) { return s.m, nil }
func (s *memStore) SaveBaseline(k Key, st Stat) error    { s.m[k] = st; return nil }

func TestBaselinesSurviveARestart(t *testing.T) {
	ms := &memStore{m: map[Key]Stat{}}
	first := NewTracker(testConfig(), ms)
	last := learn(t, first, "web", 10, 1000, 40)

	second := NewTracker(testConfig(), ms) // a new process, same storage
	next := last.AddDate(0, 0, 7)
	if got := second.Ingest(bucketLines("web", next, 6000, 40), next.Add(BucketSize)); len(got) != 1 {
		t.Errorf("a restarted tracker lost its baseline: %+v", got)
	}
}

func TestFingerprintIsStablePerBucket(t *testing.T) {
	a := Anomaly{Backend: "web", Metric: MetricRequests, Bucket: mondayNine}
	b := a
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("fingerprint is not deterministic")
	}
	b.Metric = MetricLatency
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("different metrics must not share a fingerprint")
	}
}
