package security

import "time"

// bucket holds one minute's worth of counters for a single IP or backend.
type bucket struct {
	minute      int64 // Unix minute this bucket covers
	req         int
	post        int
	s4xx        int
	s404        int
	s5xx        int
	s429        int
	loginFail   int
	paths       map[string]struct{} // capped, see maxPathsPerBucket
	patternsHit map[string]struct{} // sensitive-pattern hits this bucket
	burst       []time.Time         // request timestamps, for sub-minute bursts
}

// maxPathsPerBucket bounds memory use for a single IP hammering many random
// paths; once hit, unique-path counting for that bucket saturates rather
// than growing further (the scan rule only needs to know it's "a lot").
const maxPathsPerBucket = 256

func newBucket(minute int64) *bucket {
	return &bucket{minute: minute, paths: map[string]struct{}{}, patternsHit: map[string]struct{}{}}
}

// ipWindow is the rolling state kept for one client IP.
type ipWindow struct {
	buckets    []*bucket // oldest first, capped at ipWindowCapacity
	lastActive time.Time
	ewmaRate   float64 // requests/minute, only meaningful once warm
	firstSeen  time.Time
}

// ipWindowCapacity is how many 1-minute buckets are retained per IP — 60
// covers every window used by the detectors (the longest is 10 minutes).
const ipWindowCapacity = 60

// evictAfter is how long an IP can go idle before its window is dropped.
const evictAfter = time.Hour

// maxTrackedIPs bounds total memory: once exceeded, the oldest-idle IPs are
// swept on the next tick.
const maxTrackedIPs = 50000

func (w *ipWindow) bucketFor(now time.Time) *bucket {
	minute := now.Unix() / 60
	if n := len(w.buckets); n > 0 && w.buckets[n-1].minute == minute {
		return w.buckets[n-1]
	}
	b := newBucket(minute)
	w.buckets = append(w.buckets, b)
	if len(w.buckets) > ipWindowCapacity {
		w.buckets = w.buckets[len(w.buckets)-ipWindowCapacity:]
	}
	return b
}

// since returns the buckets covering [now-d, now].
func (w *ipWindow) since(now time.Time, d time.Duration) []*bucket {
	cutoff := now.Add(-d).Unix() / 60
	i := 0
	for ; i < len(w.buckets); i++ {
		if w.buckets[i].minute >= cutoff {
			break
		}
	}
	return w.buckets[i:]
}

// backendWindow mirrors ipWindow but for a backend name, tracking timers
// and error/timeout counts instead of paths.
type backendWindow struct {
	buckets    []*backendBucket
	lastActive time.Time
}

type backendBucket struct {
	minute   int64
	req      int
	s5xx     int
	timeouts int
	tw       []int // queue-time samples, milliseconds, this minute
}

func newBackendBucket(minute int64) *backendBucket {
	return &backendBucket{minute: minute}
}

func (w *backendWindow) bucketFor(now time.Time) *backendBucket {
	minute := now.Unix() / 60
	if n := len(w.buckets); n > 0 && w.buckets[n-1].minute == minute {
		return w.buckets[n-1]
	}
	b := newBackendBucket(minute)
	w.buckets = append(w.buckets, b)
	cap := int(BackendWindowCapacityMinutes)
	if len(w.buckets) > cap {
		w.buckets = w.buckets[len(w.buckets)-cap:]
	}
	return b
}

func (w *backendWindow) since(now time.Time, d time.Duration) []*backendBucket {
	cutoff := now.Add(-d).Unix() / 60
	i := 0
	for ; i < len(w.buckets); i++ {
		if w.buckets[i].minute >= cutoff {
			break
		}
	}
	return w.buckets[i:]
}

// BackendWindowCapacityMinutes covers the longest backend window used
// (BackendAbuseBaselineWindow, default 1h) plus headroom.
const BackendWindowCapacityMinutes = 90
