// Package waitingroom estimates how many visitors are held on the waiting page
// (HTTP 429) from the HAProxy access log. There is no session store behind the
// waiting room: a held visitor is simply a client whose latest request was
// answered 429. The numbers below are therefore counts of distinct client IPs
// as the log records them, not of people.
package waitingroom

import (
	"sort"
	"time"

	"haproxy-gui/internal/haproxylog"
)

// ActiveFor is how recently a client must have been rejected to count as still
// waiting. The waiting page retries every 5 to 40 seconds, so a client silent
// for longer has given up.
const ActiveFor = 90 * time.Second

const maxListed = 10

// Visitor is one client held in the waiting room.
type Visitor struct {
	IP             string `json:"ip"`
	Pool           string `json:"pool,omitempty"`
	Rejections     int    `json:"rejections"`
	WaitingSeconds int    `json:"waiting_seconds"`
}

// Pool is the waiting-room load of one backend.
type Pool struct {
	Name       string `json:"name"`
	Waiting    int    `json:"waiting"`
	Rejections int    `json:"rejections"`
}

// Snapshot is the waiting-room state over the look-back window.
type Snapshot struct {
	WindowSeconds int `json:"window_seconds"`
	// Waiting: rejected within ActiveFor and not let through since.
	Waiting int `json:"waiting"`
	// Admitted: was rejected in the window, then served normally.
	Admitted int `json:"admitted"`
	// Abandoned: was rejected, was never let through and stopped retrying.
	Abandoned          int       `json:"abandoned"`
	Rejections         int       `json:"rejections"`
	LongestWaitSeconds int       `json:"longest_wait_seconds"`
	ByPool             []Pool    `json:"by_pool"`
	LongestWaiting     []Visitor `json:"longest_waiting"`
	Note               string    `json:"note"`
}

type client struct {
	pool       string
	waiting    bool // latest request was a 429
	rejected   bool // was rejected at least once in the window
	streak     time.Time
	last429    time.Time
	rejections int
}

// Compute works out the waiting-room state from access-log lines, in any
// order, looking back window from now.
func Compute(lines []haproxylog.Line, now time.Time, window time.Duration) Snapshot {
	from := now.Add(-window)
	inWindow := make([]haproxylog.Line, 0, len(lines))
	for _, l := range lines {
		if l.ClientIP == "" || l.Time.IsZero() || l.Time.Before(from) || l.Time.After(now.Add(time.Minute)) {
			continue
		}
		inWindow = append(inWindow, l)
	}
	sort.SliceStable(inWindow, func(i, j int) bool { return inWindow[i].Time.Before(inWindow[j].Time) })

	clients := map[string]*client{}
	snap := Snapshot{
		WindowSeconds:  int(window / time.Second),
		ByPool:         []Pool{},
		LongestWaiting: []Visitor{},
		Note:           "Counts are distinct client IPs as logged. Visitors behind one proxy, NAT or CDN address share an IP and count once.",
	}
	for _, l := range inWindow {
		c := clients[l.ClientIP]
		if l.StatusCode == 429 {
			snap.Rejections++
			if c == nil {
				c = &client{}
				clients[l.ClientIP] = c
			}
			if !c.waiting {
				c.streak = l.Time
			}
			c.waiting, c.rejected = true, true
			c.last429 = l.Time
			c.rejections++
			c.pool = l.Backend
			continue
		}
		if c != nil && c.waiting {
			c.waiting = false // served normally after being held
		}
	}

	pools := map[string]*Pool{}
	var waiting []Visitor
	for ip, c := range clients {
		p := pools[c.pool]
		if p == nil {
			p = &Pool{Name: c.pool}
			pools[c.pool] = p
		}
		p.Rejections += c.rejections
		switch {
		case !c.waiting:
			snap.Admitted++
		case now.Sub(c.last429) <= ActiveFor:
			snap.Waiting++
			p.Waiting++
			wait := int(now.Sub(c.streak) / time.Second)
			if wait < 0 {
				wait = 0
			}
			waiting = append(waiting, Visitor{IP: ip, Pool: c.pool, Rejections: c.rejections, WaitingSeconds: wait})
		default:
			snap.Abandoned++
		}
	}
	for _, p := range pools {
		snap.ByPool = append(snap.ByPool, *p)
	}
	sort.Slice(snap.ByPool, func(i, j int) bool {
		if snap.ByPool[i].Waiting != snap.ByPool[j].Waiting {
			return snap.ByPool[i].Waiting > snap.ByPool[j].Waiting
		}
		return snap.ByPool[i].Name < snap.ByPool[j].Name
	})
	sort.Slice(waiting, func(i, j int) bool {
		if waiting[i].WaitingSeconds != waiting[j].WaitingSeconds {
			return waiting[i].WaitingSeconds > waiting[j].WaitingSeconds
		}
		return waiting[i].IP < waiting[j].IP
	})
	if len(waiting) > 0 {
		snap.LongestWaitSeconds = waiting[0].WaitingSeconds
	}
	if len(waiting) > maxListed {
		waiting = waiting[:maxListed]
	}
	if waiting != nil {
		snap.LongestWaiting = waiting
	}
	return snap
}
