// Package haproxylog reads and filters the HAProxy traffic log written by
// rsyslog (HAProxy itself only ever emits to syslog — see the "log"
// directive in haproxy.cfg's global section). It never writes to the log,
// only reads it, line by line, newest-first.
package haproxylog

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Line is one parsed log entry. Time and StatusCode are zero when the line
// doesn't match HAProxy's httplog format (startup/admin messages, for
// instance), but Raw always holds the full original line.
type Line struct {
	Raw        string
	Time       time.Time
	StatusCode int
}

// Filter narrows Read's results. A zero Date means no date filtering; an
// empty Keyword means no text filtering.
type Filter struct {
	Date    time.Time
	Keyword string
	Limit   int
}

// DefaultLimit caps how many matching lines Read returns, so a busy log
// file can't make one page load pull megabytes into memory.
const DefaultLimit = 500

// acceptDateRE matches HAProxy's own bracketed accept-date field, e.g.
// "[25/Sep/2026:16:20:15.123]" — more reliable for filtering than the
// syslog-added prefix, which some rsyslog configs emit without a year.
var acceptDateRE = regexp.MustCompile(`\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})`)

var month = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March, "Apr": time.April,
	"May": time.May, "Jun": time.June, "Jul": time.July, "Aug": time.August,
	"Sep": time.September, "Oct": time.October, "Nov": time.November, "Dec": time.December,
}

// statusRE matches the HTTP status code field in HAProxy's httplog format
// ("... status_code bytes_read ..."), which always follows the timers.
var statusRE = regexp.MustCompile(`\s(\d{3})\s\d+\s`)

func parseLine(raw string) Line {
	l := Line{Raw: raw}
	if m := acceptDateRE.FindStringSubmatch(raw); m != nil {
		day, _ := strconv.Atoi(m[1])
		mon, ok := month[m[2]]
		year, _ := strconv.Atoi(m[3])
		hour, _ := strconv.Atoi(m[4])
		min, _ := strconv.Atoi(m[5])
		sec, _ := strconv.Atoi(m[6])
		if ok {
			l.Time = time.Date(year, mon, day, hour, min, sec, 0, time.Local)
		}
	}
	if m := statusRE.FindStringSubmatch(raw); m != nil {
		l.StatusCode, _ = strconv.Atoi(m[1])
	}
	return l
}

// Read scans path and returns up to filter.Limit matching lines, most
// recent first. It always reads the whole file sequentially (no reverse
// seeking), so it's best suited to a single day's active log rather than a
// large multi-year archive — the UI only ever asks for one day at a time.
func Read(path string, filter Filter) ([]Line, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	limit := filter.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	keyword := strings.ToLower(strings.TrimSpace(filter.Keyword))
	wantDate := !filter.Date.IsZero()

	window := make([]Line, 0, limit)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		raw := sc.Text()
		if keyword != "" && !strings.Contains(strings.ToLower(raw), keyword) {
			continue
		}
		l := parseLine(raw)
		if wantDate && (l.Time.IsZero() || !sameDay(l.Time, filter.Date)) {
			continue
		}
		window = append(window, l)
		if len(window) > limit {
			window = window[1:]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	reverse(window)
	return window, nil
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

func reverse(lines []Line) {
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
}
