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
// instance), but Raw always holds the full original line. ClientIP, Frontend,
// Backend, Server, Method, Path and the timers are only populated when the
// full httplog regex matches — a line can have a valid Time/StatusCode from
// the looser fallback matchers above while still leaving these zero.
type Line struct {
	Raw        string
	Time       time.Time
	StatusCode int

	ClientIP string
	Frontend string
	Backend  string
	Server   string
	Method   string
	Path     string

	// Timers, in milliseconds, as HAProxy's httplog reports them:
	// Tq/Tw/Tc/Tr/Tt. -1 means "not applicable" per HAProxy's own convention.
	Tq, Tw, Tc, Tr, Tt int
	Termination        string
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

// httplogRE matches a full HAProxy httplog line, e.g.:
//
//	::ffff:3.111.138.44:39516 [26/Sep/2026:08:21:10.602] https_in~ https_oms/node02 0/0/3/13/16 200 1045 - - --NI 3/2/0/0/0 0/0 {oms.cni.net.id} "HEAD / HTTP/1.1"
//
// The client address itself may contain colons (IPv6, or an IPv6-mapped
// IPv4 like "::ffff:3.111.138.44"), so it's matched with a character class
// restricted to hex digits, dots and colons rather than a generic ".+" —
// that lets the match start anywhere in the line (no "^" anchor), skipping
// past whatever syslog prefix (host, timestamp, program[pid]:) precedes the
// httplog fields, since that prefix's letters fall outside the class. The
// captured-header block ("{...}") is optional — internal routes like
// haproxy_gui/local emit none.
var httplogRE = regexp.MustCompile(
	`([0-9a-fA-F.:]+):(\d+)\s+\[[^\]]+\]\s+(\S+)\s+(\S+)/(\S+)\s+` +
		`(-?\d+)/(-?\d+)/(-?\d+)/(-?\d+)/(-?\d+)\s+` +
		`(\d{3})\s+\d+\s+\S+\s+\S+\s+(\S{4})\s+` +
		`\d+/\d+/\d+/\d+/\d+\s+\d+/\d+\s+` +
		`(?:\{[^}]*\}\s+)?"(\S+)(?:\s+(\S+))?[^"]*"`,
)

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
	if m := httplogRE.FindStringSubmatch(raw); m != nil {
		l.ClientIP = m[1]
		l.Frontend = m[3]
		l.Backend = m[4]
		l.Server = m[5]
		l.Tq, _ = strconv.Atoi(m[6])
		l.Tw, _ = strconv.Atoi(m[7])
		l.Tc, _ = strconv.Atoi(m[8])
		l.Tr, _ = strconv.Atoi(m[9])
		l.Tt, _ = strconv.Atoi(m[10])
		l.Termination = m[12]
		l.Method = m[13]
		l.Path = normalizePath(m[14])
	}
	return l
}

// normalizePath reduces a request-line target to just its path, stripping
// the query string and, for absolute-form targets (HTTP/2 sends the full
// "https://host:port/path"), the scheme and authority as well.
func normalizePath(target string) string {
	if i := strings.Index(target, "://"); i >= 0 {
		if j := strings.IndexByte(target[i+3:], '/'); j >= 0 {
			target = target[i+3+j:]
		} else {
			target = "/"
		}
	}
	if i := strings.IndexByte(target, '?'); i >= 0 {
		target = target[:i]
	}
	return target
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
