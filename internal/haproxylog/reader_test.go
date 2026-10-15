package haproxylog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "haproxy.log")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

const fixture = `Sep 24 10:00:00 haproxy-cni haproxy[100]: 10.0.0.1:1111 [24/Sep/2026:10:00:00.000] http_in http_oms/node1 0/0/0/1/1 200 612 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Sep 25 09:00:00 haproxy-cni haproxy[100]: 10.0.0.2:2222 [25/Sep/2026:09:00:00.000] http_in http_oms/node1 0/0/0/1/1 404 200 - - ---- 1/1/0/0/0 0/0 "GET /missing HTTP/1.1"
Sep 25 09:05:00 haproxy-cni haproxy[100]: 10.0.0.3:3333 [25/Sep/2026:09:05:00.000] http_in http_oms/node2 0/0/0/2/2 500 100 - - ---- 1/1/0/0/0 0/0 "GET /err HTTP/1.1"
Sep 25 16:20:15 haproxy-cni haproxy[4922]: haproxy-gui listening on 127.0.0.1:9900
`

func TestRead_FiltersByDate(t *testing.T) {
	path := writeFixture(t, fixture)
	lines, err := Read(path, Filter{Date: time.Date(2026, time.September, 25, 0, 0, 0, 0, time.Local)})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2 (only Sep 25 http entries)", len(lines))
	}
	if lines[0].StatusCode != 500 || lines[1].StatusCode != 404 {
		t.Errorf("expected newest first (500 then 404), got %d then %d", lines[0].StatusCode, lines[1].StatusCode)
	}
}

func TestRead_NoDateFilterReturnsEverythingNewestFirst(t *testing.T) {
	path := writeFixture(t, fixture)
	lines, err := Read(path, Filter{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(lines) != 4 {
		t.Fatalf("lines = %d, want 4", len(lines))
	}
	if !contains(lines[0].Raw, "haproxy-gui listening") {
		t.Errorf("expected the last line in the file to come first, got %q", lines[0].Raw)
	}
}

func TestRead_KeywordFilter(t *testing.T) {
	path := writeFixture(t, fixture)
	lines, err := Read(path, Filter{Keyword: "node2"})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(lines) != 1 || lines[0].StatusCode != 500 {
		t.Errorf("lines = %+v, want exactly the node2 500 entry", lines)
	}
}

func TestRead_KeywordIsCaseInsensitive(t *testing.T) {
	path := writeFixture(t, fixture)
	lines, err := Read(path, Filter{Keyword: "NODE2"})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(lines) != 1 {
		t.Errorf("lines = %d, want 1", len(lines))
	}
}

func TestRead_LimitCapsResults(t *testing.T) {
	path := writeFixture(t, fixture)
	lines, err := Read(path, Filter{Limit: 2})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	if !contains(lines[0].Raw, "haproxy-gui listening") {
		t.Errorf("expected the newest lines to survive the cap, got %+v", lines)
	}
}

func TestRead_UnparseableLineHasZeroTimeAndStatus(t *testing.T) {
	path := writeFixture(t, "Sep 25 16:20:15 haproxy-cni haproxy[4922]: haproxy-gui listening on 127.0.0.1:9900\n")
	lines, err := Read(path, Filter{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(lines) != 1 || !lines[0].Time.IsZero() || lines[0].StatusCode != 0 {
		t.Errorf("lines = %+v, want one line with zero Time/StatusCode", lines)
	}
}

func TestParseLine_FullHTTPLogLine(t *testing.T) {
	raw := `Sep 26 08:21:10 haproxy-programmer haproxy[28813]: ::ffff:3.111.138.44:39516 [26/Sep/2026:08:21:10.602] https_in~ https_oms/node02 0/0/3/13/16 200 1045 - - --NI 3/2/0/0/0 0/0 {oms.cni.net.id} "HEAD / HTTP/1.1"`
	l := parseLine(raw)
	if l.ClientIP != "::ffff:3.111.138.44" {
		t.Errorf("ClientIP = %q", l.ClientIP)
	}
	if l.Frontend != "https_in~" {
		t.Errorf("Frontend = %q", l.Frontend)
	}
	if l.Backend != "https_oms" || l.Server != "node02" {
		t.Errorf("Backend/Server = %q/%q", l.Backend, l.Server)
	}
	if l.Tq != 0 || l.Tw != 0 || l.Tc != 3 || l.Tr != 13 || l.Tt != 16 {
		t.Errorf("timers = %d/%d/%d/%d/%d", l.Tq, l.Tw, l.Tc, l.Tr, l.Tt)
	}
	if l.StatusCode != 200 {
		t.Errorf("StatusCode = %d", l.StatusCode)
	}
	if l.Termination != "--NI" {
		t.Errorf("Termination = %q", l.Termination)
	}
	if l.Method != "HEAD" || l.Path != "/" {
		t.Errorf("Method/Path = %q/%q", l.Method, l.Path)
	}
}

func TestParseLine_NoCapturedHeaderBlock(t *testing.T) {
	raw := `Sep 26 08:21:11 haproxy-programmer haproxy[28813]: ::ffff:103.31.159.16:55768 [26/Sep/2026:08:21:10.939] https_gui_in~ haproxy_gui/local 0/0/0/338/513 200 267689 - - ---- 2/1/0/0/0 0/0 "GET https://103.31.159.8:9443/logs HTTP/2.0"`
	l := parseLine(raw)
	if l.Backend != "haproxy_gui" || l.Server != "local" {
		t.Errorf("Backend/Server = %q/%q", l.Backend, l.Server)
	}
	if l.Method != "GET" || l.Path != "/logs" {
		t.Errorf("Method/Path = %q/%q, want GET /logs (absolute-form target reduced to path)", l.Method, l.Path)
	}
}

func TestParseLine_QueryStringStripped(t *testing.T) {
	raw := `Sep 26 08:21:12 haproxy-programmer haproxy[28813]: 10.0.0.9:1234 [26/Sep/2026:08:21:12.000] http_in http_oms/node1 0/0/0/1/1 200 100 - - ---- 1/1/0/0/0 0/0 "GET /search?q=1 HTTP/1.1"`
	l := parseLine(raw)
	if l.Path != "/search" {
		t.Errorf("Path = %q, want query string stripped", l.Path)
	}
}

func TestParseLine_BadRequestLineDoesNotPanic(t *testing.T) {
	raw := `Sep 26 08:21:13 haproxy-programmer haproxy[28813]: 10.0.0.9:1234 [26/Sep/2026:08:21:13.000] http_in http_oms/<NOSRV> -1/-1/-1/-1/0 400 0 - - CR-- 1/1/0/0/0 0/0 "<BADREQ>"`
	l := parseLine(raw) // must not panic; fields may be zero
	_ = l
}

func TestRead_MissingFile_Errors(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "missing.log"), Filter{}); err == nil {
		t.Fatal("expected an error for a missing log file")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}

func TestParseLine_CapturesHostHeader(t *testing.T) {
	raw := `Sep 26 08:21:10 haproxy-programmer haproxy[28813]: ::ffff:3.111.138.44:39516 [26/Sep/2026:08:21:10.602] https_in~ https_oms/node02 0/0/3/13/16 200 1045 - - --NI 3/2/0/0/0 0/0 {oms.cni.net.id|curl/8} "HEAD / HTTP/1.1"`
	l := parseLine(raw)
	if l.Host != "oms.cni.net.id" || l.Method != "HEAD" || l.Path != "/" {
		t.Errorf("Host=%q Method=%q Path=%q", l.Host, l.Method, l.Path)
	}
	if noHost := parseLine(`x haproxy[1]: 10.0.0.1:1 [24/Sep/2026:10:00:00.000] a b/c 0/0/0/1/1 200 1 - - ---- 1/1/0/0/0 0/0 "GET /x HTTP/1.1"`); noHost.Host != "" || noHost.Path != "/x" {
		t.Errorf("no header block: Host=%q Path=%q", noHost.Host, noHost.Path)
	}
}

func TestTailRecent_OldestFirstHTTPLinesOnly(t *testing.T) {
	path := writeFixture(t, fixture)
	lines, err := TailRecent(path, 10)
	if err != nil {
		t.Fatalf("TailRecent: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want the 3 httplog lines (startup message skipped)", len(lines))
	}
	if lines[0].ClientIP != "10.0.0.1" || lines[2].ClientIP != "10.0.0.3" {
		t.Errorf("order = %s ... %s, want oldest first", lines[0].ClientIP, lines[2].ClientIP)
	}
}

func TestTailRecent_LimitKeepsNewest(t *testing.T) {
	path := writeFixture(t, fixture)
	lines, err := TailRecent(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	// The newest 2 raw lines are the 10.0.0.3 request and the startup
	// message; only the former is an httplog line.
	if len(lines) != 1 || lines[0].ClientIP != "10.0.0.3" {
		t.Errorf("lines = %+v", lines)
	}
}

func TestTailRecent_MissingFileIsError(t *testing.T) {
	if _, err := TailRecent(filepath.Join(t.TempDir(), "nope.log"), 5); err == nil {
		t.Error("want error for missing log file")
	}
}
