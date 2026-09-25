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
