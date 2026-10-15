package traffic

import (
	"testing"
	"time"

	"haproxy-gui/internal/haproxylog"
)

var base = time.Date(2026, 10, 15, 12, 10, 30, 0, time.UTC)

func line(ago time.Duration, backend string, status int, ip, path string, tr int) haproxylog.Line {
	return haproxylog.Line{Time: base.Add(-ago), Backend: backend, StatusCode: status, ClientIP: ip, Path: path, Tr: tr}
}

func TestTimeseriesBucketsAndKeepsEmptyMinutes(t *testing.T) {
	lines := []haproxylog.Line{
		line(10*time.Second, "oms", 200, "1.1.1.1", "/", 10),
		line(20*time.Second, "oms", 502, "1.1.1.1", "/", 30),
		line(25*time.Second, "oms", 404, "2.2.2.2", "/x", 20),
		// nothing during 12:08, then one request at 12:07
		line(3*time.Minute, "oms", 200, "3.3.3.3", "/", 40),
		line(2*time.Hour, "oms", 200, "9.9.9.9", "/", 1), // outside the window
	}
	got := Timeseries(lines, base, 5*time.Minute, time.Minute, "")
	if len(got) != 5 {
		t.Fatalf("got %d buckets, want 5", len(got))
	}
	// last bucket starts at 12:10:00 and holds the 3 recent requests.
	last := got[4]
	if !last.Start.Equal(time.Date(2026, 10, 15, 12, 10, 0, 0, time.UTC)) {
		t.Errorf("last bucket start = %v", last.Start)
	}
	if last.Requests != 3 || last.Errors5xx != 1 || last.Errors4xx != 1 || last.AvgLatencyMs != 20 {
		t.Errorf("last = %+v, want 3 requests, one 5xx, one 4xx, 20ms average", last)
	}
	if got[3].Requests != 0 || got[3].AvgLatencyMs != 0 || got[2].Requests != 0 {
		t.Errorf("12:08 and 12:09 = %+v %+v, want explicit empty buckets", got[2], got[3])
	}
	if got[1].Requests != 1 || got[1].AvgLatencyMs != 40 {
		t.Errorf("12:07 bucket = %+v, want the one 40ms request", got[1])
	}
	total := 0
	for _, b := range got {
		total += b.Requests
	}
	if total != 4 {
		t.Errorf("total = %d, want 4 (the 2-hour-old line is outside the window)", total)
	}
}

func TestTimeseriesBackendFilterAndBadArgs(t *testing.T) {
	lines := []haproxylog.Line{
		line(5*time.Second, "oms", 200, "1.1.1.1", "/", 1),
		line(5*time.Second, "portal", 200, "1.1.1.1", "/", 1),
	}
	got := Timeseries(lines, base, 2*time.Minute, time.Minute, "portal")
	if got[len(got)-1].Requests != 1 {
		t.Errorf("filtered bucket = %+v, want only portal", got[len(got)-1])
	}
	if Timeseries(lines, base, time.Second, time.Minute, "") != nil || Timeseries(lines, base, time.Minute, 0, "") != nil {
		t.Error("an invalid window or step must return nothing")
	}
}

func TestTopErrorsRanksPathsAndIPs(t *testing.T) {
	lines := []haproxylog.Line{
		line(0, "oms", 502, "1.1.1.1", "/api/pay", 0),
		line(0, "oms", 502, "1.1.1.1", "/api/pay", 0),
		line(0, "oms", 502, "2.2.2.2", "/api/pay", 0),
		line(0, "oms", 404, "3.3.3.3", "/old", 0),
		line(0, "oms", 200, "4.4.4.4", "/ok", 0),
		line(0, "oms", 401, "1.1.1.1", "/login", 0),
	}
	paths, ips := TopErrors(lines, "all", 10)
	if len(paths) != 3 || paths[0].Path != "/api/pay" || paths[0].Status != 502 || paths[0].Count != 3 {
		t.Fatalf("paths = %+v, want /api/pay 502 x3 first", paths)
	}
	if paths[0].TopIP != "1.1.1.1" || paths[0].TopIPCount != 2 {
		t.Errorf("top ip = %s x%d, want 1.1.1.1 x2", paths[0].TopIP, paths[0].TopIPCount)
	}
	if len(ips) == 0 || ips[0].IP != "1.1.1.1" || ips[0].Count != 3 {
		t.Errorf("ips = %+v, want 1.1.1.1 with 3 errors first", ips)
	}
	for _, p := range paths {
		if p.Path == "/ok" {
			t.Error("a 200 must never be listed as an error path")
		}
	}
}

func TestTopErrorsClassAndLimit(t *testing.T) {
	lines := []haproxylog.Line{
		line(0, "oms", 502, "1.1.1.1", "/a", 0),
		line(0, "oms", 404, "2.2.2.2", "/b", 0),
		line(0, "oms", 404, "3.3.3.3", "/c", 0),
	}
	p5, _ := TopErrors(lines, "5xx", 10)
	if len(p5) != 1 || p5[0].Status != 502 {
		t.Errorf("5xx = %+v", p5)
	}
	p4, _ := TopErrors(lines, "4xx", 1)
	if len(p4) != 1 {
		t.Errorf("limit not applied: %+v", p4)
	}
	if p, i := TopErrors(nil, "all", 5); len(p) != 0 || len(i) != 0 || p == nil || i == nil {
		t.Error("an empty input must give empty, non-nil slices (JSON arrays)")
	}
}
