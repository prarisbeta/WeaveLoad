package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"haproxy-gui/internal/store"
)

func TestAPIV1TrafficSeriesHandler_ReturnsBucketsWithGaps(t *testing.T) {
	path := writeAPILog(t,
		logLine("1.1.1.1", 20*time.Second, "oms", 200, "/"),
		logLine("1.1.1.1", 25*time.Second, "oms", 502, "/"),
		logLine("2.2.2.2", 3*time.Minute, "portal", 200, "/"),
	)
	h := &APIV1TrafficSeriesHandler{LogPath: path, Now: func() time.Time { return apiLogNow }}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/traffic/timeseries?minutes=5", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rec.Code, rec.Body)
	}
	var resp struct {
		Data []struct {
			Requests  int `json:"requests"`
			Errors5xx int `json:"errors_5xx"`
		} `json:"data"`
		Meta map[string]any `json:"meta"`
	}
	decodeBody(t, rec, &resp)
	if len(resp.Data) != 5 || resp.Meta["step_minutes"] != float64(1) {
		t.Fatalf("buckets = %d meta = %v, want 5 one-minute buckets", len(resp.Data), resp.Meta)
	}
	total, errs := 0, 0
	for _, b := range resp.Data {
		total += b.Requests
		errs += b.Errors5xx
	}
	if total != 3 || errs != 1 {
		t.Errorf("total = %d, 5xx = %d, want 3 and 1", total, errs)
	}

	// Backend filter keeps only portal's request.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/traffic/timeseries?minutes=5&backend=portal", nil))
	decodeBody(t, rec, &resp)
	total = 0
	for _, b := range resp.Data {
		total += b.Requests
	}
	if total != 1 {
		t.Errorf("backend=portal total = %d, want 1", total)
	}
}

func TestAPIV1TrafficSeriesHandler_DefaultsClampsAndValidates(t *testing.T) {
	path := writeAPILog(t, logLine("1.1.1.1", time.Second, "oms", 200, "/"))
	h := &APIV1TrafficSeriesHandler{LogPath: path, Now: func() time.Time { return apiLogNow }}

	var resp struct {
		Meta map[string]any `json:"meta"`
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/traffic/timeseries?minutes=99999", nil))
	decodeBody(t, rec, &resp)
	if resp.Meta["minutes"] != float64(360) || resp.Meta["step_minutes"] != float64(5) {
		t.Errorf("meta = %v, want the window capped at 360 minutes with 5-minute slices", resp.Meta)
	}
	for _, q := range []string{"?minutes=x", "?minutes=0", "?step=-1"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/traffic/timeseries"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code = %d, want 400", q, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	(&APIV1TrafficSeriesHandler{LogPath: filepath.Join(t.TempDir(), "nope.log")}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/traffic/timeseries", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("missing log: code = %d, want 503", rec.Code)
	}
}

func TestAPIV1TrafficErrorsHandler_RanksErrorPaths(t *testing.T) {
	path := writeAPILog(t,
		logLine("1.1.1.1", 50*time.Second, "oms", 502, "/api/pay"),
		logLine("1.1.1.1", 40*time.Second, "oms", 502, "/api/pay"),
		logLine("2.2.2.2", 30*time.Second, "oms", 404, "/old"),
		logLine("3.3.3.3", 20*time.Second, "oms", 200, "/ok"),
	)
	var resp struct {
		Data struct {
			Paths []struct {
				Path   string `json:"path"`
				Status int    `json:"status"`
				Count  int    `json:"count"`
				TopIP  string `json:"top_ip"`
			} `json:"paths"`
			IPs []struct {
				IP    string `json:"ip"`
				Count int    `json:"count"`
			} `json:"ips"`
		} `json:"data"`
	}
	h := &APIV1TrafficErrorsHandler{LogPath: path}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/traffic/errors", nil))
	decodeBody(t, rec, &resp)
	if len(resp.Data.Paths) != 2 || resp.Data.Paths[0].Path != "/api/pay" || resp.Data.Paths[0].Count != 2 || resp.Data.Paths[0].TopIP != "1.1.1.1" {
		t.Fatalf("paths = %+v, want /api/pay x2 first (and no 200)", resp.Data.Paths)
	}
	if len(resp.Data.IPs) == 0 || resp.Data.IPs[0].IP != "1.1.1.1" {
		t.Errorf("ips = %+v", resp.Data.IPs)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/traffic/errors?class=4xx", nil))
	decodeBody(t, rec, &resp)
	if len(resp.Data.Paths) != 1 || resp.Data.Paths[0].Status != 404 {
		t.Errorf("class=4xx paths = %+v, want only the 404", resp.Data.Paths)
	}
}

func TestAPIV1TrafficErrorsHandler_Validates(t *testing.T) {
	path := writeAPILog(t, logLine("1.1.1.1", time.Second, "oms", 500, "/"))
	h := &APIV1TrafficErrorsHandler{LogPath: path}
	for _, q := range []string{"?class=oops", "?lines=x", "?limit=0"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/traffic/errors"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code = %d, want 400", q, rec.Code)
		}
	}
}

func TestAPIV1IPProfileHandler_CombinesRiskEventsAndTraffic(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Now()
	if err := st.UpsertIPRisk(store.IPRisk{IP: "203.0.113.9", Score: 72, State: "high_risk", FirstSeen: now, LastSeen: now, Detections24h: 1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.UpsertSecurityEvent(store.SecurityEvent{
		Fingerprint: "fp1", Rule: "brute_force", Severity: "high", SubjectType: "ip", Subject: "203.0.113.9",
		FirstSeen: now, LastSeen: now, Count: 12,
	}); err != nil {
		t.Fatal(err)
	}
	log := writeAPILog(t,
		logLine("203.0.113.9", 30*time.Second, "oms", 401, "/login"),
		logLine("203.0.113.9", 20*time.Second, "oms", 401, "/login"),
		logLine("203.0.113.9", 10*time.Second, "oms", 200, "/home"),
		logLine("198.51.100.1", 10*time.Second, "oms", 200, "/home"),
	)

	h := &APIV1IPProfileHandler{Store: st, LogPath: log}
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/security/ip/{ip}", h)

	var resp struct {
		Data struct {
			IP   string         `json:"ip"`
			Risk map[string]any `json:"risk"`
			// events_total is how many detections exist, events is the first page.
			Events      []map[string]any `json:"events"`
			EventsTotal int              `json:"events_total"`
			Traffic     struct {
				Requests int            `json:"requests"`
				ByStatus map[string]int `json:"by_status"`
				TopPaths []struct {
					Name  string `json:"name"`
					Count int    `json:"count"`
				} `json:"top_paths"`
			} `json:"traffic"`
		} `json:"data"`
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/ip/203.0.113.9", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rec.Code, rec.Body)
	}
	decodeBody(t, rec, &resp)
	d := resp.Data
	if d.IP != "203.0.113.9" || d.Risk["State"] != "high_risk" || d.EventsTotal != 1 || len(d.Events) != 1 {
		t.Errorf("profile = %+v, want the risk and the one brute_force event", d)
	}
	if d.Traffic.Requests != 3 || d.Traffic.ByStatus["4xx"] != 2 || d.Traffic.ByStatus["2xx"] != 1 {
		t.Errorf("traffic = %+v, want 3 requests (2x 4xx, 1x 2xx) for this IP only", d.Traffic)
	}
	if len(d.Traffic.TopPaths) == 0 || d.Traffic.TopPaths[0].Name != "/login" {
		t.Errorf("top paths = %+v, want /login first", d.Traffic.TopPaths)
	}

	// An IP the gateway has never seen still answers, with empty evidence.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/ip/192.0.2.50", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("unknown IP: code = %d, want 200", rec.Code)
	}
}

func TestAPIV1IPProfileHandler_RejectsNonIP(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/security/ip/{ip}", &APIV1IPProfileHandler{Store: st})
	for _, ip := range []string{"not-an-ip", "1.2.3", "1.1.1.1;drop"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/ip/"+ip, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q: code = %d, want 400", ip, rec.Code)
		}
	}
}
