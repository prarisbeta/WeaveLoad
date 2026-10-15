package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var apiLogNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.Local)

// logLine renders one httplog line accepted ago before apiLogNow.
func logLine(ip string, ago time.Duration, backend string, status int, path string) string {
	t := apiLogNow.Add(-ago)
	return fmt.Sprintf(`%s h haproxy[1]: %s:1234 [%s] http_in %s/node1 0/0/0/5/5 %d 100 - - ---- 1/1/0/0/0 0/0 "GET %s HTTP/1.1"`,
		t.Format("Jan _2 15:04:05"), ip, t.Format("02/Jan/2006:15:04:05.000"), backend, status, path)
}

func writeAPILog(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "haproxy.log")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func getJSON(t *testing.T, h http.Handler, target string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	var resp struct {
		Success bool           `json:"success"`
		Data    map[string]any `json:"data"`
		Error   string         `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if rec.Code == http.StatusOK && !resp.Success {
		t.Fatalf("200 without success: %+v", resp)
	}
	return rec.Code, resp.Data
}

func TestAPIV1TrafficHandler_SummarisesTheAccessLog(t *testing.T) {
	path := writeAPILog(t,
		logLine("10.0.0.1", 50*time.Second, "oms", 200, "/a"),
		logLine("10.0.0.1", 40*time.Second, "oms", 200, "/a"),
		logLine("10.0.0.2", 30*time.Second, "oms", 502, "/b"),
		logLine("10.0.0.3", 20*time.Second, "oms", 200, "/a"),
	)
	code, data := getJSON(t, &APIV1TrafficHandler{LogPath: path}, "/api/v1/traffic")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if data["total_requests"] != float64(4) || data["errors_5xx"] != float64(1) {
		t.Errorf("data = %v, want 4 requests and 1 5xx", data)
	}
	if r, _ := data["error_ratio"].(float64); r != 0.25 {
		t.Errorf("error_ratio = %v, want 0.25", data["error_ratio"])
	}
	top, _ := data["top_sources"].([]any)
	if len(top) == 0 || top[0].(map[string]any)["name"] != "10.0.0.1" || top[0].(map[string]any)["count"] != float64(2) {
		t.Errorf("top_sources = %v, want 10.0.0.1 first with 2", data["top_sources"])
	}
	for _, k := range []string{"top_paths", "top_hosts", "slowest_backends"} {
		if _, ok := data[k].([]any); !ok {
			t.Errorf("%s must be a JSON array, got %T", k, data[k])
		}
	}
}

func TestAPIV1TrafficHandler_RejectsBadLinesAndMissingLog(t *testing.T) {
	path := writeAPILog(t, logLine("10.0.0.1", time.Second, "oms", 200, "/"))
	for _, q := range []string{"?lines=abc", "?lines=0", "?lines=-5"} {
		rec := httptest.NewRecorder()
		(&APIV1TrafficHandler{LogPath: path}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/traffic"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code = %d, want 400", q, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	(&APIV1TrafficHandler{LogPath: filepath.Join(t.TempDir(), "nope.log")}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/traffic", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("missing log: code = %d, want 503", rec.Code)
	}
}

func TestAPIV1WaitingRoomHandler_CountsHeldVisitors(t *testing.T) {
	path := writeAPILog(t,
		logLine("1.1.1.1", 60*time.Second, "oms", 429, "/"),
		logLine("1.1.1.1", 10*time.Second, "oms", 429, "/"),
		logLine("2.2.2.2", 50*time.Second, "oms", 429, "/"),
		logLine("2.2.2.2", 15*time.Second, "oms", 200, "/"),
		logLine("3.3.3.3", 8*time.Minute, "portal", 429, "/"),
		logLine("4.4.4.4", 5*time.Second, "oms", 200, "/"),
	)
	h := &APIV1WaitingRoomHandler{LogPath: path, Now: func() time.Time { return apiLogNow }}
	code, data := getJSON(t, h, "/api/v1/waiting-room")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if data["waiting"] != float64(1) || data["admitted"] != float64(1) || data["abandoned"] != float64(1) {
		t.Errorf("data = %v, want waiting 1, admitted 1, abandoned 1", data)
	}
	if data["window_seconds"] != float64(600) {
		t.Errorf("window_seconds = %v, want the 10 minute default", data["window_seconds"])
	}

	// A one minute window drops the 8-minute-old rejection of 3.3.3.3.
	_, data = getJSON(t, h, "/api/v1/waiting-room?minutes=1")
	if data["abandoned"] != float64(0) {
		t.Errorf("minutes=1: abandoned = %v, want 0", data["abandoned"])
	}
}

func TestAPIV1WaitingRoomHandler_ClampsAndValidatesMinutes(t *testing.T) {
	path := writeAPILog(t, logLine("1.1.1.1", time.Second, "oms", 429, "/"))
	h := &APIV1WaitingRoomHandler{LogPath: path, Now: func() time.Time { return apiLogNow }}

	_, data := getJSON(t, h, "/api/v1/waiting-room?minutes=9999")
	if data["window_seconds"] != float64(3600) {
		t.Errorf("window_seconds = %v, want it capped at 3600", data["window_seconds"])
	}
	for _, q := range []string{"?minutes=x", "?minutes=0"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/waiting-room"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code = %d, want 400", q, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	(&APIV1WaitingRoomHandler{LogPath: filepath.Join(t.TempDir(), "nope.log")}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/waiting-room", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("missing log: code = %d, want 503", rec.Code)
	}
}

func TestAPIV1SessionsHandler_SumsSessionsPerNodeBusiestFirst(t *testing.T) {
	// 10.0.0.1 serves web/node01 (3 sessions) and api/a1 (2); 10.0.0.2 serves web/node02 (0).
	h := &APIV1SessionsHandler{Config: &fakeConfigStore{active: poolCfg}, Stats: fakeStats{body: poolStats}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rec.Code, rec.Body)
	}
	var resp struct {
		Data []struct {
			Host     string `json:"host"`
			Sessions int    `json:"active_sessions"`
			Servers  []struct {
				Pool     string `json:"pool"`
				Server   string `json:"server"`
				Sessions int    `json:"active_sessions"`
			} `json:"servers"`
		} `json:"data"`
		Meta map[string]any `json:"meta"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 2 || resp.Data[0].Host != "10.0.0.1" || resp.Data[0].Sessions != 5 {
		t.Fatalf("data = %+v, want 10.0.0.1 first with 5 sessions", resp.Data)
	}
	if len(resp.Data[0].Servers) != 2 || resp.Data[0].Servers[0].Pool != "web" || resp.Data[0].Servers[0].Sessions != 3 {
		t.Errorf("servers = %+v, want web/node01 (3) before api/a1 (2)", resp.Data[0].Servers)
	}
	if resp.Meta["total_active_sessions"] != float64(5) || resp.Meta["nodes"] != float64(2) {
		t.Errorf("meta = %v, want 2 nodes and 5 total sessions", resp.Meta)
	}
}

func TestAPIV1SessionsHandler_ReportsUnavailableStats(t *testing.T) {
	h := &APIV1SessionsHandler{Config: &fakeConfigStore{active: poolCfg}, Stats: nil}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503 when live stats are missing", rec.Code)
	}
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}
