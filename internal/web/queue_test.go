package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"haproxy-gui/internal/errorpages"
	"haproxy-gui/internal/store"
)

func fakeRedisServer(t *testing.T, reply func(cmd []string) string) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					cmd, err := readRESPArrayForTest(r)
					if err != nil {
						return
					}
					if _, err := conn.Write([]byte(reply(cmd))); err != nil {
						return
					}
				}
			}()
		}
	}()
	host, port, _ = net.SplitHostPort(ln.Addr().String())
	return host, port
}

func readRESPArrayForTest(r *bufio.Reader) ([]string, error) {
	head, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	head = strings.TrimRight(head, "\r\n")
	if !strings.HasPrefix(head, "*") {
		return nil, io.EOF
	}
	var n int
	for _, c := range head[1:] {
		n = n*10 + int(c-'0')
	}
	var out []string
	for i := 0; i < n; i++ {
		lenLine, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		lenLine = strings.TrimRight(lenLine, "\r\n")
		var l int
		for _, c := range lenLine[1:] {
			l = l*10 + int(c-'0')
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		out = append(out, string(buf[:l]))
	}
	return out, nil
}

func testQueueTemplates(t *testing.T) *template.Template {
	t.Helper()
	return mustParse(t, `
{{define "queue.html"}}QUEUE configured={{.Configured}}{{if .Configured}} total={{.Total}} shown={{.Shown}}{{range .Events}}|{{.Pool}}:{{.Status}}:{{.Raw}}:{{.RawJSON}}{{end}}{{end}}{{end}}
`)
}

func TestQueueHandler_NotConfigured(t *testing.T) {
	h := &QueueHandler{Store: &fakeSettingsStore{}, Templates: testQueueTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/queue", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "configured=false") {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestQueueHandler_ListsNewestFirstAndFallsBackToRawJSON(t *testing.T) {
	validEvent := `{"pool":"oms_cni","status":429}`
	host, port := fakeRedisServer(t, func(cmd []string) string {
		switch cmd[0] {
		case "LLEN":
			return ":2\r\n"
		case "LRANGE":
			return fmt.Sprintf("*2\r\n$%d\r\n%s\r\n$7\r\nnotjson\r\n", len(validEvent), validEvent)
		}
		return "+OK\r\n"
	})
	ss := &fakeSettingsStore{}
	ss.redis.Host = host
	ss.redis.Port = port

	h := &QueueHandler{Store: ss, Templates: testQueueTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/queue", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, body)
	}
	if !strings.Contains(body, "total=2 shown=2") {
		t.Errorf("body = %q, want total=2 shown=2", body)
	}
	notJSONIdx := strings.Index(body, "notjson")
	omsIdx := strings.Index(body, "oms_cni")
	if notJSONIdx == -1 || omsIdx == -1 || notJSONIdx > omsIdx {
		t.Errorf("body = %q, want the newest entry (notjson) rendered before oms_cni", body)
	}
}

type fakeQueueRuntime struct {
	clearedTable string
	clearedKey   string
}

func (f *fakeQueueRuntime) ClearTable(table, key string) error {
	f.clearedTable = table
	f.clearedKey = key
	return nil
}

func TestQueueReleaseIPAction(t *testing.T) {
	rt := &fakeQueueRuntime{}
	audit := &fakeAudit{}
	h := &QueueReleaseIPAction{Runtime: rt, Audit: audit}

	form := url.Values{"pool": {"oms_cni"}, "ip": {"192.168.1.50"}}
	req := httptest.NewRequest(http.MethodPost, "/api/queue/release-ip", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rt.clearedTable != "oms_cni" || rt.clearedKey != "192.168.1.50" {
		t.Errorf("runtime cleared table/key = %s/%s", rt.clearedTable, rt.clearedKey)
	}
}

func TestQueueClearAction(t *testing.T) {
	host, port := fakeRedisServer(t, func(cmd []string) string {
		if cmd[0] == "DEL" {
			return ":1\r\n"
		}
		return "+OK\r\n"
	})
	ss := &fakeSettingsStore{}
	ss.redis.Host = host
	ss.redis.Port = port
	audit := &fakeAudit{}

	h := &QueueClearAction{Store: ss, Audit: audit}
	req := httptest.NewRequest(http.MethodPost, "/api/queue/clear", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestQueueForwardIncidentAction(t *testing.T) {
	incStore := newFakeIncidentStore()
	audit := &fakeAudit{}
	h := &QueueForwardIncidentAction{Store: incStore, Audit: audit}

	form := url.Values{"pool": {"web_pool"}, "ip": {"10.0.0.99"}, "severity": {"high"}}
	req := httptest.NewRequest(http.MethodPost, "/api/queue/forward-incident", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(incStore.incidents) != 1 {
		t.Fatalf("expected 1 incident created, got %d", len(incStore.incidents))
	}
	var created store.Incident
	for _, inc := range incStore.incidents {
		created = inc
	}
	if created.Severity != "high" || !strings.Contains(created.Title, "10.0.0.99") {
		t.Errorf("created incident = %+v", created)
	}
}

func TestQueueWaitingRoomHandler(t *testing.T) {
	mgr := errorpages.NewManager(t.TempDir())
	h := &QueueWaitingRoomHandler{Manager: mgr}

	req := httptest.NewRequest(http.MethodGet, "/queue/waiting-room", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Ruang Tunggu") {
		t.Errorf("body missing waiting room title")
	}
}

func TestQueueConsumeAction_RejectsWhenTokenNotConfigured(t *testing.T) {
	h := &QueueConsumeAction{Store: &fakeSettingsStore{}}
	req := httptest.NewRequest(http.MethodPost, "/api/queue/ratelimit-events/consume", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestQueueConsumeAction_RejectsMissingOrWrongToken(t *testing.T) {
	ss := &fakeSettingsStore{queueToken: "correct-token"}
	h := &QueueConsumeAction{Store: ss}

	cases := []string{"", "Bearer wrong-token", "correct-token"}
	for _, authHeader := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/queue/ratelimit-events/consume", nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization=%q: status = %d, want 401", authHeader, rec.Code)
		}
	}
}

func TestQueueConsumeAction_PopsEventsWithValidToken(t *testing.T) {
	validEvent := `{"pool":"oms_cni","status":429}`
	calls := 0
	host, port := fakeRedisServer(t, func(cmd []string) string {
		calls++
		if cmd[0] == "LPOP" && calls == 1 {
			return fmt.Sprintf("$%d\r\n%s\r\n", len(validEvent), validEvent)
		}
		return "$-1\r\n"
	})
	ss := &fakeSettingsStore{queueToken: "correct-token"}
	ss.redis.Host = host
	ss.redis.Port = port

	h := &QueueConsumeAction{Store: ss}
	req := httptest.NewRequest(http.MethodPost, "/api/queue/ratelimit-events/consume?limit=5", nil)
	req.Header.Set("Authorization", "Bearer correct-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	var resp struct {
		Count  int
		Events []struct {
			Pool   string
			Status int
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%q)", err, rec.Body.String())
	}
	if resp.Count != 1 || len(resp.Events) != 1 || resp.Events[0].Pool != "oms_cni" || resp.Events[0].Status != 429 {
		t.Errorf("resp = %+v", resp)
	}
}
