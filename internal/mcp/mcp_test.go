package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeBackend records calls and answers from a fixed table.
type fakeBackend struct {
	status int
	body   string
	err    error

	method, path string
	sent         []byte
}

func (f *fakeBackend) Do(_ context.Context, method, path string, body []byte) (int, []byte, error) {
	f.method, f.path, f.sent = method, path, body
	st := f.status
	if st == 0 {
		st = 200
	}
	return st, []byte(f.body), f.err
}

func call(t *testing.T, srv *Server, line string) *Response {
	t.Helper()
	var req Request
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		t.Fatal(err)
	}
	return srv.Handle(context.Background(), req)
}

func resultText(t *testing.T, r *Response) (string, bool) {
	t.Helper()
	if r == nil || r.Error != nil {
		t.Fatalf("response = %+v", r)
	}
	m := r.Result.(map[string]any)
	content := m["content"].([]map[string]any)
	isErr, _ := m["isError"].(bool)
	return content[0]["text"].(string), isErr
}

func TestInitialize_NegotiatesProtocolVersion(t *testing.T) {
	srv := &Server{Backend: &fakeBackend{}}
	cases := map[string]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`:                                               "2024-11-05",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`:     "2025-03-26",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`:     "2025-06-18",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}`:     "2025-06-18",
		`{"jsonrpc":"2.0","id":"abc","method":"initialize","params":{"protocolVersion":"2024-11-05"}}`: "2024-11-05",
	}
	for line, want := range cases {
		resp := call(t, srv, line)
		got := resp.Result.(map[string]any)["protocolVersion"]
		if got != want {
			t.Errorf("%s => %v, want %s", line, got, want)
		}
	}
	resp := call(t, srv, `{"jsonrpc":"2.0","id":"abc","method":"initialize"}`)
	if string(resp.ID) != `"abc"` {
		t.Errorf("id not echoed verbatim: %s", resp.ID)
	}
}

func TestNotificationsGetNoReply(t *testing.T) {
	srv := &Server{Backend: &fakeBackend{}}
	if r := call(t, srv, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); r != nil {
		t.Errorf("reply to a notification: %+v", r)
	}
	if r := call(t, srv, `{"jsonrpc":"2.0","method":"no/such/method"}`); r != nil {
		t.Errorf("reply to an unknown notification: %+v", r)
	}
}

func TestPingAndUnknownMethod(t *testing.T) {
	srv := &Server{Backend: &fakeBackend{}}
	if r := call(t, srv, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.Error != nil {
		t.Errorf("ping = %+v", r)
	}
	r := call(t, srv, `{"jsonrpc":"2.0","id":2,"method":"resources/list"}`)
	if r.Error == nil || r.Error.Code != CodeMethodNotFound {
		t.Errorf("unknown method = %+v", r)
	}
}

func TestToolsListMarksReadToolsReadOnlyAndNotPropose(t *testing.T) {
	r := call(t, &Server{Backend: &fakeBackend{}}, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	b, _ := json.Marshal(r.Result)
	var out struct {
		Tools []struct {
			Name        string         `json:"name"`
			Annotations map[string]any `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tools) != 14 {
		t.Fatalf("got %d tools, want 14", len(out.Tools))
	}
	for _, tl := range out.Tools {
		ro := tl.Annotations["readOnlyHint"] == true
		if tl.Name == "propose_action" && ro {
			t.Error("propose_action must not be marked read-only")
		}
		if tl.Name != "propose_action" && !ro {
			t.Errorf("%s should be marked read-only", tl.Name)
		}
	}
}

func TestToolCall_ReadToolsHitTheRightPaths(t *testing.T) {
	cases := map[string]string{
		`{"name":"get_status"}`:             "/status",
		`{"name":"get_traffic_summary"}`:    "/traffic",
		`{"name":"get_waiting_room"}`:       "/waiting-room",
		`{"name":"get_active_sessions"}`:    "/sessions",
		`{"name":"get_traffic_timeseries"}`: "/traffic/timeseries",
		`{"name":"get_traffic_timeseries","arguments":{"minutes":30,"step_minutes":5,"backend":"oms"}}`: "/traffic/timeseries?backend=oms&minutes=30&step=5",
		`{"name":"get_top_error_paths"}`: "/traffic/errors",
		`{"name":"get_top_error_paths","arguments":{"class":"5xx","lines":500,"limit":5}}`: "/traffic/errors?class=5xx&limit=5&lines=500",
		`{"name":"get_ip_profile","arguments":{"ip":"203.0.113.9"}}`:                       "/security/ip/203.0.113.9",
		`{"name":"get_waiting_room","arguments":{"minutes":30}}`:                           "/waiting-room?minutes=30",
		`{"name":"get_traffic_summary","arguments":{"lines":2500}}`:                        "/traffic?lines=2500",
		`{"name":"list_nodes"}`:    "/nodes",
		`{"name":"list_backends"}`: "/backends",
		`{"name":"list_servers"}`:  "/servers",
		`{"name":"list_incidents","arguments":{"status":"open","q":"a"}}`: "/incidents?q=a&status=open",
		`{"name":"get_incident","arguments":{"id":101}}`:                  "/incidents/101",
		`{"name":"get_incident","arguments":{"id":"7"}}`:                  "/incidents/7",
	}
	for params, wantPath := range cases {
		fb := &fakeBackend{body: `{"success":true}`}
		r := call(t, &Server{Backend: fb}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+params+`}`)
		text, isErr := resultText(t, r)
		if isErr || text != `{"success":true}` || fb.method != "GET" || fb.path != wantPath {
			t.Errorf("%s => text=%q err=%v %s %s, want GET %s", params, text, isErr, fb.method, fb.path, wantPath)
		}
	}
}

func TestToolCall_APIErrorStatusIsAToolErrorNotASuccess(t *testing.T) {
	fb := &fakeBackend{status: 401, body: "invalid or missing API token"}
	r := call(t, &Server{Backend: fb}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status"}}`)
	text, isErr := resultText(t, r)
	if !isErr || !strings.Contains(text, "HTTP 401") || !strings.Contains(text, "invalid or missing API token") {
		t.Errorf("text=%q isError=%v", text, isErr)
	}

	fb = &fakeBackend{err: errors.New("connection refused")}
	r = call(t, &Server{Backend: fb}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status"}}`)
	if text, isErr := resultText(t, r); !isErr || !strings.Contains(text, "connection refused") {
		t.Errorf("transport error: text=%q isError=%v", text, isErr)
	}
}

func TestToolCall_InvalidArgumentsAreRPCErrors(t *testing.T) {
	srv := &Server{Backend: &fakeBackend{}}
	for _, params := range []string{
		`{"name":"get_incident","arguments":{}}`,
		`{"name":"propose_action","arguments":{"reason":"x"}}`,
		`{"name":"propose_action","arguments":{"reason":"  ","evidence":"y"}}`,
		`{"name":"nope"}`,
	} {
		r := call(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+params+`}`)
		if r.Error == nil {
			t.Errorf("%s => %+v, want an RPC error", params, r.Result)
		}
	}
}

func TestPolicyCheckAction_PostsADryRun(t *testing.T) {
	fb := &fakeBackend{body: `{"success":true,"data":{"allowed":true,"mode":"propose"}}`}
	r := call(t, &Server{Backend: fb}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"policy_check_action","arguments":{"action":"block_ip","target":"9.9.9.9","ttl_seconds":600}}}`)
	text, isErr := resultText(t, r)
	if isErr || fb.method != "POST" || fb.path != "/policy/check" || !strings.Contains(text, `"allowed":true`) {
		t.Fatalf("err=%v %s %s %q", isErr, fb.method, fb.path, text)
	}
	var sent map[string]any
	if err := json.Unmarshal(fb.sent, &sent); err != nil || sent["action"] != "block_ip" || sent["target"] != "9.9.9.9" || sent["ttl_seconds"] != float64(600) {
		t.Errorf("sent = %s", fb.sent)
	}
	for _, params := range []string{
		`{"name":"policy_check_action","arguments":{"action":"block_ip"}}`,
		`{"name":"policy_check_action","arguments":{"target":"9.9.9.9"}}`,
	} {
		if r := call(t, &Server{Backend: &fakeBackend{}}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+params+`}`); r.Error == nil {
			t.Errorf("%s: want an RPC error", params)
		}
	}
}

func TestProposeAction_ForwardsTypedActionToThePolicyEndpoint(t *testing.T) {
	fb := &fakeBackend{status: 201, body: `{"success":true}`}
	call(t, &Server{Backend: fb}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"propose_action","arguments":{"reason":"SQLi","evidence":"e","action":"block_ip","target":"9.9.9.9"}}}`)
	var sent map[string]any
	if err := json.Unmarshal(fb.sent, &sent); err != nil || sent["action"] != "block_ip" || sent["target"] != "9.9.9.9" {
		t.Errorf("sent = %s", fb.sent)
	}
}

func TestProposeAction_PostsTheProposalAndNeverClaimsExecution(t *testing.T) {
	fb := &fakeBackend{status: 201, body: `{"success":true,"data":{"id":5}}`}
	r := call(t, &Server{Backend: fb}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"propose_action","arguments":{"reason":"High 5xx","evidence":"100 x 500"}}}`)
	text, isErr := resultText(t, r)
	if isErr || fb.method != "POST" || fb.path != "/proposals" {
		t.Fatalf("err=%v %s %s", isErr, fb.method, fb.path)
	}
	var sent map[string]string
	if err := json.Unmarshal(fb.sent, &sent); err != nil || sent["reason"] != "High 5xx" || sent["evidence"] != "100 x 500" {
		t.Errorf("sent = %s", fb.sent)
	}
	if !strings.Contains(text, `"id":5`) || !strings.Contains(text, "not executed") {
		t.Errorf("text = %q", text)
	}

	fb = &fakeBackend{status: 403, body: "insufficient permissions"}
	r = call(t, &Server{Backend: fb}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"propose_action","arguments":{"reason":"a","evidence":"b"}}}`)
	if text, isErr := resultText(t, r); !isErr || strings.Contains(text, "proposed for operator review") {
		t.Errorf("a refused proposal must be an error: %q isError=%v", text, isErr)
	}
}

// --- HTTP transport ---

func post(h http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func newHTTP(fb *fakeBackend) *HTTPHandler {
	return &HTTPHandler{NewBackend: func(*http.Request) Backend { return fb }}
}

func TestHTTP_SingleRequestGetsOneJSONResponse(t *testing.T) {
	rec := post(newHTTP(&fakeBackend{}), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Error != nil {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing CORS header")
	}
}

func TestHTTP_NotificationIs202WithNoBody(t *testing.T) {
	rec := post(newHTTP(&fakeBackend{}), `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Errorf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestHTTP_BatchRepliesOnlyToRequests(t *testing.T) {
	rec := post(newHTTP(&fakeBackend{}), `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`)
	var out []Response
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 2 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_BadInputGets400WithJSONRPCError(t *testing.T) {
	for _, body := range []string{"not json", ``, `[]`, `{"hello":"world"}`, `{"jsonrpc":"1.0","id":1,"method":"ping"}`} {
		rec := post(newHTTP(&fakeBackend{}), body)
		var resp Response
		if rec.Code != http.StatusBadRequest || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || resp.Error == nil {
			t.Errorf("%q => status=%d body=%s", body, rec.Code, rec.Body.String())
		}
	}
}

func TestHTTP_OnlyPostIsAccepted_PreflightIs204(t *testing.T) {
	h := newHTTP(&fakeBackend{})
	for _, m := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/mcp", nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") == "" {
			t.Errorf("%s: status=%d allow=%q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
	rec := httptest.NewRecorder()
	h.Preflight(rec, httptest.NewRequest(http.MethodOptions, "/mcp", nil))
	if rec.Code != http.StatusNoContent || !strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Errorf("preflight: status=%d headers=%v", rec.Code, rec.Header())
	}
}

func TestHTTP_BackendIsBuiltPerRequest(t *testing.T) {
	var seen []string
	h := &HTTPHandler{NewBackend: func(r *http.Request) Backend {
		seen = append(seen, r.Header.Get("Authorization"))
		return &fakeBackend{}
	}}
	for _, tok := range []string{"Bearer kgw_a", "Bearer kgw_b"} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Header.Set("Authorization", tok)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if len(seen) != 2 || seen[0] == seen[1] {
		t.Errorf("seen = %v, want one backend per caller", seen)
	}
}
