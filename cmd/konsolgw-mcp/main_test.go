package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPServer_Initialize(t *testing.T) {
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n")
	var out bytes.Buffer

	srv := NewMCPServer("http://localhost:8080/api/v1", "", in, &out)
	err := srv.Run()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal output: %v, raw: %s", err, out.String())
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %s", resp.JSONRPC)
	}
	if resp.Error != nil {
		t.Errorf("expected nil error, got %+v", resp.Error)
	}

	resultMap, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result to be map, got %T", resp.Result)
	}
	if resultMap["protocolVersion"] != "2024-11-05" {
		t.Errorf("unexpected protocolVersion: %v", resultMap["protocolVersion"])
	}
}

func TestMCPServer_ToolsList(t *testing.T) {
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":"tools-1","method":"tools/list"}` + "\n")
	var out bytes.Buffer

	srv := NewMCPServer("http://localhost:8080/api/v1", "", in, &out)
	if err := srv.Run(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	resultMap := resp.Result.(map[string]any)
	rawTools, ok := resultMap["tools"].([]any)
	if !ok {
		t.Fatalf("expected tools list, got %T", resultMap["tools"])
	}

	expectedTools := map[string]bool{
		"get_status":          false,
		"get_traffic_summary": false,
		"get_waiting_room":    false,
		"get_active_sessions": false,
		"list_nodes":          false,
		"list_backends":       false,
		"list_servers":        false,
		"list_incidents":      false,
		"get_incident":        false,
		"propose_action":      false,
	}

	for _, toolItem := range rawTools {
		tm := toolItem.(map[string]any)
		name := tm["name"].(string)
		if _, exists := expectedTools[name]; exists {
			expectedTools[name] = true
		}
	}

	for name, found := range expectedTools {
		if !found {
			t.Errorf("expected tool %s to be listed", name)
		}
	}
}

func TestMCPServer_ToolCalls(t *testing.T) {
	var receivedAuth string
	var requestedPath string

	mockAPIServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		requestedPath = r.URL.String()

		switch {
		case r.URL.Path == "/api/v1/status":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true,"data":{"live":true}}`))
		case r.URL.Path == "/api/v1/nodes":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true,"data":[{"host":"10.0.0.1"}]}`))
		case r.URL.Path == "/api/v1/backends":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true,"data":[{"name":"bk_web"}]}`))
		case r.URL.Path == "/api/v1/servers":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true,"data":[{"server":"srv1"}]}`))
		case r.URL.Path == "/api/v1/incidents":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true,"data":[{"id":101,"title":"Brute Force"}]}`))
		case r.URL.Path == "/api/v1/proposals" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"success":true,"data":{"id":5}}`))
		case r.URL.Path == "/api/v1/incidents/101":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true,"data":{"incident":{"id":101,"title":"Brute Force"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		}
	}))
	defer mockAPIServer.Close()

	apiURL := mockAPIServer.URL + "/api/v1"
	apiToken := "secret-bearer-token"

	tests := []struct {
		name         string
		reqJSON      string
		wantPath     string
		wantContent  string
		wantIsError  bool
		wantRPCError bool
	}{
		{
			name:        "get_status tool call",
			reqJSON:     `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"get_status"}}`,
			wantPath:    "/api/v1/status",
			wantContent: `"live":true`,
		},
		{
			name:        "list_nodes tool call",
			reqJSON:     `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"list_nodes"}}`,
			wantPath:    "/api/v1/nodes",
			wantContent: `"host":"10.0.0.1"`,
		},
		{
			name:        "list_backends tool call",
			reqJSON:     `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"list_backends"}}`,
			wantPath:    "/api/v1/backends",
			wantContent: `"name":"bk_web"`,
		},
		{
			name:        "list_servers tool call",
			reqJSON:     `{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"list_servers"}}`,
			wantPath:    "/api/v1/servers",
			wantContent: `"server":"srv1"`,
		},
		{
			name:        "list_incidents tool call with query",
			reqJSON:     `{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"list_incidents","arguments":{"status":"open","severity":"high","q":"auth"}}}`,
			wantPath:    "/api/v1/incidents?q=auth&severity=high&status=open",
			wantContent: `"id":101`,
		},
		{
			name:        "get_incident tool call with ID",
			reqJSON:     `{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"get_incident","arguments":{"id":101}}}`,
			wantPath:    "/api/v1/incidents/101",
			wantContent: `"title":"Brute Force"`,
		},
		{
			name:         "get_incident missing ID returns RPC error",
			reqJSON:      `{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"get_incident","arguments":{}}}`,
			wantRPCError: true,
		},
		{
			name:        "propose_action tool call",
			reqJSON:     `{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"propose_action","arguments":{"reason":"High 5xx error rate","evidence":"Tail log 100 500s"}}}`,
			wantContent: "Action proposed for operator review (not executed). Reason: High 5xx error rate [Evidence: Tail log 100 500s]",
			wantPath:    "/api/v1/proposals",
		},
		{
			name:         "propose_action missing reason returns RPC error",
			reqJSON:      `{"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"propose_action","arguments":{"reason":""}}}`,
			wantRPCError: true,
		},
		{
			name:         "unknown tool returns RPC error",
			reqJSON:      `{"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"unknown_action"}}`,
			wantRPCError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := bytes.NewBufferString(tt.reqJSON + "\n")
			var out bytes.Buffer

			srv := NewMCPServer(apiURL, apiToken, in, &out)
			srv.HTTPClient = mockAPIServer.Client()

			if err := srv.Run(); err != nil {
				t.Fatalf("unexpected run error: %v", err)
			}

			var resp JSONRPCResponse
			if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal error: %v, raw: %s", err, out.String())
			}

			if tt.wantRPCError {
				if resp.Error == nil {
					t.Fatalf("expected RPC error, got result: %+v", resp.Result)
				}
				return
			}

			if resp.Error != nil {
				t.Fatalf("unexpected RPC error: %+v", resp.Error)
			}

			if tt.wantPath != "" {
				if receivedAuth != "Bearer "+apiToken {
					t.Errorf("expected auth 'Bearer %s', got '%s'", apiToken, receivedAuth)
				}
				if requestedPath != tt.wantPath {
					t.Errorf("expected path '%s', got '%s'", tt.wantPath, requestedPath)
				}
			}

			resultMap := resp.Result.(map[string]any)
			contentSlice, ok := resultMap["content"].([]any)
			if !ok || len(contentSlice) == 0 {
				t.Fatalf("expected non-empty content in result: %+v", resp.Result)
			}

			firstContent := contentSlice[0].(map[string]any)
			text := firstContent["text"].(string)

			if !strings.Contains(text, tt.wantContent) {
				t.Errorf("expected text to contain '%s', got '%s'", tt.wantContent, text)
			}
		})
	}
}

func TestMCPServer_ParseError(t *testing.T) {
	in := bytes.NewBufferString("invalid json string\n")
	var out bytes.Buffer

	srv := NewMCPServer("http://localhost:8080/api/v1", "", in, &out)
	if err := srv.Run(); err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if resp.Error == nil || resp.Error.Code != -32700 {
		t.Errorf("expected parse error code -32700, got %+v", resp.Error)
	}
}
