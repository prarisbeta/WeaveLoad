// Package mcp implements the Model Context Protocol surface of Konsol
// Gateway: JSON-RPC 2.0 handling and the tool set, independent of transport.
// The stdio binary (cmd/konsolgw-mcp) and the HTTP endpoint (POST /mcp) both
// drive the same Server, so third-party apps get identical behaviour whichever
// way they connect.
//
// The tools only read state or record a proposal for a human to review; the
// AI is never a trust root and nothing here changes HAProxy.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Backend is how tools reach the Konsol Gateway API. path is relative to
// /api/v1 and may carry a query string ("/incidents?status=open").
type Backend interface {
	Do(ctx context.Context, method, path string, body []byte) (status int, resp []byte, err error)
}

// Request is one JSON-RPC message. A message without an id is a notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether no reply is expected.
func (r Request) IsNotification() bool { return len(r.ID) == 0 }

// Response is one JSON-RPC reply.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
)

// Protocol versions this server speaks. Tools-only servers behave the same in
// all of them.
var supportedVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

const defaultVersion = "2024-11-05"

// Server handles MCP requests against a Backend.
type Server struct {
	Backend Backend
	Name    string // serverInfo.name, default "konsolgw-mcp"
	Version string // serverInfo.version, default "1.1.0"
}

func errResponse(id json.RawMessage, code int, msg string) *Response {
	return &Response{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: msg}}
}

// ParseErrorResponse is the reply to bytes that are not valid JSON.
func ParseErrorResponse() *Response {
	return errResponse(json.RawMessage("null"), CodeParse, "Parse error")
}

// InvalidRequestResponse is the reply to valid JSON that is not a request.
func InvalidRequestResponse() *Response {
	return errResponse(json.RawMessage("null"), CodeInvalidRequest, "Invalid Request")
}

// Handle answers one request, or returns nil for a notification.
func (s *Server) Handle(ctx context.Context, req Request) *Response {
	if req.IsNotification() {
		// initialized, cancelled, ... : nothing to do, and nothing may be sent.
		return nil
	}
	ok := func(result any) *Response {
		return &Response{JSONRPC: "2.0", ID: req.ID, Result: result}
	}

	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		name, version := s.Name, s.Version
		if name == "" {
			name = "konsolgw-mcp"
		}
		if version == "" {
			version = "1.1.0"
		}
		return ok(map[string]any{
			"protocolVersion": negotiate(p.ProtocolVersion),
			"serverInfo":      map[string]any{"name": name, "version": version},
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"instructions":    "Read-only view of a HAProxy load balancer (status, backends, servers, security incidents). propose_action only records a proposal for a human operator; it never changes traffic.",
		})
	case "ping":
		return ok(map[string]any{})
	case "tools/list":
		return ok(map[string]any{"tools": Tools()})
	case "tools/call":
		var p CallToolParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResponse(req.ID, CodeInvalidParams, "Invalid params")
		}
		res, rpcErr := s.callTool(ctx, p)
		if rpcErr != nil {
			return &Response{JSONRPC: "2.0", ID: req.ID, Error: rpcErr}
		}
		return ok(res)
	default:
		return errResponse(req.ID, CodeMethodNotFound, "Method not found: "+req.Method)
	}
}

func negotiate(requested string) string {
	if requested == "" {
		return defaultVersion
	}
	for _, v := range supportedVersions {
		if v == requested {
			return v
		}
	}
	return supportedVersions[0]
}

// CallToolParams is the params object of tools/call.
type CallToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

func textResult(text string, isError bool) map[string]any {
	res := map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
	if isError {
		res["isError"] = true
	}
	return res
}

func (s *Server) callTool(ctx context.Context, p CallToolParams) (map[string]any, *Error) {
	get := func(path string) (map[string]any, *Error) {
		status, body, err := s.Backend.Do(ctx, "GET", path, nil)
		return apiResult(status, body, err), nil
	}

	switch p.Name {
	case "get_status":
		return get("/status")
	case "list_nodes":
		return get("/nodes")
	case "list_backends":
		return get("/backends")
	case "list_servers":
		return get("/servers")
	case "get_traffic_summary":
		path := "/traffic"
		if n := intArg(p.Arguments["lines"]); n > 0 {
			path += "?lines=" + strconv.FormatInt(n, 10)
		}
		return get(path)
	case "get_waiting_room":
		path := "/waiting-room"
		if n := intArg(p.Arguments["minutes"]); n > 0 {
			path += "?minutes=" + strconv.FormatInt(n, 10)
		}
		return get(path)
	case "get_traffic_timeseries":
		q := url.Values{}
		if n := intArg(p.Arguments["minutes"]); n > 0 {
			q.Set("minutes", strconv.FormatInt(n, 10))
		}
		if n := intArg(p.Arguments["step_minutes"]); n > 0 {
			q.Set("step", strconv.FormatInt(n, 10))
		}
		if b, _ := p.Arguments["backend"].(string); strings.TrimSpace(b) != "" {
			q.Set("backend", strings.TrimSpace(b))
		}
		path := "/traffic/timeseries"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		return get(path)
	case "get_top_error_paths":
		q := url.Values{}
		if c, _ := p.Arguments["class"].(string); c != "" {
			q.Set("class", c)
		}
		for _, arg := range []string{"lines", "limit"} {
			if n := intArg(p.Arguments[arg]); n > 0 {
				q.Set(arg, strconv.FormatInt(n, 10))
			}
		}
		path := "/traffic/errors"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		return get(path)
	case "get_ip_profile":
		ip, _ := p.Arguments["ip"].(string)
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) == nil {
			return nil, &Error{Code: CodeInvalidParams, Message: "A valid IP address is required"}
		}
		return get("/security/ip/" + url.PathEscape(ip))
	case "get_active_sessions":
		return get("/sessions")
	case "list_incidents":
		q := url.Values{}
		for _, k := range []string{"status", "severity", "q"} {
			if v, ok := p.Arguments[k].(string); ok && v != "" {
				q.Set(k, v)
			}
		}
		path := "/incidents"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		return get(path)
	case "get_incident":
		id := intArg(p.Arguments["id"])
		if id <= 0 {
			return nil, &Error{Code: CodeInvalidParams, Message: "Valid incident ID is required"}
		}
		return get(fmt.Sprintf("/incidents/%d", id))
	case "propose_action":
		reason, _ := p.Arguments["reason"].(string)
		evidence, _ := p.Arguments["evidence"].(string)
		reason, evidence = strings.TrimSpace(reason), strings.TrimSpace(evidence)
		if reason == "" || evidence == "" {
			return nil, &Error{Code: CodeInvalidParams, Message: "Both reason and evidence are required"}
		}
		payload := map[string]any{"reason": reason, "evidence": evidence}
		// Optional typed action: it goes to the Policy Engine, which for an
		// API caller never goes beyond "propose" (a human still approves).
		if action, _ := p.Arguments["action"].(string); action != "" {
			payload["action"] = action
			payload["target"], _ = p.Arguments["target"].(string)
			if ttl := intArg(p.Arguments["ttl_seconds"]); ttl > 0 {
				payload["ttl_seconds"] = ttl
			}
		}
		body, _ := json.Marshal(payload)
		status, resp, err := s.Backend.Do(ctx, "POST", "/proposals", body)
		res := apiResult(status, resp, err)
		if _, failed := res["isError"]; !failed {
			text := fmt.Sprintf("Action proposed for operator review (not executed). Reason: %s [Evidence: %s]\n%s", reason, evidence, string(resp))
			return textResult(strings.TrimSpace(text), false), nil
		}
		return res, nil
	case "policy_check_action":
		action, _ := p.Arguments["action"].(string)
		target, _ := p.Arguments["target"].(string)
		if strings.TrimSpace(action) == "" || strings.TrimSpace(target) == "" {
			return nil, &Error{Code: CodeInvalidParams, Message: "Both action and target are required"}
		}
		payload := map[string]any{"action": action, "target": target}
		if ttl := intArg(p.Arguments["ttl_seconds"]); ttl > 0 {
			payload["ttl_seconds"] = ttl
		}
		body, _ := json.Marshal(payload)
		status, resp, err := s.Backend.Do(ctx, "POST", "/policy/check", body)
		return apiResult(status, resp, err), nil
	default:
		return nil, &Error{Code: CodeMethodNotFound, Message: "Tool not found: " + p.Name}
	}
}

// apiResult turns a backend reply into a tool result. A transport failure or
// an HTTP error status is a tool error the model can see, not a success whose
// text happens to say "authentication required".
func apiResult(status int, body []byte, err error) map[string]any {
	if err != nil {
		return textResult("Error calling API: "+err.Error(), true)
	}
	if status >= 400 {
		return textResult(fmt.Sprintf("API returned HTTP %d: %s", status, strings.TrimSpace(string(body))), true)
	}
	return textResult(string(body), false)
}

func intArg(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int:
		return int64(n)
	case int64:
		return n
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	return 0
}
