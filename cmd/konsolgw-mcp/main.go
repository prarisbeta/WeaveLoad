package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CallToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema Schema `json:"inputSchema"`
}

type Schema struct {
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties"`
	Required   []string       `json:"required,omitempty"`
}

var defaultTools = []Tool{
	{
		Name:        "get_status",
		Description: "Get overall status of the HAProxy server.",
		InputSchema: Schema{Type: "object", Properties: map[string]any{}},
	},
	{
		Name:        "list_nodes",
		Description: "List all HAProxy nodes (hosts) and their pools.",
		InputSchema: Schema{Type: "object", Properties: map[string]any{}},
	},
	{
		Name:        "list_backends",
		Description: "List all backends and their status.",
		InputSchema: Schema{Type: "object", Properties: map[string]any{}},
	},
	{
		Name:        "list_servers",
		Description: "List all individual servers across backends.",
		InputSchema: Schema{Type: "object", Properties: map[string]any{}},
	},
	{
		Name:        "list_incidents",
		Description: "List security incidents with optional filters (status, severity, search query).",
		InputSchema: Schema{
			Type: "object",
			Properties: map[string]any{
				"status": map[string]any{
					"type":        "string",
					"description": "Filter by status: open, investigating, mitigated, resolved, false_positive",
				},
				"severity": map[string]any{
					"type":        "string",
					"description": "Filter by severity: critical, high, medium, low",
				},
				"q": map[string]any{
					"type":        "string",
					"description": "Search term across title, subject, and summary",
				},
			},
		},
	},
	{
		Name:        "get_incident",
		Description: "Get complete details, linked events, and investigation notes of a security incident.",
		InputSchema: Schema{
			Type: "object",
			Properties: map[string]any{
				"id": map[string]any{
					"type":        "integer",
					"description": "Incident ID",
				},
			},
			Required: []string{"id"},
		},
	},
	{
		Name:        "propose_action",
		Description: "Propose an action for a human operator or approval workflow to review.",
		InputSchema: Schema{
			Type: "object",
			Properties: map[string]any{
				"reason": map[string]any{
					"type":        "string",
					"description": "Reason for this action",
				},
				"evidence": map[string]any{
					"type":        "string",
					"description": "Evidence supporting the action",
				},
			},
			Required: []string{"reason", "evidence"},
		},
	},
}

// MCPServer handles MCP JSON-RPC requests over an io.Reader and io.Writer.
type MCPServer struct {
	APIURL     string
	APIToken   string
	HTTPClient *http.Client
	In         io.Reader
	Out        io.Writer
}

func NewMCPServer(apiURL, apiToken string, in io.Reader, out io.Writer) *MCPServer {
	if apiURL == "" {
		apiURL = "http://localhost:8080/api/v1"
	}
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	return &MCPServer{
		APIURL:     apiURL,
		APIToken:   apiToken,
		HTTPClient: http.DefaultClient,
		In:         in,
		Out:        out,
	}
}

func (s *MCPServer) Run() error {
	scanner := bufio.NewScanner(s.In)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		var req JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.sendError(nil, -32700, "Parse error")
			continue
		}

		switch req.Method {
		case "initialize":
			s.sendResult(req.ID, map[string]any{
				"protocolVersion": "2024-11-05",
				"serverInfo": map[string]any{
					"name":    "konsolgw-mcp",
					"version": "1.0.0",
				},
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
			})
		case "notifications/initialized":
			// No response needed for notification
		case "tools/list":
			s.sendResult(req.ID, map[string]any{
				"tools": defaultTools,
			})
		case "tools/call":
			var params CallToolParams
			if err := json.Unmarshal(req.Params, &params); err != nil {
				s.sendError(req.ID, -32602, "Invalid params")
				continue
			}
			s.handleToolCall(req.ID, params)
		default:
			s.sendError(req.ID, -32601, "Method not found: "+req.Method)
		}
	}
	return scanner.Err()
}

func (s *MCPServer) handleToolCall(id any, params CallToolParams) {
	var result string
	var err error

	switch params.Name {
	case "get_status":
		result, err = s.callAPI("GET", "/status", nil)
	case "list_nodes":
		result, err = s.callAPI("GET", "/nodes", nil)
	case "list_backends":
		result, err = s.callAPI("GET", "/backends", nil)
	case "list_servers":
		result, err = s.callAPI("GET", "/servers", nil)
	case "list_incidents":
		query := url.Values{}
		if val, ok := params.Arguments["status"].(string); ok && val != "" {
			query.Set("status", val)
		}
		if val, ok := params.Arguments["severity"].(string); ok && val != "" {
			query.Set("severity", val)
		}
		if val, ok := params.Arguments["q"].(string); ok && val != "" {
			query.Set("q", val)
		}
		path := "/incidents"
		if len(query) > 0 {
			path += "?" + query.Encode()
		}
		result, err = s.callAPI("GET", path, nil)
	case "get_incident":
		var incID int64
		if rawID, ok := params.Arguments["id"]; ok {
			switch v := rawID.(type) {
			case float64:
				incID = int64(v)
			case int:
				incID = int64(v)
			case int64:
				incID = v
			case string:
				incID, _ = strconv.ParseInt(v, 10, 64)
			}
		}
		if incID <= 0 {
			s.sendError(id, -32602, "Valid incident ID is required")
			return
		}
		result, err = s.callAPI("GET", fmt.Sprintf("/incidents/%d", incID), nil)
	case "propose_action":
		reason, _ := params.Arguments["reason"].(string)
		evidence, _ := params.Arguments["evidence"].(string)
		if reason == "" || evidence == "" {
			s.sendError(id, -32602, "Both reason and evidence are required")
			return
		}
		result = fmt.Sprintf("Action proposed successfully based on reason: %s [Evidence: %s]", reason, evidence)
	default:
		s.sendError(id, -32601, "Tool not found: "+params.Name)
		return
	}

	if err != nil {
		s.sendResult(id, map[string]any{
			"content": []map[string]any{
				{
					"type": "text",
					"text": "Error calling API: " + err.Error(),
				},
			},
			"isError": true,
		})
		return
	}

	s.sendResult(id, map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": result,
			},
		},
	})
}

func (s *MCPServer) callAPI(method, endpoint string, body io.Reader) (string, error) {
	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequest(method, s.APIURL+endpoint, body)
	if err != nil {
		return "", err
	}
	if s.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.APIToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(respBody), nil
}

func (s *MCPServer) sendResult(id any, result any) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	b, _ := json.Marshal(resp)
	fmt.Fprintln(s.Out, string(b))
}

func (s *MCPServer) sendError(id any, code int, msg string) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: msg,
		},
	}
	b, _ := json.Marshal(resp)
	fmt.Fprintln(s.Out, string(b))
}

func main() {
	apiURL := os.Getenv("KONSOLGW_API_URL")
	apiToken := os.Getenv("KONSOLGW_API_TOKEN")
	server := NewMCPServer(apiURL, apiToken, os.Stdin, os.Stdout)
	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}
