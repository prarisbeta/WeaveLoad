package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

var tools = []Tool{
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
		Name:        "propose_action",
		Description: "Propose an action for a human to review.",
		InputSchema: Schema{
			Type: "object",
			Properties: map[string]any{
				"reason": map[string]any{
					"type": "string",
					"description": "Reason for this action",
				},
				"evidence": map[string]any{
					"type": "string",
					"description": "Evidence supporting the action",
				},
			},
			Required: []string{"reason", "evidence"},
		},
	},
}

var apiURL string
var apiToken string

func main() {
	apiURL = os.Getenv("KONSOLGW_API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080/api/v1"
	}
	apiToken = os.Getenv("KONSOLGW_API_TOKEN")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		var req JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			sendError(nil, -32700, "Parse error")
			continue
		}

		switch req.Method {
		case "initialize":
			sendResult(req.ID, map[string]any{
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
			// Do nothing
		case "tools/list":
			sendResult(req.ID, map[string]any{
				"tools": tools,
			})
		case "tools/call":
			var params CallToolParams
			if err := json.Unmarshal(req.Params, &params); err != nil {
				sendError(req.ID, -32602, "Invalid params")
				continue
			}
			handleToolCall(req.ID, params)
		default:
			sendError(req.ID, -32601, "Method not found: "+req.Method)
		}
	}
}

func handleToolCall(id any, params CallToolParams) {
	var result string
	var err error

	switch params.Name {
	case "get_status":
		result, err = callAPI("/status")
	case "list_nodes":
		result, err = callAPI("/nodes")
	case "list_backends":
		result, err = callAPI("/backends")
	case "list_servers":
		result, err = callAPI("/servers")
	case "propose_action":
		result = fmt.Sprintf("Action proposed successfully based on reason: %s", params.Arguments["reason"])
	default:
		sendError(id, -32601, "Tool not found")
		return
	}

	if err != nil {
		sendResult(id, map[string]any{
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

	sendResult(id, map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": result,
			},
		},
	})
}

func callAPI(endpoint string) (string, error) {
	req, err := http.NewRequest("GET", apiURL+endpoint, nil)
	if err != nil {
		return "", err
	}
	if apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func sendResult(id any, result any) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	b, _ := json.Marshal(resp)
	fmt.Println(string(b))
}

func sendError(id any, code int, msg string) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: msg,
		},
	}
	b, _ := json.Marshal(resp)
	fmt.Println(string(b))
}
