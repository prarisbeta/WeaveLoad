package mcp

// Tool is one entry of tools/list.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema Schema         `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

// Schema is a JSON Schema object for a tool's arguments.
type Schema struct {
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties"`
	Required   []string       `json:"required,omitempty"`
}

var readOnly = map[string]any{"readOnlyHint": true}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

// Tools returns the tool set. Read tools carry readOnlyHint so clients can
// skip approval prompts for them; propose_action does not.
func Tools() []Tool {
	return []Tool{
		{Name: "get_status", Description: "Get overall status of the HAProxy server (live health, sessions, CPU/memory/disk).",
			InputSchema: Schema{Type: "object", Properties: map[string]any{}}, Annotations: readOnly},
		{Name: "list_nodes", Description: "List all HAProxy nodes (hosts) and the pools using them.",
			InputSchema: Schema{Type: "object", Properties: map[string]any{}}, Annotations: readOnly},
		{Name: "list_backends", Description: "List all backends with status, UP/DOWN server counts and sessions.",
			InputSchema: Schema{Type: "object", Properties: map[string]any{}}, Annotations: readOnly},
		{Name: "list_servers", Description: "List every server across all backends (status, weight, drain/maintenance).",
			InputSchema: Schema{Type: "object", Properties: map[string]any{}}, Annotations: readOnly},
		{Name: "get_traffic_summary", Description: "Analyze recent HTTP traffic from the access log: total requests, 5xx errors and error ratio, average latency, top client IPs, top paths, top hosts and the slowest backends.",
			InputSchema: Schema{Type: "object", Properties: map[string]any{
				"lines": map[string]any{"type": "integer", "description": "How many of the newest log lines to analyze (100-5000, default 1000)"},
			}}, Annotations: readOnly},
		{Name: "get_traffic_timeseries", Description: "Requests, 4xx errors, 5xx errors and average latency per time slice (oldest first, empty slices included), to place a spike, slowdown or outage in time. Optionally for one backend.",
			InputSchema: Schema{Type: "object", Properties: map[string]any{
				"minutes":      map[string]any{"type": "integer", "description": "Window length in minutes (1-360, default 60)"},
				"step_minutes": map[string]any{"type": "integer", "description": "Minutes per slice (default 1, or 5 for windows over 2 hours)"},
				"backend":      str("Only this backend (optional)"),
			}}, Annotations: readOnly},
		{Name: "get_top_error_paths", Description: "Which paths and client IPs cause the most 4xx/5xx responses in recent traffic, with the status, backend and the top IP for each path.",
			InputSchema: Schema{Type: "object", Properties: map[string]any{
				"class": str("4xx, 5xx or all (default all)"),
				"lines": map[string]any{"type": "integer", "description": "How many of the newest log lines to analyze (100-5000, default 2000)"},
				"limit": map[string]any{"type": "integer", "description": "Rows to return (1-25, default 10)"},
			}}, Annotations: readOnly},
		{Name: "get_ip_profile", Description: "Everything known about one client IP: risk score and state, recent security detections, threat intelligence when configured, and its recent request pattern (status mix, top paths).",
			InputSchema: Schema{Type: "object", Properties: map[string]any{
				"ip": str("IPv4 or IPv6 address"),
			}, Required: []string{"ip"}}, Annotations: readOnly},
		{Name: "get_waiting_room", Description: "Show how many visitors are held on the waiting page (HTTP 429) right now: visitors waiting, admitted and abandoned in the look-back window, 429 responses, longest wait, per-pool counts and the longest-waiting client IPs. Estimated from the access log, so counts are distinct client IPs.",
			InputSchema: Schema{Type: "object", Properties: map[string]any{
				"minutes": map[string]any{"type": "integer", "description": "Look-back window in minutes (1-60, default 10)"},
			}}, Annotations: readOnly},
		{Name: "get_active_sessions", Description: "Show live active sessions per node (backend host): the total for each node and the pool/server rows behind it, busiest node first. Use it to see where load sits and which node is saturated.",
			InputSchema: Schema{Type: "object", Properties: map[string]any{}}, Annotations: readOnly},
		{Name: "list_incidents", Description: "List security incidents with optional filters (status, severity, search query).",
			InputSchema: Schema{Type: "object", Properties: map[string]any{
				"status":   str("Filter by status: open, investigating, mitigated, resolved, false_positive"),
				"severity": str("Filter by severity: low, medium, high, critical"),
				"q":        str("Free-text search"),
			}}, Annotations: readOnly},
		{Name: "get_incident", Description: "Get one incident with its timeline notes and linked security events.",
			InputSchema: Schema{Type: "object", Properties: map[string]any{
				"id": map[string]any{"type": "integer", "description": "Incident ID"},
			}, Required: []string{"id"}}, Annotations: readOnly},
		{Name: "policy_check_action", Description: "Dry run: ask the Policy Engine whether a block_ip or drain_server action would be allowed, and in what mode, without recording or running anything.",
			InputSchema: Schema{Type: "object", Properties: map[string]any{
				"action":      str("block_ip or drain_server"),
				"target":      str("An IP address for block_ip, or backend/server for drain_server"),
				"ttl_seconds": map[string]any{"type": "integer", "description": "How long the action should last (optional)"},
			}, Required: []string{"action", "target"}}, Annotations: readOnly},
		{Name: "propose_action", Description: "Propose an action for a human operator to review. It is recorded on the operator's alerts page; nothing is executed. Optionally name a typed action (block_ip or drain_server) so the operator can approve it with one click in the Policy Engine; it still only runs after a human approves.",
			InputSchema: Schema{Type: "object", Properties: map[string]any{
				"reason":      str("Why this action is proposed"),
				"evidence":    str("Evidence supporting the action"),
				"action":      str("Optional: block_ip or drain_server"),
				"target":      str("Optional: IP address, or backend/server"),
				"ttl_seconds": map[string]any{"type": "integer", "description": "Optional: how long the action should last"},
			}, Required: []string{"reason", "evidence"}}},
	}
}
