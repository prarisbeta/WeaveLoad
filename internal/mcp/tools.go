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
