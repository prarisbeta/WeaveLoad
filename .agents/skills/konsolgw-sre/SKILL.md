---
name: konsolgw-sre
description: >-
  HAProxy SRE, Traffic Management, and Incident Investigation Assistant for Konsol Gateway.
  Use when observing HAProxy live health, listing backends/servers/nodes, investigating security
  incidents and attack patterns, or proposing traffic mitigations via Konsol Gateway MCP tools.
---

# Konsol Gateway SRE Assistant Skill

This skill guides the Antigravity agent in operating and investigating HAProxy instances managed by Konsol Gateway.

## Principles
1. **AI is NOT a Trust Root**: Never attempt to bypass approval workflows. Traffic mutations must be proposed using `propose_action` with clear `reason` and supporting `evidence`.
2. **Investigation Loop**: Follow **Observe → Context → Decide → Propose**:
   - **Observe**: Check live status (`get_status`), backends (`list_backends`), servers (`list_servers`), and nodes (`list_nodes`).
   - **Context**: Check incidents (`list_incidents`, `get_incident`) and correlated security events.
   - **Decide**: Formulate root cause hypotheses based on status codes, latency, or anomaly patterns.
   - **Propose**: Generate structured mitigation proposals via `propose_action`.

## Available MCP Tools

### 1. Observability (READ)
- `get_status`: Live status, active sessions, frontend/backend counts, system resources (CPU, Memory, Disk).
- `list_nodes`: List of host machines and pool mappings.
- `list_backends`: List of backends, server counts (UP/DOWN), and active session counts.
- `list_servers`: Granular server details (status, weight, maintenance/drain state, health checks).

### 2. Incident Investigation (INVESTIGATE)
- `list_incidents`: Query security incidents with filters (`status`, `severity`, `q`).
- `get_incident`: Detailed view of an incident with timeline notes, linked security events, and evidence.

### 3. Action Proposal (PROPOSE)
- `propose_action`: Proposes a mitigation action for operator review.
  - `reason`: Concrete justification (e.g., "502 surge on backend bk_core_api due to upstream node failure").
  - `evidence`: Specific metric or log evidence supporting the action.

## REST API Reference
If executing via HTTP API directly:
- `GET /api/v1/status`
- `GET /api/v1/backends`
- `GET /api/v1/servers`
- `GET /api/v1/nodes`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{id}`
