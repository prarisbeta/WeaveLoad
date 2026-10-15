package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// MaxBodyBytes caps one MCP HTTP request.
const MaxBodyBytes = 1 << 20

// HTTPHandler serves MCP over HTTP (the "Streamable HTTP" transport, in its
// simple form: every POST is answered with one JSON body, no server-initiated
// streaming and no session state). Remote MCP clients — Claude Code, Cursor,
// n8n, MCP Inspector, anything that takes a URL plus an Authorization header
// — connect here instead of spawning the stdio binary.
//
// Authentication is the caller's job (auth.RequireAPIToken); NewBackend then
// builds the Backend that acts as that caller.
type HTTPHandler struct {
	NewBackend func(r *http.Request) Backend
	Name       string
	Version    string
}

func setCORS(w http.ResponseWriter) {
	h := w.Header()
	// Bearer tokens are not ambient browser credentials, so a wildcard origin
	// lets browser-based MCP clients work without enabling CSRF-style abuse.
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Mcp-Protocol-Version, Mcp-Session-Id")
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	h.Set("Access-Control-Max-Age", "600")
}

// Preflight answers the CORS preflight, which carries no credentials and so
// must be routed outside the token check.
func (h *HTTPHandler) Preflight(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method != http.MethodPost {
		// GET would open a server-to-client stream and DELETE ends a session;
		// this server has neither, which the spec allows it to say with 405.
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "this MCP endpoint only accepts POST", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		writeRPC(w, http.StatusRequestEntityTooLarge, ParseErrorResponse())
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		writeRPC(w, http.StatusBadRequest, InvalidRequestResponse())
		return
	}

	srv := &Server{Backend: h.NewBackend(r), Name: h.Name, Version: h.Version}

	if body[0] == '[' {
		var msgs []json.RawMessage
		if err := json.Unmarshal(body, &msgs); err != nil {
			writeRPC(w, http.StatusBadRequest, ParseErrorResponse())
			return
		}
		if len(msgs) == 0 {
			writeRPC(w, http.StatusBadRequest, InvalidRequestResponse())
			return
		}
		var out []*Response
		for _, m := range msgs {
			if resp := h.one(r, srv, m); resp != nil {
				out = append(out, resp)
			}
		}
		if len(out) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	resp := h.one(r, srv, body)
	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	status := http.StatusOK
	if resp.Error != nil && (resp.Error.Code == CodeParse || resp.Error.Code == CodeInvalidRequest) {
		status = http.StatusBadRequest
	}
	writeRPC(w, status, resp)
}

func (h *HTTPHandler) one(r *http.Request, srv *Server, raw []byte) *Response {
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		var probe any
		if json.Unmarshal(raw, &probe) != nil {
			return ParseErrorResponse()
		}
		return InvalidRequestResponse()
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		// Not a JSON-RPC request or notification at all, so it is answered
		// with an error even without an id.
		return InvalidRequestResponse()
	}
	return srv.Handle(r.Context(), req)
}

func writeRPC(w http.ResponseWriter, status int, resp *Response) { writeJSON(w, status, resp) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
