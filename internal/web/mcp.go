package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"

	"haproxy-gui/internal/mcp"
)

// NewMCPHandler serves POST /mcp. Its tools call the gateway's own /api/v1
// handlers in-process, through api (the full mux), carrying the caller's
// Bearer token — so every tool call passes the same authentication and
// capability checks as a direct HTTP request, and a token can never reach
// more through MCP than through the API.
func NewMCPHandler(api http.Handler) *mcp.HTTPHandler {
	return &mcp.HTTPHandler{
		NewBackend: func(r *http.Request) mcp.Backend {
			return &inProcessBackend{
				api:        api,
				authHeader: r.Header.Get("Authorization"),
				remoteAddr: r.RemoteAddr,
				forwarded:  r.Header.Get("X-Forwarded-For"),
			}
		},
	}
}

type inProcessBackend struct {
	api                               http.Handler
	authHeader, remoteAddr, forwarded string
}

func (b *inProcessBackend) Do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	var rd *bytes.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, "/api/v1"+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", b.authHeader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.RemoteAddr = b.remoteAddr
	if b.forwarded != "" {
		req.Header.Set("X-Forwarded-For", b.forwarded)
	}
	rec := httptest.NewRecorder()
	b.api.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes(), nil
}
