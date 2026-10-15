// konsolgw-mcp is the stdio transport of Konsol Gateway's MCP server, for
// clients that launch a local command (Claude Desktop, Cursor, Claude Code,
// Antigravity). Clients that take a URL instead can use the gateway's own
// POST /mcp endpoint; both run the same tools (internal/mcp).
//
// Configuration, from the environment:
//
//	KONSOLGW_API_URL    gateway API base, default http://127.0.0.1:9900/api/v1
//	KONSOLGW_API_TOKEN  API token created under Settings > API tokens
//	KONSOLGW_INSECURE   "1" to accept the gateway's self-signed TLS certificate
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"haproxy-gui/internal/mcp"
)

// DefaultAPIURL is where the gateway listens when it is not behind HAProxy.
const DefaultAPIURL = "http://127.0.0.1:9900/api/v1"

// JSONRPCResponse is kept as an alias so tests can decode replies.
type JSONRPCResponse = mcp.Response

// MCPServer reads JSON-RPC lines from In and writes replies to Out, calling
// the gateway API over HTTP.
type MCPServer struct {
	APIURL     string
	APIToken   string
	HTTPClient *http.Client
	In         io.Reader
	Out        io.Writer
}

func NewMCPServer(apiURL, apiToken string, in io.Reader, out io.Writer) *MCPServer {
	if apiURL == "" {
		apiURL = DefaultAPIURL
	}
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	return &MCPServer{APIURL: apiURL, APIToken: apiToken, HTTPClient: http.DefaultClient, In: in, Out: out}
}

// Do implements mcp.Backend.
func (s *MCPServer) Do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.APIURL+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.APIToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, b, err
}

func (s *MCPServer) Run() error {
	core := &mcp.Server{Backend: s}
	scanner := bufio.NewScanner(s.In)
	scanner.Buffer(make([]byte, 64*1024), mcp.MaxBodyBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var req mcp.Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.write(mcp.ParseErrorResponse())
			continue
		}
		if resp := core.Handle(context.Background(), req); resp != nil {
			s.write(resp)
		}
	}
	return scanner.Err()
}

func (s *MCPServer) write(resp *mcp.Response) {
	b, _ := json.Marshal(resp)
	fmt.Fprintln(s.Out, string(b))
}

func main() {
	srv := NewMCPServer(os.Getenv("KONSOLGW_API_URL"), os.Getenv("KONSOLGW_API_TOKEN"), os.Stdin, os.Stdout)
	srv.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	if os.Getenv("KONSOLGW_INSECURE") == "1" {
		// The gateway is usually reached by IP with a self-signed certificate.
		srv.HTTPClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	if err := srv.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}
