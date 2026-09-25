// Package runtime talks to HAProxy's Runtime API over the stats admin socket
// (a Unix domain socket, level admin). One command per connection, matching
// HAProxy's own protocol: write the command line, read until the socket closes.
package runtime

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Client sends Runtime API commands to a single HAProxy stats socket.
type Client struct {
	SocketPath string
	Timeout    time.Duration
}

func New(socketPath string) *Client {
	return &Client{SocketPath: socketPath, Timeout: 5 * time.Second}
}

// nameRE matches the backend/server/ACL identifiers HAProxy itself allows.
// Anything else is rejected before it ever reaches the socket, so a value
// coming from user input can never inject a second command via newlines,
// semicolons or spaces.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidName reports whether s is safe to interpolate into a Runtime API command.
func ValidName(s string) bool {
	return nameRE.MatchString(s)
}

// ErrInvalidName is returned when a caller-supplied identifier fails ValidName.
type ErrInvalidName struct{ Field, Value string }

func (e *ErrInvalidName) Error() string {
	return fmt.Sprintf("invalid %s: %q", e.Field, e.Value)
}

// run sends a single command line and returns the full response body.
func (c *Client) run(cmd string) (string, error) {
	conn, err := net.DialTimeout("unix", c.SocketPath, c.Timeout)
	if err != nil {
		return "", fmt.Errorf("connect to haproxy socket: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(c.Timeout))

	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return "", fmt.Errorf("write command: %w", err)
	}

	var sb strings.Builder
	r := bufio.NewReader(conn)
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break // EOF (or timeout) ends the response; HAProxy closes after replying.
		}
	}
	return sb.String(), nil
}

// ShowStat returns the raw CSV body of "show stat".
func (c *Client) ShowStat() (string, error) {
	return c.run("show stat")
}

// ShowInfo returns the raw body of "show info".
func (c *Client) ShowInfo() (string, error) {
	return c.run("show info")
}

// ServerState is one of the states HAProxy accepts for "set server ... state".
type ServerState string

const (
	StateReady ServerState = "ready"
	StateDrain ServerState = "drain"
	StateMaint ServerState = "maint"
)

// SetServerState enables, drains or maintenance-disables one server.
func (c *Client) SetServerState(backend, server string, state ServerState) error {
	if !ValidName(backend) {
		return &ErrInvalidName{"backend", backend}
	}
	if !ValidName(server) {
		return &ErrInvalidName{"server", server}
	}
	switch state {
	case StateReady, StateDrain, StateMaint:
	default:
		return fmt.Errorf("invalid server state: %q", state)
	}
	out, err := c.run(fmt.Sprintf("set server %s/%s state %s", backend, server, state))
	return wrapIfError(out, err)
}

// SetServerWeight sets a server's load-balancing weight (0-256, or "NN%").
func (c *Client) SetServerWeight(backend, server string, weight string) error {
	if !ValidName(backend) {
		return &ErrInvalidName{"backend", backend}
	}
	if !ValidName(server) {
		return &ErrInvalidName{"server", server}
	}
	if !weightRE.MatchString(weight) {
		return fmt.Errorf("invalid weight: %q", weight)
	}
	out, err := c.run(fmt.Sprintf("set weight %s/%s %s", backend, server, weight))
	return wrapIfError(out, err)
}

var weightRE = regexp.MustCompile(`^[0-9]{1,3}%?$`)

// AddMapEntry adds one "<key> <value>" pair to a runtime map, without
// persisting it to the map file on disk (callers should also append to the
// file so the entry survives a reload).
func (c *Client) AddMapEntry(mapFile, key, value string) error {
	if strings.ContainsAny(mapFile, "\n\r") || !strings.HasPrefix(mapFile, "/") {
		return fmt.Errorf("invalid map file path: %q", mapFile)
	}
	if strings.ContainsAny(key, "\n\r ") || strings.ContainsAny(value, "\n\r ") {
		return fmt.Errorf("map key/value must not contain whitespace or newlines")
	}
	out, err := c.run(fmt.Sprintf("add map %s %s %s", mapFile, key, value))
	return wrapIfError(out, err)
}

// wrapIfError turns a non-empty Runtime API reply into a Go error. HAProxy
// replies with an empty body on success and a one-line message on failure.
func wrapIfError(out string, err error) error {
	if err != nil {
		return err
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	return fmt.Errorf("haproxy: %s", out)
}
