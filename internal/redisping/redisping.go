// Package redisping does just enough of RESP to talk to a Redis-compatible
// server for haproxy-gui's needs: check connectivity (PING), push events onto
// a list (RPUSH, for the rate-limit queue), and read/drain that list (LRANGE,
// LLEN, LPOP, for the queue viewer page and the external consumption API).
// It is not a general Redis client — no pooling, no pipelining, no support
// for the rest of the command set.
package redisping

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Options configures one connectivity check.
type Options struct {
	Host     string
	Port     string
	Password string
	DB       int
	TLS      bool
	Timeout  time.Duration // defaults to 5s
}

// Ping dials Host:Port, optionally authenticates and selects DB, then sends
// PING and requires a successful (non-error) reply.
func Ping(o Options) error {
	conn, err := connect(o)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.command("PING"); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	return nil
}

// Push sends "RPUSH key value" — used to hand one event (already serialized
// by the caller, typically as JSON) to a Redis list acting as a simple
// queue. Like Ping, this opens and closes its own connection each call;
// callers pushing many events in a tight loop should batch them instead of
// calling this per-event.
func Push(o Options, key, value string) error {
	conn, err := connect(o)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.command("RPUSH", key, value); err != nil {
		return fmt.Errorf("rpush %s: %w", key, err)
	}
	return nil
}

// LLen returns the number of elements in key (0 if it doesn't exist) — used
// by the queue viewer to show the backlog size.
func LLen(o Options, key string) (int64, error) {
	conn, err := connect(o)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	reply, err := conn.command("LLEN", key)
	if err != nil {
		return 0, fmt.Errorf("llen %s: %w", key, err)
	}
	n, _ := reply.(int64)
	return n, nil
}

// LRange returns key's elements from start to stop inclusive (Redis's usual
// 0-based, negative-counts-from-the-end indexing — e.g. -200,-1 for "the
// last 200"), without removing them. Used by the queue viewer page, which
// only peeks at the backlog rather than consuming it.
func LRange(o Options, key string, start, stop int) ([]string, error) {
	conn, err := connect(o)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	reply, err := conn.command("LRANGE", key, strconv.Itoa(start), strconv.Itoa(stop))
	if err != nil {
		return nil, fmt.Errorf("lrange %s: %w", key, err)
	}
	return toStrings(reply), nil
}

// PopN removes and returns up to n elements from the head of key (oldest
// first, since events are RPUSHed onto the tail) — the destructive read the
// consumption API uses to hand events to a downstream consumer exactly
// once. It stops early, without error, once the list runs dry. n <= 0
// returns no elements.
func PopN(o Options, key string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	conn, err := connect(o)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		reply, err := conn.command("LPOP", key)
		if err != nil {
			return out, fmt.Errorf("lpop %s: %w", key, err)
		}
		if reply == nil {
			break // list is now empty
		}
		s, _ := reply.(string)
		out = append(out, s)
	}
	return out, nil
}

// Set sends "SET key value EX ttlSeconds", used to publish a snapshot (e.g.
// a security risk profile) with automatic expiry. ttl <= 0 sends a plain SET
// with no expiry.
func Set(o Options, key, value string, ttl time.Duration) error {
	conn, err := connect(o)
	if err != nil {
		return err
	}
	defer conn.Close()
	args := []string{"SET", key, value}
	if ttl > 0 {
		args = append(args, "EX", strconv.Itoa(int(ttl.Seconds())))
	}
	if _, err := conn.command(args...); err != nil {
		return fmt.Errorf("set %s: %w", key, err)
	}
	return nil
}

// LTrim trims key to the range [start, stop] (same indexing as LRange),
// discarding everything outside it — used to cap a list Redis key that
// would otherwise grow without bound.
func LTrim(o Options, key string, start, stop int) error {
	conn, err := connect(o)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.command("LTRIM", key, strconv.Itoa(start), strconv.Itoa(stop)); err != nil {
		return fmt.Errorf("ltrim %s: %w", key, err)
	}
	return nil
}

// toStrings converts an array reply's elements to strings, skipping any nil
// entries (RESP allows null bulk strings inside an array; none of our
// commands produce them, but this stays defensive rather than panicking).
func toStrings(reply any) []string {
	arr, _ := reply.([]any)
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// conn wraps a net.Conn with the buffered reader RESP replies need (bulk and
// array replies can span multiple reads, and a plain net.Conn.Read isn't
// guaranteed to return a whole reply in one call).
type conn struct {
	net.Conn
	r *bufio.Reader
}

// connect dials Host:Port and, if configured, authenticates and selects DB.
func connect(o Options) (*conn, error) {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	addr := net.JoinHostPort(o.Host, o.Port)
	dialer := net.Dialer{Timeout: o.Timeout}

	var nc net.Conn
	var err error
	if o.TLS {
		nc, err = tls.DialWithDialer(&dialer, "tcp", addr, &tls.Config{ServerName: o.Host, MinVersion: tls.VersionTLS12})
	} else {
		nc, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	_ = nc.SetDeadline(time.Now().Add(o.Timeout))
	c := &conn{Conn: nc, r: bufio.NewReader(nc)}

	if o.Password != "" {
		if _, err := c.command("AUTH", o.Password); err != nil {
			nc.Close()
			return nil, fmt.Errorf("auth: %w", err)
		}
	}
	if o.DB != 0 {
		if _, err := c.command("SELECT", strconv.Itoa(o.DB)); err != nil {
			nc.Close()
			return nil, fmt.Errorf("select db %d: %w", o.DB, err)
		}
	}
	return c, nil
}

// command sends args as a RESP array and returns the parsed reply: nil for a
// RESP nil bulk/array, string for a simple or bulk string, int64 for an
// integer reply, or []any for an array (of the same types, recursively). A
// RESP error reply ('-...') is returned as a Go error instead of a value.
func (c *conn) command(args ...string) (any, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := c.Write([]byte(b.String())); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	return readReply(c.r)
}

// readReply reads one RESP value, recursing once per nesting level for
// array replies.
func readReply(r *bufio.Reader) (any, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read reply: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, fmt.Errorf("empty reply")
	}

	switch line[0] {
	case '-':
		return nil, fmt.Errorf("%s", line[1:])
	case '+':
		return line[1:], nil
	case ':':
		n, err := strconv.ParseInt(line[1:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("malformed integer reply %q: %w", line, err)
		}
		return n, nil
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("malformed bulk length %q: %w", line, err)
		}
		if n < 0 {
			return nil, nil // nil bulk string
		}
		buf := make([]byte, n+2) // payload + trailing \r\n
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("read bulk payload: %w", err)
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("malformed array length %q: %w", line, err)
		}
		if n < 0 {
			return nil, nil // nil array
		}
		out := make([]any, n)
		for i := 0; i < n; i++ {
			v, err := readReply(r)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unexpected reply prefix %q", line[0])
	}
}
