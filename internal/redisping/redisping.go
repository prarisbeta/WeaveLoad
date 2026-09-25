// Package redisping does one thing: check that a Redis-compatible server at
// a given address is reachable and answers PING. It is not a Redis client —
// there is no pooling, no pipelining, no support for bulk/array replies —
// just enough of RESP to authenticate, optionally SELECT a DB, and confirm
// a PONG comes back, for the Settings page's "test connection" button.
package redisping

import (
	"crypto/tls"
	"fmt"
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
// PING and requires a successful (non-error) reply. Every step returns as
// soon as the server reports a RESP error, so the caller sees exactly which
// step failed (connect, auth, select, or ping).
func Ping(o Options) error {
	conn, err := connect(o)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := command(conn, "PING"); err != nil {
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
	if err := command(conn, "RPUSH", key, value); err != nil {
		return fmt.Errorf("rpush %s: %w", key, err)
	}
	return nil
}

// connect dials Host:Port and, if configured, authenticates and selects DB —
// the setup Ping and Push both need before sending their own command.
func connect(o Options) (net.Conn, error) {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	addr := net.JoinHostPort(o.Host, o.Port)
	dialer := net.Dialer{Timeout: o.Timeout}

	var conn net.Conn
	var err error
	if o.TLS {
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, &tls.Config{ServerName: o.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(o.Timeout))

	if o.Password != "" {
		if err := command(conn, "AUTH", o.Password); err != nil {
			conn.Close()
			return nil, fmt.Errorf("auth: %w", err)
		}
	}
	if o.DB != 0 {
		if err := command(conn, "SELECT", strconv.Itoa(o.DB)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("select db %d: %w", o.DB, err)
		}
	}
	return conn, nil
}

// command sends args as a RESP array and reads back one line, treating a
// leading '-' (RESP error) as failure. Bulk/array replies aren't expected
// from AUTH/SELECT/PING and aren't parsed here.
func command(conn net.Conn, args ...string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read reply: %w", err)
	}
	line := strings.TrimRight(string(buf[:n]), "\r\n")
	if strings.HasPrefix(line, "-") {
		return fmt.Errorf("%s", strings.TrimPrefix(line, "-"))
	}
	return nil
}
