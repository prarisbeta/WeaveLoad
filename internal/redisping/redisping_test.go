package redisping

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeRedis starts a TCP listener that reads one RESP array command per
// connection-round-trip and replies according to reply(cmd). It stops when
// the test ends.
func fakeRedis(t *testing.T, reply func(cmd []string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					cmd, err := readRESPArray(r)
					if err != nil {
						return
					}
					if _, err := conn.Write([]byte(reply(cmd))); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// readRESPArray reads one "*N\r\n$len\r\narg\r\n..." command — just enough
// to drive the fake server, mirroring what Ping's command() writes.
func readRESPArray(r *bufio.Reader) ([]string, error) {
	head, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	head = strings.TrimRight(head, "\r\n")
	if !strings.HasPrefix(head, "*") {
		return nil, err
	}
	var n int
	for _, c := range head[1:] {
		n = n*10 + int(c-'0')
	}
	var out []string
	for i := 0; i < n; i++ {
		lenLine, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		lenLine = strings.TrimRight(lenLine, "\r\n")
		var l int
		for _, c := range lenLine[1:] {
			l = l*10 + int(c-'0')
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		out = append(out, string(buf[:l]))
	}
	return out, nil
}

func splitHostPort(t *testing.T, addr string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	return host, port
}

func TestPing_Success(t *testing.T) {
	addr := fakeRedis(t, func(cmd []string) string { return "+OK\r\n" })
	host, port := splitHostPort(t, addr)

	if err := Ping(Options{Host: host, Port: port, Timeout: 2 * time.Second}); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestPing_AuthFailure(t *testing.T) {
	addr := fakeRedis(t, func(cmd []string) string {
		if len(cmd) > 0 && cmd[0] == "AUTH" {
			return "-ERR invalid password\r\n"
		}
		return "+OK\r\n"
	})
	host, port := splitHostPort(t, addr)

	err := Ping(Options{Host: host, Port: port, Password: "wrong", Timeout: 2 * time.Second})
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if !strings.Contains(err.Error(), "invalid password") {
		t.Errorf("error = %v, want it to mention the server's reply", err)
	}
}

func TestPush_SendsRPUSHAndSucceedsOnIntegerReply(t *testing.T) {
	var gotCmd []string
	addr := fakeRedis(t, func(cmd []string) string {
		gotCmd = cmd
		return ":1\r\n"
	})
	host, port := splitHostPort(t, addr)

	if err := Push(Options{Host: host, Port: port, Timeout: 2 * time.Second}, "events", `{"pool":"web"}`); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(gotCmd) != 3 || gotCmd[0] != "RPUSH" || gotCmd[1] != "events" || gotCmd[2] != `{"pool":"web"}` {
		t.Errorf("command sent = %v", gotCmd)
	}
}

func TestPush_ReportsServerError(t *testing.T) {
	addr := fakeRedis(t, func(cmd []string) string { return "-ERR wrong number of arguments\r\n" })
	host, port := splitHostPort(t, addr)

	err := Push(Options{Host: host, Port: port, Timeout: 2 * time.Second}, "events", "x")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPing_ConnectFailure(t *testing.T) {
	// Nothing listens on this port.
	err := Ping(Options{Host: "127.0.0.1", Port: "1", Timeout: 500 * time.Millisecond})
	if err == nil {
		t.Fatal("expected error connecting to a closed port")
	}
}
