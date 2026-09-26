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

func TestLLen_ParsesIntegerReply(t *testing.T) {
	addr := fakeRedis(t, func(cmd []string) string { return ":3\r\n" })
	host, port := splitHostPort(t, addr)

	n, err := LLen(Options{Host: host, Port: port, Timeout: 2 * time.Second}, "events")
	if err != nil {
		t.Fatalf("LLen: %v", err)
	}
	if n != 3 {
		t.Errorf("n = %d, want 3", n)
	}
}

func TestLRange_ParsesArrayOfBulkStrings(t *testing.T) {
	var gotCmd []string
	addr := fakeRedis(t, func(cmd []string) string {
		gotCmd = cmd
		return "*2\r\n$5\r\nfirst\r\n$6\r\nsecond\r\n"
	})
	host, port := splitHostPort(t, addr)

	got, err := LRange(Options{Host: host, Port: port, Timeout: 2 * time.Second}, "events", -2, -1)
	if err != nil {
		t.Fatalf("LRange: %v", err)
	}
	if len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Errorf("got = %v", got)
	}
	if len(gotCmd) != 4 || gotCmd[0] != "LRANGE" || gotCmd[1] != "events" || gotCmd[2] != "-2" || gotCmd[3] != "-1" {
		t.Errorf("command sent = %v", gotCmd)
	}
}

func TestLRange_EmptyArrayReply(t *testing.T) {
	addr := fakeRedis(t, func(cmd []string) string { return "*0\r\n" })
	host, port := splitHostPort(t, addr)

	got, err := LRange(Options{Host: host, Port: port, Timeout: 2 * time.Second}, "events", 0, -1)
	if err != nil {
		t.Fatalf("LRange: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got = %v, want empty", got)
	}
}

func TestPopN_StopsAtNilBulkWhenListRunsDry(t *testing.T) {
	replies := []string{"$3\r\none\r\n", "$3\r\ntwo\r\n", "$-1\r\n"}
	i := 0
	addr := fakeRedis(t, func(cmd []string) string {
		r := replies[i]
		i++
		return r
	})
	host, port := splitHostPort(t, addr)

	got, err := PopN(Options{Host: host, Port: port, Timeout: 2 * time.Second}, "events", 5)
	if err != nil {
		t.Fatalf("PopN: %v", err)
	}
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Errorf("got = %v, want [one two] (stopping once the list is empty)", got)
	}
}

func TestPopN_RespectsLimitWithoutDrainingFurther(t *testing.T) {
	calls := 0
	addr := fakeRedis(t, func(cmd []string) string {
		calls++
		return "$3\r\none\r\n"
	})
	host, port := splitHostPort(t, addr)

	got, err := PopN(Options{Host: host, Port: port, Timeout: 2 * time.Second}, "events", 2)
	if err != nil {
		t.Fatalf("PopN: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got = %v, want 2 elements", got)
	}
	if calls != 2 {
		t.Errorf("LPOP called %d times, want exactly 2", calls)
	}
}

func TestSet_SendsSETWithEX(t *testing.T) {
	var gotCmd []string
	addr := fakeRedis(t, func(cmd []string) string {
		gotCmd = cmd
		return "+OK\r\n"
	})
	host, port := splitHostPort(t, addr)

	if err := Set(Options{Host: host, Port: port, Timeout: 2 * time.Second}, "security:1.2.3.4", `{"score":50}`, 24*time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}
	want := []string{"SET", "security:1.2.3.4", `{"score":50}`, "EX", "86400"}
	if len(gotCmd) != len(want) {
		t.Fatalf("command sent = %v, want %v", gotCmd, want)
	}
	for i := range want {
		if gotCmd[i] != want[i] {
			t.Errorf("command sent = %v, want %v", gotCmd, want)
			break
		}
	}
}

func TestSet_NoTTLOmitsEX(t *testing.T) {
	var gotCmd []string
	addr := fakeRedis(t, func(cmd []string) string {
		gotCmd = cmd
		return "+OK\r\n"
	})
	host, port := splitHostPort(t, addr)

	if err := Set(Options{Host: host, Port: port, Timeout: 2 * time.Second}, "k", "v", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(gotCmd) != 3 || gotCmd[0] != "SET" {
		t.Errorf("command sent = %v, want a plain SET with no EX", gotCmd)
	}
}

func TestSet_ReportsServerError(t *testing.T) {
	addr := fakeRedis(t, func(cmd []string) string { return "-ERR busy\r\n" })
	host, port := splitHostPort(t, addr)

	if err := Set(Options{Host: host, Port: port, Timeout: 2 * time.Second}, "k", "v", time.Minute); err == nil {
		t.Fatal("expected error")
	}
}

func TestLTrim_SendsLTRIM(t *testing.T) {
	var gotCmd []string
	addr := fakeRedis(t, func(cmd []string) string {
		gotCmd = cmd
		return "+OK\r\n"
	})
	host, port := splitHostPort(t, addr)

	if err := LTrim(Options{Host: host, Port: port, Timeout: 2 * time.Second}, "events", 0, 999); err != nil {
		t.Fatalf("LTrim: %v", err)
	}
	if len(gotCmd) != 4 || gotCmd[0] != "LTRIM" || gotCmd[1] != "events" || gotCmd[2] != "0" || gotCmd[3] != "999" {
		t.Errorf("command sent = %v", gotCmd)
	}
}

func TestPopN_ZeroOrNegativeReturnsNothingWithoutConnecting(t *testing.T) {
	got, err := PopN(Options{Host: "127.0.0.1", Port: "1", Timeout: 500 * time.Millisecond}, "events", 0)
	if err != nil || len(got) != 0 {
		t.Errorf("PopN with n=0 = %v, %v, want nil, nil (and no connection attempt)", got, err)
	}
}
