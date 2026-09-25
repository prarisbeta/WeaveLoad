package runtime

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSocket starts a Unix listener that hands each accepted connection's
// first line to handler and writes back whatever handler returns, then
// closes the connection (mirrors HAProxy's one-shot Runtime API socket).
func fakeSocket(t *testing.T, handler func(cmd string) string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "haproxy.sock")

	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, _ := bufio.NewReader(conn).ReadString('\n')
				cmd := strings.TrimRight(line, "\r\n")
				_, _ = conn.Write([]byte(handler(cmd)))
			}()
		}
	}()

	return path
}

func TestShowStat_ReturnsRawBody(t *testing.T) {
	sock := fakeSocket(t, func(cmd string) string {
		if cmd != "show stat" {
			t.Errorf("unexpected command: %q", cmd)
		}
		return "# pxname,svname,...\nhttp_oms,node1,...\n"
	})
	c := New(sock)
	c.Timeout = time.Second

	out, err := c.ShowStat()
	if err != nil {
		t.Fatalf("ShowStat: %v", err)
	}
	if !strings.Contains(out, "http_oms,node1") {
		t.Errorf("unexpected body: %q", out)
	}
}

func TestSetServerState_SendsExactCommand(t *testing.T) {
	var got string
	sock := fakeSocket(t, func(cmd string) string {
		got = cmd
		return "" // empty body = success
	})
	c := New(sock)
	c.Timeout = time.Second

	if err := c.SetServerState("http_oms", "node1", StateDrain); err != nil {
		t.Fatalf("SetServerState: %v", err)
	}
	want := "set server http_oms/node1 state drain"
	if got != want {
		t.Errorf("command = %q, want %q", got, want)
	}
}

func TestSetServerState_RejectsBadState(t *testing.T) {
	sock := fakeSocket(t, func(string) string { return "" })
	c := New(sock)

	if err := c.SetServerState("http_oms", "node1", "banana"); err == nil {
		t.Fatal("expected error for invalid state, got nil")
	}
}

func TestSetServerState_ErrorReplyBecomesGoError(t *testing.T) {
	sock := fakeSocket(t, func(string) string {
		return "No such server.\n"
	})
	c := New(sock)
	c.Timeout = time.Second

	err := c.SetServerState("http_oms", "ghost", StateReady)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "No such server") {
		t.Errorf("error = %v, want to contain haproxy reply", err)
	}
}

// --- injection safety: these are the load-bearing tests for this package ---

func TestSetServerState_RejectsInjectionInBackendName(t *testing.T) {
	sock := fakeSocket(t, func(cmd string) string {
		t.Errorf("socket should never be contacted, got command: %q", cmd)
		return ""
	})
	c := New(sock)

	malicious := "http_oms\nset server other/node1 state maint"
	err := c.SetServerState(malicious, "node1", StateMaint)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var badName *ErrInvalidName
	if !errorsAs(err, &badName) {
		t.Errorf("error = %v, want *ErrInvalidName", err)
	}
}

func TestSetServerState_RejectsInjectionInServerName(t *testing.T) {
	c := New(fakeSocket(t, func(cmd string) string {
		t.Errorf("socket should never be contacted, got command: %q", cmd)
		return ""
	}))

	err := c.SetServerState("http_oms", "node1; set server http_oms/node2 state maint", StateMaint)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestValidName(t *testing.T) {
	cases := map[string]bool{
		"http_oms":              true,
		"node01":                true,
		"cdn.cni.net.id":        true,
		"a-b_c.d":               true,
		"":                      false,
		"has space":             false,
		"newline\nhere":         false,
		"semi;colon":            false,
		strings.Repeat("a", 65): false,
		strings.Repeat("a", 64): true,
	}
	for in, want := range cases {
		if got := ValidName(in); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSetServerWeight_RejectsBadWeight(t *testing.T) {
	c := New(fakeSocket(t, func(string) string { return "" }))
	for _, bad := range []string{"abc", "-1", "1000", "50%%", "50; drop"} {
		if err := c.SetServerWeight("http_oms", "node1", bad); err == nil {
			t.Errorf("weight %q: expected error, got nil", bad)
		}
	}
}

func TestAddMapEntry_RejectsWhitespaceInValue(t *testing.T) {
	c := New(fakeSocket(t, func(string) string { return "" }))
	err := c.AddMapEntry("/etc/haproxy/maps/hosts_http.map", "evil.example.com", "http_oms extra")
	if err == nil {
		t.Fatal("expected error for value containing whitespace")
	}
}

func TestSetMapEntry_SendsExactCommand(t *testing.T) {
	var got string
	c := New(fakeSocket(t, func(cmd string) string {
		got = cmd
		return ""
	}))
	if err := c.SetMapEntry("/etc/haproxy/maps/hosts_http.map", "app.example.id", "http_new"); err != nil {
		t.Fatalf("SetMapEntry: %v", err)
	}
	want := "set map /etc/haproxy/maps/hosts_http.map app.example.id http_new"
	if got != want {
		t.Errorf("command = %q, want %q", got, want)
	}
}

func TestSetMapEntry_RejectsWhitespaceInValue(t *testing.T) {
	c := New(fakeSocket(t, func(string) string { return "" }))
	err := c.SetMapEntry("/etc/haproxy/maps/hosts_http.map", "app.example.id", "http new")
	if err == nil {
		t.Fatal("expected error for value containing whitespace")
	}
}

func TestSetMapEntry_ErrorReplyBecomesGoError(t *testing.T) {
	c := New(fakeSocket(t, func(string) string { return "No such entry.\n" }))
	err := c.SetMapEntry("/etc/haproxy/maps/hosts_http.map", "ghost.example.id", "http_new")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestDelMapEntry_SendsExactCommand(t *testing.T) {
	var got string
	c := New(fakeSocket(t, func(cmd string) string {
		got = cmd
		return ""
	}))
	if err := c.DelMapEntry("/etc/haproxy/maps/hosts_http.map", "old.example.com"); err != nil {
		t.Fatalf("DelMapEntry: %v", err)
	}
	want := "del map /etc/haproxy/maps/hosts_http.map old.example.com"
	if got != want {
		t.Errorf("command = %q, want %q", got, want)
	}
}

func TestDelMapEntry_RejectsWhitespaceInKey(t *testing.T) {
	c := New(fakeSocket(t, func(string) string { return "" }))
	err := c.DelMapEntry("/etc/haproxy/maps/hosts_http.map", "evil key")
	if err == nil {
		t.Fatal("expected error for key containing whitespace")
	}
}

func TestDelMapEntry_ErrorReplyBecomesGoError(t *testing.T) {
	c := New(fakeSocket(t, func(string) string { return "No such entry.\n" }))
	err := c.DelMapEntry("/etc/haproxy/maps/hosts_http.map", "ghost.example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// errorsAs avoids importing "errors" just for one helper in tests.
func errorsAs(err error, target **ErrInvalidName) bool {
	e, ok := err.(*ErrInvalidName)
	if ok {
		*target = e
	}
	return ok
}
