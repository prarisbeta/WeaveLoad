package security

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// A tiny RESP-speaking fake, mirroring internal/redisping's own test helper,
// duplicated here (rather than exported from redisping) since it's only
// needed to verify the Runner calls redisping.Set — not to test RESP
// parsing itself, which redisping's own tests already cover.

var fakeRedisMu sync.Mutex
var fakeRedisLast []string

func startFakeRedisForTest(t *testing.T) string {
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
					cmd, err := readRESPArrayForTest(r)
					if err != nil {
						return
					}
					fakeRedisMu.Lock()
					fakeRedisLast = cmd
					fakeRedisMu.Unlock()
					if _, err := conn.Write([]byte("+OK\r\n")); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func fakeRedisLastCommand() []string {
	fakeRedisMu.Lock()
	defer fakeRedisMu.Unlock()
	return fakeRedisLast
}

func splitAddr(addr string) (string, string, error) {
	return net.SplitHostPort(addr)
}

func readRESPArrayForTest(r *bufio.Reader) ([]string, error) {
	head, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	head = strings.TrimRight(head, "\r\n")
	if !strings.HasPrefix(head, "*") {
		return nil, io.ErrUnexpectedEOF
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
