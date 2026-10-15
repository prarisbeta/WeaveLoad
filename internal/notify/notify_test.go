package notify

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recChannel struct {
	mu    sync.Mutex
	sent  []string
	err   error
	calls int
}

func (r *recChannel) Name() string { return "rec" }
func (r *recChannel) Send(_ context.Context, text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.sent = append(r.sent, text)
	return nil
}

func TestManyNoticesBecomeOneDigest(t *testing.T) {
	ch := &recChannel{}
	n := &Notifier{Channels: []Channel{ch}, Hostname: "gw1"}
	for i := 0; i < 30; i++ {
		n.Notify(Notice{Severity: "high", Title: "SQLi dari 203.0.113.9"})
	}
	n.Notify(Notice{Severity: "critical", Title: "Log4Shell dari 198.51.100.4", Detail: "3 hit\nT1190"})

	if got := n.Flush(context.Background()); got != 31 {
		t.Fatalf("flushed %d, want 31", got)
	}
	if len(ch.sent) != 1 {
		t.Fatalf("sent %d messages, want exactly one digest", len(ch.sent))
	}
	d := ch.sent[0]
	if !strings.HasPrefix(d, "[gw1] 31 peringatan (1 critical, 30 high)") {
		t.Errorf("header = %q", strings.SplitN(d, "\n", 2)[0])
	}
	if strings.Index(d, "Log4Shell") > strings.Index(d, "SQLi") {
		t.Error("the critical notice must come first")
	}
	if !strings.Contains(d, "3 hit T1190") || !strings.Contains(d, "dan 16 lainnya") {
		t.Errorf("digest = %s", d)
	}
	if n.Flush(context.Background()) != 0 || len(ch.sent) != 1 {
		t.Error("an empty buffer must send nothing")
	}
}

func TestSeverityFilter(t *testing.T) {
	ch := &recChannel{}
	n := &Notifier{Channels: []Channel{ch}}
	n.Notify(Notice{Severity: "low", Title: "a"})
	n.Notify(Notice{Severity: "medium", Title: "b"})
	if n.Flush(context.Background()) != 0 {
		t.Error("below the default high threshold must be dropped")
	}
	n.MinSeverity = "medium"
	n.Notify(Notice{Severity: "medium", Title: "b"})
	if n.Flush(context.Background()) != 1 {
		t.Error("medium must pass when MinSeverity is medium")
	}
}

func TestFailedDeliveryIsRetriedOnceAndNeverGrowsUnbounded(t *testing.T) {
	ch := &recChannel{err: errors.New("down")}
	n := &Notifier{Channels: []Channel{ch}, MaxBuffer: 5}
	n.Notify(Notice{Severity: "high", Title: "x"})
	if n.Flush(context.Background()) != 0 {
		t.Fatal("reported delivery although the channel failed")
	}
	ch.err = nil
	if n.Flush(context.Background()) != 1 {
		t.Error("the notice was lost after a failed delivery")
	}
	for i := 0; i < 500; i++ {
		n.Notify(Notice{Severity: "high", Title: "flood"})
	}
	n.mu.Lock()
	size, dropped := len(n.pending), n.dropped
	n.mu.Unlock()
	if size > 50 || dropped == 0 {
		t.Errorf("buffer = %d dropped = %d; the queue must be capped", size, dropped)
	}
}

func TestNilAndEmptyNotifierAreNoOps(t *testing.T) {
	var n *Notifier
	n.Notify(Notice{Severity: "critical"}) // must not panic
	(&Notifier{}).Notify(Notice{Severity: "critical"})
}

func TestWebhookAndTelegramPayloads(t *testing.T) {
	var gotBody, gotType, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotType, gotPath = string(b), r.Header.Get("Content-Type"), r.URL.Path
	}))
	defer srv.Close()

	if err := (&Webhook{URL: srv.URL + "/hook"}).Send(context.Background(), "halo"); err != nil {
		t.Fatal(err)
	}
	if gotType != "application/json" || gotBody != `{"text":"halo"}` {
		t.Errorf("webhook: %s %s", gotType, gotBody)
	}
	if err := (&Telegram{Token: "123:abc", ChatID: "-100", BaseURL: srv.URL}).Send(context.Background(), "halo dunia"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/bot123:abc/sendMessage" || !strings.Contains(gotBody, "chat_id=-100") || !strings.Contains(gotBody, "halo+dunia") {
		t.Errorf("telegram: %s %s", gotPath, gotBody)
	}
}

func TestHTTPErrorStatusIsAnErrorAndSecretsStayOutOfIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer srv.Close()
	if err := (&Webhook{URL: srv.URL}).Send(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v", err)
	}
	// A connection failure must not echo the secret-bearing URL into logs.
	err := (&Telegram{Token: "SECRET-TOKEN", ChatID: "1", BaseURL: "http://127.0.0.1:1"}).Send(context.Background(), "x")
	if err == nil || strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Errorf("err = %v", err)
	}
}

func TestRunFlushesOnContextEnd(t *testing.T) {
	ch := &recChannel{}
	n := &Notifier{Channels: []Channel{ch}, Window: time.Hour}
	n.Notify(Notice{Severity: "critical", Title: "last words"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	cancel()
	<-done
	if len(ch.sent) != 1 {
		t.Errorf("sent %d on shutdown, want the pending digest", len(ch.sent))
	}
}
