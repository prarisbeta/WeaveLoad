package ai

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGeminiProvider_SendsKeyInHeaderAndParsesReply(t *testing.T) {
	var gotKey, gotURL, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotURL = r.Header.Get("x-goog-api-key"), r.URL.String()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"{\"risk\":\"HIGH\"}"}]}}]}`))
	}))
	defer srv.Close()

	p := &GeminiProvider{APIKey: "secret-key", BaseURL: srv.URL}
	out, err := p.Analyze(context.Background(), "sys", "usr")
	if err != nil || out != `{"risk":"HIGH"}` {
		t.Fatalf("Analyze = %q, %v", out, err)
	}
	if gotKey != "secret-key" {
		t.Errorf("x-goog-api-key = %q", gotKey)
	}
	if strings.Contains(gotURL, "secret-key") || strings.Contains(gotURL, "key=") {
		t.Errorf("API key leaked into URL: %s", gotURL)
	}
	if !strings.Contains(gotURL, "gemini-2.0-flash:generateContent") {
		t.Errorf("default model missing from URL: %s", gotURL)
	}
	if !strings.Contains(gotBody, "sys") || !strings.Contains(gotBody, "usr") {
		t.Errorf("prompts missing from body: %s", gotBody)
	}
}

func TestGeminiProvider_Errors(t *testing.T) {
	if _, err := (&GeminiProvider{}).Analyze(context.Background(), "s", "u"); err == nil {
		t.Error("missing key: want error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "quota", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	if _, err := (&GeminiProvider{APIKey: "k", BaseURL: srv.URL}).Analyze(context.Background(), "s", "u"); err == nil || !strings.Contains(err.Error(), "429") {
		t.Errorf("HTTP 429: err = %v", err)
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"candidates":[]}`)) }))
	defer empty.Close()
	if _, err := (&GeminiProvider{APIKey: "k", BaseURL: empty.URL}).Analyze(context.Background(), "s", "u"); err == nil {
		t.Error("empty candidates: want error")
	}
}

func TestExtractJSON(t *testing.T) {
	for in, want := range map[string]string{
		"```json\n{\"a\":1}\n```":    `{"a":1}`,
		"here: {\"a\":{\"b\":2}} ok": `{"a":{"b":2}}`,
		"no object":                  "no object",
	} {
		if got := ExtractJSON(in); got != want {
			t.Errorf("ExtractJSON(%q) = %q, want %q", in, got, want)
		}
	}
}

type countingProvider struct {
	calls atomic.Int32
	err   error
}

func (c *countingProvider) Analyze(context.Context, string, string) (string, error) {
	c.calls.Add(1)
	return "answer", c.err
}

func TestCachedProvider(t *testing.T) {
	inner := &countingProvider{}
	now := time.Now()
	c := &CachedProvider{Inner: inner, TTL: time.Minute, Now: func() time.Time { return now }}

	for i := 0; i < 3; i++ {
		if out, err := c.Analyze(context.Background(), "s", "u"); err != nil || out != "answer" {
			t.Fatalf("Analyze = %q, %v", out, err)
		}
	}
	if n := inner.calls.Load(); n != 1 {
		t.Errorf("upstream calls = %d, want 1 (cached)", n)
	}
	_, _ = c.Analyze(context.Background(), "s", "other")
	if n := inner.calls.Load(); n != 2 {
		t.Errorf("different prompt must miss the cache, calls = %d", n)
	}
	now = now.Add(2 * time.Minute)
	_, _ = c.Analyze(context.Background(), "s", "u")
	if n := inner.calls.Load(); n != 3 {
		t.Errorf("expired entry must refetch, calls = %d", n)
	}
}

func TestCachedProvider_DoesNotCacheErrors(t *testing.T) {
	inner := &countingProvider{err: errors.New("boom")}
	c := &CachedProvider{Inner: inner}
	_, _ = c.Analyze(context.Background(), "s", "u")
	_, _ = c.Analyze(context.Background(), "s", "u")
	if n := inner.calls.Load(); n != 2 {
		t.Errorf("errors must not be cached, calls = %d", n)
	}
}

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if p := FromEnv(env(nil)); p != nil {
		t.Errorf("no keys: want nil provider, got %T", p)
	}
	p := FromEnv(env(map[string]string{"KONSOLGW_GEMINI_API_KEY": "k", "KONSOLGW_ANTHROPIC_API_KEY": "a"}))
	cp, ok := p.(*CachedProvider)
	if !ok {
		t.Fatalf("got %T, want *CachedProvider", p)
	}
	if _, ok := cp.Inner.(*GeminiProvider); !ok {
		t.Errorf("Gemini must win when both keys are set, got %T", cp.Inner)
	}
	p = FromEnv(env(map[string]string{"KONSOLGW_ANTHROPIC_API_KEY": "a"}))
	if _, ok := p.(*CachedProvider).Inner.(*AnthropicProvider); !ok {
		t.Errorf("anthropic-only: wrong inner provider")
	}
}
