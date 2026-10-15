package fleet

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type memRepo struct {
	payloads map[string][]byte
	times    map[string]time.Time
}

func newRepo() *memRepo {
	return &memRepo{payloads: map[string][]byte{}, times: map[string]time.Time{}}
}
func (m *memRepo) UpsertFleetNode(n string, p []byte, at time.Time) error {
	m.payloads[n], m.times[n] = p, at
	return nil
}
func (m *memRepo) ListFleetNodes() (map[string][]byte, map[string]time.Time, error) {
	return m.payloads, m.times, nil
}

func post(h http.Handler, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/v1/fleet/report", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const goodReport = `{"node":"gw-surabaya","version":"1.2","haproxy_up":true,"sessions":42,"backends":[{"name":"web","up":3,"down":1}],"high_risk_ips":2}`

func TestHub_AcceptsAValidReportAndListsIt(t *testing.T) {
	repo := newRepo()
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	h := &Hub{Repo: repo, Token: "s3cret", Now: func() time.Time { return now }}

	if rec := post(h, "s3cret", goodReport); rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d: %s", rec.Code, rec.Body)
	}
	nodes, err := h.List()
	if err != nil || len(nodes) != 1 {
		t.Fatalf("nodes = %+v, err %v", nodes, err)
	}
	n := nodes[0]
	if n.Node != "gw-surabaya" || n.Sessions != 42 || n.HighRiskIPs != 2 || n.Backends[0].Down != 1 {
		t.Errorf("node = %+v", n)
	}
	if n.Stale(now.Add(time.Minute)) || !n.Stale(now.Add(4*time.Minute)) {
		t.Error("staleness window is wrong")
	}
}

func TestHub_RejectsBadCallers(t *testing.T) {
	h := &Hub{Repo: newRepo(), Token: "s3cret"}
	for name, c := range map[string]struct {
		token, body string
		want        int
	}{
		"no token":        {"", goodReport, http.StatusUnauthorized},
		"wrong token":     {"nope", goodReport, http.StatusUnauthorized},
		"not json":        {"s3cret", "hello", http.StatusBadRequest},
		"bad node name":   {"s3cret", `{"node":"../etc/passwd"}`, http.StatusBadRequest},
		"empty node name": {"s3cret", `{"node":""}`, http.StatusBadRequest},
	} {
		if rec := post(h, c.token, c.body); rec.Code != c.want {
			t.Errorf("%s: code = %d, want %d", name, rec.Code, c.want)
		}
	}
	if rec := post(&Hub{Repo: newRepo()}, "", goodReport); rec.Code != http.StatusNotFound {
		t.Errorf("a hub without a token must be disabled, got %d", rec.Code)
	}
}

func TestHub_LimitsBodySizeAndNodeCount(t *testing.T) {
	h := &Hub{Repo: newRepo(), Token: "t"}
	huge := `{"node":"a","version":"` + strings.Repeat("x", MaxReportBytes) + `"}`
	if rec := post(h, "t", huge); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", rec.Code)
	}
	for i := 0; i < MaxNodes; i++ {
		h.Repo.UpsertFleetNode(fmt.Sprintf("n%d", i), []byte(`{}`), time.Now())
	}
	if rec := post(h, "t", `{"node":"brand-new-node"}`); rec.Code != http.StatusForbidden {
		t.Errorf("past the node limit: %d", rec.Code)
	}
	existing := ""
	for n := range h.Repo.(*memRepo).payloads {
		existing = n
		break
	}
	if rec := post(h, "t", `{"node":"`+existing+`"}`); rec.Code != http.StatusNoContent {
		t.Errorf("a known node must still be able to report: %d", rec.Code)
	}
}

func TestReportDown(t *testing.T) {
	if !(Report{HAProxyUp: false}).Down() {
		t.Error("HAProxy unreachable must count as down")
	}
	if !(Report{HAProxyUp: true, Backends: []BackendHealth{{Name: "w", Up: 0, Down: 2}}}).Down() {
		t.Error("a backend with all servers down must count as down")
	}
	if (Report{HAProxyUp: true, Backends: []BackendHealth{{Name: "w", Up: 1, Down: 1}}}).Down() {
		t.Error("a degraded but serving backend is not down")
	}
}

func TestAgentPushesToTheHub(t *testing.T) {
	repo := newRepo()
	hub := &Hub{Repo: repo, Token: "tok"}
	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/fleet/report", hub)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	a := &Agent{HubURL: srv.URL + "/", Token: "tok", Collect: func(context.Context) Report {
		return Report{Node: "edge-1", HAProxyUp: true, Sessions: 7}
	}}
	if err := a.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	if nodes, _ := hub.List(); len(nodes) != 1 || nodes[0].Sessions != 7 || nodes[0].SentAt.IsZero() {
		t.Errorf("nodes = %+v", nodes)
	}

	a.Token = "wrong"
	if err := a.Push(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a wrong token must surface the status: %v", err)
	}
	a.Collect = func(context.Context) Report { return Report{Node: "bad name!"} }
	if err := a.Push(context.Background()); err == nil {
		t.Error("an invalid report must not be sent")
	}
}
