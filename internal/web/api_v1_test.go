package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"haproxy-gui/internal/store"
)

func TestAPIV1StatusHandler_ReturnsLiveAndSystemInfo(t *testing.T) {
	st := fakeStats{body: poolStats}
	h := &APIV1StatusHandler{Stats: st}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", rec.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success {
		t.Errorf("success=%v, want true", resp.Success)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok || data["live"] != true {
		t.Errorf("data=%v, want live:true", data)
	}
}

func TestAPIV1BackendsHandler_ListsBackends(t *testing.T) {
	st := fakeStats{body: poolStats}
	h := &APIV1BackendsHandler{Stats: st}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", rec.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success {
		t.Errorf("success=%v, want true", resp.Success)
	}
	backends, ok := resp.Data.([]any)
	if !ok || len(backends) == 0 {
		t.Errorf("backends=%v, want non-empty slice", resp.Data)
	}
}

func TestAPIV1ServersHandler_ListsServers(t *testing.T) {
	st := fakeStats{body: poolStats}
	h := &APIV1ServersHandler{Stats: st}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", rec.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success {
		t.Errorf("success=%v, want true", resp.Success)
	}
	servers, ok := resp.Data.([]any)
	if !ok || len(servers) == 0 {
		t.Errorf("servers=%v, want non-empty slice", resp.Data)
	}
}

func TestAPIV1NodesHandler_ListsNodes(t *testing.T) {
	cs := &fakeConfigStore{active: poolCfg}
	st := fakeStats{body: poolStats}
	h := &APIV1NodesHandler{Config: cs, Stats: st}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", rec.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success {
		t.Errorf("success=%v, want true", resp.Success)
	}
	nodes, ok := resp.Data.([]any)
	if !ok || len(nodes) == 0 {
		t.Errorf("nodes=%v, want non-empty slice", resp.Data)
	}
}

func TestAPIV1IncidentsHandler_ListsIncidents(t *testing.T) {
	st := newFakeIncidentStore()
	_, _ = st.CreateIncident(store.Incident{Title: "API Abuse", Status: "open"}, nil)

	h := &APIV1IncidentsHandler{Store: st}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", rec.Code)
	}
	var resp APIResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success {
		t.Errorf("success=%v, want true", resp.Success)
	}
}

func TestAPIV1IncidentDetailHandler_ReturnsDetails(t *testing.T) {
	st := newFakeIncidentStore()
	incID, _ := st.CreateIncident(store.Incident{Title: "API Abuse", Status: "open"}, nil)

	h := &APIV1IncidentDetailHandler{Store: st}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/1", nil)
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", rec.Code)
	}
	var resp APIResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success {
		t.Errorf("success=%v, want true", resp.Success)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok || data["incident"] == nil {
		t.Errorf("data=%v, want incident key", data)
	}
	_ = incID
}
