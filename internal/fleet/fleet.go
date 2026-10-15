// Package fleet lets one gateway (the hub) show the state of other gateways
// (nodes). Each node runs the same binary and pushes a small status report to
// the hub over HTTPS; the hub never connects to a node, so nodes need no
// inbound port. This first stage is read-only: the hub shows every node's
// health and risk but cannot change a node's configuration.
package fleet

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// MaxReportBytes bounds one report body.
const MaxReportBytes = 64 << 10

// StaleAfter is how long a node may stay silent before the hub marks it stale.
const StaleAfter = 3 * time.Minute

var nodeNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// BackendHealth is one backend's server count.
type BackendHealth struct {
	Name string `json:"name"`
	Up   int    `json:"up"`
	Down int    `json:"down"`
}

// Report is what a node tells the hub. It deliberately holds no secrets,
// no client IPs and no configuration.
type Report struct {
	Node         string          `json:"node"`
	Version      string          `json:"version"`
	HAProxyUp    bool            `json:"haproxy_up"`
	Sessions     int             `json:"sessions"`
	Backends     []BackendHealth `json:"backends"`
	HighRiskIPs  int             `json:"high_risk_ips"`
	OpenEvents   int             `json:"open_events"`
	OpenIncident int             `json:"open_incidents"`
	KillSwitch   bool            `json:"kill_switch"`
	SentAt       time.Time       `json:"sent_at"`
}

// Validate checks a report received from the network.
func (r Report) Validate() error {
	if !nodeNameRE.MatchString(r.Node) {
		return errors.New("node must be 1-64 characters of letters, digits, dot, dash or underscore")
	}
	if len(r.Backends) > 500 {
		return errors.New("too many backends in one report")
	}
	for _, b := range r.Backends {
		if len(b.Name) > 128 {
			return errors.New("backend name too long")
		}
	}
	if len(r.Version) > 64 {
		return errors.New("version too long")
	}
	return nil
}

// Down reports whether the node needs attention: HAProxy unreachable or a
// backend with every server down.
func (r Report) Down() bool {
	if !r.HAProxyUp {
		return true
	}
	for _, b := range r.Backends {
		if b.Up == 0 && b.Down > 0 {
			return true
		}
	}
	return false
}

// Node is a stored report plus when the hub got it.
type Node struct {
	Report
	ReceivedAt time.Time
}

// Stale reports whether the node has been silent too long at time now.
func (n Node) Stale(now time.Time) bool { return now.Sub(n.ReceivedAt) > StaleAfter }

// Repo stores the latest report per node.
type Repo interface {
	UpsertFleetNode(name string, payload []byte, receivedAt time.Time) error
	ListFleetNodes() (map[string][]byte, map[string]time.Time, error)
}

// Hub accepts reports and lists nodes.
type Hub struct {
	Repo  Repo
	Token string // shared secret; empty disables the hub endpoint
	Now   func() time.Time
}

func (h *Hub) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// MaxNodes bounds how many distinct nodes a hub tracks, so a leaked token
// cannot fill the database with made-up names.
const MaxNodes = 200

// ServeHTTP handles POST /api/v1/fleet/report.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Token == "" {
		http.Error(w, "fleet reporting is not enabled on this gateway", http.StatusNotFound)
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(h.Token)) != 1 {
		http.Error(w, "invalid fleet token", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxReportBytes))
	if err != nil {
		http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
		return
	}
	var rep Report
	if err := json.Unmarshal(body, &rep); err != nil {
		http.Error(w, "body must be a JSON report", http.StatusBadRequest)
		return
	}
	if err := rep.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	existing, _, err := h.Repo.ListFleetNodes()
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if _, known := existing[rep.Node]; !known && len(existing) >= MaxNodes {
		http.Error(w, "node limit reached", http.StatusForbidden)
		return
	}
	if err := h.Repo.UpsertFleetNode(rep.Node, body, h.now()); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// List returns every node, ordered by name.
func (h *Hub) List() ([]Node, error) {
	payloads, times, err := h.Repo.ListFleetNodes()
	if err != nil {
		return nil, err
	}
	out := make([]Node, 0, len(payloads))
	for name, p := range payloads {
		var rep Report
		if json.Unmarshal(p, &rep) != nil {
			continue
		}
		rep.Node = name
		out = append(out, Node{Report: rep, ReceivedAt: times[name]})
	}
	sortNodes(out)
	return out, nil
}

func sortNodes(n []Node) {
	for i := 1; i < len(n); i++ {
		for j := i; j > 0 && n[j].Node < n[j-1].Node; j-- {
			n[j], n[j-1] = n[j-1], n[j]
		}
	}
}

// Agent pushes this gateway's report to a hub.
type Agent struct {
	HubURL string // e.g. https://hub.example:9443
	Token  string
	Client *http.Client
	// Collect builds the current report.
	Collect func(ctx context.Context) Report
}

// Push sends one report.
func (a *Agent) Push(ctx context.Context) error {
	rep := a.Collect(ctx)
	rep.SentAt = time.Now().UTC()
	if err := rep.Validate(); err != nil {
		return fmt.Errorf("invalid report: %w", err)
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.HubURL, "/")+"/api/v1/fleet/report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.Token)
	c := a.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("push to hub: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<14))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("hub answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// Run pushes every interval until ctx ends.
func (a *Agent) Run(ctx context.Context, interval time.Duration, logf func(string, ...any)) {
	push := func() {
		if err := a.Push(ctx); err != nil && logf != nil {
			logf("fleet agent: %v", err)
		}
	}
	push()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			push()
		}
	}
}
