// Package retention keeps the gateway's own data from growing without bound.
// The app shares a host with production HAProxy, so a table or backup
// directory that only ever grows is a slow outage; this package prunes each
// one on a schedule with an explicit, per-kind age or count limit.
package retention

import (
	"context"
	"log"
	"time"
)

// Store is the pruning surface of *store.Store.
type Store interface {
	PruneExpiredSessions() (int64, error)
	PruneAudit(olderThan time.Duration) (int64, error)
	PruneStaleSecurityEvents(olderThan time.Time) (int64, error)
	PruneIPRisk(olderThan time.Time) (int64, error)
	PruneAlerts(olderThan time.Time) (int64, error)
	PrunePolicyActions(olderThan time.Time) (int64, error)
	PruneIPIntel(olderThan time.Time) (int64, error)
}

// Backups prunes config backups, keeping the newest N.
type Backups interface {
	PruneBackups(keep int) (int, error)
}

// Policy sets how long each kind of data is kept. A zero value disables
// pruning for that kind: nothing is ever deleted by accident of a missing
// setting.
type Policy struct {
	Audit          time.Duration
	SecurityEvents time.Duration
	IPRisk         time.Duration
	Alerts         time.Duration
	PolicyActions  time.Duration
	IPIntel        time.Duration
	KeepBackups    int
}

// DefaultPolicy is the retention the gateway ships with.
func DefaultPolicy() Policy {
	const day = 24 * time.Hour
	return Policy{
		Audit:          30 * day,
		SecurityEvents: 90 * day,
		IPRisk:         90 * day,
		Alerts:         90 * day,
		PolicyActions:  90 * day,
		IPIntel:        30 * day,
		KeepBackups:    50,
	}
}

// Sweeper applies a Policy.
type Sweeper struct {
	Store   Store
	Backups Backups // may be nil
	Policy  Policy
	// Now defaults to time.Now; overridable for tests.
	Now func() time.Time
}

// Result counts what one Sweep deleted, by kind. A kind whose prune failed
// is absent and named in Errors.
type Result struct {
	Deleted map[string]int64
	Errors  map[string]error
}

// Sweep runs every enabled prune once. One failing prune never stops the rest.
func (s *Sweeper) Sweep() Result {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	t := now()
	res := Result{Deleted: map[string]int64{}, Errors: map[string]error{}}
	record := func(kind string, n int64, err error) {
		if err != nil {
			res.Errors[kind] = err
			return
		}
		res.Deleted[kind] = n
	}

	n, err := s.Store.PruneExpiredSessions()
	record("sessions", n, err)

	p := s.Policy
	if p.Audit > 0 {
		n, err = s.Store.PruneAudit(p.Audit)
		record("audit", n, err)
	}
	if p.SecurityEvents > 0 {
		n, err = s.Store.PruneStaleSecurityEvents(t.Add(-p.SecurityEvents))
		record("security_events", n, err)
	}
	if p.IPRisk > 0 {
		n, err = s.Store.PruneIPRisk(t.Add(-p.IPRisk))
		record("ip_risk", n, err)
	}
	if p.Alerts > 0 {
		n, err = s.Store.PruneAlerts(t.Add(-p.Alerts))
		record("alerts", n, err)
	}
	if p.PolicyActions > 0 {
		n, err = s.Store.PrunePolicyActions(t.Add(-p.PolicyActions))
		record("policy_actions", n, err)
	}
	if p.IPIntel > 0 {
		n, err = s.Store.PruneIPIntel(t.Add(-p.IPIntel))
		record("ip_intel", n, err)
	}
	if s.Backups != nil && p.KeepBackups > 0 {
		b, err := s.Backups.PruneBackups(p.KeepBackups)
		record("config_backups", int64(b), err)
	}
	return res
}

// Run sweeps once shortly after start, then every interval, until ctx ends.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	first := time.NewTimer(time.Minute)
	defer first.Stop()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-tick.C:
		}
		res := s.Sweep()
		for kind, n := range res.Deleted {
			if n > 0 {
				log.Printf("retention: pruned %d %s", n, kind)
			}
		}
		for kind, err := range res.Errors {
			log.Printf("retention: prune %s: %v", kind, err)
		}
	}
}
