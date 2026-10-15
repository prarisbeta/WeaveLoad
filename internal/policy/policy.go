// Package policy is the single gate between "something wants to change
// traffic" and HAProxy actually changing. Detectors, API callers and the AI
// only ever Submit an Action; the Engine decides, from persisted
// configuration, whether it is refused, merely logged (shadow), queued for a
// human (propose) or run at once (auto). Every executed action is
// time-limited and undone by ExpireDue, caps limit how much damage a
// misbehaving source can do per hour, and a kill switch turns it all off.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"haproxy-gui/internal/store"
)

// ActionType is a kind of change the engine knows how to perform and undo.
type ActionType string

const (
	BlockIP     ActionType = "block_ip"
	DrainServer ActionType = "drain_server"
)

// Types lists every supported ActionType.
var Types = []ActionType{BlockIP, DrainServer}

// Mode is how the engine treats an action type.
type Mode string

const (
	ModeOff     Mode = "off"     // refused
	ModeShadow  Mode = "shadow"  // recorded as "would do", never run
	ModePropose Mode = "propose" // queued until a human approves
	ModeAuto    Mode = "auto"    // run immediately
)

func modeRank(m Mode) int {
	switch m {
	case ModeShadow:
		return 1
	case ModePropose:
		return 2
	case ModeAuto:
		return 3
	}
	return 0
}

// Action is a request to change something.
type Action struct {
	Type       ActionType
	Target     string // an IP for block_ip, "backend/server" for drain_server
	TTL        time.Duration
	Reason     string
	Evidence   string
	Source     string
	Confidence float64
	// MaxMode caps how far this particular request may go no matter what the
	// configured mode is. API tokens and the AI use ModePropose, so they can
	// never cause an automatic change. Empty means no cap.
	MaxMode Mode
}

// Config is the persisted policy.
type Config struct {
	KillSwitch     bool                `json:"kill_switch"`
	Modes          map[ActionType]Mode `json:"modes"`
	MaxPerHour     map[ActionType]int  `json:"max_per_hour"`
	DefaultTTL     time.Duration       `json:"default_ttl"`
	MaxTTL         time.Duration       `json:"max_ttl"`
	ProtectedCIDRs []string            `json:"protected_cidrs"`
	// CanaryMinutes is how long after a config apply the gateway watches the
	// 5xx rate and rolls the change back on a spike. 0 turns the canary off.
	CanaryMinutes int `json:"canary_minutes"`
}

// DefaultConfig is the safe starting policy: nothing runs without a human.
func DefaultConfig() Config {
	return Config{
		Modes:      map[ActionType]Mode{BlockIP: ModePropose, DrainServer: ModePropose},
		MaxPerHour: map[ActionType]int{BlockIP: 50, DrainServer: 3},
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}
}

func (c Config) mode(t ActionType) Mode {
	if c.KillSwitch {
		return ModeOff
	}
	if m, ok := c.Modes[t]; ok {
		return m
	}
	return ModeOff
}

// Decision is the engine's verdict on an Action.
type Decision struct {
	Mode    Mode     // what would happen: off, shadow, propose or auto
	Allowed bool     // false when Reasons explain a refusal
	Reasons []string // why it was refused
}

// Repo is the persistence the engine needs; *store.Store satisfies it.
type Repo interface {
	GetSetting(key string) (string, error)
	SetSetting(key, value string) error
	CreatePolicyAction(store.PolicyAction) (int64, error)
	UpdatePolicyAction(store.PolicyAction) error
	GetPolicyAction(id int64) (store.PolicyAction, error)
	CountPolicyActionsSince(typ string, statuses []string, since time.Time) (int, error)
	HasOpenPolicyAction(typ, target string) (bool, error)
	ListExpiredPolicyActions(now time.Time) ([]store.PolicyAction, error)
}

// Executor performs and undoes the actual change.
type Executor interface {
	BlockIP(ip string) error
	UnblockIP(ip string) error
	Drain(backend, server string) error
	Undrain(backend, server string) error
}

// Auditor records what the engine did.
type Auditor interface {
	Record(store.AuditEntry) error
}

// Engine decides and executes Actions.
type Engine struct {
	Repo  Repo
	Exec  Executor
	Audit Auditor
	// Allow reports whether a licensed feature may run ("auto_remediation",
	// "canary"); nil allows everything.
	Allow func(feature string) bool
	// Now defaults to time.Now; overridable for tests.
	Now func() time.Time
}

func (e *Engine) allowed(feature string) bool { return e.Allow == nil || e.Allow(feature) }

const configKey = "policy_config"

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Config loads the persisted policy, falling back to DefaultConfig.
func (e *Engine) Config() Config {
	c := DefaultConfig()
	raw, err := e.Repo.GetSetting(configKey)
	if err != nil || raw == "" {
		return c
	}
	var stored Config
	if json.Unmarshal([]byte(raw), &stored) != nil {
		return c
	}
	for t, m := range stored.Modes {
		c.Modes[t] = m
	}
	for t, n := range stored.MaxPerHour {
		c.MaxPerHour[t] = n
	}
	c.KillSwitch = stored.KillSwitch
	if stored.DefaultTTL > 0 {
		c.DefaultTTL = stored.DefaultTTL
	}
	if stored.MaxTTL > 0 {
		c.MaxTTL = stored.MaxTTL
	}
	c.ProtectedCIDRs = stored.ProtectedCIDRs
	c.CanaryMinutes = stored.CanaryMinutes
	return c
}

// CanaryWindow is how long to watch after a config apply; zero means the
// canary is off (or the kill switch is on).
func (e *Engine) CanaryWindow() time.Duration {
	c := e.Config()
	if c.KillSwitch || c.CanaryMinutes <= 0 || !e.allowed("canary") {
		return 0
	}
	return time.Duration(c.CanaryMinutes) * time.Minute
}

// SaveConfig validates and persists c, recording who changed it.
func (e *Engine) SaveConfig(c Config, actor string) error {
	for t, m := range c.Modes {
		if !validType(t) {
			return fmt.Errorf("unknown action type %q", t)
		}
		if m != ModeOff && m != ModeShadow && m != ModePropose && m != ModeAuto {
			return fmt.Errorf("invalid mode %q for %s", m, t)
		}
	}
	for _, cidr := range c.ProtectedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid protected CIDR %q", cidr)
		}
	}
	if c.CanaryMinutes < 0 || c.CanaryMinutes > 60 {
		return errors.New("canary minutes must be between 0 and 60")
	}
	if c.DefaultTTL <= 0 || c.MaxTTL <= 0 || c.DefaultTTL > c.MaxTTL {
		return errors.New("default TTL must be positive and not exceed max TTL")
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := e.Repo.SetSetting(configKey, string(b)); err != nil {
		return err
	}
	e.audit(actor, "policy.config", "", string(b))
	return nil
}

func validType(t ActionType) bool {
	for _, v := range Types {
		if v == t {
			return true
		}
	}
	return false
}

func (e *Engine) audit(actor, action, target, detail string) {
	if e.Audit == nil {
		return
	}
	_ = e.Audit.Record(store.AuditEntry{UserEmail: actor, Action: action, Target: target, Detail: detail})
}

// validate checks an Action's shape and target. It returns the refusal reasons.
func (e *Engine) validate(a *Action, c Config) []string {
	var why []string
	if !validType(a.Type) {
		return []string{"unknown action type " + string(a.Type)}
	}
	if a.TTL <= 0 {
		a.TTL = c.DefaultTTL
	}
	if a.TTL > c.MaxTTL {
		why = append(why, fmt.Sprintf("ttl %s exceeds the maximum %s", a.TTL, c.MaxTTL))
	}
	switch a.Type {
	case BlockIP:
		ip := net.ParseIP(a.Target)
		switch {
		case ip == nil:
			why = append(why, "target is not an IP address")
		case ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast():
			why = append(why, "refusing to block a loopback, unspecified, link-local or multicast address")
		default:
			for _, cidr := range c.ProtectedCIDRs {
				if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
					why = append(why, "target is inside protected range "+cidr)
					break
				}
			}
		}
	case DrainServer:
		parts := strings.Split(a.Target, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			why = append(why, `target must be "backend/server"`)
		}
	}
	return why
}

// capReason returns a refusal reason when running a now would exceed the
// hourly blast-radius cap for its type.
func (e *Engine) capReason(a Action, c Config) string {
	limit, ok := c.MaxPerHour[a.Type]
	if !ok || limit <= 0 {
		return ""
	}
	n, err := e.Repo.CountPolicyActionsSince(string(a.Type), []string{"executed", "expired"}, e.now().Add(-time.Hour))
	if err != nil {
		return "cannot verify the hourly cap: " + err.Error()
	}
	if n >= limit {
		return fmt.Sprintf("hourly cap reached: %d %s actions in the last hour (limit %d)", n, a.Type, limit)
	}
	return ""
}

// Check is a dry run: what would Submit do with a, without recording or
// running anything.
func (e *Engine) Check(a Action) Decision {
	c := e.Config()
	mode := c.mode(a.Type)
	if c.KillSwitch {
		return Decision{Mode: ModeOff, Reasons: []string{"kill switch is on"}}
	}
	if a.MaxMode != "" && modeRank(mode) > modeRank(a.MaxMode) {
		mode = a.MaxMode
	}
	if mode == ModeAuto && !e.allowed("auto_remediation") {
		mode = ModePropose // Community edition: a human always decides
	}
	if mode == ModeOff {
		return Decision{Mode: ModeOff, Reasons: []string{"policy mode for " + string(a.Type) + " is off"}}
	}
	why := e.validate(&a, c)
	if len(why) == 0 && mode == ModeAuto {
		if r := e.capReason(a, c); r != "" {
			why = append(why, r)
		}
	}
	if open, err := e.Repo.HasOpenPolicyAction(string(a.Type), a.Target); err == nil && open {
		why = append(why, "an identical action is already pending or in force")
	}
	if len(why) > 0 {
		return Decision{Mode: mode, Reasons: why}
	}
	return Decision{Mode: mode, Allowed: true}
}

// Submit evaluates a and acts on the result. A refused action is not
// recorded (the Decision explains why); every other outcome leaves a record.
func (e *Engine) Submit(a Action) (store.PolicyAction, Decision, error) {
	d := e.Check(a)
	if !d.Allowed {
		return store.PolicyAction{}, d, nil
	}
	c := e.Config()
	e.validate(&a, c) // fills the default TTL

	rec := store.PolicyAction{
		CreatedAt: e.now(), Type: string(a.Type), Target: a.Target, TTLSeconds: int(a.TTL.Seconds()),
		Reason: a.Reason, Evidence: a.Evidence, Source: a.Source, Confidence: a.Confidence,
	}
	switch d.Mode {
	case ModeShadow:
		rec.Status = "shadow"
		rec.Result = "shadow mode: not executed"
	case ModePropose:
		rec.Status = "pending"
	case ModeAuto:
		rec.Status = "pending" // becomes executed or failed below
	}
	id, err := e.Repo.CreatePolicyAction(rec)
	if err != nil {
		return store.PolicyAction{}, d, err
	}
	rec.ID = id
	e.audit(a.Source, "policy."+rec.Status, rec.Type+" "+rec.Target, a.Reason)

	if d.Mode == ModeAuto {
		rec = e.execute(rec, a.Source)
	}
	return rec, d, nil
}

// execute runs rec and persists the outcome.
func (e *Engine) execute(rec store.PolicyAction, actor string) store.PolicyAction {
	now := e.now()
	rec.DecidedBy, rec.DecidedAt = actor, &now
	var err error
	switch ActionType(rec.Type) {
	case BlockIP:
		err = e.Exec.BlockIP(rec.Target)
	case DrainServer:
		be, sv, _ := strings.Cut(rec.Target, "/")
		err = e.Exec.Drain(be, sv)
	default:
		err = fmt.Errorf("unknown action type %q", rec.Type)
	}
	if err != nil {
		rec.Status, rec.Result = "failed", err.Error()
	} else {
		exp := now.Add(time.Duration(rec.TTLSeconds) * time.Second)
		rec.Status, rec.ExecutedAt, rec.ExpiresAt, rec.Result = "executed", &now, &exp, "ok"
	}
	_ = e.Repo.UpdatePolicyAction(rec)
	e.audit(actor, "policy."+rec.Status, rec.Type+" "+rec.Target, rec.Result)
	return rec
}

// Approve runs a pending action on behalf of a human. The hourly cap and
// target checks are applied again, since time has passed.
func (e *Engine) Approve(id int64, actor string) (store.PolicyAction, error) {
	rec, err := e.Repo.GetPolicyAction(id)
	if err != nil {
		return rec, err
	}
	if rec.Status != "pending" {
		return rec, fmt.Errorf("action %d is %s, not pending", id, rec.Status)
	}
	c := e.Config()
	if c.KillSwitch {
		return rec, errors.New("kill switch is on")
	}
	a := Action{Type: ActionType(rec.Type), Target: rec.Target, TTL: time.Duration(rec.TTLSeconds) * time.Second}
	if why := e.validate(&a, c); len(why) > 0 {
		return rec, errors.New(strings.Join(why, "; "))
	}
	if r := e.capReason(a, c); r != "" {
		return rec, errors.New(r)
	}
	return e.execute(rec, actor), nil
}

// Reject closes a pending action without running it.
func (e *Engine) Reject(id int64, actor string) error {
	rec, err := e.Repo.GetPolicyAction(id)
	if err != nil {
		return err
	}
	if rec.Status != "pending" {
		return fmt.Errorf("action %d is %s, not pending", id, rec.Status)
	}
	now := e.now()
	rec.Status, rec.DecidedBy, rec.DecidedAt, rec.Result = "rejected", actor, &now, "rejected by operator"
	if err := e.Repo.UpdatePolicyAction(rec); err != nil {
		return err
	}
	e.audit(actor, "policy.rejected", rec.Type+" "+rec.Target, "")
	return nil
}

// Revert undoes an executed action before its TTL ends.
func (e *Engine) Revert(id int64, actor string) error {
	rec, err := e.Repo.GetPolicyAction(id)
	if err != nil {
		return err
	}
	if rec.Status != "executed" {
		return fmt.Errorf("action %d is %s, not executed", id, rec.Status)
	}
	if err := e.undo(rec); err != nil {
		return err
	}
	now := e.now()
	rec.Status, rec.Result = "expired", "reverted by "+actor
	rec.DecidedBy, rec.DecidedAt = actor, &now
	if err := e.Repo.UpdatePolicyAction(rec); err != nil {
		return err
	}
	e.audit(actor, "policy.reverted", rec.Type+" "+rec.Target, "")
	return nil
}

func (e *Engine) undo(rec store.PolicyAction) error {
	switch ActionType(rec.Type) {
	case BlockIP:
		return e.Exec.UnblockIP(rec.Target)
	case DrainServer:
		be, sv, _ := strings.Cut(rec.Target, "/")
		return e.Exec.Undrain(be, sv)
	}
	return fmt.Errorf("unknown action type %q", rec.Type)
}

// ExpireDue undoes every executed action whose TTL has ended and returns how
// many it reverted. An action that fails to revert stays "executed" so the
// next sweep retries it.
func (e *Engine) ExpireDue() (int, error) {
	due, err := e.Repo.ListExpiredPolicyActions(e.now())
	if err != nil {
		return 0, err
	}
	n := 0
	var firstErr error
	for _, rec := range due {
		if err := e.undo(rec); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("expire %s %s: %w", rec.Type, rec.Target, err)
			}
			continue
		}
		rec.Status, rec.Result = "expired", "ttl ended"
		if err := e.Repo.UpdatePolicyAction(rec); err != nil && firstErr == nil {
			firstErr = err
		}
		e.audit("policy-engine", "policy.expired", rec.Type+" "+rec.Target, "")
		n++
	}
	return n, firstErr
}
