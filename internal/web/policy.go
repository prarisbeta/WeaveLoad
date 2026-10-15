package web

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/store"
)

// PolicyEngine is the slice of *policy.Engine the web layer drives.
type PolicyEngine interface {
	Config() policy.Config
	SaveConfig(c policy.Config, actor string) error
	Check(policy.Action) policy.Decision
	Submit(policy.Action) (store.PolicyAction, policy.Decision, error)
	Approve(id int64, actor string) (store.PolicyAction, error)
	Reject(id int64, actor string) error
	Revert(id int64, actor string) error
}

// PolicyStore lists recorded policy actions.
type PolicyStore interface {
	ListPolicyActions(status string, limit int) ([]store.PolicyAction, error)
}

// PolicyHandler renders GET /policy: the kill switch, per-action modes,
// pending approvals and recent history.
type PolicyHandler struct {
	Engine    PolicyEngine
	Store     PolicyStore
	Templates *template.Template
	Edition   string // one-line licence summary shown on the page
}

func (h *PolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pending, err := h.Store.ListPolicyActions("pending", 100)
	if err != nil {
		http.Error(w, "failed to load policy actions: "+err.Error(), http.StatusInternalServerError)
		return
	}
	history, err := h.Store.ListPolicyActions("", 50)
	if err != nil {
		http.Error(w, "failed to load policy actions: "+err.Error(), http.StatusInternalServerError)
		return
	}
	u, _ := auth.UserFromContext(r.Context())
	cfg := h.Engine.Config()
	renderTemplate(w, h.Templates, "policy.html", struct {
		Chrome
		Config       policy.Config
		Types        []policy.ActionType
		Pending      []store.PolicyAction
		History      []store.PolicyAction
		CanDecide    bool
		CanConfigure bool
		DefaultMin   int
		MaxMin       int
		Protected    string
		Notice       string
		Edition      string
	}{
		Chrome: NewChrome(r, "policy"), Config: cfg, Types: policy.Types,
		Pending: pending, History: history,
		CanDecide:    u.Role.Can(store.CapRuntimeControl),
		CanConfigure: u.Role.Can(store.CapManageSettings),
		DefaultMin:   int(cfg.DefaultTTL / time.Minute), MaxMin: int(cfg.MaxTTL / time.Minute),
		Protected: strings.Join(cfg.ProtectedCIDRs, "\n"),
		Notice:    takeFlash(w, r),
		Edition:   h.Edition,
	})
}

// PolicyDecisionAction handles POST /api/policy/{id}/{approve|reject|revert}.
type PolicyDecisionAction struct {
	Engine PolicyEngine
	Verb   string // approve | reject | revert
}

func (h *PolicyDecisionAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid action id", http.StatusBadRequest)
		return
	}
	u, _ := auth.UserFromContext(r.Context())
	notice := ""
	switch h.Verb {
	case "approve":
		var rec store.PolicyAction
		rec, err = h.Engine.Approve(id, u.Email)
		if err == nil && rec.Status == "failed" {
			err = fmt.Errorf("execution failed: %s", rec.Result)
		}
		notice = "Aksi dijalankan."
	case "reject":
		err = h.Engine.Reject(id, u.Email)
		notice = "Aksi ditolak."
	case "revert":
		err = h.Engine.Revert(id, u.Email)
		notice = "Aksi dibatalkan."
	default:
		http.Error(w, "unknown verb", http.StatusBadRequest)
		return
	}
	if err != nil {
		notice = "Gagal: " + err.Error()
	}
	redirectPolicy(w, r, notice)
}

// PolicyKillSwitchAction handles POST /api/policy/kill-switch (on=1|0).
type PolicyKillSwitchAction struct{ Engine PolicyEngine }

func (h *PolicyKillSwitchAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	u, _ := auth.UserFromContext(r.Context())
	c := h.Engine.Config()
	c.KillSwitch = r.FormValue("on") == "1"
	notice := "Kill switch dimatikan: Policy Engine aktif kembali."
	if c.KillSwitch {
		notice = "Kill switch AKTIF: semua aksi otomatis ditolak."
	}
	if err := h.Engine.SaveConfig(c, u.Email); err != nil {
		notice = "Gagal: " + err.Error()
	}
	redirectPolicy(w, r, notice)
}

// PolicyConfigAction handles POST /api/policy/config.
type PolicyConfigAction struct{ Engine PolicyEngine }

func (h *PolicyConfigAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	u, _ := auth.UserFromContext(r.Context())
	c := h.Engine.Config()

	for _, t := range policy.Types {
		if v := r.FormValue("mode_" + string(t)); v != "" {
			c.Modes[t] = policy.Mode(v)
		}
		if v := r.FormValue("max_" + string(t)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				redirectPolicy(w, r, "Gagal: batas per jam harus angka >= 0")
				return
			}
			c.MaxPerHour[t] = n
		}
	}
	if v := r.FormValue("default_ttl_min"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			redirectPolicy(w, r, "Gagal: TTL bawaan harus angka > 0 (menit)")
			return
		}
		c.DefaultTTL = time.Duration(n) * time.Minute
	}
	if v := r.FormValue("max_ttl_min"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			redirectPolicy(w, r, "Gagal: TTL maksimum harus angka > 0 (menit)")
			return
		}
		c.MaxTTL = time.Duration(n) * time.Minute
	}
	if v := r.FormValue("canary_min"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 60 {
			redirectPolicy(w, r, "Gagal: menit canary harus 0-60 (0 = mati)")
			return
		}
		c.CanaryMinutes = n
	}
	c.ProtectedCIDRs = nil
	for _, line := range strings.FieldsFunc(r.FormValue("protected_cidrs"), func(r rune) bool { return r == '\n' || r == ',' || r == ' ' || r == '\r' }) {
		c.ProtectedCIDRs = append(c.ProtectedCIDRs, line)
	}

	notice := "Konfigurasi policy disimpan."
	if err := h.Engine.SaveConfig(c, u.Email); err != nil {
		notice = "Gagal: " + err.Error()
	}
	redirectPolicy(w, r, notice)
}

func redirectPolicy(w http.ResponseWriter, r *http.Request, notice string) {
	http.SetCookie(w, &http.Cookie{
		Name: "policy_notice", Value: url.QueryEscape(notice), Path: "/policy",
		MaxAge: 60, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/policy", http.StatusSeeOther)
}

// takeFlash returns the one-shot message set by the last action and clears
// it. It travels in a cookie the server set, not in the URL, so a crafted link
// cannot put text of its choosing on the page.
func takeFlash(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie("policy_notice")
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: "policy_notice", Path: "/policy", MaxAge: -1})
	v, err := url.QueryUnescape(c.Value)
	if err != nil {
		return ""
	}
	return v
}
