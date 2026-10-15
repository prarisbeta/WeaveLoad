// Package license implements the offline, signed licence behind the
// Community / Pro / Enterprise editions. A licence is a small JSON document
// signed with the vendor's Ed25519 private key; the gateway carries only the
// public key and checks the signature locally, so no licence server is needed.
//
// A build without a public key (a development build) does not enforce
// anything: every feature is available. Release builds stamp the key in.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Edition is a product tier.
type Edition string

const (
	Community  Edition = "community"
	Pro        Edition = "pro"
	Enterprise Edition = "enterprise"
)

func (e Edition) rank() int {
	switch e {
	case Enterprise:
		return 2
	case Pro:
		return 1
	}
	return 0
}

// License is the signed payload.
type License struct {
	Customer string    `json:"customer"`
	Edition  Edition   `json:"edition"`
	NotAfter time.Time `json:"not_after"`
	Nodes    int       `json:"nodes,omitempty"` // fleet size cap; 0 = unlimited
}

// minEdition is the lowest edition that includes each gated feature. Anything
// not listed is part of Community.
var minEdition = map[string]Edition{
	"auto_remediation": Pro,
	"canary":           Pro,
	"intel_feeds":      Pro,
	"anomaly":          Pro,
	"copilot":          Pro,
	"fleet":            Enterprise,
}

// Features lists every gated feature name, for documentation and tests.
func Features() []string {
	out := make([]string, 0, len(minEdition))
	for f := range minEdition {
		out = append(out, f)
	}
	return out
}

// Sign produces the licence token: base64url(payload) "." base64url(signature).
func Sign(priv ed25519.PrivateKey, l License) (string, error) {
	if l.Customer == "" {
		return "", errors.New("customer is required")
	}
	if l.Edition != Community && l.Edition != Pro && l.Edition != Enterprise {
		return "", fmt.Errorf("unknown edition %q", l.Edition)
	}
	if l.NotAfter.IsZero() {
		return "", errors.New("not_after is required")
	}
	payload, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(sig), nil
}

// Errors Verify can return.
var (
	ErrMalformed = errors.New("licence is malformed")
	ErrSignature = errors.New("licence signature is not valid for this build")
	ErrExpired   = errors.New("licence has expired")
)

// Verify checks token against pub and the clock.
func Verify(pub ed25519.PublicKey, token string, now time.Time) (License, error) {
	token = strings.TrimSpace(token)
	p, s, ok := strings.Cut(token, ".")
	if !ok {
		return License{}, ErrMalformed
	}
	enc := base64.RawURLEncoding
	payload, err1 := enc.DecodeString(p)
	sig, err2 := enc.DecodeString(s)
	if err1 != nil || err2 != nil {
		return License{}, ErrMalformed
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, payload, sig) {
		return License{}, ErrSignature
	}
	var l License
	if err := json.Unmarshal(payload, &l); err != nil {
		return License{}, ErrMalformed
	}
	if now.After(l.NotAfter) {
		return l, ErrExpired
	}
	return l, nil
}

// Gate answers "may this feature run?".
type Gate struct {
	enforcing bool
	lic       License
	problem   string
}

// Load builds the Gate. pubKeyHex is the compiled-in public key (empty in a
// development build, which disables enforcement). path is the licence file.
// A missing, invalid or expired licence yields Community, never a crash: the
// gateway keeps routing traffic either way.
func Load(pubKeyHex, path string, now time.Time) *Gate {
	if pubKeyHex == "" {
		return &Gate{}
	}
	g := &Gate{enforcing: true, lic: License{Customer: "-", Edition: Community}}
	pub, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		g.problem = "the public key compiled into this build is invalid"
		return g
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			g.problem = "no licence file"
		} else {
			g.problem = "cannot read the licence file: " + err.Error()
		}
		return g
	}
	l, err := Verify(ed25519.PublicKey(pub), string(raw), now)
	if err != nil {
		g.problem = err.Error()
		return g
	}
	g.lic = l
	return g
}

// Allows reports whether feature is included. A nil Gate allows everything.
func (g *Gate) Allows(feature string) bool {
	if g == nil || !g.enforcing {
		return true
	}
	min, gated := minEdition[feature]
	if !gated {
		return true
	}
	return g.lic.Edition.rank() >= min.rank()
}

// Edition is the active edition ("development" when not enforcing).
func (g *Gate) Edition() string {
	if g == nil || !g.enforcing {
		return "development"
	}
	return string(g.lic.Edition)
}

// Describe is a one-line human summary for the UI and the log.
func (g *Gate) Describe() string {
	switch {
	case g == nil || !g.enforcing:
		return "development build: all features enabled"
	case g.problem != "":
		return fmt.Sprintf("community (%s)", g.problem)
	default:
		return fmt.Sprintf("%s licensed to %s until %s", g.lic.Edition, g.lic.Customer, g.lic.NotAfter.Format("2006-01-02"))
	}
}

// MaxNodes is the fleet size cap from the licence (0 = unlimited).
func (g *Gate) MaxNodes() int {
	if g == nil || !g.enforcing {
		return 0
	}
	return g.lic.Nodes
}
