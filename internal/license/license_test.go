package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sign(t *testing.T, priv ed25519.PrivateKey, ed Edition, notAfter time.Time) string {
	t.Helper()
	tok, err := Sign(priv, License{Customer: "PT CNI", Edition: ed, NotAfter: notAfter, Nodes: 5})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := keypair(t)
	l, err := Verify(pub, sign(t, priv, Pro, now.AddDate(1, 0, 0)), now)
	if err != nil || l.Customer != "PT CNI" || l.Edition != Pro || l.Nodes != 5 {
		t.Fatalf("l=%+v err=%v", l, err)
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv := keypair(t)
	otherPub, _ := keypair(t)
	good := sign(t, priv, Enterprise, now.AddDate(1, 0, 0))

	if _, err := Verify(otherPub, good, now); err != ErrSignature {
		t.Errorf("another vendor's key: %v", err)
	}
	// Flip the edition in the payload while keeping the old signature.
	p, s, _ := strings.Cut(good, ".")
	forged := strings.Replace(p, p[:4], "AAAA", 1) + "." + s
	if _, err := Verify(pub, forged, now); err == nil {
		t.Error("a tampered payload verified")
	}
	if _, err := Verify(pub, "not-a-licence", now); err != ErrMalformed {
		t.Errorf("garbage: %v", err)
	}
	if _, err := Verify(pub, "!!.!!", now); err != ErrMalformed {
		t.Errorf("bad base64: %v", err)
	}
	if _, err := Verify(pub, sign(t, priv, Pro, now.Add(-time.Hour)), now); err != ErrExpired {
		t.Errorf("expired: %v", err)
	}
}

func TestSignValidatesInput(t *testing.T) {
	_, priv := keypair(t)
	for name, l := range map[string]License{
		"no customer": {Edition: Pro, NotAfter: now},
		"bad edition": {Customer: "x", Edition: "gold", NotAfter: now},
		"no expiry":   {Customer: "x", Edition: Pro},
	} {
		if _, err := Sign(priv, l); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func writeLicense(t *testing.T, tok string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "license.key")
	if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGateByEdition(t *testing.T) {
	pub, priv := keypair(t)
	pubHex := hex.EncodeToString(pub)

	cases := []struct {
		name    string
		g       *Gate
		auto    bool
		fleet   bool
		edition string
	}{
		{"development build", Load("", "/nope", now), true, true, "development"},
		{"no licence file", Load(pubHex, filepath.Join(t.TempDir(), "missing"), now), false, false, "community"},
		{"pro", Load(pubHex, writeLicense(t, sign(t, priv, Pro, now.AddDate(1, 0, 0))), now), true, false, "pro"},
		{"enterprise", Load(pubHex, writeLicense(t, sign(t, priv, Enterprise, now.AddDate(1, 0, 0))), now), true, true, "enterprise"},
		{"expired pro", Load(pubHex, writeLicense(t, sign(t, priv, Pro, now.Add(-time.Hour))), now), false, false, "community"},
		{"forged file", Load(pubHex, writeLicense(t, "aaaa.bbbb"), now), false, false, "community"},
		{"bad compiled key", Load("zz", "/nope", now), false, false, "community"},
	}
	for _, c := range cases {
		if got := c.g.Allows("auto_remediation"); got != c.auto {
			t.Errorf("%s: auto_remediation = %v, want %v", c.name, got, c.auto)
		}
		if got := c.g.Allows("fleet"); got != c.fleet {
			t.Errorf("%s: fleet = %v, want %v", c.name, got, c.fleet)
		}
		if !c.g.Allows("propose_actions") { // a Community feature is never gated
			t.Errorf("%s: a community feature was blocked", c.name)
		}
		if c.g.Edition() != c.edition {
			t.Errorf("%s: edition = %s, want %s", c.name, c.g.Edition(), c.edition)
		}
		if c.g.Describe() == "" {
			t.Errorf("%s: empty description", c.name)
		}
	}
}

func TestNilGateAllowsEverything(t *testing.T) {
	var g *Gate
	if !g.Allows("fleet") || g.Edition() != "development" || g.MaxNodes() != 0 {
		t.Error("a nil Gate must behave like a development build")
	}
}

func TestEveryGatedFeatureIsKnown(t *testing.T) {
	if len(Features()) != len(minEdition) || len(Features()) < 5 {
		t.Errorf("features = %v", Features())
	}
}
