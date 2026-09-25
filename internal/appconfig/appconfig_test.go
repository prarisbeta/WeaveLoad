package appconfig

import (
	"os"
	"testing"
)

func clearEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		old, had := os.LookupEnv(k)
		os.Unsetenv(k)
		t.Cleanup(func() {
			if had {
				os.Setenv(k, old)
			}
		})
	}
}

var oidcKeys = []string{"OIDC_ISSUER_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URL"}

func setRequiredOIDCEnv(t *testing.T) {
	t.Helper()
	vals := map[string]string{
		"OIDC_ISSUER_URL":    "https://oms.cni.net.id/sso",
		"OIDC_CLIENT_ID":     "haproxy-gui",
		"OIDC_CLIENT_SECRET": "s3cr3t",
		"OIDC_REDIRECT_URL":  "https://haproxy-gui.cni.net.id/auth/callback",
	}
	for k, v := range vals {
		os.Setenv(k, v)
	}
	t.Cleanup(func() { clearEnv(t, oidcKeys...) })
}

func TestLoad_MissingRequiredVars_Fails(t *testing.T) {
	clearEnv(t, oidcKeys...)
	if _, err := Load(); err == nil {
		t.Fatal("expected error when OIDC env vars are missing")
	}
}

func TestLoad_MissingOneRequiredVar_ReportsIt(t *testing.T) {
	setRequiredOIDCEnv(t)
	os.Unsetenv("OIDC_CLIENT_SECRET")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when OIDC_CLIENT_SECRET is missing")
	}
	if got := err.Error(); !contains(got, "OIDC_CLIENT_SECRET") {
		t.Errorf("error = %q, want it to name the missing variable", got)
	}
}

func TestLoad_DefaultsAppliedWhenUnset(t *testing.T) {
	setRequiredOIDCEnv(t)
	clearEnv(t, "LISTEN_ADDR", "HAPROXY_SOCKET", "DB_PATH", "COOKIE_SECURE")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9900" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.HAProxySocket != "/var/lib/haproxy/stats" {
		t.Errorf("HAProxySocket = %q", cfg.HAProxySocket)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure should default to true (production-safe default)")
	}
}

func TestLoad_ExplicitValuesOverrideDefaults(t *testing.T) {
	setRequiredOIDCEnv(t)
	os.Setenv("LISTEN_ADDR", "0.0.0.0:8080")
	os.Setenv("COOKIE_SECURE", "false")
	t.Cleanup(func() { clearEnv(t, "LISTEN_ADDR", "COOKIE_SECURE") })

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:8080" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.CookieSecure {
		t.Error("CookieSecure should be false when explicitly set")
	}
}

func TestLoad_InvalidCookieSecure_Fails(t *testing.T) {
	setRequiredOIDCEnv(t)
	os.Setenv("COOKIE_SECURE", "maybe")
	t.Cleanup(func() { clearEnv(t, "COOKIE_SECURE") })

	if _, err := Load(); err == nil {
		t.Fatal("expected error for a non-boolean COOKIE_SECURE")
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
