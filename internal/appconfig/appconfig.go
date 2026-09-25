// Package appconfig loads haproxy-gui's own runtime configuration from
// environment variables (conventionally /etc/haproxy-gui/env, loaded by the
// systemd unit's EnvironmentFile=), with validation so a missing required
// value fails fast at startup instead of misbehaving later.
package appconfig

import (
	"fmt"
	"os"
	"strconv"
)

// Config is everything main() needs to wire the app together.
type Config struct {
	ListenAddr string // e.g. 127.0.0.1:9900

	HAProxySocket string // e.g. /var/lib/haproxy/stats
	HAProxyBin    string // e.g. /usr/sbin/haproxy
	HAProxyCfg    string // e.g. /etc/haproxy/haproxy.cfg
	StagingDir    string // e.g. /var/lib/haproxy-gui/staging
	ApplyScript   string // e.g. /usr/local/sbin/haproxy-gui-apply
	SSLDir        string // e.g. /etc/haproxy/ssl

	DBPath string // e.g. /var/lib/haproxy-gui/app.db

	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string

	CookieSecure bool // true in production (HTTPS); false only for local dev
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func required(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", fmt.Errorf("required environment variable %s is not set", key)
	}
	return v, nil
}

// Load reads Config from the environment, applying sensible defaults for
// paths that match haproxy-cni's actual layout and requiring the OIDC
// client credentials (there is no safe default for those).
func Load() (Config, error) {
	var errs []error
	must := func(key string) string {
		v, err := required(key)
		if err != nil {
			errs = append(errs, err)
		}
		return v
	}

	cfg := Config{
		ListenAddr: getenv("LISTEN_ADDR", "127.0.0.1:9900"),

		HAProxySocket: getenv("HAPROXY_SOCKET", "/var/lib/haproxy/stats"),
		HAProxyBin:    getenv("HAPROXY_BIN", "/usr/sbin/haproxy"),
		HAProxyCfg:    getenv("HAPROXY_CFG", "/etc/haproxy/haproxy.cfg"),
		StagingDir:    getenv("STAGING_DIR", "/var/lib/haproxy-gui/staging"),
		ApplyScript:   getenv("APPLY_SCRIPT", "/usr/local/sbin/haproxy-gui-apply"),
		SSLDir:        getenv("SSL_DIR", "/etc/haproxy/ssl"),

		DBPath: getenv("DB_PATH", "/var/lib/haproxy-gui/app.db"),

		OIDCIssuerURL:    must("OIDC_ISSUER_URL"),
		OIDCClientID:     must("OIDC_CLIENT_ID"),
		OIDCClientSecret: must("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  must("OIDC_REDIRECT_URL"),
	}

	secure, err := strconv.ParseBool(getenv("COOKIE_SECURE", "true"))
	if err != nil {
		errs = append(errs, fmt.Errorf("COOKIE_SECURE must be true or false: %w", err))
	}
	cfg.CookieSecure = secure

	if len(errs) > 0 {
		return Config{}, fmt.Errorf("invalid configuration: %w", joinErrs(errs))
	}
	return cfg, nil
}

func joinErrs(errs []error) error {
	msg := ""
	for i, e := range errs {
		if i > 0 {
			msg += "; "
		}
		msg += e.Error()
	}
	return fmt.Errorf("%s", msg)
}
