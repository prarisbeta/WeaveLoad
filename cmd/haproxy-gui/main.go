// Command haproxy-gui serves the web management UI for the haproxy-cni
// load balancer: live dashboard, runtime server control, config editor with
// validate/apply/rollback, SSL certificate inventory, and ACL/map
// management, all behind OMS CNI SSO login with role-based access and a
// full audit trail.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"haproxy-gui/internal/appconfig"
	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/certs"
	"haproxy-gui/internal/cfgfile"
	"haproxy-gui/internal/haproxycfg"
	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/i18n"
	"haproxy-gui/internal/omsdir"
	"haproxy-gui/internal/ratelimitqueue"
	"haproxy-gui/internal/redisping"
	"haproxy-gui/internal/runtime"
	"haproxy-gui/internal/security"
	"haproxy-gui/internal/store"
	"haproxy-gui/internal/sysinfo"
)

//go:embed templates/*.html
var templatesFS embed.FS

func main() {
	if err := run(); err != nil {
		log.Fatalf("fatal error starting haproxy-gui: %v", err)
	}
}

func run() error {
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}

	tpl, err := template.New("").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"bytes": sysinfo.FormatBytes,
		"t":     i18n.T,
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return err
	}

	s, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer s.Close()

	rt := runtime.New(cfg.HAProxySocket)

	cf := cfgfile.New(cfg.HAProxyCfg)
	cf.BackupDir = cfg.BackupDir
	cf.HAProxyBin = cfg.HAProxyBin
	cf.StagingDir = cfg.StagingDir
	cf.ApplyScript = cfg.ApplyScript
	cf.RestartScript = cfg.RestartScript
	cf.SudoBin = cfg.SudoBin
	cfgfile.EnsureDefaultMapFiles()

	certStore := certs.New(cfg.SSLDir)
	certStore.StagingDir = cfg.StagingDir
	certStore.InstallScript = cfg.CertScript
	certStore.SudoBin = cfg.SudoBin
	dirClient := omsdir.New(cfg.OMSDirBaseURL, cfg.OMSDirClientID, cfg.OMSDirClientSecret)
	sysSampler := sysinfo.NewSampler()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	provider, err := auth.NewProvider(ctx, auth.Config{
		IssuerURL:    cfg.OIDCIssuerURL,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		CookieSecure: cfg.CookieSecure,
	})
	cancel()
	if err != nil {
		return err
	}

	mux := buildRoutes(routeDeps{
		templates: tpl,
		store:     s,
		runtime:   rt,
		cfgfile:   cf,
		certs:     certStore,
		provider:  provider,
		dir:       dirClient,
		sys:       sysSampler,
		cfg:       cfg,
	})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go pruneSessionsPeriodically(s)
	go pushRateLimitEventsPeriodically(s, cf, cfg.LogPath)
	if err := runSecurityEnginePeriodically(s, cfg.LogPath); err != nil {
		log.Printf("security engine disabled: %v", err)
	}

	log.Printf("haproxy-gui listening on %s", cfg.ListenAddr)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	case <-sigCh:
		log.Print("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
	return nil
}

func pruneSessionsPeriodically(s *store.Store) {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		if n, err := s.PruneExpiredSessions(); err != nil {
			log.Printf("prune sessions: %v", err)
		} else if n > 0 {
			log.Printf("pruned %d expired sessions", n)
		}
		if n, err := s.PruneAudit(30 * 24 * time.Hour); err != nil {
			log.Printf("prune audit log: %v", err)
		} else if n > 0 {
			log.Printf("pruned %d old audit entries (>30 days)", n)
		}
	}
}

// rateLimitBlockStatus is the HTTP status haproxycfg.SetRateLimit's block
// always answers with (both "deny" and "tarpit" actions use it), so it's
// what identifies a rate-limit rejection in the access log.
const rateLimitBlockStatus = 429

// pushRateLimitEventsPeriodically is the "Queue" a Redis connection saved on
// the Settings page is for: every tick, it checks which pools currently
// have a rate limit configured, scans the access log for rejections against
// them since the last tick, and pushes each as a JSON event onto a Redis
// list (ratelimitqueue.QueueKey) for something downstream to consume.
// Entirely best-effort — Redis unset/unreachable or the log being
// momentarily unavailable just skips this tick, never crashes the app.
func pushRateLimitEventsPeriodically(s *store.Store, cf *cfgfile.Store, logPath string) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	var since time.Time
	for range t.C {
		rs, err := s.GetRedisSettings()
		if err != nil || rs.Host == "" {
			continue // feature not configured, or settings unreadable this tick
		}
		content, err := cf.Active()
		if err != nil {
			continue
		}
		limited := map[string]bool{}
		for _, p := range haproxycfg.Parse(content).Pools {
			if p.RateLimit != nil {
				limited[p.Name] = true
			}
		}
		events, newest, err := ratelimitqueue.Extract(logPath, since, limited, rateLimitBlockStatus)
		if err != nil {
			log.Printf("scan access log for rate-limit events: %v", err)
			continue
		}
		since = newest
		for _, ev := range events {
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			opts := redisping.Options{Host: rs.Host, Port: rs.Port, Password: rs.Password, DB: rs.DB, TLS: rs.TLS}
			if err := redisping.Push(opts, ratelimitqueue.QueueKey, string(b)); err != nil {
				log.Printf("push rate-limit event to redis: %v", err)
			}
		}
	}
}

// runSecurityEnginePeriodically starts the internal/security Runner on a
// background ticker, scanning newly appended access-log lines for the
// brute-force/scan/abuse patterns in internal/security's detectors. It
// starts the tailer at the current end of the log — a process restart never
// replays the whole day's traffic — and publishing to Redis for at-risk IPs
// reuses whatever Redis connection the Settings page has configured for the
// rate-limit queue, read fresh on every tick so a later configuration
// change takes effect without a restart.
func runSecurityEnginePeriodically(s *store.Store, logPath string) error {
	tailer, err := haproxylog.NewTailerAtEnd(logPath)
	if err != nil {
		return err
	}
	r := &security.Runner{
		Store:  s,
		Engine: security.NewEngine(security.DefaultThresholds()),
		Tailer: tailer,
		RedisOpts: func() (redisping.Options, bool) {
			rs, err := s.GetRedisSettings()
			if err != nil || rs.Host == "" {
				return redisping.Options{}, false
			}
			return redisping.Options{Host: rs.Host, Port: rs.Port, Password: rs.Password, DB: rs.DB, TLS: rs.TLS}, true
		},
	}
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for range t.C {
			if err := r.Tick(); err != nil {
				log.Printf("security engine tick: %v", err)
			}
		}
	}()
	return nil
}
