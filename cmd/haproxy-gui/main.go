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
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"haproxy-gui/internal/anomaly"
	"haproxy-gui/internal/appconfig"
	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/canary"
	"haproxy-gui/internal/certs"
	"haproxy-gui/internal/cfgfile"
	"haproxy-gui/internal/fleet"
	"haproxy-gui/internal/haproxycfg"
	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/license"
	"haproxy-gui/internal/notify"
	"haproxy-gui/internal/omsdir"
	"haproxy-gui/internal/policy"
	"haproxy-gui/internal/ratelimitqueue"
	"haproxy-gui/internal/redisping"
	"haproxy-gui/internal/retention"
	"haproxy-gui/internal/runtime"
	"haproxy-gui/internal/security"
	"haproxy-gui/internal/stats"
	"haproxy-gui/internal/store"
	"haproxy-gui/internal/sysinfo"
	"haproxy-gui/internal/threatintel"
	"haproxy-gui/internal/web"
)

//go:embed templates/*.html
var templatesFS embed.FS

// blocklistPath is the HAProxy map file the Policy Engine adds blocked IPs to
// (the same "Blocklist IP" list the ACL page manages).
const blocklistPath = "/etc/haproxy/maps/blocklist_ip.lst"

// newIntelService builds the threat-intelligence service from the environment,
// or returns nil when neither blocklist feeds nor an AbuseIPDB key are set, so
// a default install makes no outbound calls.
//
//	KONSOLGW_INTEL_FEEDS=spamhaus_drop,tor_exit,et_compromised
//	KONSOLGW_ABUSEIPDB_KEY=...   KONSOLGW_ABUSEIPDB_DAILY_LIMIT=900
func newIntelService(s *store.Store) *threatintel.Service {
	feeds, unknown := threatintel.FeedsFromNames(strings.Split(os.Getenv("KONSOLGW_INTEL_FEEDS"), ","))
	for _, u := range unknown {
		log.Printf("threat intel: ignoring unknown feed %q (known: spamhaus_drop, tor_exit, et_compromised)", u)
	}
	key := os.Getenv("KONSOLGW_ABUSEIPDB_KEY")
	if len(feeds) == 0 && key == "" {
		return nil
	}
	limit, _ := strconv.Atoi(os.Getenv("KONSOLGW_ABUSEIPDB_DAILY_LIMIT"))
	log.Printf("threat intel enabled: %d feed(s), abuseipdb=%v", len(feeds), key != "")
	return &threatintel.Service{Feeds: feeds, Store: s, AbuseKey: key, AbuseDailyLimit: limit}
}

// newFleetAgent returns the agent that reports this gateway's state to a hub,
// or nil unless KONSOLGW_FLEET_HUB_URL, KONSOLGW_FLEET_TOKEN and
// KONSOLGW_NODE_NAME are all set. The hub URL must be https.
func newFleetAgent(s *store.Store, rt *runtime.Client, pe *policy.Engine) *fleet.Agent {
	hub, tok, name := os.Getenv("KONSOLGW_FLEET_HUB_URL"), os.Getenv("KONSOLGW_FLEET_TOKEN"), os.Getenv("KONSOLGW_NODE_NAME")
	if hub == "" || tok == "" || name == "" {
		return nil
	}
	if !strings.HasPrefix(hub, "https://") {
		log.Printf("fleet agent disabled: KONSOLGW_FLEET_HUB_URL must start with https://")
		return nil
	}
	log.Printf("fleet agent enabled: reporting as %q", name)
	return &fleet.Agent{HubURL: hub, Token: tok, Collect: func(ctx context.Context) fleet.Report {
		rep := fleet.Report{Node: name, Version: version, KillSwitch: pe.Config().KillSwitch}
		if raw, err := rt.ShowStat(); err == nil {
			if snap, err := stats.Parse(raw); err == nil {
				rep.HAProxyUp, rep.Sessions = true, snap.Summary().Sessions
				for _, be := range snap.Backends {
					h := fleet.BackendHealth{Name: be.Name}
					for _, sv := range be.Servers {
						switch {
						case sv.Up():
							h.Up++
						case sv.Down():
							h.Down++
						}
					}
					rep.Backends = append(rep.Backends, h)
				}
			}
		}
		if risks, err := s.ListTopRisk(500); err == nil {
			for _, r := range risks {
				if r.State == "high_risk" {
					rep.HighRiskIPs++
				}
			}
		}
		_, rep.OpenEvents, _ = s.ListSecurityEvents(store.SecurityFilter{Status: "open", Limit: 1})
		_, rep.OpenIncident, _ = s.ListIncidents(store.IncidentFilter{Status: "open", Limit: 1})
		return rep
	}}
}

// version and licensePublicKey are stamped at build time with
// -ldflags "-X main.version=... -X main.licensePublicKey=...".
var (
	version          = "dev"
	licensePublicKey = ""
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// newNotifier builds the alert notifier from the environment, or returns nil
// when no channel is configured (a nil *Notifier ignores every Notify call).
//
//	KONSOLGW_NOTIFY_WEBHOOK_URL                      generic JSON webhook, {"text": "..."}
//	KONSOLGW_NOTIFY_TELEGRAM_TOKEN / _CHAT_ID        Telegram bot
//	KONSOLGW_NOTIFY_MIN_SEVERITY=high                low|medium|high|critical
//	KONSOLGW_NOTIFY_WINDOW_SECONDS=300               digest window
func newNotifier() *notify.Notifier {
	var chans []notify.Channel
	if u := os.Getenv("KONSOLGW_NOTIFY_WEBHOOK_URL"); u != "" {
		chans = append(chans, &notify.Webhook{URL: u})
	}
	if tok, chat := os.Getenv("KONSOLGW_NOTIFY_TELEGRAM_TOKEN"), os.Getenv("KONSOLGW_NOTIFY_TELEGRAM_CHAT_ID"); tok != "" && chat != "" {
		chans = append(chans, &notify.Telegram{Token: tok, ChatID: chat})
	}
	if len(chans) == 0 {
		return nil
	}
	secs, _ := strconv.Atoi(os.Getenv("KONSOLGW_NOTIFY_WINDOW_SECONDS"))
	host, _ := os.Hostname()
	log.Printf("notifications enabled: %d channel(s)", len(chans))
	return &notify.Notifier{
		Channels: chans, MinSeverity: os.Getenv("KONSOLGW_NOTIFY_MIN_SEVERITY"),
		Window: time.Duration(secs) * time.Second, Hostname: host,
	}
}

// notifierOrNil avoids handing the Runner an interface that wraps a nil pointer.
func notifierOrNil(n *notify.Notifier) security.Notifier {
	if n == nil {
		return nil
	}
	return n
}

// intelOrNil avoids handing the Runner an interface that wraps a nil pointer.
func intelOrNil(s *threatintel.Service) security.IntelLookup {
	if s == nil {
		return nil
	}
	return s
}

// expirePolicyPeriodically undoes policy actions whose TTL has ended.
func expirePolicyPeriodically(ctx context.Context, e *policy.Engine) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := e.ExpireDue(); err != nil {
				log.Printf("policy expire: %v", err)
			} else if n > 0 {
				log.Printf("policy: reverted %d expired action(s)", n)
			}
		}
	}
}

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

	tpl, err := template.New("").Funcs(web.TemplateFuncs()).ParseFS(templatesFS, "templates/*.html")
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
	certStore.RemoveScript = cfg.CertRemoveScript
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

	policyEngine := &policy.Engine{
		Repo:  s,
		Exec:  &policy.HAProxyExecutor{Maps: rt, Servers: rt, BlocklistPath: blocklistPath},
		Audit: s,
	}

	notifier := newNotifier()
	notifyCtx, stopNotify := context.WithCancel(context.Background())
	defer stopNotify()
	if notifier != nil {
		go notifier.Run(notifyCtx)
	}

	canaryWatcher := &canary.Watcher{
		Window: policyEngine.CanaryWindow,
		NewSource: func() (canary.LogSource, error) {
			return haproxylog.NewTailerAtEnd(cfg.LogPath)
		},
		Rollback: func(prev string) error {
			draft, err := cf.SaveDraft("canary-rollback", prev)
			if err != nil {
				return err
			}
			res, err := cf.Apply(draft)
			if err != nil {
				return err
			}
			if !res.OK {
				return fmt.Errorf("apply helper refused the previous config: %s", res.Output)
			}
			return nil
		},
		Alert: func(rule, severity, subject, message string) {
			if _, err := s.CreateAlert(rule, severity, subject, message); err != nil {
				log.Printf("canary: create alert: %v", err)
			}
			notifier.Notify(notify.Notice{Severity: severity, Title: rule + " " + subject, Detail: message})
		},
		Audit: s,
	}

	retentionCtx, stopRetention := context.WithCancel(context.Background())
	defer stopRetention()

	// Features above Community stay off unless the licence includes them; a
	// development build (no compiled-in key) enables everything.
	gate := license.Load(licensePublicKey, getenv("KONSOLGW_LICENSE_FILE", "/etc/haproxy-gui/license.key"), time.Now())
	log.Printf("edition: %s", gate.Describe())
	policyEngine.Allow = gate.Allows

	fleetHub := &fleet.Hub{Repo: s}
	if gate.Allows("fleet") {
		fleetHub.Token = os.Getenv("KONSOLGW_FLEET_TOKEN")
		if agent := newFleetAgent(s, rt, policyEngine); agent != nil {
			go agent.Run(retentionCtx, time.Minute, log.Printf)
		}
	}

	var intel *threatintel.Service
	if gate.Allows("intel_feeds") {
		intel = newIntelService(s)
	}
	intelCtx, stopIntel := context.WithCancel(context.Background())
	defer stopIntel()
	if intel != nil {
		go intel.Run(intelCtx, 6*time.Hour)
	}

	mux := buildRoutes(routeDeps{
		gate:      gate,
		fleetHub:  fleetHub,
		intel:     intel,
		policy:    policyEngine,
		canary:    canaryWatcher,
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

	sweeper := &retention.Sweeper{Store: s, Backups: cf, Policy: retention.DefaultPolicy()}
	go sweeper.Run(retentionCtx, time.Hour)
	go expirePolicyPeriodically(retentionCtx, policyEngine)
	go pushRateLimitEventsPeriodically(s, cf, cfg.LogPath)
	if err := runSecurityEnginePeriodically(s, cfg.LogPath, policyEngine, intel, notifier, gate.Allows("anomaly")); err != nil {
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
func runSecurityEnginePeriodically(s *store.Store, logPath string, pe *policy.Engine, intel *threatintel.Service, nf *notify.Notifier, withAnomaly bool) error {
	tailer, err := haproxylog.NewTailerAtEnd(logPath)
	if err != nil {
		return err
	}
	var tracker *anomaly.Tracker // nil: the licence does not include seasonal anomaly detection
	if withAnomaly {
		tracker = anomaly.NewTracker(anomaly.DefaultConfig(), s)
	}
	r := &security.Runner{
		Store:    s,
		Engine:   security.NewEngine(security.DefaultThresholds()),
		Tailer:   tailer,
		Policy:   pe,
		Intel:    intelOrNil(intel),
		Notifier: notifierOrNil(nf),
		Anomaly:  tracker,
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
