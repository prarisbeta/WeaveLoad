// Command haproxy-gui serves the web management UI for the haproxy-cni
// load balancer: live dashboard, runtime server control, config editor with
// validate/apply/rollback, SSL certificate inventory, and ACL/map
// management, all behind OMS CNI SSO login with role-based access and a
// full audit trail.
package main

import (
	"context"
	"embed"
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
	"haproxy-gui/internal/omsdir"
	"haproxy-gui/internal/runtime"
	"haproxy-gui/internal/store"
	"haproxy-gui/internal/sysinfo"
)

//go:embed templates/*.html
var templatesFS embed.FS

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
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
	cf.HAProxyBin = cfg.HAProxyBin
	cf.StagingDir = cfg.StagingDir
	cf.ApplyScript = cfg.ApplyScript
	cf.RestartScript = cfg.RestartScript
	cf.SudoBin = cfg.SudoBin

	certStore := certs.New(cfg.SSLDir)
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
	}
}
