package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"haproxy-gui/internal/store"
	"log"
	"sync"
)

// Config holds the OIDC client registration against OMS CNI SSO
// (https://oms.cni.net.id/sso). Values come from /etc/haproxy-gui/env, never
// hardcoded.
type Config struct {
	IssuerURL    string // e.g. https://oms.cni.net.id/sso
	ClientID     string
	ClientSecret string
	RedirectURL  string // e.g. https://haproxy-gui.cni.net.id/auth/callback
	CookieSecure bool   // false only for local http:// development
}

// Claims is what this app needs out of an ID token; anything else the IdP
// sends is ignored.
type Claims struct {
	Subject string
	Email   string
	Name    string
}

// Verifier checks a raw ID token JWT and extracts Claims. Production code
// uses oidc.IDTokenVerifier; tests use a fake so they don't need a live IdP.
type Verifier interface {
	Verify(ctx context.Context, rawIDToken string) (Claims, error)
}

type oidcVerifier struct{ v *oidc.IDTokenVerifier }

func (o *oidcVerifier) Verify(ctx context.Context, rawIDToken string) (Claims, error) {
	tok, err := o.v.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, fmt.Errorf("verify id_token: %w", err)
	}
	var c struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := tok.Claims(&c); err != nil {
		return Claims{}, fmt.Errorf("decode id_token claims: %w", err)
	}
	return Claims{Subject: tok.Subject, Email: c.Email, Name: c.Name}, nil
}

// Provider wires together the OIDC discovery document, an oauth2.Config for
// the authorization-code flow, and the token verifier.
type Provider struct {
	cfg          Config
	mu           sync.RWMutex
	oauth2Config *oauth2.Config
	verifier     Verifier
}

// NewProvider performs OIDC discovery against cfg.IssuerURL. If the IdP is
// temporarily down (e.g. backend returning 503), it logs a warning and will
// retry discovery in the background so haproxy-gui can start without fatal exits.
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	p := &Provider{cfg: cfg}
	if err := p.initDiscovery(ctx); err != nil {
		log.Printf("warning: initial oidc discovery against %s failed (%v); will retry in background and upon login", cfg.IssuerURL, err)
		go p.retryDiscoveryLoop()
	}
	return p, nil
}

func (p *Provider) initDiscovery(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.oauth2Config != nil && p.verifier != nil {
		return nil
	}
	prov, err := oidc.NewProvider(ctx, p.cfg.IssuerURL)
	if err != nil {
		return fmt.Errorf("oidc discovery against %s: %w", p.cfg.IssuerURL, err)
	}
	oc := &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		RedirectURL:  p.cfg.RedirectURL,
		Endpoint:     prov.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	verifier := prov.Verifier(&oidc.Config{ClientID: p.cfg.ClientID})
	p.oauth2Config = oc
	p.verifier = &oidcVerifier{verifier}
	log.Printf("oidc provider initialized successfully for %s", p.cfg.IssuerURL)
	return nil
}

func (p *Provider) retryDiscoveryLoop() {
	for i := 0; i < 120; i++ {
		time.Sleep(10 * time.Second)
		p.mu.RLock()
		ready := (p.oauth2Config != nil && p.verifier != nil)
		p.mu.RUnlock()
		if ready {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := p.initDiscovery(ctx)
		cancel()
		if err == nil {
			return
		}
	}
}

func (p *Provider) ensureReady(ctx context.Context) error {
	p.mu.RLock()
	ready := (p.oauth2Config != nil && p.verifier != nil)
	p.mu.RUnlock()
	if ready {
		return nil
	}
	return p.initDiscovery(ctx)
}

// state is what we round-trip through the IdP and back, bound to a short-
// lived cookie so the callback can confirm the redirect wasn't forged and
// recover the PKCE verifier used to start the flow.
type flowState struct {
	State        string
	PKCEVerifier string
}

const flowCookieName = "haproxygui_oidc_flow"

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// BeginLogin redirects the browser to the IdP, after stashing state+PKCE in
// a short-lived cookie for the callback to verify against.
func (p *Provider) BeginLogin(w http.ResponseWriter, r *http.Request, secureCookie bool) error {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := p.ensureReady(ctx); err != nil {
		return fmt.Errorf("layanan SSO belum siap: %w", err)
	}

	state, err := randomURLSafe(24)
	if err != nil {
		return err
	}
	verifier := oauth2.GenerateVerifier()

	http.SetCookie(w, &http.Cookie{
		Name:     flowCookieName,
		Value:    state + "." + verifier,
		Path:     "/auth",
		HttpOnly: true,
		Secure:   secureCookie,
		SameSite: http.SameSiteLaxMode, // Lax: must survive the top-level redirect back from the IdP
		MaxAge:   600,
	})

	p.mu.RLock()
	oc := p.oauth2Config
	p.mu.RUnlock()

	url := oc.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusFound)
	return nil
}

// HandleCallback validates the state cookie, exchanges the code, verifies
// the ID token, and returns the resulting Claims. It does not touch the
// database or set a session cookie — see CompleteLogin for that, kept
// separate so this half (the actual OIDC protocol handling) can be tested
// with a fake Verifier and this codebase's own fake oauth2 token source is
// unnecessary: exchangeFunc lets tests substitute the network call.
func (p *Provider) HandleCallback(r *http.Request) (Claims, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := p.ensureReady(ctx); err != nil {
		return Claims{}, fmt.Errorf("layanan SSO belum siap: %w", err)
	}

	flow, err := r.Cookie(flowCookieName)
	if err != nil {
		return Claims{}, fmt.Errorf("missing oidc flow cookie (state expired or cookies blocked)")
	}
	wantState, verifier, ok := splitFlowCookie(flow.Value)
	if !ok {
		return Claims{}, fmt.Errorf("malformed oidc flow cookie")
	}
	if r.URL.Query().Get("state") != wantState {
		return Claims{}, fmt.Errorf("state mismatch: possible CSRF on login callback")
	}
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		return Claims{}, fmt.Errorf("identity provider returned error: %s", errMsg)
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return Claims{}, fmt.Errorf("missing authorization code")
	}

	p.mu.RLock()
	oc := p.oauth2Config
	ver := p.verifier
	p.mu.RUnlock()

	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Claims{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Claims{}, fmt.Errorf("token response did not include id_token")
	}
	return ver.Verify(ctx, rawIDToken)
}

func splitFlowCookie(v string) (state, verifier string, ok bool) {
	for i := 0; i < len(v); i++ {
		if v[i] == '.' {
			return v[:i], v[i+1:], true
		}
	}
	return "", "", false
}

// CompleteLogin turns verified Claims into a local user and a fresh
// session, and writes the session cookie. This is the pure, easily-tested
// core of "what happens on successful SSO login".
func CompleteLogin(w http.ResponseWriter, s *store.Store, claims Claims, secureCookie bool) (store.User, error) {
	if claims.Email == "" {
		return store.User{}, fmt.Errorf("identity provider did not supply an email claim")
	}
	u, err := s.UpsertSSOUser(claims.Email, claims.Name, claims.Subject)
	if err != nil {
		return store.User{}, fmt.Errorf("upsert user: %w", err)
	}
	if !u.Enabled {
		return store.User{}, fmt.Errorf("account %s is disabled", u.Email)
	}
	sess, err := s.CreateSession(u.ID, SessionTTL)
	if err != nil {
		return store.User{}, fmt.Errorf("create session: %w", err)
	}
	SetSessionCookie(w, sess, secureCookie)
	return u, nil
}
