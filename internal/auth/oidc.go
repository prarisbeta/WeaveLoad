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
	oauth2Config *oauth2.Config
	verifier     Verifier
}

// NewProvider performs OIDC discovery against cfg.IssuerURL. Call once at
// startup; a discovery failure (SSO unreachable) should stop the server
// from starting rather than silently disabling login.
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	p, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery against %s: %w", cfg.IssuerURL, err)
	}
	oc := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     p.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	verifier := p.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	return &Provider{oauth2Config: oc, verifier: &oidcVerifier{verifier}}, nil
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

	url := p.oauth2Config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
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

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	tok, err := p.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Claims{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Claims{}, fmt.Errorf("token response did not include id_token")
	}
	return p.verifier.Verify(ctx, rawIDToken)
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
