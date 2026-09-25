// Package omsdir looks up accounts in the OMS CNI SSO employee directory, so
// an admin can pre-register a user by picking them from a search instead of
// typing their email by hand. This is a separate API from the OIDC login
// flow in internal/auth — OIDC only ever authenticates the one person
// currently logging in, it has no "list the directory" operation. The
// directory lives at OMS CNI's own "sso/users" endpoint, authenticated with
// the same client_id/client_secret issued for the OIDC registration, sent
// as headers rather than a bearer token (this mirrors the integration
// aplikadata.id's CMS already runs successfully against the same system).
package omsdir

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// User is one directory entry. Only Email is guaranteed non-empty.
type User struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Department string `json:"department"`
	Position   string `json:"position"`
}

// Client queries the OMS CNI directory API.
type Client struct {
	BaseURL      string // e.g. https://oms.cni.net.id (no trailing slash)
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

func New(baseURL, clientID, clientSecret string) *Client {
	return &Client{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTPClient:   &http.Client{Timeout: 8 * time.Second},
	}
}

// Enabled reports whether enough configuration is present to call the API
// at all, so callers can degrade to manual entry instead of erroring.
func (c *Client) Enabled() bool {
	return c != nil && c.BaseURL != "" && c.ClientID != "" && c.ClientSecret != ""
}

func (c *Client) get(path string, query url.Values) ([]byte, error) {
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Client-Id", c.ClientID)
	req.Header.Set("X-Client-Secret", c.ClientSecret)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to OMS CNI directory failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read OMS CNI directory response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OMS CNI directory returned %s", resp.Status)
	}
	return body, nil
}

// LookupByEmail returns the directory entry for an exact email, or nil if
// there's no match.
func (c *Client) LookupByEmail(email string) (*User, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, nil
	}
	body, err := c.get("/sso/users", url.Values{"email": {email}})
	if err != nil {
		return nil, err
	}
	var out struct {
		User *User `json:"user"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode OMS CNI directory response: %w", err)
	}
	return out.User, nil
}

// Search looks up directory accounts by name or email fragment. A query
// containing "@" is treated as a full email and tried as an exact lookup
// first (optionally also trying it appended with "@cni.net.id" when the
// query has no domain), falling back to the directory's own free-text
// search endpoint. Mirrors the proven search order from aplikadata.id's
// integration against the same OMS CNI instance.
func (c *Client) Search(query string) ([]User, error) {
	query = strings.TrimSpace(query)
	if len(query) < 2 {
		return nil, nil
	}

	if strings.Contains(query, "@") {
		u, err := c.LookupByEmail(query)
		if err != nil {
			return nil, err
		}
		if u == nil {
			return nil, nil
		}
		return []User{*u}, nil
	}

	if u, err := c.LookupByEmail(query + "@cni.net.id"); err == nil && u != nil {
		return []User{*u}, nil
	}

	body, err := c.get("/sso/users", url.Values{"q": {query}})
	if err != nil {
		return nil, err
	}
	var out struct {
		Users []User `json:"users"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode OMS CNI directory response: %w", err)
	}
	return out.Users, nil
}
