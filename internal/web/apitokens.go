package web

import (
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/store"
)

// APITokenStore is the subset of *store.Store the API token screens need.
type APITokenStore interface {
	ListAPITokens() ([]store.APIToken, error)
	CreateAPIToken(name, createdBy string) (string, store.APIToken, error)
	RevokeAPIToken(id int64) error
}

// publicURL returns scheme://host as the caller addressed the gateway, so
// the Settings page can show the exact /mcp URL to paste into a client. It
// trusts X-Forwarded-Proto because HAProxy terminates TLS in front of the app.
func publicURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// APITokenCreateAction makes a token and shows its plaintext once.
type APITokenCreateAction struct {
	Store     APITokenStore
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *APITokenCreateAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "nama token wajib diisi", http.StatusBadRequest)
		return
	}
	if len(name) > 80 {
		http.Error(w, "nama token terlalu panjang (maks 80 karakter)", http.StatusBadRequest)
		return
	}
	u, _ := auth.UserFromContext(r.Context())

	plain, tok, err := h.Store.CreateAPIToken(name, u.Email)
	if err != nil {
		http.Error(w, "failed to create token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "api_token.create", Target: tok.Name, Detail: "prefix=" + tok.Prefix,
	}); err != nil {
		// The token exists but its creation is not on record: revoke it
		// rather than leave an unaudited credential behind.
		_ = h.Store.RevokeAPIToken(tok.ID)
		http.Error(w, "token not created: could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, h.Templates, "api_token_result.html", struct {
		Language string
		Name     string
		Token    string
		MCPURL   string
	}{Language: NewChrome(r, "").Language, Name: tok.Name, Token: plain, MCPURL: publicURL(r) + "/mcp"})
}

// APITokenRevokeAction disables a token at once.
type APITokenRevokeAction struct {
	Store     APITokenStore
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *APITokenRevokeAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	u, _ := auth.UserFromContext(r.Context())

	if err := h.Store.RevokeAPIToken(id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "token not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to revoke token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "api_token.revoke", Target: strconv.FormatInt(id, 10),
	}); err != nil {
		http.Error(w, "token revoked but could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// The list is server-rendered; HX-Refresh redraws it without the revoked
	// token's "Revoke" button.
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusNoContent)
}
