package web

import (
	"net/http"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/store"
)

// Chrome carries the data every authenticated page needs to render the
// shared header, side navigation and user menu. Handlers embed it
// anonymously in their own template data struct, which promotes User,
// CSRFToken and Active as top-level template fields (so templates write
// .CSRFToken, not .Chrome.CSRFToken).
type Chrome struct {
	User      store.User
	CSRFToken string
	// Active is the nav key of the current page ("dashboard", "config",
	// "certs", "acl", "audit", "users"), used to highlight it in chrome_nav.
	Active   string
	Language string
}

// NewChrome builds Chrome for the current request. Call once per handler,
// after auth.RequireAuth has attached the user/session to the context.
func NewChrome(r *http.Request, active string) Chrome {
	u, _ := auth.UserFromContext(r.Context())
	sess, _ := auth.SessionFromContext(r.Context())
	lang := u.Language
	if lang == "" {
		if c, err := r.Cookie("gateway_lang"); err == nil && c.Value != "" {
			lang = c.Value
		}
	}
	if lang == "" {
		al := r.Header.Get("Accept-Language")
		if len(al) >= 2 {
			prefix := al[0:2]
			if prefix == "id" || prefix == "en" || prefix == "zh" || prefix == "ja" {
				lang = prefix
			} else {
				lang = "id"
			}
		} else {
			lang = "id" // default
		}
	}
	return Chrome{User: u, CSRFToken: sess.CSRFToken, Active: active, Language: lang}
}
