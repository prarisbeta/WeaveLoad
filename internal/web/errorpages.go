package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/errorpages"
	"haproxy-gui/internal/store"
)

// ErrorPagesHandler renders the custom error pages manager inside the configuration view.
type ErrorPagesHandler struct {
	Manager   *errorpages.Manager
	Audit     AuditRecorder
	Templates *template.Template
	// Config, when set, lets the page warn about error pages that haproxy.cfg
	// does not reference (HAProxy would then show its plain built-in page).
	Config interface{ Active() (string, error) }
}

// ErrorPagesView holds data for rendering error pages management UI.
type ErrorPagesView struct {
	Chrome
	Pages      []errorpages.Page
	ActivePage errorpages.Page
	ActiveCode int
	SuccessMsg string
	ErrorMsg   string

	// WiringChecked is false when the active config could not be read, in which
	// case no warning is shown rather than a wrong one.
	WiringChecked bool
	WiringByCode  map[int]errorpages.Wiring
	ActiveWiring  errorpages.Wiring
	Directive     string // the config line that would wire the active page
}

func (h *ErrorPagesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pages := h.Manager.List()
	activeCode := 429
	if codeStr := r.URL.Query().Get("code"); codeStr != "" {
		if c, err := strconv.Atoi(codeStr); err == nil {
			activeCode = c
		}
	}

	activePage, err := h.Manager.Get(activeCode)
	if err != nil && len(pages) > 0 {
		activePage = pages[0]
		activeCode = activePage.Code
	}

	view := ErrorPagesView{
		Chrome:     NewChrome(r, "config"),
		Pages:      pages,
		ActivePage: activePage,
		ActiveCode: activeCode,
		Directive:  h.Manager.Directive(activeCode),
	}
	if h.Config != nil {
		if content, err := h.Config.Active(); err == nil {
			view.WiringChecked = true
			view.WiringByCode = h.Manager.CheckWiring(content)
			view.ActiveWiring = view.WiringByCode[activeCode]
		}
	}
	renderTemplate(w, h.Templates, "error_pages.html", view)
}

// ErrorPageSaveAction saves an edited error page .http file to disk.
type ErrorPageSaveAction struct {
	Manager   *errorpages.Manager
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *ErrorPageSaveAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}

	codeStr := r.PathValue("code")
	if codeStr == "" {
		codeStr = r.FormValue("code")
	}
	code, err := strconv.Atoi(codeStr)
	if err != nil || code < 400 || code > 599 {
		http.Error(w, "invalid status code", http.StatusBadRequest)
		return
	}

	content := r.FormValue("content")
	if strings.TrimSpace(content) == "" {
		http.Error(w, "konten halaman error tidak boleh kosong", http.StatusBadRequest)
		return
	}

	if err := h.Manager.Save(code, content); err != nil {
		http.Error(w, "gagal menyimpan berkas error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	_ = h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email,
		RemoteIP:  clientIP(r),
		Action:    "config.error_page.save",
		Target:    fmt.Sprintf("%d.http", code),
		Detail:    fmt.Sprintf("Saved custom error page HTTP %d", code),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": fmt.Sprintf("Halaman error HTTP %d berhasil disimpan. HAProxy hanya memuat halaman error saat reload: jalankan Save & Apply di editor Config agar mulai dipakai.", code),
		"code":    code,
	})
}

// ErrorPagePreviewHandler serves the raw HTML content of an error page for sandboxed iframe preview.
type ErrorPagePreviewHandler struct {
	Manager *errorpages.Manager
}

func (h *ErrorPagePreviewHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	codeStr := r.PathValue("code")
	if codeStr == "" {
		codeStr = r.URL.Query().Get("code")
	}
	code, err := strconv.Atoi(codeStr)
	if err != nil || code < 400 || code > 599 {
		code = 429
	}

	page, err := h.Manager.Get(code)
	if err != nil {
		http.Error(w, "error page not found: "+err.Error(), http.StatusNotFound)
		return
	}

	// If POST preview requested with draft content
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if draft := r.FormValue("content"); strings.TrimSpace(draft) != "" {
			page.HTMLBody = errorpages.ExtractHTMLBody(draft)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	_, _ = w.Write([]byte(page.HTMLBody))
}

// ErrorPagePresetHandler returns the enterprise preset content for a status code.
type ErrorPagePresetHandler struct{}

func (h *ErrorPagePresetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	codeStr := r.PathValue("code")
	if codeStr == "" {
		codeStr = r.URL.Query().Get("code")
	}
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		code = 429
	}

	preset := errorpages.GetPreset(code)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(preset))
}
