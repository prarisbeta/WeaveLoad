package web

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/certs"
	"haproxy-gui/internal/store"
)

// CertLister is the subset of *certs.Store the SSL page needs.
type CertLister interface {
	List() ([]certs.Info, error)
}

// CertStager is the subset of *certs.Store the upload action needs.
type CertStager interface {
	StagePEM(stagingDir, targetFileName string, content []byte) (string, certs.Info, error)
}

// CertsHandler renders the certificate list.
type CertsHandler struct {
	Certs     CertLister
	Templates *template.Template
}

func (h *CertsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	list, err := h.Certs.List()
	if err != nil {
		http.Error(w, "failed to list certificates: "+err.Error(), http.StatusInternalServerError)
		return
	}
	u, _ := auth.UserFromContext(r.Context())
	renderTemplate(w, h.Templates, "certs.html", struct {
		Chrome
		Certs     []certs.Info
		Now       time.Time
		CanUpload bool
	}{Chrome: NewChrome(r, "certs"), Certs: list, Now: time.Now(), CanUpload: u.Role.Allows(store.RoleAdmin)})
}

// CertUploadStagingDir is where uploaded bundles land pending review; an
// admin still has to move them into the live ssl/ directory (via the
// deploy runbook) since HAProxy's "crt" list is static per-frontend and
// wiring a brand new file in requires a config change anyway, which goes
// through the normal validate-then-apply config flow.
type CertUploadHandler struct {
	Stager     CertStager
	StagingDir string
	Audit      AuditRecorder
	Templates  *template.Template
	MaxBytes   int64 // 0 means DefaultMaxCertBytes
}

const DefaultMaxCertBytes = 1 << 20 // 1 MiB is generous for a PEM bundle

func (h *CertUploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	max := h.MaxBytes
	if max == 0 {
		max = DefaultMaxCertBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, max)

	if err := r.ParseMultipartForm(max); err != nil {
		http.Error(w, "invalid or too-large upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	filename := r.FormValue("filename")
	file, _, err := r.FormFile("bundle")
	if err != nil {
		http.Error(w, "missing file field 'bundle'", http.StatusBadRequest)
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "failed to read upload: "+err.Error(), http.StatusBadRequest)
		return
	}

	path, info, err := h.Stager.StagePEM(h.StagingDir, filename, content)
	u, _ := auth.UserFromContext(r.Context())

	if err != nil {
		_ = h.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: clientIP(r),
			Action: "cert.upload", Target: filename, Detail: "rejected: " + err.Error(),
		})
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "cert.upload", Target: path,
		Detail: fmt.Sprintf("cn=%s expires=%s", info.CommonName, info.NotAfter.Format("2006-01-02")),
	}); err != nil {
		http.Error(w, "upload succeeded but could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, h.Templates, "apply_result.html", struct {
		OK     bool
		Output string
	}{OK: true, Output: fmt.Sprintf("Staged at %s (CN=%s, expires %s). Wire it into a bind line via the Config editor to activate.", path, info.CommonName, info.NotAfter.Format("2006-01-02"))})
}
