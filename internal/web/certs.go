package web

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"time"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/certs"
	"haproxy-gui/internal/store"
)

// CertLister is the subset of *certs.Store the SSL page needs.
type CertLister interface {
	List() ([]certs.Info, error)
	ListStaged() ([]certs.Info, error)
}

// CertInstaller is the subset of *certs.Store the install action needs.
type CertInstaller interface {
	Install(fileName string) (certs.InstallResult, error)
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
	staged, err := h.Certs.ListStaged()
	if err != nil {
		http.Error(w, "failed to list staged certificates: "+err.Error(), http.StatusInternalServerError)
		return
	}
	u, _ := auth.UserFromContext(r.Context())
	renderTemplate(w, h.Templates, "certs.html", struct {
		Chrome
		Certs     []certs.Info
		Staged    []certs.Info
		Now       time.Time
		CanUpload bool
	}{Chrome: NewChrome(r, "certs"), Certs: list, Staged: staged, Now: time.Now(), CanUpload: u.Role.Can(store.CapManageConfig)})
}

// CertUploadHandler stages an uploaded bundle for review. Activating it is a
// separate step (CertInstallHandler), since that touches the live ssl/
// directory and reloads HAProxy.
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

	renderTemplate(w, h.Templates, "apply_result.html", newResultView(r, true,
		fmt.Sprintf("Staged at %s (CN=%s, expires %s). Reload this page and use the Ready to install list to activate it.", path, info.CommonName, info.NotAfter.Format("2006-01-02"))))
}

// CertInstallHandler moves a staged bundle into the live ssl directory and
// reloads HAProxy through the root helper. Every attempt is audit-logged,
// success or failure.
type CertInstallHandler struct {
	Installer CertInstaller
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *CertInstallHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("filename")
	u, _ := auth.UserFromContext(r.Context())

	res, err := h.Installer.Install(filename)
	if errors.Is(err, certs.ErrInvalidFileName) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "failed to run install helper: "+err.Error(), http.StatusInternalServerError)
		return
	}

	detail := "installed and reloaded"
	if !res.OK {
		detail = "install failed (auto rollback expected): " + res.Output
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "cert.install", Target: filename, Detail: detail,
	}); err != nil {
		http.Error(w, "install outcome could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !res.OK {
		http.Error(w, "Pemasangan gagal, sertifikat lama dipulihkan otomatis: "+res.Output, http.StatusBadGateway)
		return
	}
	renderTemplate(w, h.Templates, "apply_result.html", newResultView(r, true, res.Output))
}

// CertRemover is the subset of *certs.Store the remove action needs.
type CertRemover interface {
	Remove(fileName string) (certs.InstallResult, error)
	RemoveStaged(fileName string) error
}

// CertRemoveHandler deletes either an uploaded-but-not-installed bundle
// (scope "staged", no root needed) or a live certificate (scope "live", via
// the root helper, which refuses files haproxy.cfg still references). Every
// attempt is audit-logged.
type CertRemoveHandler struct {
	Remover   CertRemover
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *CertRemoveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("filename")
	scope := r.FormValue("scope")
	u, _ := auth.UserFromContext(r.Context())

	var (
		action string
		res    certs.InstallResult
		err    error
	)
	switch scope {
	case "staged":
		action = "cert.remove_staged"
		res.OK = true
		err = h.Remover.RemoveStaged(filename)
	case "live":
		action = "cert.remove"
		res, err = h.Remover.Remove(filename)
	default:
		http.Error(w, "scope must be staged or live", http.StatusBadRequest)
		return
	}
	switch {
	case errors.Is(err, certs.ErrInvalidFileName):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, os.ErrNotExist):
		http.Error(w, "certificate not found: "+filename, http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, "failed to remove certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	detail := "removed"
	if !res.OK {
		detail = "remove failed: " + res.Output
	}
	if err := h.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: action, Target: filename, Detail: detail,
	}); err != nil {
		http.Error(w, "removal outcome could not be audit-logged: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !res.OK {
		http.Error(w, "Penghapusan ditolak atau gagal: "+res.Output, http.StatusBadGateway)
		return
	}
	msg := res.Output
	if scope == "staged" {
		msg = "Staged file " + filename + " removed."
	}
	renderTemplate(w, h.Templates, "apply_result.html", newResultView(r, true, msg))
}
