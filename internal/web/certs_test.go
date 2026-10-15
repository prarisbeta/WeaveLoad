package web

import (
	"bytes"
	"fmt"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/certs"
	"haproxy-gui/internal/store"
)

type fakeCertLister struct {
	list   []certs.Info
	staged []certs.Info
	err    error
}

func (f fakeCertLister) List() ([]certs.Info, error)       { return f.list, f.err }
func (f fakeCertLister) ListStaged() ([]certs.Info, error) { return f.staged, f.err }

type fakeCertStager struct {
	stagedPath string
	info       certs.Info
	err        error
	gotDir     string
	gotName    string
}

func (f *fakeCertStager) StagePEM(dir, name string, content []byte) (string, certs.Info, error) {
	f.gotDir, f.gotName = dir, name
	return f.stagedPath, f.info, f.err
}

func certsTemplates(t *testing.T) *template.Template {
	return mustParse(t, `
{{define "certs.html"}}{{range .Certs}}{{.CommonName}}{{end}}{{end}}
{{define "apply_result.html"}}LANG={{.Language}} OK={{.OK}} {{.Output}}{{end}}
`)
}

func TestCertsHandler_ListsCertificates(t *testing.T) {
	lister := fakeCertLister{list: []certs.Info{{CommonName: "oms.cni.net.id", NotAfter: time.Now().Add(90 * 24 * time.Hour)}}}
	h := &CertsHandler{Certs: lister, Templates: certsTemplates(t)}

	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "oms.cni.net.id") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestCertsHandler_ListError_500(t *testing.T) {
	h := &CertsHandler{Certs: fakeCertLister{err: assertErr("permission denied")}, Templates: certsTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func multipartBody(t *testing.T, filename string, fileContent []byte) (*bytes.Buffer, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	_ = w.WriteField("filename", filename)
	fw, err := w.CreateFormFile("bundle", filename)
	if err != nil {
		t.Fatal(err)
	}
	fw.Write(fileContent)
	w.Close()
	return buf, w.FormDataContentType()
}

func TestCertUploadHandler_ValidUpload_Staged(t *testing.T) {
	stager := &fakeCertStager{stagedPath: "/staging/new.pem", info: certs.Info{CommonName: "new.cni.net.id", NotAfter: time.Now().Add(60 * 24 * time.Hour)}}
	au := &fakeAudit{}
	h := &CertUploadHandler{Stager: stager, StagingDir: "/staging", Audit: au, Templates: certsTemplates(t)}

	body, ct := multipartBody(t, "new.pem", []byte("fake pem content"))
	req := httptest.NewRequest(http.MethodPost, "/api/certs/upload", body)
	req.Header.Set("Content-Type", ct)
	req = withUser(req, store.User{Email: "admin@example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if stager.gotDir != "/staging" || stager.gotName != "new.pem" {
		t.Errorf("stager called with dir=%q name=%q", stager.gotDir, stager.gotName)
	}
	if !strings.Contains(rec.Body.String(), "LANG=id") {
		t.Errorf("result partial missing language, body = %q", rec.Body.String())
	}
	if len(au.entries) != 1 || au.entries[0].Action != "cert.upload" {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestCertUploadHandler_InvalidBundle_400AndAudited(t *testing.T) {
	stager := &fakeCertStager{err: assertErr("certificate and key do not match")}
	au := &fakeAudit{}
	h := &CertUploadHandler{Stager: stager, StagingDir: "/staging", Audit: au, Templates: certsTemplates(t)}

	body, ct := multipartBody(t, "bad.pem", []byte("garbage"))
	req := httptest.NewRequest(http.MethodPost, "/api/certs/upload", body)
	req.Header.Set("Content-Type", ct)
	req = withUser(req, store.User{Email: "admin@example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if len(au.entries) != 1 || !strings.Contains(au.entries[0].Detail, "rejected") {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestCertUploadHandler_MissingFileField_400(t *testing.T) {
	h := &CertUploadHandler{Stager: &fakeCertStager{}, StagingDir: "/staging", Audit: &fakeAudit{}, Templates: certsTemplates(t)}

	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	_ = w.WriteField("filename", "x.pem")
	w.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/certs/upload", buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req = withUser(req, store.User{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing file field", rec.Code)
	}
}

type fakeCertInstaller struct {
	res     certs.InstallResult
	err     error
	gotName string
}

func (f *fakeCertInstaller) Install(name string) (certs.InstallResult, error) {
	f.gotName = name
	return f.res, f.err
}

func installRequest(name string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/certs/install", strings.NewReader("filename="+name))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return withUser(req, store.User{Email: "admin@example.com"})
}

func TestCertInstallHandler_Success_AuditedAndRendered(t *testing.T) {
	inst := &fakeCertInstaller{res: certs.InstallResult{OK: true, Output: "installed and reloaded"}}
	au := &fakeAudit{}
	h := &CertInstallHandler{Installer: inst, Audit: au, Templates: certsTemplates(t)}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, installRequest("palapacloud.id.pem"))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "LANG=id OK=true") {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if inst.gotName != "palapacloud.id.pem" {
		t.Errorf("installer got %q", inst.gotName)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "cert.install" || au.entries[0].Target != "palapacloud.id.pem" {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestCertInstallHandler_HelperFailure_502AndAudited(t *testing.T) {
	inst := &fakeCertInstaller{res: certs.InstallResult{OK: false, Output: "haproxy -c failed, rolled back"}}
	au := &fakeAudit{}
	h := &CertInstallHandler{Installer: inst, Audit: au, Templates: certsTemplates(t)}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, installRequest("x.pem"))

	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "rolled back") {
		t.Errorf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if len(au.entries) != 1 || !strings.Contains(au.entries[0].Detail, "failed") {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestCertInstallHandler_InvalidName_400(t *testing.T) {
	inst := &fakeCertInstaller{err: certs.ErrInvalidFileName}
	h := &CertInstallHandler{Installer: inst, Audit: &fakeAudit{}, Templates: certsTemplates(t)}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, installRequest("..%2Fetc.pem"))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

type fakeCertRemover struct {
	res        certs.InstallResult
	liveErr    error
	stagedErr  error
	liveName   string
	stagedName string
}

func (f *fakeCertRemover) Remove(name string) (certs.InstallResult, error) {
	f.liveName = name
	return f.res, f.liveErr
}

func (f *fakeCertRemover) RemoveStaged(name string) error {
	f.stagedName = name
	return f.stagedErr
}

func removeRequest(name, scope string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/certs/remove", strings.NewReader("filename="+name+"&scope="+scope))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return withUser(req, store.User{Email: "admin@example.com"})
}

func TestCertRemoveHandler_Live_AuditedAndRendered(t *testing.T) {
	rm := &fakeCertRemover{res: certs.InstallResult{OK: true, Output: "removed"}}
	au := &fakeAudit{}
	h := &CertRemoveHandler{Remover: rm, Audit: au, Templates: certsTemplates(t)}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, removeRequest("old.pem", "live"))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "LANG=id OK=true") {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if rm.liveName != "old.pem" || rm.stagedName != "" {
		t.Errorf("live=%q staged=%q", rm.liveName, rm.stagedName)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "cert.remove" || au.entries[0].Target != "old.pem" {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestCertRemoveHandler_Staged_NeverTouchesLive(t *testing.T) {
	rm := &fakeCertRemover{}
	au := &fakeAudit{}
	h := &CertRemoveHandler{Remover: rm, Audit: au, Templates: certsTemplates(t)}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, removeRequest("new.pem", "staged"))

	if rec.Code != http.StatusOK || rm.stagedName != "new.pem" || rm.liveName != "" {
		t.Fatalf("status=%d staged=%q live=%q", rec.Code, rm.stagedName, rm.liveName)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "cert.remove_staged" {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestCertRemoveHandler_HelperRefusal_502AndAudited(t *testing.T) {
	rm := &fakeCertRemover{res: certs.InstallResult{OK: false, Output: "still referenced by haproxy.cfg"}}
	au := &fakeAudit{}
	h := &CertRemoveHandler{Remover: rm, Audit: au, Templates: certsTemplates(t)}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, removeRequest("in-use.pem", "live"))

	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "still referenced") {
		t.Errorf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if len(au.entries) != 1 || !strings.Contains(au.entries[0].Detail, "failed") {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestCertRemoveHandler_BadInput_400(t *testing.T) {
	cases := []struct {
		name, scope string
		liveErr     error
	}{
		{"x.pem", "elsewhere", nil},
		{"..%2Fetc.pem", "live", certs.ErrInvalidFileName},
	}
	for _, c := range cases {
		h := &CertRemoveHandler{Remover: &fakeCertRemover{liveErr: c.liveErr}, Audit: &fakeAudit{}, Templates: certsTemplates(t)}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, removeRequest(c.name, c.scope))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s/%s: status = %d, want 400", c.name, c.scope, rec.Code)
		}
	}
}

func TestCertRemoveHandler_StagedMissing_404(t *testing.T) {
	rm := &fakeCertRemover{stagedErr: fmt.Errorf("remove staged certificate: %w", os.ErrNotExist)}
	h := &CertRemoveHandler{Remover: rm, Audit: &fakeAudit{}, Templates: certsTemplates(t)}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, removeRequest("gone.pem", "staged"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
