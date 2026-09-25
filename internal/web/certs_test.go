package web

import (
	"bytes"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"haproxy-gui/internal/certs"
	"haproxy-gui/internal/store"
)

type fakeCertLister struct {
	list []certs.Info
	err  error
}

func (f fakeCertLister) List() ([]certs.Info, error) { return f.list, f.err }

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
{{define "apply_result.html"}}OK={{.OK}} {{.Output}}{{end}}
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
