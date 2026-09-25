package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"haproxy-gui/internal/store"
)

type fakeMapRuntime struct {
	added   map[string][2]string // mapFile -> [key, value]
	deleted map[string]string    // mapFile -> key
	err     error
}

func newFakeMapRuntime() *fakeMapRuntime {
	return &fakeMapRuntime{added: map[string][2]string{}, deleted: map[string]string{}}
}

func (f *fakeMapRuntime) AddMapEntry(mapFile, key, value string) error {
	if f.err != nil {
		return f.err
	}
	f.added[mapFile] = [2]string{key, value}
	return nil
}

func (f *fakeMapRuntime) DelMapEntry(mapFile, key string) error {
	if f.err != nil {
		return f.err
	}
	if f.deleted == nil {
		f.deleted = map[string]string{}
	}
	f.deleted[mapFile] = key
	return nil
}

func aclTemplates(t *testing.T) *template.Template {
	return mustParse(t, `{{define "acl.html"}}{{range .Files}}{{.Label}}:{{range .Entries}}{{.Key}}={{.Value}} {{end}}{{end}}{{end}}`)
}

func TestAclHandler_ReadsMapFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts_http.map")
	os.WriteFile(path, []byte("# comment\noms.cni.net.id http_oms\n\n"), 0o640)

	h := &AclHandler{
		Files:     []MapFile{{Label: "HTTP routing", Path: path, HasValue: true}},
		Templates: aclTemplates(t),
	}
	req := httptest.NewRequest(http.MethodGet, "/acl", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "oms.cni.net.id=http_oms") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestAclHandler_MissingFile_NoEntries(t *testing.T) {
	h := &AclHandler{
		Files:     []MapFile{{Label: "X", Path: filepath.Join(t.TempDir(), "missing.lst"), HasValue: false}},
		Templates: aclTemplates(t),
	}
	req := httptest.NewRequest(http.MethodGet, "/acl", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (missing map file should read as empty)", rec.Code)
	}
}

func TestAclAddHandler_AddsRuntimeAndPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts_http.map")

	rt := newFakeMapRuntime()
	au := &fakeAudit{}
	base := &AclHandler{
		Files:     []MapFile{{Label: "HTTP routing", Path: path, HasValue: true}},
		Runtime:   rt,
		Audit:     au,
		Templates: aclTemplates(t),
	}
	h := &AclAddHandler{AclHandler: base}

	req := httptest.NewRequest(http.MethodPost, "/api/acl/add", strings.NewReader("path="+path+"&key=new.example.id&value=http_new"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{Email: "admin@example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if rt.added[path] != [2]string{"new.example.id", "http_new"} {
		t.Errorf("runtime not called correctly: %+v", rt.added)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "new.example.id http_new") {
		t.Errorf("file not persisted: %q", got)
	}
	if len(au.entries) != 1 {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestAclAddHandler_RejectsWhitespaceInKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.lst")
	rt := newFakeMapRuntime()
	base := &AclHandler{Files: []MapFile{{Label: "L", Path: path}}, Runtime: rt, Audit: &fakeAudit{}, Templates: aclTemplates(t)}
	h := &AclAddHandler{AclHandler: base}

	req := httptest.NewRequest(http.MethodPost, "/api/acl/add", strings.NewReader("path="+path+"&key=has space"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if len(rt.added) != 0 {
		t.Error("runtime should not be called for an invalid key")
	}
}

func TestAclAddHandler_UnknownMapFile_400(t *testing.T) {
	base := &AclHandler{Files: []MapFile{{Label: "L", Path: "/etc/haproxy/maps/known.lst"}}, Runtime: newFakeMapRuntime(), Audit: &fakeAudit{}, Templates: aclTemplates(t)}
	h := &AclAddHandler{AclHandler: base}

	req := httptest.NewRequest(http.MethodPost, "/api/acl/add", strings.NewReader("path=/etc/passwd&key=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a path not in the managed file list", rec.Code)
	}
}

func TestAclDeleteHandler_RemovesRuntimeAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts_http.map")
	os.WriteFile(path, []byte("old.example.id http_old\nkeep.example.id http_keep\n"), 0o640)

	rt := newFakeMapRuntime()
	au := &fakeAudit{}
	base := &AclHandler{
		Files:     []MapFile{{Label: "HTTP routing", Path: path, HasValue: true}},
		Runtime:   rt,
		Audit:     au,
		Templates: aclTemplates(t),
	}
	h := &AclDeleteHandler{AclHandler: base}

	req := httptest.NewRequest(http.MethodPost, "/api/acl/delete", strings.NewReader("path="+path+"&key=old.example.id"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{Email: "admin@example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if rt.deleted[path] != "old.example.id" {
		t.Errorf("runtime not called correctly: %+v", rt.deleted)
	}
	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "old.example.id") {
		t.Errorf("entry should have been removed from file: %q", got)
	}
	if !strings.Contains(string(got), "keep.example.id") {
		t.Errorf("unrelated entry should survive: %q", got)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "acl.delete" {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestAclDeleteHandler_UnknownMapFile_400(t *testing.T) {
	base := &AclHandler{Files: []MapFile{{Label: "L", Path: "/etc/known.lst"}}, Runtime: newFakeMapRuntime(), Audit: &fakeAudit{}, Templates: aclTemplates(t)}
	h := &AclDeleteHandler{AclHandler: base}

	req := httptest.NewRequest(http.MethodPost, "/api/acl/delete", strings.NewReader("path=/etc/passwd&key=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a path not in the managed file list", rec.Code)
	}
}

func TestAclDeleteHandler_RuntimeFailure_502(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.lst")
	os.WriteFile(path, []byte("1.2.3.4\n"), 0o640)
	rt := &fakeMapRuntime{added: map[string][2]string{}, err: assertErr("no such entry")}
	au := &fakeAudit{}
	base := &AclHandler{Files: []MapFile{{Label: "L", Path: path}}, Runtime: rt, Audit: au, Templates: aclTemplates(t)}
	h := &AclDeleteHandler{AclHandler: base}

	req := httptest.NewRequest(http.MethodPost, "/api/acl/delete", strings.NewReader("path="+path+"&key=1.2.3.4"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "1.2.3.4") {
		t.Error("file should be unchanged when the runtime call failed")
	}
}

func TestAclAddHandler_RuntimeFailure_502(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.lst")
	rt := &fakeMapRuntime{added: map[string][2]string{}, err: assertErr("no such map")}
	au := &fakeAudit{}
	base := &AclHandler{Files: []MapFile{{Label: "L", Path: path}}, Runtime: rt, Audit: au, Templates: aclTemplates(t)}
	h := &AclAddHandler{AclHandler: base}

	req := httptest.NewRequest(http.MethodPost, "/api/acl/add", strings.NewReader("path="+path+"&key=1.2.3.4"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("file should not be written when the runtime call failed")
	}
}
