package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/cfgfile"
	"haproxy-gui/internal/store"
)

type fakeConfigStore struct {
	active      string
	activeErr   error
	validateRes cfgfile.ValidateResult
	validateErr error
	savedDrafts []string
	draftPath   string
	draftErr    error
	applyRes    cfgfile.ApplyResult
	applyErr    error
	appliedPath string
	backups     []cfgfile.Backup
	backupsErr  error
}

func (f *fakeConfigStore) Active() (string, error) { return f.active, f.activeErr }
func (f *fakeConfigStore) Validate(content string) (cfgfile.ValidateResult, error) {
	return f.validateRes, f.validateErr
}
func (f *fakeConfigStore) SaveDraft(author, content string) (string, error) {
	f.savedDrafts = append(f.savedDrafts, content)
	return f.draftPath, f.draftErr
}
func (f *fakeConfigStore) Apply(stagedPath string) (cfgfile.ApplyResult, error) {
	f.appliedPath = stagedPath
	return f.applyRes, f.applyErr
}
func (f *fakeConfigStore) ListBackups() ([]cfgfile.Backup, error) { return f.backups, f.backupsErr }

func testConfigTemplates(t *testing.T) *template.Template {
	t.Helper()
	return mustParse(t, `
{{define "config.html"}}CFG:{{.Active}}{{end}}
{{define "validate_result.html"}}VALID={{.OK}} OUT={{.Output}}{{end}}
{{define "apply_result.html"}}APPLIED={{.OK}} OUT={{.Output}}{{end}}
`)
}

func withUser(r *http.Request, u store.User) *http.Request {
	return r.WithContext(auth.WithUser(r.Context(), u, store.Session{CSRFToken: "csrf"}))
}

func TestConfigHandler_RendersActiveConfig(t *testing.T) {
	cs := &fakeConfigStore{active: "global\n    daemon\n"}
	h := &ConfigHandler{Config: cs, Templates: testConfigTemplates(t)}
	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "daemon") {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestValidateAction_ValidConfig(t *testing.T) {
	cs := &fakeConfigStore{validateRes: cfgfile.ValidateResult{OK: true, Output: "Configuration file is valid"}}
	h := &ValidateAction{Config: cs, Templates: testConfigTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/config/validate", strings.NewReader("content=global"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "VALID=true") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestValidateAction_EmptyContent_400(t *testing.T) {
	h := &ValidateAction{Config: &fakeConfigStore{}, Templates: testConfigTemplates(t)}
	req := httptest.NewRequest(http.MethodPost, "/api/config/validate", strings.NewReader("content="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestSaveApplyAction_InvalidConfig_NeverStagesOrApplies(t *testing.T) {
	cs := &fakeConfigStore{validateRes: cfgfile.ValidateResult{OK: false, Output: "syntax error"}}
	au := &fakeAudit{}
	h := &SaveApplyAction{Config: cs, Audit: au, Templates: testConfigTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", strings.NewReader("content=BROKEN"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{Email: "admin@example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if len(cs.savedDrafts) != 0 {
		t.Error("an invalid config should never be staged")
	}
	if cs.appliedPath != "" {
		t.Error("an invalid config should never be applied")
	}
	if len(au.entries) != 1 || !strings.Contains(au.entries[0].Detail, "rejected") {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestSaveApplyAction_ValidConfig_StagesAndApplies(t *testing.T) {
	cs := &fakeConfigStore{
		validateRes: cfgfile.ValidateResult{OK: true},
		draftPath:   "/staging/draft-1.cfg",
		applyRes:    cfgfile.ApplyResult{OK: true, Output: "applied"},
	}
	au := &fakeAudit{}
	h := &SaveApplyAction{Config: cs, Audit: au, Templates: testConfigTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", strings.NewReader("content=global"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{Email: "admin@example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if cs.appliedPath != "/staging/draft-1.cfg" {
		t.Errorf("applied path = %q", cs.appliedPath)
	}
	if len(au.entries) != 1 || au.entries[0].Detail != "applied" {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestSaveApplyAction_ApplyHelperFails_502AndAudited(t *testing.T) {
	cs := &fakeConfigStore{
		validateRes: cfgfile.ValidateResult{OK: true},
		draftPath:   "/staging/draft-2.cfg",
		applyRes:    cfgfile.ApplyResult{OK: false, Output: "reload failed, rolled back"},
	}
	au := &fakeAudit{}
	h := &SaveApplyAction{Config: cs, Audit: au, Templates: testConfigTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", strings.NewReader("content=global"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{Email: "admin@example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if len(au.entries) != 1 || !strings.Contains(au.entries[0].Detail, "rolled back") {
		t.Errorf("audit entries = %+v", au.entries)
	}
}

func TestRollbackAction_RejectsUnknownBackupPath(t *testing.T) {
	cs := &fakeConfigStore{backups: []cfgfile.Backup{{Path: "/etc/haproxy/haproxy.cfg.bak-1"}}}
	h := &RollbackAction{Config: cs, Audit: &fakeAudit{}, Templates: testConfigTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/config/rollback", strings.NewReader("backup_path=/etc/passwd"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a path not in ListBackups()", rec.Code)
	}
	if cs.appliedPath != "" {
		t.Error("Apply should never be called for an unknown backup path")
	}
}

func TestRollbackAction_KnownBackup_Applies(t *testing.T) {
	cs := &fakeConfigStore{
		backups:  []cfgfile.Backup{{Path: "/etc/haproxy/haproxy.cfg.bak-1"}},
		applyRes: cfgfile.ApplyResult{OK: true, Output: "applied"},
	}
	au := &fakeAudit{}
	h := &RollbackAction{Config: cs, Audit: au, Templates: testConfigTemplates(t)}

	req := httptest.NewRequest(http.MethodPost, "/api/config/rollback", strings.NewReader("backup_path=/etc/haproxy/haproxy.cfg.bak-1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, store.User{Email: "admin@example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if cs.appliedPath != "/etc/haproxy/haproxy.cfg.bak-1" {
		t.Errorf("applied path = %q", cs.appliedPath)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "config.rollback" {
		t.Errorf("audit entries = %+v", au.entries)
	}
}
