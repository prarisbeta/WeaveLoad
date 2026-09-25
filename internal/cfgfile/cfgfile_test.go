package cfgfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// fakeHAProxyBin writes a tiny shell script standing in for the real
// haproxy binary: it inspects the -f file's content and exits 0 for
// "valid", 1 otherwise, printing a message either way (matching haproxy -c).
func fakeHAProxyBin(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake haproxy script requires a POSIX shell (runs under Docker/Linux in CI)")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-haproxy.sh")
	script := `#!/bin/sh
# usage: fake-haproxy.sh -c -q -f <file>
for a in "$@"; do
  file="$a"
done
if grep -q BROKEN "$file"; then
  echo "[ALERT] config file : error near line 1"
  exit 1
fi
echo "Configuration file is valid"
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake haproxy: %v", err)
	}
	return path
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	active := filepath.Join(dir, "haproxy.cfg")
	if err := os.WriteFile(active, []byte("global\n    daemon\n"), 0o640); err != nil {
		t.Fatalf("seed active config: %v", err)
	}
	s := New(active)
	s.HAProxyBin = fakeHAProxyBin(t)
	s.StagingDir = filepath.Join(dir, "staging")
	fixed := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return fixed }
	return s
}

func TestValidate_ValidConfig(t *testing.T) {
	s := newTestStore(t)
	res, err := s.Validate("global\n    daemon\n")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !res.OK {
		t.Errorf("OK = false, output: %s", res.Output)
	}
}

func TestValidate_BrokenConfig(t *testing.T) {
	s := newTestStore(t)
	res, err := s.Validate("BROKEN garbage\n")
	if err != nil {
		t.Fatalf("Validate returned Go error (should report via OK instead): %v", err)
	}
	if res.OK {
		t.Error("OK = true for a config the validator rejected")
	}
	if res.Output == "" {
		t.Error("expected non-empty diagnostic output")
	}
}

func TestValidate_NeverTouchesActiveFile(t *testing.T) {
	s := newTestStore(t)
	before, _ := s.Active()

	if _, err := s.Validate("BROKEN\n"); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	after, _ := s.Active()
	if before != after {
		t.Errorf("active config changed after Validate: before=%q after=%q", before, after)
	}
}

func TestSaveDraft_WritesUnderStagingDir(t *testing.T) {
	s := newTestStore(t)
	path, err := s.SaveDraft("Budi Santoso", "global\n")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}
	if filepath.Dir(path) != s.StagingDir {
		t.Errorf("draft path %q not under staging dir %q", path, s.StagingDir)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read draft: %v", err)
	}
	if string(got) != "global\n" {
		t.Errorf("draft content = %q", got)
	}
}

func TestSaveDraft_SanitizesAuthorForFilename(t *testing.T) {
	s := newTestStore(t)
	path, err := s.SaveDraft("../../etc/passwd", "x")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}
	if filepath.Dir(path) != s.StagingDir {
		t.Errorf("path escaped staging dir: %q", path)
	}
}

func TestApply_RejectsPathOutsideStagingDir(t *testing.T) {
	s := newTestStore(t)
	outside := filepath.Join(t.TempDir(), "evil.cfg")
	if err := os.WriteFile(outside, []byte("global\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := s.Apply(outside)
	if err == nil {
		t.Fatal("expected error applying a path outside the staging dir")
	}
}

func TestApply_CallsApplyScriptWithStagedPath(t *testing.T) {
	s := newTestStore(t)
	draft, err := s.SaveDraft("root", "global\n")
	if err != nil {
		t.Fatal(err)
	}

	scriptDir := t.TempDir()
	script := filepath.Join(scriptDir, "apply.sh")
	logFile := filepath.Join(scriptDir, "called-with.txt")
	body := "#!/bin/sh\necho \"$1\" > " + logFile + "\necho applied\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("requires POSIX shell")
		}
		t.Fatal(err)
	}
	s.ApplyScript = script

	res, err := s.Apply(draft)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.OK {
		t.Errorf("OK = false, output: %s", res.Output)
	}
	got, _ := os.ReadFile(logFile)
	if string(got) != draft+"\n" {
		t.Errorf("apply script called with %q, want %q", got, draft)
	}
}

func TestListBackups_SortedNewestFirst(t *testing.T) {
	s := newTestStore(t)
	older := filepath.Join(s.BackupDir, "haproxy.cfg.bak-100")
	newer := filepath.Join(s.BackupDir, "haproxy.cfg.bak-200")
	for _, p := range []string{older, newer} {
		if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	os.Chtimes(older, now.Add(-time.Hour), now.Add(-time.Hour))
	os.Chtimes(newer, now, now)

	backups, err := s.ListBackups()
	if err != nil {
		t.Fatalf("ListBackups: %v", err)
	}
	if len(backups) != 2 {
		t.Fatalf("backups = %d, want 2", len(backups))
	}
	if backups[0].Path != newer {
		t.Errorf("newest backup = %q, want %q", backups[0].Path, newer)
	}
}

func TestListBackups_IgnoresUnrelatedFiles(t *testing.T) {
	s := newTestStore(t)
	if err := os.WriteFile(filepath.Join(s.BackupDir, "dhparam.pem"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	backups, err := s.ListBackups()
	if err != nil {
		t.Fatalf("ListBackups: %v", err)
	}
	if len(backups) != 0 {
		t.Errorf("backups = %+v, want none", backups)
	}
}
