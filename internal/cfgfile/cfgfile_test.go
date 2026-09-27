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

// fakeSudo stands in for /usr/bin/sudo: it drops the "-n" flag and execs
// whatever follows, so tests can verify SudoBin actually gets used without
// needing real sudoers configured.
func fakeSudo(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "fake-sudo.sh")
	body := "#!/bin/sh\nshift\nexec \"$@\"\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("requires POSIX shell")
		}
		t.Fatal(err)
	}
	return path
}

func TestApply_WrapsWithSudoWhenConfigured(t *testing.T) {
	s := newTestStore(t)
	draft, err := s.SaveDraft("root", "global\n")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "apply.sh")
	logFile := filepath.Join(dir, "called-with.txt")
	body := "#!/bin/sh\necho \"$1\" > " + logFile + "\necho applied\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("requires POSIX shell")
		}
		t.Fatal(err)
	}
	s.ApplyScript = script
	s.SudoBin = fakeSudo(t, dir)

	res, err := s.Apply(draft)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.OK {
		t.Errorf("OK = false, output: %s", res.Output)
	}
	got, _ := os.ReadFile(logFile)
	if string(got) != draft+"\n" {
		t.Errorf("apply script called with %q via sudo, want %q — SudoBin was not actually used", got, draft)
	}
}

func TestRestart_CallsRestartScript(t *testing.T) {
	s := newTestStore(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "restart.sh")
	logFile := filepath.Join(dir, "called.txt")
	body := "#!/bin/sh\necho called > " + logFile + "\necho restarted\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("requires POSIX shell")
		}
		t.Fatal(err)
	}
	s.RestartScript = script

	res, err := s.Restart()
	if err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if !res.OK {
		t.Errorf("OK = false, output: %s", res.Output)
	}
	if _, err := os.Stat(logFile); err != nil {
		t.Errorf("restart script was not called: %v", err)
	}
}

func TestRestart_WrapsWithSudoWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t)
	script := filepath.Join(dir, "restart.sh")
	logFile := filepath.Join(dir, "called.txt")
	body := "#!/bin/sh\necho called > " + logFile + "\necho restarted\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("requires POSIX shell")
		}
		t.Fatal(err)
	}
	s.RestartScript = script
	s.SudoBin = fakeSudo(t, dir)

	res, err := s.Restart()
	if err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if !res.OK {
		t.Errorf("OK = false, output: %s", res.Output)
	}
	if _, err := os.Stat(logFile); err != nil {
		t.Errorf("restart script was not called via sudo: %v", err)
	}
}

func TestRestart_ReportsFailureWithoutError(t *testing.T) {
	s := newTestStore(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "restart.sh")
	body := "#!/bin/sh\necho \"systemctl: haproxy.service failed\" >&2\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("requires POSIX shell")
		}
		t.Fatal(err)
	}
	s.RestartScript = script

	res, err := s.Restart()
	if err != nil {
		t.Fatalf("Restart returned Go error (should report via OK instead): %v", err)
	}
	if res.OK {
		t.Error("OK = true for a script that exited non-zero")
	}
	if res.Output == "" {
		t.Error("expected non-empty diagnostic output")
	}
}

func TestListBackups_SortedNewestFirst(t *testing.T) {
	s := newTestStore(t)
	_ = os.MkdirAll(s.BackupDir, 0o750)
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
	if backups[0].Path != newer || backups[0].Name != "haproxy.cfg.bak-200" {
		t.Errorf("newest backup = %+v, want %q", backups[0], newer)
	}
}

func TestListBackups_IgnoresUnrelatedFiles(t *testing.T) {
	s := newTestStore(t)
	_ = os.MkdirAll(s.BackupDir, 0o750)
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

func TestGetBackupPath_And_DeleteBackup(t *testing.T) {
	s := newTestStore(t)
	_ = os.MkdirAll(s.BackupDir, 0o750)
	target := filepath.Join(s.BackupDir, "haproxy.cfg.bak-12345")
	if err := os.WriteFile(target, []byte("backup content"), 0o640); err != nil {
		t.Fatal(err)
	}

	p, err := s.GetBackupPath("haproxy.cfg.bak-12345")
	if err != nil {
		t.Fatalf("GetBackupPath: %v", err)
	}
	if p != target {
		t.Errorf("GetBackupPath = %q, want %q", p, target)
	}

	// Rejects invalid names / traversal attempts
	if _, err := s.GetBackupPath("../../../etc/passwd"); err == nil {
		t.Error("GetBackupPath should reject traversal path")
	}

	// Delete
	if err := s.DeleteBackup("haproxy.cfg.bak-12345"); err != nil {
		t.Fatalf("DeleteBackup: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("file still exists after DeleteBackup")
	}
}

func TestEncryptedBackup_CreateAndRead(t *testing.T) {
	s := newTestStore(t)
	plainContent := "global\n    stats socket /var/lib/haproxy/stats\nbackend test_pool\n    server s1 127.0.0.1:8080 check\n"

	filename, err := s.CreateBackup(plainContent)
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	backupPath := filepath.Join(s.BackupDir, filename)
	rawBytes, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read raw backup file: %v", err)
	}

	// Verify that raw file on disk is encrypted and starts with magic header
	if !IsBackupEncrypted(rawBytes) {
		t.Fatalf("expected backup on disk to be encrypted, got plain string: %s", string(rawBytes))
	}
	if strings.Contains(string(rawBytes), "test_pool") {
		t.Errorf("raw backup file contains sensitive plaintext string")
	}

	// Verify ReadBackup transparently decrypts
	decrypted, err := s.ReadBackup(filename)
	if err != nil {
		t.Fatalf("ReadBackup failed: %v", err)
	}
	if decrypted != plainContent {
		t.Errorf("decrypted content = %q, want %q", decrypted, plainContent)
	}
}

func TestEncryptedBackup_LegacyMigration(t *testing.T) {
	s := newTestStore(t)
	// Place a legacy unencrypted backup in the active/parent dir
	legacyDir := filepath.Dir(s.ActivePath)
	legacyPath := filepath.Join(legacyDir, "haproxy.cfg.bak-999999")
	plain := "global\n    daemon\n"
	if err := os.WriteFile(legacyPath, []byte(plain), 0o640); err != nil {
		t.Fatal(err)
	}

	// ListBackups should migrate legacy backup into BackupDir and encrypt it
	backups, err := s.ListBackups()
	if err != nil {
		t.Fatalf("ListBackups failed: %v", err)
	}

	if len(backups) == 0 {
		t.Fatalf("expected at least 1 backup migrated, got 0")
	}

	// Verify old file in parent directory was cleaned up
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Errorf("legacy file in root dir still exists, was not cleaned up: %s", legacyPath)
	}

	// Verify new file in dedicated BackupDir exists and is encrypted
	newPath := filepath.Join(s.BackupDir, "haproxy.cfg.bak-999999")
	raw, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatalf("migrated file not in BackupDir: %v", err)
	}
	if !IsBackupEncrypted(raw) {
		t.Errorf("migrated backup was not encrypted in-place")
	}

	// Verify ReadBackup returns the original plain content
	content, err := s.ReadBackup("haproxy.cfg.bak-999999")
	if err != nil {
		t.Fatalf("ReadBackup for migrated file failed: %v", err)
	}
	if content != plain {
		t.Errorf("content = %q, want %q", content, plain)
	}
}
