// Package cfgfile manages the on-disk haproxy.cfg: staging edits, validating
// them against the real haproxy binary, keeping timestamped backups, and
// applying a validated draft via a narrow root helper (see deploy/apply.sh).
// No function here ever runs as root itself — Validate and Apply both shell
// out to fixed, non-configurable commands so the web process can stay
// unprivileged.
package cfgfile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Store manages one haproxy.cfg and its backups/staging area.
type Store struct {
	ActivePath    string // e.g. /etc/haproxy/haproxy.cfg
	BackupDir     string // e.g. /etc/haproxy (backups sit next to the active file)
	StagingDir    string // e.g. /var/lib/haproxy-gui/staging
	HAProxyBin    string // e.g. /usr/sbin/haproxy
	ApplyScript   string // e.g. /usr/local/sbin/haproxy-gui-apply
	RestartScript string // e.g. /usr/local/sbin/haproxy-gui-restart

	// SudoBin, when non-empty, is prepended to ApplyScript/RestartScript
	// invocations (as "<SudoBin> -n <script> [args...]") so the unprivileged
	// haproxy-gui process can reach a root-owned helper via the sudoers rule
	// in deploy/sudoers.haproxy-gui. Left empty in tests, which point
	// ApplyScript/RestartScript at a plain executable script they own.
	SudoBin string

	// Now is overridable in tests so backup filenames are deterministic.
	Now func() time.Time
}

func New(activePath string) *Store {
	return &Store{
		ActivePath:    activePath,
		BackupDir:     filepath.Dir(activePath),
		StagingDir:    filepath.Dir(activePath),
		HAProxyBin:    "haproxy",
		ApplyScript:   "/usr/local/sbin/haproxy-gui-apply",
		RestartScript: "/usr/local/sbin/haproxy-gui-restart",
		Now:           time.Now,
	}
}

// helperCommand builds the exec.Cmd for a root helper script, wrapping it in
// SudoBin when one is configured.
func (s *Store) helperCommand(script string, args ...string) *exec.Cmd {
	if s.SudoBin != "" {
		return exec.Command(s.SudoBin, append([]string{"-n", script}, args...)...)
	}
	return exec.Command(script, args...)
}

// Active returns the currently-live config's contents.
func (s *Store) Active() (string, error) {
	b, err := os.ReadFile(s.ActivePath)
	if err != nil {
		return "", fmt.Errorf("read active config: %w", err)
	}
	return string(b), nil
}

// ValidateResult is the outcome of running "haproxy -c" against a draft.
type ValidateResult struct {
	OK     bool
	Output string
}

// Validate writes content to a throwaway file and runs "haproxy -c -f" on
// it, so a bad draft never touches the active config or the staging area.
func (s *Store) Validate(content string) (ValidateResult, error) {
	tmp, err := os.CreateTemp("", "haproxy-gui-validate-*.cfg")
	if err != nil {
		return ValidateResult{}, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return ValidateResult{}, fmt.Errorf("write temp file: %w", err)
	}
	tmp.Close()

	cmd := exec.Command(s.HAProxyBin, "-c", "-q", "-f", tmp.Name())
	out, err := cmd.CombinedOutput()
	if err == nil {
		return ValidateResult{OK: true, Output: string(out)}, nil
	}
	if _, isExit := err.(*exec.ExitError); isExit {
		return ValidateResult{OK: false, Output: string(out)}, nil
	}
	return ValidateResult{}, fmt.Errorf("run haproxy -c: %w", err)
}

// SaveDraft writes content into the staging area under a name derived from
// who saved it, so concurrent editors don't clobber each other's drafts.
func (s *Store) SaveDraft(author, content string) (string, error) {
	if err := os.MkdirAll(s.StagingDir, 0o750); err != nil {
		return "", fmt.Errorf("create staging dir: %w", err)
	}
	name := fmt.Sprintf("draft-%s-%d.cfg", sanitizeAuthor(author), s.Now().UnixNano())
	path := filepath.Join(s.StagingDir, name)
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		return "", fmt.Errorf("write draft: %w", err)
	}
	return path, nil
}

func sanitizeAuthor(a string) string {
	a = strings.ToLower(a)
	var sb strings.Builder
	for _, r := range a {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			sb.WriteRune(r)
		default:
			sb.WriteByte('_')
		}
	}
	if sb.Len() == 0 {
		return "anon"
	}
	return sb.String()
}

// Apply validates content, backs up the active config, installs content as
// the new active config, and reloads HAProxy — all via ApplyScript, which
// runs as root under a tight sudoers rule (see deploy/sudoers). The staged
// file must already live under StagingDir; Apply refuses anything else so a
// caller can never point the root helper at an arbitrary path.
func (s *Store) Apply(stagedPath string) (ApplyResult, error) {
	abs, err := filepath.Abs(stagedPath)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("resolve staged path: %w", err)
	}
	stagingAbs, err := filepath.Abs(s.StagingDir)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("resolve staging dir: %w", err)
	}
	rel, err := filepath.Rel(stagingAbs, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ApplyResult{}, fmt.Errorf("staged path %q is outside staging dir %q", stagedPath, s.StagingDir)
	}

	cmd := s.helperCommand(s.ApplyScript, abs)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ApplyResult{OK: false, Output: string(out)}, nil
	}
	return ApplyResult{OK: true, Output: string(out)}, nil
}

// Restart restarts the haproxy systemd service via RestartScript, a root
// helper separate from ApplyScript (see deploy/haproxy-gui-restart.sh) —
// unlike Apply/reload this briefly drops in-flight connections, so it's a
// distinct, explicit action rather than something config changes trigger.
func (s *Store) Restart() (ApplyResult, error) {
	cmd := s.helperCommand(s.RestartScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ApplyResult{OK: false, Output: string(out)}, nil
	}
	return ApplyResult{OK: true, Output: string(out)}, nil
}

// ApplyResult is the outcome of running ApplyScript or RestartScript.
type ApplyResult struct {
	OK     bool
	Output string
}

// Backup is one timestamped copy of haproxy.cfg found in BackupDir.
type Backup struct {
	Path    string
	ModTime time.Time
}

// backupRE matches the pattern this codebase and its predecessor use:
// haproxy.cfg.bak-<unix-seconds>.
var backupSuffix = ".cfg.bak-"

// ListBackups returns known backups, newest first.
func (s *Store) ListBackups() ([]Backup, error) {
	entries, err := os.ReadDir(s.BackupDir)
	if err != nil {
		return nil, fmt.Errorf("read backup dir: %w", err)
	}
	var backups []Backup
	for _, e := range entries {
		if e.IsDir() || !strings.Contains(e.Name(), backupSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, Backup{
			Path:    filepath.Join(s.BackupDir, e.Name()),
			ModTime: info.ModTime(),
		})
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].ModTime.After(backups[j].ModTime) })
	return backups, nil
}
