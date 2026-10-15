// Package certs inspects and validates the PEM bundles HAProxy loads for
// TLS termination (concatenated cert+chain+key, as HAProxy's "crt" option
// expects). It never writes to the live ssl/ directory directly — see
// Store.StagePEM, which writes into a staging area for cfgfile-style
// validate-then-apply handling.
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Info describes one certificate found in the ssl directory.
type Info struct {
	FileName   string
	CommonName string
	DNSNames   []string
	NotAfter   time.Time
	NotBefore  time.Time
	IsCA       bool
}

// ExpiresWithin reports whether the certificate expires within d of now.
func (i Info) ExpiresWithin(now time.Time, d time.Duration) bool {
	return i.NotAfter.Before(now.Add(d))
}

// Expired reports whether the certificate's NotAfter has already passed.
func (i Info) Expired(now time.Time) bool {
	return now.After(i.NotAfter)
}

// ExpiresWithin30 is a template-friendly shorthand for the common "renew
// soon" threshold, since html/template can't easily pass a time.Duration
// literal as a method argument.
func (i Info) ExpiresWithin30(now time.Time) bool {
	return i.ExpiresWithin(now, 30*24*time.Hour)
}

// Store manages the directory HAProxy's "bind ... crt" options point at.
type Store struct {
	Dir string

	// StagingDir is where StagePEM-written bundles wait for Install.
	StagingDir string
	// InstallScript is the root helper (deploy/haproxy-gui-install-cert.sh)
	// that moves a staged bundle into Dir and reloads HAProxy. SudoBin, when
	// set, is prepended as "<SudoBin> -n <script> <path>" (see
	// deploy/sudoers.haproxy-gui); tests leave it empty.
	InstallScript string
	RemoveScript  string // deploy/haproxy-gui-remove-cert.sh
	SudoBin       string
}

func New(dir string) *Store { return &Store{Dir: dir} }

// List returns Info for every *.pem file in Dir that contains a parseable
// leaf certificate. Files that aren't valid PEM bundles are skipped rather
// than failing the whole listing, since ssl/ may contain standalone .crt/
// .key files alongside the combined .pem HAProxy actually loads.
func (s *Store) List() ([]Info, error) { return listDir(s.Dir) }

// ListStaged is List for StagingDir: uploaded bundles not yet installed. A
// staging dir that doesn't exist yet (nothing uploaded) is an empty list.
func (s *Store) ListStaged() ([]Info, error) {
	list, err := listDir(s.StagingDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return list, err
}

func listDir(dir string) ([]Info, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read cert dir: %w", err)
	}
	var out []Info
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		info, err := ParseLeaf(data)
		if err != nil {
			continue
		}
		info.FileName = e.Name()
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NotAfter.Before(out[j].NotAfter) })
	return out, nil
}

// ParseLeaf extracts the first (leaf) certificate from a PEM bundle.
// HAProxy expects leaf-first bundles (cert, then intermediates, then key),
// so the first CERTIFICATE block is the one that matters for expiry and
// hostname checks.
func ParseLeaf(pemData []byte) (Info, error) {
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return Info{}, fmt.Errorf("no CERTIFICATE block found in PEM data")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return Info{}, fmt.Errorf("parse certificate: %w", err)
		}
		return Info{
			CommonName: cert.Subject.CommonName,
			DNSNames:   cert.DNSNames,
			NotAfter:   cert.NotAfter,
			NotBefore:  cert.NotBefore,
			IsCA:       cert.IsCA,
		}, nil
	}
}

// ValidateBundle checks that pemData contains a certificate whose public
// key matches the accompanying private key, and that the certificate is
// not already expired. This is what StagePEM should call before a bundle
// is ever written to disk or referenced by a running config.
func ValidateBundle(pemData []byte) (Info, error) {
	info, err := ParseLeaf(pemData)
	if err != nil {
		return Info{}, err
	}
	if _, err := tls.X509KeyPair(pemData, pemData); err != nil {
		return Info{}, fmt.Errorf("certificate and private key do not match (or key is missing from the bundle): %w", err)
	}
	if time.Now().After(info.NotAfter) {
		return Info{}, fmt.Errorf("certificate for %s expired on %s", info.CommonName, info.NotAfter.Format("2006-01-02"))
	}
	return info, nil
}

// StagePEM validates content and writes it into stagingDir under a fixed
// name derived from the target filename (never the caller's raw input), so
// the result can be handed to the same validate-then-apply flow as
// haproxy.cfg. It does not touch s.Dir.
func (s *Store) StagePEM(stagingDir, targetFileName string, content []byte) (string, Info, error) {
	if !validPEMFileName(targetFileName) {
		return "", Info{}, fmt.Errorf("invalid certificate file name: %q", targetFileName)
	}
	info, err := ValidateBundle(content)
	if err != nil {
		return "", Info{}, err
	}
	if err := os.MkdirAll(stagingDir, 0o750); err != nil {
		return "", Info{}, fmt.Errorf("create staging dir: %w", err)
	}
	path := filepath.Join(stagingDir, targetFileName)
	if err := os.WriteFile(path, content, 0o640); err != nil {
		return "", Info{}, fmt.Errorf("write staged cert: %w", err)
	}
	return path, info, nil
}

// ErrInvalidFileName is returned for a certificate file name that is empty,
// has a path separator, or does not end in .pem.
var ErrInvalidFileName = errors.New("invalid certificate file name")

// InstallResult is the outcome of running InstallScript.
type InstallResult struct {
	OK     bool
	Output string
}

// Install hands the staged bundle fileName to the root helper, which
// validates it again, backs up any cert it replaces, installs it into the
// live ssl directory, checks the HAProxy config and reloads — rolling back on
// failure. The helper's own failure is reported in the result, not as an
// error, so callers can show its output; an error means the helper never ran.
func (s *Store) Install(fileName string) (InstallResult, error) {
	if !validPEMFileName(fileName) {
		return InstallResult{}, fmt.Errorf("%w: %q", ErrInvalidFileName, fileName)
	}
	return s.runHelper(s.InstallScript, filepath.Join(s.StagingDir, fileName))
}

// Remove deletes the live certificate fileName from the ssl directory via the
// root helper, which refuses a file haproxy.cfg still references, backs it up
// first, checks the config, reloads, and restores it on failure. Like
// Install, the helper's refusal or failure comes back in the result.
func (s *Store) Remove(fileName string) (InstallResult, error) {
	if !validPEMFileName(fileName) {
		return InstallResult{}, fmt.Errorf("%w: %q", ErrInvalidFileName, fileName)
	}
	return s.runHelper(s.RemoveScript, fileName)
}

// RemoveStaged deletes an uploaded bundle that was never installed. It needs
// no root: the staging directory belongs to the service user.
func (s *Store) RemoveStaged(fileName string) error {
	if !validPEMFileName(fileName) {
		return fmt.Errorf("%w: %q", ErrInvalidFileName, fileName)
	}
	if err := os.Remove(filepath.Join(s.StagingDir, fileName)); err != nil {
		return fmt.Errorf("remove staged certificate: %w", err)
	}
	return nil
}

func (s *Store) runHelper(script, arg string) (InstallResult, error) {
	var cmd *exec.Cmd
	if s.SudoBin != "" {
		cmd = exec.Command(s.SudoBin, "-n", script, arg)
	} else {
		cmd = exec.Command(script, arg)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return InstallResult{OK: false, Output: string(out)}, nil
		}
		return InstallResult{}, fmt.Errorf("run %s: %w", filepath.Base(script), err)
	}
	return InstallResult{OK: true, Output: string(out)}, nil
}

func validPEMFileName(name string) bool {
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return false
	}
	return strings.HasSuffix(name, ".pem")
}
