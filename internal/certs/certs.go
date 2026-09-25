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
	"fmt"
	"os"
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
}

func New(dir string) *Store { return &Store{Dir: dir} }

// List returns Info for every *.pem file in Dir that contains a parseable
// leaf certificate. Files that aren't valid PEM bundles are skipped rather
// than failing the whole listing, since ssl/ may contain standalone .crt/
// .key files alongside the combined .pem HAProxy actually loads.
func (s *Store) List() ([]Info, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, fmt.Errorf("read cert dir: %w", err)
	}
	var out []Info
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.Dir, e.Name()))
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

func validPEMFileName(name string) bool {
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return false
	}
	return strings.HasSuffix(name, ".pem")
}
