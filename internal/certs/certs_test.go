package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genCertPEM creates a self-signed leaf certificate + private key, returned
// as a HAProxy-style concatenated PEM bundle (cert then key).
func genCertPEM(t *testing.T, cn string, notAfter time.Time, dns []string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return buf.Bytes()
}

func TestParseLeaf_ExtractsFields(t *testing.T) {
	future := time.Now().Add(90 * 24 * time.Hour)
	data := genCertPEM(t, "oms.cni.net.id", future, []string{"oms.cni.net.id", "dcam.cni.net.id"})

	info, err := ParseLeaf(data)
	if err != nil {
		t.Fatalf("ParseLeaf: %v", err)
	}
	if info.CommonName != "oms.cni.net.id" {
		t.Errorf("CommonName = %q", info.CommonName)
	}
	if len(info.DNSNames) != 2 {
		t.Errorf("DNSNames = %v", info.DNSNames)
	}
}

func TestInfo_ExpiresWithin(t *testing.T) {
	now := time.Now()
	info := Info{NotAfter: now.Add(10 * 24 * time.Hour)}
	if !info.ExpiresWithin(now, 30*24*time.Hour) {
		t.Error("expected cert expiring in 10 days to be within a 30-day window")
	}
	if info.ExpiresWithin(now, 5*24*time.Hour) {
		t.Error("cert expiring in 10 days should not be within a 5-day window")
	}
}

func TestInfo_ExpiresWithin30(t *testing.T) {
	now := time.Now()
	if !(Info{NotAfter: now.Add(10 * 24 * time.Hour)}).ExpiresWithin30(now) {
		t.Error("expected cert expiring in 10 days to trip the 30-day helper")
	}
	if (Info{NotAfter: now.Add(60 * 24 * time.Hour)}).ExpiresWithin30(now) {
		t.Error("cert expiring in 60 days should not trip the 30-day helper")
	}
}

func TestInfo_Expired(t *testing.T) {
	now := time.Now()
	if (Info{NotAfter: now.Add(-time.Hour)}).Expired(now) != true {
		t.Error("expected past NotAfter to report expired")
	}
	if (Info{NotAfter: now.Add(time.Hour)}).Expired(now) {
		t.Error("expected future NotAfter to report not expired")
	}
}

func TestValidateBundle_ValidMatchingPair(t *testing.T) {
	data := genCertPEM(t, "isc.id", time.Now().Add(30*24*time.Hour), nil)
	info, err := ValidateBundle(data)
	if err != nil {
		t.Fatalf("ValidateBundle: %v", err)
	}
	if info.CommonName != "isc.id" {
		t.Errorf("CommonName = %q", info.CommonName)
	}
}

func TestValidateBundle_ExpiredCertificate(t *testing.T) {
	data := genCertPEM(t, "expired.cni.net.id", time.Now().Add(-24*time.Hour), nil)
	if _, err := ValidateBundle(data); err == nil {
		t.Fatal("expected error for an already-expired certificate")
	}
}

func TestValidateBundle_MissingKey(t *testing.T) {
	full := genCertPEM(t, "nokey.cni.net.id", time.Now().Add(30*24*time.Hour), nil)
	block, _ := pem.Decode(full)
	certOnly := pem.EncodeToMemory(block)

	if _, err := ValidateBundle(certOnly); err == nil {
		t.Fatal("expected error for a bundle with no private key")
	}
}

func TestValidateBundle_MismatchedKey(t *testing.T) {
	certData := genCertPEM(t, "a.cni.net.id", time.Now().Add(30*24*time.Hour), nil)
	otherData := genCertPEM(t, "b.cni.net.id", time.Now().Add(30*24*time.Hour), nil)

	certBlock, _ := pem.Decode(certData)
	_, keyRest := pem.Decode(otherData)
	keyBlock, _ := pem.Decode(keyRest)

	var mixed bytes.Buffer
	pem.Encode(&mixed, certBlock)
	pem.Encode(&mixed, keyBlock)

	if _, err := ValidateBundle(mixed.Bytes()); err == nil {
		t.Fatal("expected error for a certificate paired with the wrong private key")
	}
}

func TestList_SortedByExpiryAscending(t *testing.T) {
	dir := t.TempDir()
	soon := genCertPEM(t, "soon.cni.net.id", time.Now().Add(5*24*time.Hour), nil)
	later := genCertPEM(t, "later.cni.net.id", time.Now().Add(400*24*time.Hour), nil)

	os.WriteFile(filepath.Join(dir, "later.pem"), later, 0o600)
	os.WriteFile(filepath.Join(dir, "soon.pem"), soon, 0o600)
	os.WriteFile(filepath.Join(dir, "ignored.key"), []byte("not a cert"), 0o600)

	s := New(dir)
	list, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List returned %d entries, want 2 (should skip .key)", len(list))
	}
	if list[0].CommonName != "soon.cni.net.id" {
		t.Errorf("first entry = %q, want the one expiring soonest", list[0].CommonName)
	}
}

func TestStagePEM_RejectsPathTraversal(t *testing.T) {
	s := New(t.TempDir())
	data := genCertPEM(t, "x.cni.net.id", time.Now().Add(30*24*time.Hour), nil)
	_, _, err := s.StagePEM(t.TempDir(), "../../etc/passwd.pem", data)
	if err == nil {
		t.Fatal("expected error for a traversal file name")
	}
}

func TestStagePEM_RejectsNonPemExtension(t *testing.T) {
	s := New(t.TempDir())
	data := genCertPEM(t, "x.cni.net.id", time.Now().Add(30*24*time.Hour), nil)
	_, _, err := s.StagePEM(t.TempDir(), "evil.sh", data)
	if err == nil {
		t.Fatal("expected error for a non-.pem file name")
	}
}

func TestStagePEM_WritesValidatedBundle(t *testing.T) {
	s := New(t.TempDir())
	staging := t.TempDir()
	data := genCertPEM(t, "new.cni.net.id", time.Now().Add(60*24*time.Hour), nil)

	path, info, err := s.StagePEM(staging, "new.pem", data)
	if err != nil {
		t.Fatalf("StagePEM: %v", err)
	}
	if info.CommonName != "new.cni.net.id" {
		t.Errorf("CommonName = %q", info.CommonName)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("staged file content does not match input")
	}
}

func TestStagePEM_RejectsInvalidBundle(t *testing.T) {
	s := New(t.TempDir())
	_, _, err := s.StagePEM(t.TempDir(), "bad.pem", []byte("not a pem file"))
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
}

func TestListStaged_ReturnsOnlyValidPEMBundles(t *testing.T) {
	staging := t.TempDir()
	good := genCertPEM(t, "new.cni.net.id", time.Now().Add(90*24*time.Hour), nil)
	os.WriteFile(filepath.Join(staging, "new.pem"), good, 0o600)
	os.WriteFile(filepath.Join(staging, "draft-1.cfg"), []byte("global\n"), 0o600)
	os.WriteFile(filepath.Join(staging, "broken.pem"), []byte("junk"), 0o600)

	s := New(t.TempDir())
	s.StagingDir = staging
	list, err := s.ListStaged()
	if err != nil {
		t.Fatalf("ListStaged: %v", err)
	}
	if len(list) != 1 || list[0].FileName != "new.pem" {
		t.Fatalf("ListStaged = %+v, want only new.pem", list)
	}
}

func TestListStaged_MissingDirIsEmptyNotError(t *testing.T) {
	s := New(t.TempDir())
	s.StagingDir = filepath.Join(t.TempDir(), "does-not-exist")
	list, err := s.ListStaged()
	if err != nil || len(list) != 0 {
		t.Fatalf("ListStaged = %v, %v; want empty, nil", list, err)
	}
}

func installScript(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "install-cert.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstall_PassesStagedPathToHelperViaSudo(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "called-with.txt")
	sudo := filepath.Join(dir, "fake-sudo.sh")
	os.WriteFile(sudo, []byte("#!/bin/sh\nshift\nexec \"$@\"\n"), 0o755)

	s := New(t.TempDir())
	s.StagingDir = "/var/lib/haproxy-gui/staging"
	s.InstallScript = installScript(t, dir, "echo \"$1\" > "+logFile+"\necho installed\n")
	s.SudoBin = sudo

	res, err := s.Install("palapacloud.id.pem")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.OK || res.Output != "installed\n" {
		t.Errorf("res = %+v", res)
	}
	got, _ := os.ReadFile(logFile)
	if string(got) != "/var/lib/haproxy-gui/staging/palapacloud.id.pem\n" {
		t.Errorf("helper called with %q", got)
	}
}

func TestInstall_HelperFailureReportedNotError(t *testing.T) {
	dir := t.TempDir()
	s := New(t.TempDir())
	s.StagingDir = dir
	s.InstallScript = installScript(t, dir, "echo 'haproxy -c failed' >&2\nexit 1\n")

	res, err := s.Install("x.pem")
	if err != nil {
		t.Fatalf("Install returned error %v, want OK=false result", err)
	}
	if res.OK || res.Output != "haproxy -c failed\n" {
		t.Errorf("res = %+v", res)
	}
}

func TestInstall_RejectsBadFileName(t *testing.T) {
	s := New(t.TempDir())
	s.InstallScript = "/bin/true"
	for _, name := range []string{"", "../x.pem", "a/b.pem", "x.crt"} {
		if _, err := s.Install(name); err == nil {
			t.Errorf("Install(%q) = nil error, want rejection", name)
		}
	}
}
