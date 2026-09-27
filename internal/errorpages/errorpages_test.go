package errorpages

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestErrorPages_GetAndPresets(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	for _, sc := range SupportedCodes {
		p, err := mgr.Get(sc.Code)
		if err != nil {
			t.Fatalf("Get(%d) failed: %v", sc.Code, err)
		}
		if p.Code != sc.Code {
			t.Errorf("Code = %d, want %d", p.Code, sc.Code)
		}
		if !strings.Contains(p.Content, "HTTP/1.1") {
			t.Errorf("Content for %d does not contain HTTP/1.1 header", sc.Code)
		}
		if p.HTMLBody == "" {
			t.Errorf("HTMLBody for %d is empty", sc.Code)
		}
	}
}

func TestErrorPages_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	customHTML := `<!DOCTYPE html><html><body><h1>Custom Waiting Room</h1></body></html>`
	err := mgr.Save(429, customHTML)
	if err != nil {
		t.Fatalf("Save(429) failed: %v", err)
	}

	p, err := mgr.Get(429)
	if err != nil {
		t.Fatalf("Get(429) failed: %v", err)
	}
	if !strings.Contains(p.Content, "HTTP/1.1 429") {
		t.Errorf("Content missing HTTP/1.1 header: %q", p.Content)
	}
	if !strings.Contains(p.HTMLBody, "Custom Waiting Room") {
		t.Errorf("HTMLBody mismatch: %q", p.HTMLBody)
	}

	// Verify file on disk
	diskData, err := os.ReadFile(filepath.Join(tmpDir, "429.http"))
	if err != nil {
		t.Fatalf("read 429.http: %v", err)
	}
	if !strings.Contains(string(diskData), "Custom Waiting Room") {
		t.Errorf("disk content mismatch")
	}
}

func TestErrorPages_InvalidCode(t *testing.T) {
	mgr := NewManager(t.TempDir())
	_, err := mgr.Get(200)
	if err == nil {
		t.Error("Get(200) should fail for non-error code")
	}
	err = mgr.Save(999, "test")
	if err == nil {
		t.Error("Save(999) should fail for invalid code")
	}
}
