package i18n

import (
	"testing"
)

func TestCheckMissingKeys(t *testing.T) {
	missing := CheckMissingKeys()
	if len(missing) > 0 {
		for _, m := range missing {
			t.Errorf("%s", m)
		}
	}
}

func TestT(t *testing.T) {
	if got := T("id", "home"); got != "Beranda" {
		t.Errorf("expected Beranda, got %q", got)
	}
	if got := T("en", "home"); got != "Home" {
		t.Errorf("expected Home, got %q", got)
	}
	if got := T("zh", "home"); got != "首页" {
		t.Errorf("expected 首页, got %q", got)
	}
	if got := T("zh-CN", "home"); got != "首页" {
		t.Errorf("expected 首页, got %q", got)
	}
	if got := T("ja", "home"); got != "ホーム" {
		t.Errorf("expected ホーム, got %q", got)
	}
	if got := T("ja-JP", "home"); got != "ホーム" {
		t.Errorf("expected ホーム, got %q", got)
	}
	if got := T("id-ID", "home"); got != "Beranda" {
		t.Errorf("expected Beranda, got %q", got)
	}
	if got := T("en-US", "home"); got != "Home" {
		t.Errorf("expected Home, got %q", got)
	}
	// Missing key fallback
	if got := T("id", "unknown_key"); got != "[unknown_key]" {
		t.Errorf("expected [unknown_key], got %q", got)
	}
}
