package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAPIToken_CreateReturnsPlaintextOnceAndStoresOnlyAHash(t *testing.T) {
	s := newTestDB(t)

	plain, tok, err := s.CreateAPIToken("claude-code", "admin@x.id")
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if !strings.HasPrefix(plain, "kgw_") || len(plain) < 40 {
		t.Errorf("token = %q, want kgw_ prefix and at least 40 chars", plain)
	}
	if tok.Name != "claude-code" || tok.CreatedBy != "admin@x.id" || tok.Prefix != plain[:8] {
		t.Errorf("tok = %+v", tok)
	}

	var stored string
	if err := s.db.QueryRow(`SELECT token_hash FROM api_tokens WHERE id = ?`, tok.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, plain) || stored == plain || len(stored) != 64 {
		t.Errorf("stored value %q must be a 64-char hash, not the token", stored)
	}
}

func TestAPIToken_Verify(t *testing.T) {
	s := newTestDB(t)
	plain, created, _ := s.CreateAPIToken("n8n", "admin@x.id")

	got, err := s.VerifyAPIToken(plain)
	if err != nil || got.ID != created.ID || got.Name != "n8n" {
		t.Fatalf("VerifyAPIToken = %+v, %v", got, err)
	}
	for _, bad := range []string{"", "kgw_", plain + "x", plain[:len(plain)-1], "kgw_" + strings.Repeat("a", 40)} {
		if _, err := s.VerifyAPIToken(bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("VerifyAPIToken(%q) = %v, want ErrNotFound", bad, err)
		}
	}
}

func TestAPIToken_RevokedTokenNoLongerVerifies(t *testing.T) {
	s := newTestDB(t)
	plain, tok, _ := s.CreateAPIToken("old", "admin@x.id")

	if err := s.RevokeAPIToken(tok.ID); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}
	if _, err := s.VerifyAPIToken(plain); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked token verified: %v", err)
	}
	if err := s.RevokeAPIToken(9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an unknown token = %v, want ErrNotFound", err)
	}
}

func TestAPIToken_ListNewestFirstWithStatusAndLastUsed(t *testing.T) {
	s := newTestDB(t)
	p1, t1, _ := s.CreateAPIToken("first", "a@x.id")
	_, t2, _ := s.CreateAPIToken("second", "a@x.id")
	if _, err := s.VerifyAPIToken(p1); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAPIToken(t2.ID); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListAPITokens()
	if err != nil || len(list) != 2 {
		t.Fatalf("ListAPITokens = %+v, %v", list, err)
	}
	if list[0].ID != t2.ID || !list[0].Revoked {
		t.Errorf("first = %+v, want the newer, revoked token", list[0])
	}
	if list[1].ID != t1.ID || list[1].LastUsedAt.IsZero() || time.Since(list[1].LastUsedAt) > time.Minute {
		t.Errorf("second = %+v, want last_used_at set by Verify", list[1])
	}
	if list[0].Name == "" || strings.Contains(list[0].Prefix, " ") {
		t.Errorf("list must expose name and prefix: %+v", list[0])
	}
}

func TestAPIToken_NameIsRequiredAndTrimmed(t *testing.T) {
	s := newTestDB(t)
	if _, _, err := s.CreateAPIToken("   ", "a@x.id"); err == nil {
		t.Error("blank name accepted")
	}
	_, tok, err := s.CreateAPIToken("  spaced  ", "a@x.id")
	if err != nil || tok.Name != "spaced" {
		t.Errorf("tok = %+v, %v", tok, err)
	}
}
