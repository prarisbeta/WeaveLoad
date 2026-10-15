package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

const totpStep = 30
const totpDigits = 6

// GenerateTOTPSecret generates a random 16-byte base32 encoded secret key.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateTOTPCode calculates the 6-digit TOTP code for secret at given time t.
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		// Fallback try decoding with padding
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", fmt.Errorf("invalid base32 secret: %w", err)
		}
	}

	counter := uint64(t.Unix() / totpStep)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	code := (uint32(h[offset]&0x7f)<<24 |
		uint32(h[offset+1]&0xff)<<16 |
		uint32(h[offset+2]&0xff)<<8 |
		uint32(h[offset+3]&0xff)) % uint32(math.Pow10(totpDigits))

	return fmt.Sprintf("%0*d", totpDigits, code), nil
}

// VerifyTOTPCode checks if passCode matches secret within a +/- 1 time step window.
func VerifyTOTPCode(secret, passCode string, t time.Time) bool {
	passCode = strings.TrimSpace(passCode)
	if len(passCode) != totpDigits {
		return false
	}

	// Check t - 30s, t, t + 30s
	for _, dt := range []int64{-totpStep, 0, totpStep} {
		code, err := GenerateTOTPCode(secret, t.Add(time.Duration(dt)*time.Second))
		if err == nil && hmac.Equal([]byte(code), []byte(passCode)) {
			return true
		}
	}
	return false
}

// GenerateRecoveryCodes generates 8 random 8-character recovery codes.
func GenerateRecoveryCodes() ([]string, error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	codes := make([]string, 8)
	for i := 0; i < 8; i++ {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		var sb strings.Builder
		for j := 0; j < 8; j++ {
			sb.WriteByte(charset[int(b[j])%len(charset)])
		}
		codes[i] = sb.String()
	}
	return codes, nil
}
