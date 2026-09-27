package cfgfile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// EncryptedHeaderMagic is the signature placed at the beginning of encrypted backup files.
const EncryptedHeaderMagic = "KONSOLGW_ENC_V1:"

// defaultSalt is a fixed fallback salt for key derivation.
var defaultSalt = []byte("konsol-gateway-haproxy-backup-salt-v1")

// GetEncryptionKey derives or loads a 32-byte AES-256 key.
func (s *Store) GetEncryptionKey() []byte {
	// 1. Check environment variable override
	if envKey := os.Getenv("KONSOLGW_BACKUP_KEY"); envKey != "" {
		hash := sha256.Sum256([]byte(envKey))
		return hash[:]
	}
	if envKey := os.Getenv("BACKUP_ENCRYPTION_KEY"); envKey != "" {
		hash := sha256.Sum256([]byte(envKey))
		return hash[:]
	}

	// 2. Check keyfile in BackupDir or parent dir
	keyPaths := []string{
		filepath.Join(s.BackupDir, ".backup_key"),
		filepath.Join(filepath.Dir(s.ActivePath), ".backup_key"),
		filepath.Join(s.StagingDir, ".backup_key"),
	}

	for _, kp := range keyPaths {
		if data, err := os.ReadFile(kp); err == nil && len(data) >= 32 {
			hash := sha256.Sum256(data)
			return hash[:]
		}
	}

	// 3. Try to create a key file in BackupDir or StagingDir if possible
	for _, kp := range keyPaths {
		keyBytes := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, keyBytes); err == nil {
			_ = os.MkdirAll(filepath.Dir(kp), 0o750)
			if err := os.WriteFile(kp, keyBytes, 0o600); err == nil {
				return keyBytes
			}
		}
	}

	// 4. Deterministic machine fallback key based on active path and machine identifier
	seed := string(defaultSalt) + s.ActivePath
	if hostname, err := os.Hostname(); err == nil {
		seed += hostname
	}
	hash := sha256.Sum256([]byte(seed))
	return hash[:]
}

// EncryptBackupContent encrypts plaintext configuration bytes with AES-256-GCM.
func (s *Store) EncryptBackupContent(plaintext []byte) ([]byte, error) {
	key := s.GetEncryptionKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	sealed := gcm.Seal(nil, nonce, plaintext, []byte(EncryptedHeaderMagic))

	var output []byte
	output = append(output, []byte(EncryptedHeaderMagic)...)
	output = append(output, nonce...)
	output = append(output, sealed...)

	return output, nil
}

// DecryptBackupContent decrypts data. If the data is not encrypted (legacy backup),
// it returns the raw data cleanly.
func (s *Store) DecryptBackupContent(data []byte) ([]byte, error) {
	if !IsBackupEncrypted(data) {
		// Legacy unencrypted backup
		return data, nil
	}

	magicLen := len(EncryptedHeaderMagic)
	key := s.GetEncryptionKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < magicLen+nonceSize {
		return nil, fmt.Errorf("encrypted backup data is too short")
	}

	nonce := data[magicLen : magicLen+nonceSize]
	ciphertext := data[magicLen+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(EncryptedHeaderMagic))
	if err != nil {
		return nil, fmt.Errorf("decrypt backup (invalid key or corrupted data): %w", err)
	}

	return plaintext, nil
}

// IsBackupEncrypted returns true if the data starts with the encryption header signature.
func IsBackupEncrypted(data []byte) bool {
	return strings.HasPrefix(string(data), EncryptedHeaderMagic)
}

// EncryptBackupFileInPlace checks if a backup file on disk is encrypted; if not, encrypts it.
func (s *Store) EncryptBackupFileInPlace(filePath string) error {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	if IsBackupEncrypted(raw) {
		return nil // Already encrypted
	}

	encrypted, err := s.EncryptBackupContent(raw)
	if err != nil {
		return fmt.Errorf("encrypt %s: %w", filePath, err)
	}

	info, _ := os.Stat(filePath)
	perm := os.FileMode(0o640)
	if info != nil {
		perm = info.Mode()
	}

	return os.WriteFile(filePath, encrypted, perm)
}
