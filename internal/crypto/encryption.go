// Package crypto provides cryptographic operations for the password manager.
// This includes AES-256-GCM encryption, Argon2id key derivation, BIP39 recovery
// phrases, and Master Encryption Key (MEK) handling.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrInvalidKey is returned when the encryption key is not 32 bytes.
	ErrInvalidKey = errors.New("invalid key size: must be 32 bytes for AES-256")
	// ErrInvalidCiphertext is returned when ciphertext is malformed or too short.
	ErrInvalidCiphertext = errors.New("invalid ciphertext: too short")
	// ErrDecryptionFailed is returned when decryption fails due to wrong key or tampering.
	ErrDecryptionFailed = errors.New("decryption failed: authentication error")
)

// KeySize is the AES-256 key size in bytes.
const KeySize = 32

// NonceSize is the GCM nonce size in bytes.
const NonceSize = 12

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// The nonce is prepended to the ciphertext.
// Returns ciphertext as: nonce (12 bytes) + encrypted data + auth tag (16 bytes).
func Encrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal appends the ciphertext to the nonce slice
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext encrypted with Encrypt.
// Expects ciphertext format: nonce (12 bytes) + encrypted data + auth tag (16 bytes).
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	// Minimum size: nonce (12) + auth tag (16) = 28 bytes
	if len(ciphertext) < NonceSize+16 {
		return nil, ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := ciphertext[:NonceSize]
	encryptedData := ciphertext[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// ZeroMemory securely zeroes a byte slice to prevent sensitive data
// from remaining in memory.
func ZeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// GenerateRandomBytes generates n cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}
