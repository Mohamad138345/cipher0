// Package crypto provides cryptographic operations for the password manager.
package crypto

import (
	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for key derivation.
const (
	// Argon2Time is the number of iterations.
	Argon2Time = 5
	// Argon2Memory is the memory usage in KB (256 MB).
	Argon2Memory = 256 * 1024
	// Argon2Threads is the degree of parallelism.
	Argon2Threads = 4
	// Argon2KeyLen is the derived key length in bytes.
	Argon2KeyLen = 32
	// SaltSize is the salt length in bytes.
	SaltSize = 32
)

// DeriveKey derives a 32-byte key from a password using Argon2id.
// Uses the parameters: 5 iterations, 256MB memory, 4 threads.
func DeriveKey(password, salt []byte) []byte {
	return argon2.IDKey(
		password,
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		Argon2KeyLen,
	)
}

// DeriveKeyWithKeyring derives a key from password combined with keyring secret.
func DeriveKeyWithKeyring(password, salt, keyringSecret []byte) []byte {
	combined := make([]byte, len(password)+len(keyringSecret))
	copy(combined, password)
	copy(combined[len(password):], keyringSecret)
	defer ZeroMemory(combined)

	return argon2.IDKey(
		combined,
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		Argon2KeyLen,
	)
}

// GenerateSalt generates a cryptographically secure random salt.
func GenerateSalt() ([]byte, error) {
	return GenerateRandomBytes(SaltSize)
}
