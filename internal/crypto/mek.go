// Package crypto provides cryptographic operations for the password manager.
package crypto

import (
	"errors"
	"fmt"
)

var (
	// ErrMEKDecryptionFailed is returned when MEK decryption fails.
	ErrMEKDecryptionFailed = errors.New("failed to decrypt master encryption key: wrong password or phrase")
)

// MEKSize is the size of the Master Encryption Key (32 bytes for AES-256).
const MEKSize = 32

// GenerateMEK generates a new random Master Encryption Key.
// The MEK is used to encrypt all vault data.
func GenerateMEK() ([]byte, error) {
	return GenerateRandomBytes(MEKSize)
}

// EncryptMEK encrypts the Master Encryption Key with a derived key.
// This is used to store the MEK encrypted with either the password-derived key
// or the recovery phrase-derived key.
func EncryptMEK(mek, derivedKey []byte) ([]byte, error) {
	return Encrypt(mek, derivedKey)
}

// DecryptMEK decrypts the Master Encryption Key with a derived key.
// Returns ErrMEKDecryptionFailed if the key is wrong.
func DecryptMEK(encryptedMEK, derivedKey []byte) ([]byte, error) {
	mek, err := Decrypt(encryptedMEK, derivedKey)
	if err != nil {
		if errors.Is(err, ErrDecryptionFailed) {
			return nil, ErrMEKDecryptionFailed
		}
		return nil, err
	}
	return mek, nil
}

// MEKBundle contains both encrypted versions of the MEK and their salts.
// This is stored in the vault database.
type MEKBundle struct {
	// SaltPassword is the salt used for password-based key derivation.
	SaltPassword []byte
	// SaltPhrase is the salt used for recovery phrase-based key derivation.
	SaltPhrase []byte
	// EncryptedMEKPassword is the MEK encrypted with the password-derived key.
	EncryptedMEKPassword []byte
	// EncryptedMEKPhrase is the MEK encrypted with the phrase-derived key.
	EncryptedMEKPhrase []byte
}

// CreateMEKBundle creates a new MEK bundle with the MEK encrypted using both
// the master password (combined with keyring secret) and the recovery phrase.
// Returns the bundle and the recovery phrase (which must be shown to the user).
func CreateMEKBundle(password string) (*MEKBundle, string, error) {
	mek, err := GenerateMEK()
	if err != nil {
		return nil, "", err
	}
	defer ZeroMemory(mek)

	phrase, err := GenerateRecoveryPhrase()
	if err != nil {
		return nil, "", err
	}

	saltPassword, err := GenerateSalt()
	if err != nil {
		return nil, "", err
	}

	saltPhrase, err := GenerateSalt()
	if err != nil {
		return nil, "", err
	}

	keyringSecret, err := GetOrCreateKeyringSecret()
	if err != nil {
		return nil, "", fmt.Errorf("keyring is required: %w", err)
	}
	defer ZeroMemory(keyringSecret)

	passwordKey := DeriveKeyWithKeyring([]byte(password), saltPassword, keyringSecret)
	defer ZeroMemory(passwordKey)

	phraseKey, err := PhraseToKey(phrase)
	if err != nil {
		return nil, "", err
	}
	defer ZeroMemory(phraseKey)

	encryptedMEKPassword, err := EncryptMEK(mek, passwordKey)
	if err != nil {
		return nil, "", err
	}

	encryptedMEKPhrase, err := EncryptMEK(mek, phraseKey)
	if err != nil {
		return nil, "", err
	}

	bundle := &MEKBundle{
		SaltPassword:         saltPassword,
		SaltPhrase:           saltPhrase,
		EncryptedMEKPassword: encryptedMEKPassword,
		EncryptedMEKPhrase:   encryptedMEKPhrase,
	}

	return bundle, phrase, nil
}

// DecryptMEKWithPassword decrypts the MEK using the master password combined with keyring secret.
func (b *MEKBundle) DecryptMEKWithPassword(password string) ([]byte, error) {
	keyringSecret, err := GetKeyringSecret()
	if keyringSecret != nil {
		defer ZeroMemory(keyringSecret)
	}

	var key []byte
	if err == nil && keyringSecret != nil {
		key = DeriveKeyWithKeyring([]byte(password), b.SaltPassword, keyringSecret)
	} else {
		// Fallback to password-only (for backward compatibility)
		key = DeriveKey([]byte(password), b.SaltPassword)
	}
	defer ZeroMemory(key)

	return DecryptMEK(b.EncryptedMEKPassword, key)
}

// DecryptMEKWithPhrase decrypts the MEK using the recovery phrase.
func (b *MEKBundle) DecryptMEKWithPhrase(phrase string) ([]byte, error) {
	key, err := PhraseToKey(phrase)
	if err != nil {
		return nil, err
	}
	defer ZeroMemory(key)

	return DecryptMEK(b.EncryptedMEKPhrase, key)
}

// ReEncryptMEKWithNewPassword generates new password-derived encryption for the MEK.
// Used when changing the master password.
func (b *MEKBundle) ReEncryptMEKWithNewPassword(mek []byte, newPassword string) error {
	newSalt, err := GenerateSalt()
	if err != nil {
		return err
	}

	keyringSecret, kerr := GetOrCreateKeyringSecret()
	if keyringSecret != nil {
		defer ZeroMemory(keyringSecret)
	}

	var newKey []byte
	if kerr == nil && keyringSecret != nil {
		newKey = DeriveKeyWithKeyring([]byte(newPassword), newSalt, keyringSecret)
	} else {
		newKey = DeriveKey([]byte(newPassword), newSalt)
	}
	defer ZeroMemory(newKey)

	newEncryptedMEK, err := EncryptMEK(mek, newKey)
	if err != nil {
		return err
	}

	b.SaltPassword = newSalt
	b.EncryptedMEKPassword = newEncryptedMEK

	return nil
}
