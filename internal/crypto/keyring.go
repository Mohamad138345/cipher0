// Package crypto provides cryptographic operations for the password manager.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/zalando/go-keyring"
)

// KeyringProvider abstracts keyring operations for testing.
type KeyringProvider interface {
	Get(service, account string) (string, error)
	Set(service, account, password string) error
	Delete(service, account string) error
}

// osKeyring implements KeyringProvider using the actual OS keyring.
type osKeyring struct{}

func (o *osKeyring) Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func (o *osKeyring) Set(service, account, password string) error {
	return keyring.Set(service, account, password)
}

func (o *osKeyring) Delete(service, account string) error {
	return keyring.Delete(service, account)
}

var (
	keyringProviderMu sync.RWMutex
	keyringProvider   KeyringProvider = &osKeyring{}
)

// SetKeyringProvider sets the keyring provider. Used for testing with mock providers.
func SetKeyringProvider(provider KeyringProvider) {
	keyringProviderMu.Lock()
	defer keyringProviderMu.Unlock()
	keyringProvider = provider
}

// getKeyringProvider returns the current keyring provider.
func getKeyringProvider() KeyringProvider {
	keyringProviderMu.RLock()
	defer keyringProviderMu.RUnlock()
	return keyringProvider
}

const (
	// KeyringService is the service name used for keyring entries.
	KeyringService = "cipher0"
	// KeyringAccount is the account name used for keyring entries.
	KeyringAccount = "vault-secret"
	// KeyringSecretSize is the size of the keyring secret in bytes.
	KeyringSecretSize = 32
)

// ErrKeyringNotAvailable is returned when the OS keyring is not accessible.
var ErrKeyringNotAvailable = errors.New("OS keyring not available")

// ErrKeyringSecretNotFound is returned when no keyring secret exists.
var ErrKeyringSecretNotFound = errors.New("keyring secret not found")

// GetKeyringSecret retrieves the vault secret from the OS keyring.
func GetKeyringSecret() ([]byte, error) {
	provider := getKeyringProvider()
	secret, err := provider.Get(KeyringService, KeyringAccount)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) || errors.Is(err, ErrKeyringSecretNotFound) {
			return nil, ErrKeyringSecretNotFound
		}
		return nil, err
	}

	// Decode from base64
	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

// CreateKeyringSecret generates and stores a new random secret in the OS keyring.
func CreateKeyringSecret() ([]byte, error) {
	// Generate random secret
	secret := make([]byte, KeyringSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}

	// Encode to base64 for storage
	encoded := base64.StdEncoding.EncodeToString(secret)

	provider := getKeyringProvider()
	if err := provider.Set(KeyringService, KeyringAccount, encoded); err != nil {
		return nil, err
	}

	return secret, nil
}

// GetOrCreateKeyringSecret retrieves the secret from keyring, or creates one if it doesn't exist.
func GetOrCreateKeyringSecret() ([]byte, error) {
	secret, err := GetKeyringSecret()
	if err == nil {
		return secret, nil
	}

	if errors.Is(err, ErrKeyringSecretNotFound) {
		return CreateKeyringSecret()
	}

	return nil, err
}

// GenerateKeyringFingerprint computes a SHA-256 fingerprint of the given secret.
func GenerateKeyringFingerprint(secret []byte) string {
	hash := sha256.Sum256(secret)
	return hex.EncodeToString(hash[:])
}

// GetKeyringFingerprint retrieves the fingerprint of the current keyring secret.
func GetKeyringFingerprint() string {
	secret, err := GetKeyringSecret()
	if err != nil {
		return ""
	}
	defer ZeroMemory(secret)
	return GenerateKeyringFingerprint(secret)
}
