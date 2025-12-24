// Package crypto provides cryptographic operations for the password manager.
package crypto

import (
	"sync"
)

// MockKeyring is an in-memory keyring implementation for testing.
// It implements KeyringProvider and stores secrets in a map.
type MockKeyring struct {
	mu      sync.RWMutex
	secrets map[string]string
}

// NewMockKeyring creates a new mock keyring for testing.
func NewMockKeyring() *MockKeyring {
	return &MockKeyring{
		secrets: make(map[string]string),
	}
}

// makeKey creates a storage key from service and account.
func (m *MockKeyring) makeKey(service, account string) string {
	return service + ":" + account
}

// Get retrieves a secret from the mock keyring.
func (m *MockKeyring) Get(service, account string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.makeKey(service, account)
	if secret, ok := m.secrets[key]; ok {
		return secret, nil
	}
	return "", ErrKeyringSecretNotFound
}

// Set stores a secret in the mock keyring.
func (m *MockKeyring) Set(service, account, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.makeKey(service, account)
	m.secrets[key] = password
	return nil
}

// Delete removes a secret from the mock keyring.
func (m *MockKeyring) Delete(service, account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.makeKey(service, account)
	delete(m.secrets, key)
	return nil
}

// Reset clears all secrets from the mock keyring.
func (m *MockKeyring) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets = make(map[string]string)
}

// HasSecret checks if a secret exists in the mock keyring.
func (m *MockKeyring) HasSecret(service, account string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.makeKey(service, account)
	_, ok := m.secrets[key]
	return ok
}

// UseMockKeyring sets a mock keyring as the provider and returns a cleanup function.
// Usage:
//
//	cleanup := crypto.UseMockKeyring()
//	defer cleanup()
func UseMockKeyring() (mock *MockKeyring, cleanup func()) {
	mock = NewMockKeyring()
	SetKeyringProvider(mock)
	return mock, func() {
		SetKeyringProvider(&osKeyring{})
	}
}
