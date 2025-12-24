package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	password := []byte("my-secure-password")
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	key := DeriveKey(password, salt)

	// Verify key length
	if len(key) != Argon2KeyLen {
		t.Errorf("Expected key length %d, got %d", Argon2KeyLen, len(key))
	}

	// Verify same password + salt produces same key
	key2 := DeriveKey(password, salt)
	if !bytes.Equal(key, key2) {
		t.Error("Same password and salt should produce same key")
	}
}

func TestDeriveKeyDifferentSalts(t *testing.T) {
	password := []byte("my-secure-password")
	salt1, _ := GenerateSalt()
	salt2, _ := GenerateSalt()

	key1 := DeriveKey(password, salt1)
	key2 := DeriveKey(password, salt2)

	// Different salts should produce different keys
	if bytes.Equal(key1, key2) {
		t.Error("Different salts should produce different keys")
	}
}

func TestDeriveKeyDifferentPasswords(t *testing.T) {
	salt, _ := GenerateSalt()
	password1 := []byte("password1")
	password2 := []byte("password2")

	key1 := DeriveKey(password1, salt)
	key2 := DeriveKey(password2, salt)

	// Different passwords should produce different keys
	if bytes.Equal(key1, key2) {
		t.Error("Different passwords should produce different keys")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Verify salt length
	if len(salt1) != SaltSize {
		t.Errorf("Expected salt length %d, got %d", SaltSize, len(salt1))
	}

	// Two salts should be different
	if bytes.Equal(salt1, salt2) {
		t.Error("Two generated salts should be different")
	}
}

func TestDeriveKeyEmptyPassword(t *testing.T) {
	salt, _ := GenerateSalt()
	password := []byte("")

	// Should still work with empty password
	key := DeriveKey(password, salt)
	if len(key) != Argon2KeyLen {
		t.Errorf("Key derivation with empty password should still produce %d byte key", Argon2KeyLen)
	}
}
