package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateRandomBytes(KeySize)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("This is a secret message that should be encrypted!")

	// Encrypt
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should not equal plaintext")
	}

	// Verify ciphertext is longer (nonce + tag)
	if len(ciphertext) <= len(plaintext) {
		t.Error("Ciphertext should be longer than plaintext")
	}

	// Decrypt
	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify decrypted matches original
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key, _ := GenerateRandomBytes(KeySize)
	plaintext := []byte{}

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt empty failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt empty failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted empty text doesn't match")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1, _ := GenerateRandomBytes(KeySize)
	key2, _ := GenerateRandomBytes(KeySize)
	plaintext := []byte("Secret data")

	ciphertext, err := Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with wrong key
	_, err = Decrypt(ciphertext, key2)
	if err == nil {
		t.Error("Decrypt should fail with wrong key")
	}
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestInvalidKeySize(t *testing.T) {
	shortKey := make([]byte, 16) // Too short
	plaintext := []byte("test")

	_, err := Encrypt(plaintext, shortKey)
	if err != ErrInvalidKey {
		t.Errorf("Expected ErrInvalidKey for short key, got: %v", err)
	}

	longKey := make([]byte, 64) // Too long
	_, err = Encrypt(plaintext, longKey)
	if err != ErrInvalidKey {
		t.Errorf("Expected ErrInvalidKey for long key, got: %v", err)
	}
}

func TestInvalidCiphertext(t *testing.T) {
	key, _ := GenerateRandomBytes(KeySize)

	// Too short ciphertext
	shortCiphertext := make([]byte, 10)
	_, err := Decrypt(shortCiphertext, key)
	if err != ErrInvalidCiphertext {
		t.Errorf("Expected ErrInvalidCiphertext, got: %v", err)
	}
}

func TestZeroMemory(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ZeroMemory(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d is not zero: %d", i, b)
		}
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	b1, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	b2, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	// Two random generations should be different
	if bytes.Equal(b1, b2) {
		t.Error("Two random byte generations should not be equal")
	}

	// Verify correct length
	if len(b1) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(b1))
	}
}

func TestEncryptDifferentNonces(t *testing.T) {
	key, _ := GenerateRandomBytes(KeySize)
	plaintext := []byte("Same text encrypted twice")

	c1, _ := Encrypt(plaintext, key)
	c2, _ := Encrypt(plaintext, key)

	// Same plaintext should produce different ciphertext (different nonces)
	if bytes.Equal(c1, c2) {
		t.Error("Two encryptions should produce different ciphertext due to random nonces")
	}
}

func TestEncryptDecryptWithAAD(t *testing.T) {
	key, err := GenerateRandomBytes(KeySize)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("Secret message with authenticated metadata")
	aad := []byte(`{"version":"1.1","salt":"abc123"}`)

	// Encrypt with AAD
	ciphertext, err := EncryptWithAAD(plaintext, key, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}

	// Decrypt with same AAD
	decrypted, err := DecryptWithAAD(ciphertext, key, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original")
	}
}

func TestDecryptWithWrongAAD(t *testing.T) {
	key, _ := GenerateRandomBytes(KeySize)
	plaintext := []byte("Secret data")
	correctAAD := []byte(`{"version":"1.1"}`)
	wrongAAD := []byte(`{"version":"1.0"}`)

	ciphertext, err := EncryptWithAAD(plaintext, key, correctAAD)
	if err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}

	// Try to decrypt with wrong AAD - should fail
	_, err = DecryptWithAAD(ciphertext, key, wrongAAD)
	if err == nil {
		t.Error("DecryptWithAAD should fail with wrong AAD")
	}
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestAADEmpty(t *testing.T) {
	key, _ := GenerateRandomBytes(KeySize)
	plaintext := []byte("Data with empty AAD")

	// Empty AAD should work
	ciphertext, err := EncryptWithAAD(plaintext, key, nil)
	if err != nil {
		t.Fatalf("EncryptWithAAD with nil AAD failed: %v", err)
	}

	decrypted, err := DecryptWithAAD(ciphertext, key, nil)
	if err != nil {
		t.Fatalf("DecryptWithAAD with nil AAD failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text doesn't match with empty AAD")
	}

	// Empty slice should be equivalent to nil
	decrypted2, err := DecryptWithAAD(ciphertext, key, []byte{})
	if err != nil {
		t.Fatalf("DecryptWithAAD with empty slice AAD failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted2) {
		t.Error("Decrypted text doesn't match with empty slice AAD")
	}
}
