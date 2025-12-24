package crypto

import (
	"os"
	"testing"
)

// TestMain sets up a mock keyring for all tests in this package.
func TestMain(m *testing.M) {
	// Use mock keyring for all tests
	_, cleanup := UseMockKeyring()
	defer cleanup()

	os.Exit(m.Run())
}

func TestGenerateMEK(t *testing.T) {
	mek, err := GenerateMEK()
	if err != nil {
		t.Fatalf("Failed to generate MEK: %v", err)
	}

	if len(mek) != MEKSize {
		t.Errorf("Expected MEK size %d, got %d", MEKSize, len(mek))
	}
}

func TestEncryptDecryptMEK(t *testing.T) {
	mek, _ := GenerateMEK()
	key, _ := GenerateRandomBytes(KeySize)

	encrypted, err := EncryptMEK(mek, key)
	if err != nil {
		t.Fatalf("EncryptMEK failed: %v", err)
	}

	decrypted, err := DecryptMEK(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptMEK failed: %v", err)
	}

	if string(mek) != string(decrypted) {
		t.Error("Decrypted MEK should match original")
	}
}

func TestDecryptMEKWrongKey(t *testing.T) {
	mek, _ := GenerateMEK()
	key1, _ := GenerateRandomBytes(KeySize)
	key2, _ := GenerateRandomBytes(KeySize)

	encrypted, _ := EncryptMEK(mek, key1)

	_, err := DecryptMEK(encrypted, key2)
	if err != ErrMEKDecryptionFailed {
		t.Errorf("Expected ErrMEKDecryptionFailed, got: %v", err)
	}
}

func TestCreateMEKBundle(t *testing.T) {
	password := "test-password-123"

	bundle, phrase, err := CreateMEKBundle(password)
	if err != nil {
		t.Fatalf("CreateMEKBundle failed: %v", err)
	}

	// Verify phrase is valid
	if !ValidateRecoveryPhrase(phrase) {
		t.Error("Recovery phrase should be valid")
	}

	// Verify salts are set
	if len(bundle.SaltPassword) != SaltSize {
		t.Errorf("SaltPassword should be %d bytes", SaltSize)
	}
	if len(bundle.SaltPhrase) != SaltSize {
		t.Errorf("SaltPhrase should be %d bytes", SaltSize)
	}

	// Verify encrypted MEKs are set
	if len(bundle.EncryptedMEKPassword) == 0 {
		t.Error("EncryptedMEKPassword should not be empty")
	}
	if len(bundle.EncryptedMEKPhrase) == 0 {
		t.Error("EncryptedMEKPhrase should not be empty")
	}
}

func TestMEKBundleDecryptWithPassword(t *testing.T) {
	password := "test-password-123"
	bundle, _, err := CreateMEKBundle(password)
	if err != nil {
		t.Fatalf("CreateMEKBundle failed: %v", err)
	}

	mek, err := bundle.DecryptMEKWithPassword(password)
	if err != nil {
		t.Fatalf("DecryptMEKWithPassword failed: %v", err)
	}

	if len(mek) != MEKSize {
		t.Errorf("Decrypted MEK should be %d bytes", MEKSize)
	}
}

func TestMEKBundleDecryptWithWrongPassword(t *testing.T) {
	password := "correct-password"
	bundle, _, _ := CreateMEKBundle(password)

	_, err := bundle.DecryptMEKWithPassword("wrong-password")
	if err == nil {
		t.Error("Should fail with wrong password")
	}
}

func TestMEKBundleDecryptWithPhrase(t *testing.T) {
	password := "test-password"
	bundle, phrase, err := CreateMEKBundle(password)
	if err != nil {
		t.Fatalf("CreateMEKBundle failed: %v", err)
	}

	mek, err := bundle.DecryptMEKWithPhrase(phrase)
	if err != nil {
		t.Fatalf("DecryptMEKWithPhrase failed: %v", err)
	}

	if len(mek) != MEKSize {
		t.Errorf("Decrypted MEK should be %d bytes", MEKSize)
	}
}

func TestMEKBundleBothMethodsProduceSameMEK(t *testing.T) {
	password := "test-password"
	bundle, phrase, err := CreateMEKBundle(password)
	if err != nil {
		t.Fatalf("CreateMEKBundle failed: %v", err)
	}

	mekFromPassword, err := bundle.DecryptMEKWithPassword(password)
	if err != nil {
		t.Fatalf("DecryptMEKWithPassword failed: %v", err)
	}

	mekFromPhrase, err := bundle.DecryptMEKWithPhrase(phrase)
	if err != nil {
		t.Fatalf("DecryptMEKWithPhrase failed: %v", err)
	}

	// Both methods should produce the same MEK
	if string(mekFromPassword) != string(mekFromPhrase) {
		t.Error("Password and phrase should decrypt to the same MEK")
	}
}

func TestReEncryptMEKWithNewPassword(t *testing.T) {
	oldPassword := "old-password"
	newPassword := "new-password"

	bundle, phrase, err := CreateMEKBundle(oldPassword)
	if err != nil {
		t.Fatalf("CreateMEKBundle failed: %v", err)
	}

	// Get original MEK
	originalMEK, _ := bundle.DecryptMEKWithPassword(oldPassword)

	// Re-encrypt with new password
	err = bundle.ReEncryptMEKWithNewPassword(originalMEK, newPassword)
	if err != nil {
		t.Fatalf("ReEncryptMEKWithNewPassword failed: %v", err)
	}

	// Old password should no longer work
	_, err = bundle.DecryptMEKWithPassword(oldPassword)
	if err == nil {
		t.Error("Old password should no longer work")
	}

	// New password should work
	newMEK, err := bundle.DecryptMEKWithPassword(newPassword)
	if err != nil {
		t.Fatalf("New password should work: %v", err)
	}

	// MEK should be the same
	if string(originalMEK) != string(newMEK) {
		t.Error("MEK should remain the same after password change")
	}

	// Recovery phrase should still work
	phraseMEK, err := bundle.DecryptMEKWithPhrase(phrase)
	if err != nil {
		t.Fatalf("Recovery phrase should still work: %v", err)
	}

	if string(originalMEK) != string(phraseMEK) {
		t.Error("Recovery phrase should still decrypt to the same MEK")
	}
}
