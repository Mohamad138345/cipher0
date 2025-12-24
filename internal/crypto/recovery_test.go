package crypto

import (
	"strings"
	"testing"
)

func TestGenerateRecoveryPhrase(t *testing.T) {
	phrase, err := GenerateRecoveryPhrase()
	if err != nil {
		t.Fatalf("Failed to generate recovery phrase: %v", err)
	}

	words := strings.Fields(phrase)
	if len(words) != RecoveryPhraseWordCount {
		t.Errorf("Expected %d words, got %d", RecoveryPhraseWordCount, len(words))
	}

	// Verify phrase is valid BIP39
	if !ValidateRecoveryPhrase(phrase) {
		t.Error("Generated phrase should be valid BIP39")
	}
}

func TestGenerateRecoveryPhraseUnique(t *testing.T) {
	phrase1, _ := GenerateRecoveryPhrase()
	phrase2, _ := GenerateRecoveryPhrase()

	if phrase1 == phrase2 {
		t.Error("Two generated phrases should be different")
	}
}

func TestValidateRecoveryPhrase(t *testing.T) {
	// Valid phrase
	validPhrase := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	if !ValidateRecoveryPhrase(validPhrase) {
		t.Error("Valid phrase should pass validation")
	}

	// Invalid phrase - wrong words
	invalidPhrase := "notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword"
	if ValidateRecoveryPhrase(invalidPhrase) {
		t.Error("Invalid phrase should fail validation")
	}

	// Invalid phrase - wrong checksum
	invalidChecksum := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	if ValidateRecoveryPhrase(invalidChecksum) {
		t.Error("Phrase with wrong checksum should fail validation")
	}

	// Empty phrase
	if ValidateRecoveryPhrase("") {
		t.Error("Empty phrase should fail validation")
	}
}

func TestNormalizePhrase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  word  one   two  ", "word one two"},
		{"UPPER CASE", "upper case"},
		{"MixedCase", "mixedcase"},
		{"   ", ""},
		{"single", "single"},
	}

	for _, tt := range tests {
		result := NormalizePhrase(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizePhrase(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestPhraseToKey(t *testing.T) {
	phrase := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	key, err := PhraseToKey(phrase)
	if err != nil {
		t.Fatalf("PhraseToKey failed: %v", err)
	}

	// Verify key length
	if len(key) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key))
	}

	// Same phrase should produce same key
	key2, _ := PhraseToKey(phrase)
	if string(key) != string(key2) {
		t.Error("Same phrase should produce same key")
	}

	// Different case should produce same key
	key3, _ := PhraseToKey(strings.ToUpper(phrase))
	if string(key) != string(key3) {
		t.Error("Case-insensitive phrase should produce same key")
	}
}

func TestPhraseToKeyInvalid(t *testing.T) {
	_, err := PhraseToKey("invalid phrase here")
	if err != ErrInvalidMnemonic {
		t.Errorf("Expected ErrInvalidMnemonic, got: %v", err)
	}
}

func TestGetWordList(t *testing.T) {
	words := GetWordList()
	if len(words) != 2048 {
		t.Errorf("BIP39 word list should have 2048 words, got %d", len(words))
	}
}

func TestParsePhraseWords(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"one two three", 3},
		{"  one   two   three  ", 3},
		{"single", 1},
		{"", 0},
		{"   ", 0},
	}

	for _, tt := range tests {
		result := ParsePhraseWords(tt.input)
		if len(result) != tt.expected {
			t.Errorf("ParsePhraseWords(%q) = %d words, expected %d", tt.input, len(result), tt.expected)
		}
	}
}
