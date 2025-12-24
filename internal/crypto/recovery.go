// Package crypto provides cryptographic operations for the password manager.
package crypto

import (
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/luxfi/go-bip39"
)

var (
	// ErrInvalidMnemonic is returned when the recovery phrase is invalid.
	ErrInvalidMnemonic = errors.New("invalid recovery phrase")
)

// RecoveryPhraseWordCount is the number of words in the recovery phrase.
const RecoveryPhraseWordCount = 12

// RecoveryPhraseEntropyBits is the entropy bits for 12-word mnemonic (128 bits).
const RecoveryPhraseEntropyBits = 128

// GenerateRecoveryPhrase generates a 12-word BIP39 recovery phrase.
// Returns the phrase as a space-separated string.
func GenerateRecoveryPhrase() (string, error) {
	entropy, err := bip39.NewEntropy(RecoveryPhraseEntropyBits)
	if err != nil {
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	return mnemonic, nil
}

// ValidateRecoveryPhrase checks if a phrase is a valid BIP39 mnemonic.
func ValidateRecoveryPhrase(phrase string) bool {
	return bip39.IsMnemonicValid(phrase)
}

// NormalizePhrase normalizes a recovery phrase (lowercase, trim, single spaces).
func NormalizePhrase(phrase string) string {
	phrase = strings.ToLower(strings.TrimSpace(phrase))
	words := strings.Fields(phrase)
	return strings.Join(words, " ")
}

// PhraseToKey derives a 32-byte key from a recovery phrase.
// Uses SHA-256 of the BIP39 seed for key derivation.
// This provides a deterministic key from the phrase.
func PhraseToKey(phrase string) ([]byte, error) {
	phrase = NormalizePhrase(phrase)

	if !ValidateRecoveryPhrase(phrase) {
		return nil, ErrInvalidMnemonic
	}

	// BIP39 seed is expanded then hashed to 32 bytes for AES-256
	seed := bip39.NewSeed(phrase, "")
	hash := sha256.Sum256(seed)

	ZeroMemory(seed)

	return hash[:], nil
}

// GetWordList returns the BIP39 word list for autocomplete purposes.
func GetWordList() []string {
	return bip39.GetWordList()
}

// ParsePhraseWords splits a phrase into individual words.
func ParsePhraseWords(phrase string) []string {
	phrase = NormalizePhrase(phrase)
	if phrase == "" {
		return []string{}
	}
	return strings.Fields(phrase)
}
