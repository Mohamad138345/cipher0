// Package utils provides utility functions for the password manager.
package utils

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// PasswordStrength represents the strength level of a password.
type PasswordStrength int

const (
	StrengthWeak PasswordStrength = iota
	StrengthFair
	StrengthGood
	StrengthStrong
	StrengthVeryStrong
)

// String returns a human-readable strength label.
func (s PasswordStrength) String() string {
	switch s {
	case StrengthWeak:
		return "Weak"
	case StrengthFair:
		return "Fair"
	case StrengthGood:
		return "Good"
	case StrengthStrong:
		return "Strong"
	case StrengthVeryStrong:
		return "Very Strong"
	default:
		return "Unknown"
	}
}

// Color returns a color code for the strength.
func (s PasswordStrength) Color() string {
	switch s {
	case StrengthWeak:
		return "#FF4444" // Red
	case StrengthFair:
		return "#FFA500" // Orange
	case StrengthGood:
		return "#FFFF00" // Yellow
	case StrengthStrong:
		return "#90EE90" // Light green
	case StrengthVeryStrong:
		return "#00FF00" // Green
	default:
		return "#FFFFFF"
	}
}

// Percentage returns a 0-100 percentage for the strength meter.
func (s PasswordStrength) Percentage() int {
	switch s {
	case StrengthWeak:
		return 20
	case StrengthFair:
		return 40
	case StrengthGood:
		return 60
	case StrengthStrong:
		return 80
	case StrengthVeryStrong:
		return 100
	default:
		return 0
	}
}

// GeneratorOptions configures the password generator.
type GeneratorOptions struct {
	Length           int
	IncludeUppercase bool
	IncludeLowercase bool
	IncludeDigits    bool
	IncludeSymbols   bool
	ExcludeAmbiguous bool
}

// DefaultGeneratorOptions returns sensible default options.
func DefaultGeneratorOptions() GeneratorOptions {
	return GeneratorOptions{
		Length:           16,
		IncludeUppercase: true,
		IncludeLowercase: true,
		IncludeDigits:    true,
		IncludeSymbols:   true,
		ExcludeAmbiguous: false,
	}
}

const (
	lowercase      = "abcdefghijklmnopqrstuvwxyz"
	uppercase      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits         = "0123456789"
	symbols        = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	ambiguousChars = "0O1lI"
)

// GeneratePassword generates a random password with the given options.
func GeneratePassword(opts GeneratorOptions) (string, error) {
	if opts.Length < 1 {
		opts.Length = 16
	}
	if opts.Length > 128 {
		opts.Length = 128
	}

	var charset string
	if opts.IncludeLowercase {
		charset += lowercase
	}
	if opts.IncludeUppercase {
		charset += uppercase
	}
	if opts.IncludeDigits {
		charset += digits
	}
	if opts.IncludeSymbols {
		charset += symbols
	}

	if charset == "" {
		charset = lowercase + digits
	}

	if opts.ExcludeAmbiguous {
		for _, c := range ambiguousChars {
			charset = strings.ReplaceAll(charset, string(c), "")
		}
	}

	password := make([]byte, opts.Length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < opts.Length; i++ {
		n, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		password[i] = charset[n.Int64()]
	}

	return string(password), nil
}

// CalculateStrength calculates the strength of a password.
func CalculateStrength(password string) PasswordStrength {
	if len(password) == 0 {
		return StrengthWeak
	}

	var score int

	length := len(password)
	if length >= 16 {
		score += 2
	} else if length >= 12 {
		score += 1
	} else if length < 8 {
		score -= 1
	}

	hasLower := strings.ContainsAny(password, lowercase)
	hasUpper := strings.ContainsAny(password, uppercase)
	hasDigit := strings.ContainsAny(password, digits)
	hasSymbol := strings.ContainsAny(password, symbols)

	varieties := 0
	if hasLower {
		varieties++
	}
	if hasUpper {
		varieties++
	}
	if hasDigit {
		varieties++
	}
	if hasSymbol {
		varieties++
	}

	score += varieties

	// Penalize common weak patterns
	lowerPassword := strings.ToLower(password)
	for _, pattern := range []string{"password", "123456", "qwerty", "abc123", "letmein"} {
		if strings.Contains(lowerPassword, pattern) {
			score -= 2
			break
		}
	}

	switch {
	case score <= 1:
		return StrengthWeak
	case score == 2:
		return StrengthFair
	case score == 3:
		return StrengthGood
	case score == 4:
		return StrengthStrong
	default:
		return StrengthVeryStrong
	}
}
