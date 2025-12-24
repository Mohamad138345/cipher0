// Package totp provides TOTP (Time-based One-Time Password) functionality.
package totp

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

var (
	// ErrInvalidSecret is returned when the TOTP secret is invalid.
	ErrInvalidSecret = errors.New("invalid TOTP secret")
	// ErrCodeGenerationFailed is returned when code generation fails.
	ErrCodeGenerationFailed = errors.New("failed to generate TOTP code")
)

// DefaultPeriod is the standard TOTP period in seconds.
const DefaultPeriod = 30

// DefaultDigits is the standard number of digits in a TOTP code.
const DefaultDigits = 6

// GenerateCode generates a TOTP code for the given secret.
// Returns the code, seconds remaining in the current period, and any error.
func GenerateCode(secret string) (string, int, error) {
	secret = NormalizeSecret(secret)

	if !ValidateSecret(secret) {
		return "", 0, ErrInvalidSecret
	}

	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrCodeGenerationFailed, err)
	}

	// Calculate seconds remaining
	secondsRemaining := DefaultPeriod - (int(now.Unix()) % DefaultPeriod)

	return code, secondsRemaining, nil
}

// ValidateSecret checks if a TOTP secret is valid base32.
func ValidateSecret(secret string) bool {
	secret = NormalizeSecret(secret)

	if len(secret) < 16 {
		return false
	}

	// Check if it's valid base32
	const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	for _, c := range secret {
		if !strings.ContainsRune(base32Chars, c) && c != '=' {
			return false
		}
	}

	return true
}

// NormalizeSecret normalizes a TOTP secret (uppercase, no spaces).
func NormalizeSecret(secret string) string {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.ReplaceAll(secret, "-", "")
	return secret
}

// FormatCode formats a TOTP code with a space in the middle for readability.
// Example: "123456" -> "123 456"
func FormatCode(code string) string {
	if len(code) == 6 {
		return code[:3] + " " + code[3:]
	}
	return code
}

// BuildOTPAuthURL builds an otpauth:// URL for the given parameters.
func BuildOTPAuthURL(secret, issuer, account string) string {
	secret = NormalizeSecret(secret)
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, account, secret, issuer)
}
