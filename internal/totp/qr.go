// Package totp provides TOTP functionality.
package totp

import (
	"fmt"

	"github.com/skip2/go-qrcode"
)

// RenderQRCodeASCII renders a QR code as ASCII/Unicode art for terminal display.
// Uses Unicode block characters for a compact, scannable representation.
// Returns the QR code as a string that can be printed directly to the terminal.
func RenderQRCodeASCII(secret, issuer, account string) (string, error) {
	if secret == "" {
		return "", ErrInvalidSecret
	}

	url := BuildOTPAuthURL(secret, issuer, account)

	// Create QR code with low recovery level for smaller size
	qr, err := qrcode.New(url, qrcode.Low)
	if err != nil {
		return "", fmt.Errorf("failed to create QR code: %w", err)
	}

	// Disable the border for a cleaner look
	qr.DisableBorder = false

	// Convert to ASCII string using Unicode block characters
	// The library's ToString method uses unicode blocks for better scanning
	return qr.ToSmallString(false), nil
}

// RenderQRCodeForEntry renders a QR code as ASCII art for a password entry.
// The issuer and account are derived from the entry's title and username.
func RenderQRCodeForEntry(secret, title, username string) (string, error) {
	if secret == "" {
		return "", ErrInvalidSecret
	}

	issuer := title
	if issuer == "" {
		issuer = "PasswordManager"
	}

	account := username
	if account == "" {
		account = "user"
	}

	return RenderQRCodeASCII(secret, issuer, account)
}
