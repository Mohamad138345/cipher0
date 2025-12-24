// Package config provides configuration management for the password manager.
package config

// Application constants
const (
	// AppName is the application name.
	AppName = "cipher0"
	// AppVersion is the current version.
	AppVersion = "1.0.0"
)

// Default timeouts and limits
const (
	// DefaultAutoLockTimeout is the default auto-lock timeout in seconds (15 minutes).
	DefaultAutoLockTimeout = 900
	// DefaultClipboardTimeout is the default clipboard timeout in seconds.
	DefaultClipboardTimeout = 30
	// DefaultBackupReminderDays is the default backup reminder period.
	DefaultBackupReminderDays = 30
)

// UI constants
const (
	// MinTerminalWidth is the minimum terminal width for the TUI.
	MinTerminalWidth = 80
	// MinTerminalHeight is the minimum terminal height for the TUI.
	MinTerminalHeight = 24
	// SearchDebounceMs is the debounce time for search in milliseconds.
	SearchDebounceMs = 300
)

// Password constraints
const (
	// MinPasswordLength is the minimum master password length.
	MinPasswordLength = 8
	// MaxPasswordLength is the maximum password generator length.
	MaxPasswordLength = 128
	// DefaultPasswordLength is the default generated password length.
	DefaultPasswordLength = 16
)

// File permissions
const (
	// VaultFileMode is the file mode for vault files (owner read/write only).
	VaultFileMode = 0600
	// ConfigFileMode is the file mode for config files.
	ConfigFileMode = 0644
	// DirMode is the directory mode.
	DirMode = 0700
)
