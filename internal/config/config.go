// Package config provides configuration management for the password manager.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// Config holds the application configuration.
type Config struct {
	// VaultPath is the path to the vault file.
	VaultPath string `json:"vault_path"`
	// AutoLockTimeout is the auto-lock timeout in seconds.
	AutoLockTimeout int `json:"auto_lock_timeout"`
	// ClipboardTimeout is the clipboard auto-clear timeout in seconds.
	ClipboardTimeout int `json:"clipboard_timeout"`
	// AutoBackup enables automatic backups after changes.
	AutoBackup bool `json:"auto_backup"`
	// BackupReminderDays is the number of days before showing a backup reminder.
	BackupReminderDays int `json:"backup_reminder_days"`
	// BackupDirectory is the directory for backup files.
	BackupDirectory string `json:"backup_directory"`
	// Theme is the UI theme name.
	Theme string `json:"theme"`
	// PasswordGenerator contains password generator settings.
	PasswordGenerator PasswordGeneratorConfig `json:"password_generator"`
}

// PasswordGeneratorConfig holds password generator settings.
type PasswordGeneratorConfig struct {
	DefaultLength    int  `json:"default_length"`
	IncludeUpper     bool `json:"include_upper"`
	IncludeLower     bool `json:"include_lower"`
	IncludeDigits    bool `json:"include_digits"`
	IncludeSymbols   bool `json:"include_symbols"`
	ExcludeAmbiguous bool `json:"exclude_ambiguous"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		VaultPath:          DefaultVaultPath(),
		AutoLockTimeout:    DefaultAutoLockTimeout,
		ClipboardTimeout:   DefaultClipboardTimeout,
		AutoBackup:         true,
		BackupReminderDays: DefaultBackupReminderDays,
		BackupDirectory:    DefaultBackupDir(),
		Theme:              "default",
		PasswordGenerator: PasswordGeneratorConfig{
			DefaultLength:    16,
			IncludeUpper:     true,
			IncludeLower:     true,
			IncludeDigits:    true,
			IncludeSymbols:   true,
			ExcludeAmbiguous: false,
		},
	}
}

// Load loads the configuration from the default location.
func Load() (*Config, error) {
	path := ConfigPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config if file doesn't exist
			return DefaultConfig(), nil
		}
		return nil, err
	}

	config := DefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

// Save saves the configuration to the default location.
func Save(config *Config) error {
	path := ConfigPath()

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// ConfigDir returns the configuration directory path.
func ConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), AppName)
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", AppName)
	default: // Linux and others
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", AppName)
	}
}

// ConfigPath returns the path to the config file.
func ConfigPath() string {
	return filepath.Join(ConfigDir(), "config.json")
}

// DefaultVaultPath returns the default vault file path.
func DefaultVaultPath() string {
	return filepath.Join(ConfigDir(), "vault.c0")
}

// DefaultBackupDir returns the default backup directory.
func DefaultBackupDir() string {
	return filepath.Join(ConfigDir(), "backups")
}

// EnsureConfigDir creates the config directory if it doesn't exist.
func EnsureConfigDir() error {
	return os.MkdirAll(ConfigDir(), 0700)
}
