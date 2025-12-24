// Package vault provides vault management for the password manager.
package vault

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// Entry represents a password entry in the vault.
type Entry struct {
	// ID is the unique identifier for the entry.
	ID string `json:"id"`
	// Title is the name/title of the entry (required).
	Title string `json:"title"`
	// Username is the username/email for the entry.
	Username string `json:"username,omitempty"`
	// Password is the password for the entry.
	Password string `json:"password,omitempty"`
	// URL is the website URL for the entry.
	URL string `json:"url,omitempty"`
	// Notes contains additional notes (multiline).
	Notes string `json:"notes,omitempty"`
	// TOTPSecret is the TOTP secret for 2FA (optional).
	TOTPSecret string `json:"totp_secret,omitempty"`
	// Created is the timestamp when the entry was created.
	Created time.Time `json:"created"`
	// Updated is the timestamp when the entry was last updated.
	Updated time.Time `json:"updated"`
}

// NewEntry creates a new entry with a generated UUID and current timestamp.
func NewEntry(title string) *Entry {
	now := time.Now()
	return &Entry{
		ID:      uuid.New().String(),
		Title:   title,
		Created: now,
		Updated: now,
	}
}

// Update marks the entry as updated with the current timestamp.
func (e *Entry) Update() {
	e.Updated = time.Now()
}

// HasTOTP returns true if the entry has a TOTP secret configured.
func (e *Entry) HasTOTP() bool {
	return e.TOTPSecret != ""
}

// EntryList is a slice of entries with helper methods.
type EntryList []*Entry

// FindByID finds an entry by its ID.
func (el EntryList) FindByID(id string) *Entry {
	for _, e := range el {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// FindByTitle finds entries matching the title (case-insensitive substring).
func (el EntryList) FindByTitle(title string) EntryList {
	var results EntryList
	for _, e := range el {
		if containsIgnoreCase(e.Title, title) {
			results = append(results, e)
		}
	}
	return results
}

// Search searches entries by title, username, or URL.
func (el EntryList) Search(query string) EntryList {
	if query == "" {
		return el
	}

	var results EntryList
	for _, e := range el {
		if containsIgnoreCase(e.Title, query) ||
			containsIgnoreCase(e.Username, query) ||
			containsIgnoreCase(e.URL, query) {
			results = append(results, e)
		}
	}
	return results
}

// containsIgnoreCase checks if s contains substr (case-insensitive).
// Uses strings.ToLower for proper Unicode support.
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
