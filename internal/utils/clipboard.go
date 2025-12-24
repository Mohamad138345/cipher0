// Package utils provides utility functions for the password manager.
package utils

import (
	"errors"
	"sync"
	"time"

	"github.com/atotto/clipboard"
)

// ErrClipboardUnavailable is returned when the clipboard is not available.
var ErrClipboardUnavailable = errors.New("clipboard is not available on this system")

// ClipboardManager manages clipboard operations with auto-clear functionality.
type ClipboardManager struct {
	mu          sync.Mutex
	clearTimer  *time.Timer
	lastContent string
	timeout     time.Duration
}

// NewClipboardManager creates a new clipboard manager with the given timeout.
func NewClipboardManager(timeout time.Duration) *ClipboardManager {
	return &ClipboardManager{
		timeout: timeout,
	}
}

// Copy copies text to the clipboard and schedules auto-clear.
func (cm *ClipboardManager) Copy(text string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if clipboard.Unsupported {
		return ErrClipboardUnavailable
	}

	if cm.clearTimer != nil {
		cm.clearTimer.Stop()
	}

	if err := clipboard.WriteAll(text); err != nil {
		return err
	}

	cm.lastContent = text

	if cm.timeout > 0 {
		cm.clearTimer = time.AfterFunc(cm.timeout, func() {
			_ = cm.Clear()
		})
	}

	return nil
}

// Clear clears the clipboard if it still contains the last copied content.
func (cm *ClipboardManager) Clear() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if clipboard.Unsupported {
		return ErrClipboardUnavailable
	}

	current, err := clipboard.ReadAll()
	if err != nil {
		return err
	}

	if current == cm.lastContent {
		if err := clipboard.WriteAll(""); err != nil {
			return err
		}
	}

	cm.lastContent = ""
	return nil
}

// IsAvailable returns true if the clipboard is available.
func (cm *ClipboardManager) IsAvailable() bool {
	return !clipboard.Unsupported
}

// SetTimeout sets the auto-clear timeout.
func (cm *ClipboardManager) SetTimeout(timeout time.Duration) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.timeout = timeout
}

// CancelClear cancels any pending auto-clear.
func (cm *ClipboardManager) CancelClear() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.clearTimer != nil {
		cm.clearTimer.Stop()
		cm.clearTimer = nil
	}
}

// CopyWithNotification copies text and returns a channel that signals when cleared.
func (cm *ClipboardManager) CopyWithNotification(text string) (<-chan bool, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if clipboard.Unsupported {
		return nil, ErrClipboardUnavailable
	}

	if cm.clearTimer != nil {
		cm.clearTimer.Stop()
	}

	if err := clipboard.WriteAll(text); err != nil {
		return nil, err
	}

	cm.lastContent = text

	ch := make(chan bool, 1)

	if cm.timeout > 0 {
		cm.clearTimer = time.AfterFunc(cm.timeout, func() {
			_ = cm.Clear()
			ch <- true
			close(ch)
		})
	}

	return ch, nil
}
