// Package utils provides utility functions for the password manager.
package utils

import (
	"sync"
	"time"
)

// AutoLockTimer manages the auto-lock timeout for the vault.
type AutoLockTimer struct {
	mu       sync.Mutex
	timeout  time.Duration
	timer    *time.Timer
	callback func()
	active   bool
}

// NewAutoLockTimer creates a new auto-lock timer.
func NewAutoLockTimer(timeout time.Duration, callback func()) *AutoLockTimer {
	return &AutoLockTimer{
		timeout:  timeout,
		callback: callback,
	}
}

// Start starts the auto-lock timer.
func (t *AutoLockTimer) Start() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.timer != nil {
		t.timer.Stop()
	}

	if t.timeout > 0 {
		t.timer = time.AfterFunc(t.timeout, t.onTimeout)
		t.active = true
	}
}

// Reset resets the auto-lock timer (user activity).
func (t *AutoLockTimer) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.timer != nil {
		t.timer.Stop()
	}

	if t.timeout > 0 && t.active {
		t.timer = time.AfterFunc(t.timeout, t.onTimeout)
	}
}

// Stop stops the auto-lock timer.
func (t *AutoLockTimer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	t.active = false
}

// SetTimeout updates the timeout duration.
func (t *AutoLockTimer) SetTimeout(timeout time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.timeout = timeout

	// Restart if active
	if t.active && t.timer != nil {
		t.timer.Stop()
		if timeout > 0 {
			t.timer = time.AfterFunc(timeout, t.onTimeout)
		}
	}
}

// IsActive returns true if the timer is active.
func (t *AutoLockTimer) IsActive() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.active
}

// onTimeout is called when the timer expires.
func (t *AutoLockTimer) onTimeout() {
	t.mu.Lock()
	callback := t.callback
	t.active = false
	t.timer = nil
	t.mu.Unlock()

	if callback != nil {
		callback()
	}
}

// Remaining returns the approximate time remaining before lock.
func (t *AutoLockTimer) Remaining() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.active || t.timer == nil {
		return 0
	}

	// Note: This is an approximation since Go's timer doesn't expose remaining time
	return t.timeout
}
