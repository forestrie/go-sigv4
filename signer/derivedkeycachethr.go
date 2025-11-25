package signer

import (
	"sync"
	"time"
)

// derivedKeyCacheThr caches derived keys per region/service/date combination.
// This implementation is thread-safe and can be used concurrently from
// multiple goroutines.
// Reference: AWS SDK v4 signer internal/v4/cache.go derivedKeyCache
type derivedKeyCacheThr struct {
	mu     sync.RWMutex
	values map[string]derivedKey
}

// newDerivedKeyCacheThr creates a new thread-safe cache.
func newDerivedKeyCacheThr() *derivedKeyCacheThr {
	return &derivedKeyCacheThr{
		values: make(map[string]derivedKey),
	}
}

// get retrieves a cached key if it exists and is valid.
// Uses a read lock for thread-safe access.
func (c *derivedKeyCacheThr) get(key string, accessKeyID string, t time.Time) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.values[key]
	if !ok {
		return nil, false
	}
	if entry.accessKeyID != accessKeyID {
		return nil, false
	}
	if !isSameDay(t, entry.date) {
		return nil, false
	}
	return entry.key, true
}

// set stores a derived key in the cache.
// Uses a write lock for thread-safe access.
func (c *derivedKeyCacheThr) set(key string, accessKeyID string, t time.Time, k []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.values[key] = derivedKey{
		accessKeyID: accessKeyID,
		date:        t,
		key:         k,
	}
}

