package signer

import "time"

// derivedKeyCacheNoThr caches derived keys per region/service/date combination.
// This implementation is not thread-safe and assumes the caller ensures
// single-threaded access. Each Signer instance must be used from a single
// goroutine at a time when using this cache.
// Reference: AWS SDK v4 signer internal/v4/cache.go derivedKeyCache
type derivedKeyCacheNoThr struct {
	values map[string]derivedKey
}

// newDerivedKeyCacheNoThr creates a new non-thread-safe cache.
func newDerivedKeyCacheNoThr() *derivedKeyCacheNoThr {
	return &derivedKeyCacheNoThr{
		values: make(map[string]derivedKey),
	}
}

// get retrieves a cached key if it exists and is valid.
func (c *derivedKeyCacheNoThr) get(key string, accessKeyID string, t time.Time) ([]byte, bool) {
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
func (c *derivedKeyCacheNoThr) set(key string, accessKeyID string, t time.Time, k []byte) {
	c.values[key] = derivedKey{
		accessKeyID: accessKeyID,
		date:        t,
		key:         k,
	}
}

