package signer

import (
	"strings"
	"time"
)

// keyDerivator is an interface for deriving signing keys.
// Reference: AWS SDK v4 signer v4.go keyDerivator interface
type keyDerivator interface {
	DeriveKey(accessKeyID, secretAccessKey, service, region string, signingTime SigningTime) []byte
}

// derivedKey represents a cached derived key.
type derivedKey struct {
	accessKeyID string
	date        time.Time
	key         []byte
}

// derivedKeyCacheInterface defines the interface for cache implementations.
// Implementations may be thread-safe or not, depending on the use case.
type derivedKeyCacheInterface interface {
	get(key string, accessKeyID string, t time.Time) ([]byte, bool)
	set(key string, accessKeyID string, t time.Time, k []byte)
}

// lookupKey creates a cache key from service and region.
func lookupKey(service, region string) string {
	var b strings.Builder
	b.Grow(len(region) + len(service) + 3)
	b.WriteString(region)
	b.WriteRune('/')
	b.WriteString(service)
	return b.String()
}


// isSameDay checks if two times are on the same day.
func isSameDay(t1, t2 time.Time) bool {
	y1, m1, d1 := t1.Date()
	y2, m2, d2 := t2.Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}

// SigningKeyDeriver derives signing keys with caching.
// Thread safety depends on the cache implementation provided.
// Reference: AWS SDK v4 signer internal/v4/cache.go
type SigningKeyDeriver struct {
	cache derivedKeyCacheInterface
}

// NewSigningKeyDeriver creates a new SigningKeyDeriver with the provided cache.
func NewSigningKeyDeriver(cache derivedKeyCacheInterface) *SigningKeyDeriver {
	return &SigningKeyDeriver{
		cache: cache,
	}
}

// DeriveKey derives a signing key from credentials.
// Implements the SigV4 key derivation algorithm:
//   - kDate = HMAC-SHA256("AWS4" + secret, date)
//   - kRegion = HMAC-SHA256(kDate, region)
//   - kService = HMAC-SHA256(kRegion, service)
//   - kSigning = HMAC-SHA256(kService, "aws4_request")
//
// Keys are cached per day/region/service/accessKeyID combination.
// Thread safety depends on the cache implementation provided to NewSigningKeyDeriver.
// Reference: AWS SigV4 spec and AWS SDK v4 signer internal/v4/cache.go
func (k *SigningKeyDeriver) DeriveKey(accessKeyID, secretAccessKey, service, region string, signingTime SigningTime) []byte {
	cacheKey := lookupKey(service, region)
	if key, ok := k.cache.get(cacheKey, accessKeyID, signingTime.Time); ok {
		return key
	}

	// Derive the key using HMAC-SHA256 chain
	key := DeriveKey(secretAccessKey, service, region, signingTime)

	// Cache the derived key
	k.cache.set(cacheKey, accessKeyID, signingTime.Time, key)

	return key
}
