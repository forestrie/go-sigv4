package signer

import (
	"crypto/hmac"
	"crypto/sha256"
)

// DeriveKey performs the actual key derivation.
// Implements the SigV4 key derivation algorithm:
//   - kDate = HMAC-SHA256("AWS4" + secret, date)
//   - kRegion = HMAC-SHA256(kDate, region)
//   - kService = HMAC-SHA256(kRegion, service)
//   - kSigning = HMAC-SHA256(kService, "aws4_request")
// Reference: AWS SDK v4 signer internal/v4/cache.go deriveKey function
func DeriveKey(secret, service, region string, t SigningTime) []byte {
	dateStr := t.ShortTimeFormat()

	// kDate = HMAC-SHA256("AWS4" + secret, date)
	kDate := HMACSHA256([]byte("AWS4"+secret), []byte(dateStr))

	// kRegion = HMAC-SHA256(kDate, region)
	kRegion := HMACSHA256(kDate, []byte(region))

	// kService = HMAC-SHA256(kRegion, service)
	kService := HMACSHA256(kRegion, []byte(service))

	// kSigning = HMAC-SHA256(kService, "aws4_request")
	return HMACSHA256(kService, []byte("aws4_request"))
}

// HMACSHA256 computes HMAC-SHA256 of data with the given key.
// Reference: AWS SDK v4 signer internal/v4/hmac.go HMACSHA256
func HMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

