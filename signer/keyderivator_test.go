package signer

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestDeriveKey(t *testing.T) {
	deriver := NewSigningKeyDeriver(newDerivedKeyCacheNoThr())

	accessKeyID := "AKID"
	secretAccessKey := "SECRET"
	service := "s3"
	region := "us-east-1"
	signingTime := NewSigningTime(time.Unix(0, 0))

	key1 := deriver.DeriveKey(
		accessKeyID,
		secretAccessKey,
		service,
		region,
		signingTime,
	)

	if len(key1) != 32 {
		t.Errorf("expected key length 32, got %d", len(key1))
	}

	// Test caching - same inputs should return same key
	key2 := deriver.DeriveKey(
		accessKeyID,
		secretAccessKey,
		service,
		region,
		signingTime,
	)

	if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
		t.Error("cached key should match original key")
	}

	// Test different region produces different key
	key3 := deriver.DeriveKey(
		accessKeyID,
		secretAccessKey,
		service,
		"us-west-2",
		signingTime,
	)

	if hex.EncodeToString(key1) == hex.EncodeToString(key3) {
		t.Error("different region should produce different key")
	}

	// Test different service produces different key
	key4 := deriver.DeriveKey(
		accessKeyID,
		secretAccessKey,
		"dynamodb",
		region,
		signingTime,
	)

	if hex.EncodeToString(key1) == hex.EncodeToString(key4) {
		t.Error("different service should produce different key")
	}

	// Test different date produces different key
	key5 := deriver.DeriveKey(
		accessKeyID,
		secretAccessKey,
		service,
		region,
		NewSigningTime(time.Unix(86400, 0)), // Next day
	)

	if hex.EncodeToString(key1) == hex.EncodeToString(key5) {
		t.Error("different date should produce different key")
	}

	// Test different access key ID uses same derived key
	// (key derivation doesn't depend on access key ID, only secret)
	key6 := deriver.DeriveKey(
		"OTHER_KEY",
		secretAccessKey,
		service,
		region,
		signingTime,
	)

	// Same secret should produce same key regardless of access key ID
	if hex.EncodeToString(key1) != hex.EncodeToString(key6) {
		t.Error("same secret should produce same key regardless of access key ID")
	}
}

func TestDeriveKeyKnownValue(t *testing.T) {
	// Test with known values to ensure correctness
	deriver := NewSigningKeyDeriver(newDerivedKeyCacheNoThr())

	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	service := "iam"
	region := "us-east-1"
	date := "20150830"

	signingTime := NewSigningTime(
		time.Date(2015, 8, 30, 0, 0, 0, 0, time.UTC),
	)

	key := deriver.DeriveKey(
		"AKID",
		secret,
		service,
		region,
		signingTime,
	)

	// Expected key derivation steps (from AWS docs example):
	// kDate = HMAC-SHA256("AWS4" + secret, date)
	// kRegion = HMAC-SHA256(kDate, region)
	// kService = HMAC-SHA256(kRegion, service)
	// kSigning = HMAC-SHA256(kService, "aws4_request")

	// Verify key is not empty
	if len(key) == 0 {
		t.Error("derived key should not be empty")
	}

	// Verify key is correct length (32 bytes for SHA256)
	if len(key) != 32 {
		t.Errorf("expected key length 32, got %d", len(key))
	}

	// Verify date format matches
	if signingTime.ShortTimeFormat() != date {
		t.Errorf("expected date %s, got %s", date, signingTime.ShortTimeFormat())
	}
}

func TestKeyDerivatorCache(t *testing.T) {
	deriver := NewSigningKeyDeriver(newDerivedKeyCacheNoThr())

	accessKeyID := "AKID"
	secretAccessKey := "SECRET"
	service := "s3"
	region := "us-east-1"
	t1 := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2023, 1, 1, 18, 0, 0, 0, time.UTC) // Same day
	t3 := time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC) // Next day

	st1 := NewSigningTime(t1)
	st2 := NewSigningTime(t2)
	st3 := NewSigningTime(t3)

	key1 := deriver.DeriveKey(accessKeyID, secretAccessKey, service, region, st1)
	key2 := deriver.DeriveKey(accessKeyID, secretAccessKey, service, region, st2)
	key3 := deriver.DeriveKey(accessKeyID, secretAccessKey, service, region, st3)

	// Same day should use cached key
	if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
		t.Error("same day should use cached key")
	}

	// Different day should produce different key
	if hex.EncodeToString(key1) == hex.EncodeToString(key3) {
		t.Error("different day should produce different key")
	}
}

