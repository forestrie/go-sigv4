package signer

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBuildCredentialScope(t *testing.T) {
	tm := NewSigningTime(time.Date(2023, 12, 1, 12, 0, 0, 0, time.UTC))
	scope := BuildCredentialScope(tm, "us-east-1", "s3")

	expected := "20231201/us-east-1/s3/aws4_request"
	if scope != expected {
		t.Errorf("expected %s, got %s", expected, scope)
	}
}

func TestGetURIPath(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "simple path",
			url:      "https://example.com/bucket/key",
			expected: "/bucket/key",
		},
		{
			name:     "root path",
			url:      "https://example.com/",
			expected: "/",
		},
		{
			name:     "no path",
			url:      "https://example.com",
			expected: "/",
		},
		{
			name:     "path with query",
			url:      "https://example.com/bucket/key?foo=bar",
			expected: "/bucket/key",
		},
		{
			name:     "opaque URL",
			url:      "https://example.com",
			expected: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("failed to parse URL: %v", err)
			}

			path := GetURIPath(u)
			if path != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, path)
			}
		})
	}
}

func TestStripExcessSpaces(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no spaces",
			input:    "test",
			expected: "test",
		},
		{
			name:     "single space",
			input:    "test value",
			expected: "test value",
		},
		{
			name:     "multiple spaces",
			input:    "test    value",
			expected: "test value",
		},
		{
			name:     "leading spaces",
			input:    "   test",
			expected: "test",
		},
		{
			name:     "trailing spaces",
			input:    "test   ",
			expected: "test",
		},
		{
			name:     "all spaces",
			input:    "   test    value   ",
			expected: "test value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripExcessSpaces(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestBuildCanonicalHeaders(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Host", "example.com")
	headers.Set("Content-Type", "application/json")
	headers.Set("X-Amz-Meta-Custom", "value")

	signed, signedHeadersStr, canonicalStr := BuildCanonicalHeaders(
		"example.com",
		IgnoredHeaders,
		headers,
		0,
	)

	if signed == nil {
		t.Error("signed headers should not be nil")
	}

	if !strings.Contains(signedHeadersStr, "host") {
		t.Error("signed headers should include host")
	}

	if !strings.Contains(canonicalStr, "host:example.com") {
		t.Error("canonical string should include host header")
	}

	// Verify headers are sorted
	parts := strings.Split(signedHeadersStr, ";")
	for i := 1; i < len(parts); i++ {
		if parts[i-1] > parts[i] {
			t.Error("signed headers should be sorted")
		}
	}
}

func TestBuildCanonicalString(t *testing.T) {
	method := "GET"
	uri := "/bucket/key"
	query := "foo=bar"
	signedHeaders := "host;x-amz-date"
	canonicalHeaders := "host:example.com\nx-amz-date:20231201T120000Z\n"
	payloadHash := EmptyStringSHA256

	result := BuildCanonicalString(
		method,
		uri,
		query,
		signedHeaders,
		canonicalHeaders,
		payloadHash,
	)

	expected := strings.Join([]string{
		method,
		uri,
		query,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	if result != expected {
		t.Errorf("expected:\n%s\ngot:\n%s", expected, result)
	}
}

func TestBuildStringToSign(t *testing.T) {
	algorithm := SigningAlgorithm
	timestamp := "20231201T120000Z"
	credentialScope := "20231201/us-east-1/s3/aws4_request"
	canonicalRequest := "GET\n/bucket/key\n\nhost:example.com\n\nhost\n" + EmptyStringSHA256

	result := BuildStringToSign(
		algorithm,
		timestamp,
		credentialScope,
		canonicalRequest,
	)

	// Should start with algorithm
	if !strings.HasPrefix(result, algorithm) {
		t.Error("string to sign should start with algorithm")
	}

	// Should contain timestamp
	if !strings.Contains(result, timestamp) {
		t.Error("string to sign should contain timestamp")
	}

	// Should contain credential scope
	if !strings.Contains(result, credentialScope) {
		t.Error("string to sign should contain credential scope")
	}
}

func TestBuildSignature(t *testing.T) {
	key := []byte("test-key-32-bytes-long-for-sha256!")
	stringToSign := "test string to sign"

	signature := BuildSignature(key, stringToSign)

	// Signature should be hex-encoded
	if len(signature) != 64 {
		t.Errorf("expected signature length 64, got %d", len(signature))
	}

	// Should be valid hex
	_, err := hex.DecodeString(signature)
	if err != nil {
		t.Errorf("signature should be valid hex: %v", err)
	}
}

func TestBuildAuthorizationHeader(t *testing.T) {
	credentialStr := "AKID/20231201/us-east-1/s3/aws4_request"
	signedHeadersStr := "host;x-amz-date"
	signature := "abc123"

	result := BuildAuthorizationHeader(credentialStr, signedHeadersStr, signature)

	if !strings.Contains(result, SigningAlgorithm) {
		t.Error("authorization header should contain algorithm")
	}

	if !strings.Contains(result, credentialStr) {
		t.Error("authorization header should contain credential")
	}

	if !strings.Contains(result, signedHeadersStr) {
		t.Error("authorization header should contain signed headers")
	}

	if !strings.Contains(result, signature) {
		t.Error("authorization header should contain signature")
	}
}

func TestSanitizeHostForHeader(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		host     string
		expected string
	}{
		{
			name:     "default HTTP port",
			url:      "http://example.com:80/path",
			host:     "example.com:80",
			expected: "example.com",
		},
		{
			name:     "default HTTPS port",
			url:      "https://example.com:443/path",
			host:     "example.com:443",
			expected: "example.com",
		},
		{
			name:     "non-default port",
			url:      "https://example.com:8080/path",
			host:     "example.com:8080",
			expected: "example.com:8080",
		},
		{
			name:     "no port",
			url:      "https://example.com/path",
			host:     "example.com",
			expected: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("failed to parse URL: %v", err)
			}

			req := &http.Request{
				URL:  u,
				Host: tt.host,
			}

			SanitizeHostForHeader(req)

			if req.Host != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, req.Host)
			}
		})
	}
}

