package signer

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

var testConfig = Config{
	Region:          "us-east-1",
	AccessKeyID:     "AKID",
	SecretAccessKey: "SECRET",
	Service:         "s3",
}

func buildTestRequest(method, urlStr, body string) (*http.Request, string) {
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}

	req, _ := http.NewRequest(method, urlStr, bodyReader)
	if body != "" {
		req.ContentLength = int64(len(body))
	}

	hash, err := ComputePayloadHash(bodyReader)
	if err != nil {
		panic(err)
	}
	bodyReader.Seek(0, 0)

	return req, hash
}

func TestNewSigner(t *testing.T) {
	config := Config{
		Region:          "us-east-1",
		AccessKeyID:     "AKID",
		SecretAccessKey: "SECRET",
	}

	signer, err := NewSigner(config)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if signer == nil {
		t.Fatal("signer should not be nil")
	}

	if signer.config.Region != config.Region {
		t.Errorf("expected region %s, got %s", config.Region, signer.config.Region)
	}
}

func TestNewSignerValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Region:          "us-east-1",
				AccessKeyID:     "AKID",
				SecretAccessKey: "SECRET",
			},
			wantErr: false,
		},
		{
			name: "missing region",
			config: Config{
				AccessKeyID:     "AKID",
				SecretAccessKey: "SECRET",
			},
			wantErr: true,
		},
		{
			name: "missing access key",
			config: Config{
				Region:          "us-east-1",
				SecretAccessKey: "SECRET",
			},
			wantErr: true,
		},
		{
			name: "missing secret key",
			config: Config{
				Region:      "us-east-1",
				AccessKeyID: "AKID",
			},
			wantErr: true,
		},
		{
			name: "default service",
			config: Config{
				Region:          "us-east-1",
				AccessKeyID:     "AKID",
				SecretAccessKey: "SECRET",
				Service:         "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if signer != nil {
					t.Error("signer should be nil on error")
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if signer == nil {
					t.Error("signer should not be nil")
				}
				if tt.config.Service == "" && signer.config.Service != "s3" {
					t.Errorf("expected default service 's3', got %s", signer.config.Service)
				}
			}
		})
	}
}

func TestSignHTTP(t *testing.T) {
	signer, err := NewSigner(testConfig)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	req, payloadHash := buildTestRequest(
		"GET",
		"https://example.com/bucket/key",
		"",
	)

	err = signer.SignHTTP(req, payloadHash, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	authHeader := req.Header.Get(AuthorizationHeader)
	if authHeader == "" {
		t.Error("Authorization header should be set")
	}

	if !strings.HasPrefix(authHeader, SigningAlgorithm) {
		t.Errorf("authorization header should start with %s", SigningAlgorithm)
	}

	amzDate := req.Header.Get(AmzDateKey)
	if amzDate == "" {
		t.Error("X-Amz-Date header should be set")
	}

	expectedDate := "19700101T000000Z"
	if amzDate != expectedDate {
		t.Errorf("expected date %s, got %s", expectedDate, amzDate)
	}
}

func TestSignHTTPWithBody(t *testing.T) {
	signer, err := NewSigner(testConfig)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	body := `{"test": "data"}`
	req, payloadHash := buildTestRequest(
		"PUT",
		"https://example.com/bucket/key",
		body,
	)

	err = signer.SignHTTP(req, payloadHash, time.Now())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	authHeader := req.Header.Get(AuthorizationHeader)
	if authHeader == "" {
		t.Error("Authorization header should be set")
	}
}

func TestSignHTTPMissingPayloadHash(t *testing.T) {
	signer, err := NewSigner(testConfig)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	req, _ := buildTestRequest(
		"GET",
		"https://example.com/bucket/key",
		"",
	)

	err = signer.SignHTTP(req, "", time.Now())
	if err == nil {
		t.Error("expected error for missing payload hash")
	}
}

func TestPresignHTTP(t *testing.T) {
	signer, err := NewSigner(testConfig)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	req, payloadHash := buildTestRequest(
		"GET",
		"https://example.com/bucket/key",
		"",
	)

	query := req.URL.Query()
	query.Set("X-Amz-Expires", "300")
	req.URL.RawQuery = query.Encode()

	signedURL, signedHeaders, err := signer.PresignHTTP(
		req,
		payloadHash,
		time.Unix(0, 0),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if signedURL == "" {
		t.Error("signed URL should not be empty")
	}

	parsedURL, err := url.Parse(signedURL)
	if err != nil {
		t.Fatalf("failed to parse signed URL: %v", err)
	}

	query = parsedURL.Query()

	// Check required query parameters
	if query.Get(AmzAlgorithmKey) != SigningAlgorithm {
		t.Errorf("expected algorithm %s, got %s", SigningAlgorithm, query.Get(AmzAlgorithmKey))
	}

	if query.Get(AmzDateKey) == "" {
		t.Error("X-Amz-Date should be set")
	}

	expectedDate := "19700101T000000Z"
	if query.Get(AmzDateKey) != expectedDate {
		t.Errorf("expected date %s, got %s", expectedDate, query.Get(AmzDateKey))
	}

	if query.Get(AmzCredentialKey) == "" {
		t.Error("X-Amz-Credential should be set")
	}

	if query.Get(AmzSignedHeadersKey) == "" {
		t.Error("X-Amz-SignedHeaders should be set")
	}

	if query.Get(AmzSignatureKey) == "" {
		t.Error("X-Amz-Signature should be set")
	}

	// Check signed headers
	if signedHeaders == nil {
		t.Error("signed headers should not be nil")
	}

	if signedHeaders.Get("Host") == "" {
		t.Error("Host should be in signed headers")
	}
}

func TestPresignHTTPWithExpires(t *testing.T) {
	signer, err := NewSigner(testConfig)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	req, payloadHash := buildTestRequest(
		"GET",
		"https://example.com/bucket/key",
		"",
	)

	query := req.URL.Query()
	query.Set("X-Amz-Expires", "600")
	req.URL.RawQuery = query.Encode()

	signedURL, _, err := signer.PresignHTTP(req, payloadHash, time.Now())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	parsedURL, err := url.Parse(signedURL)
	if err != nil {
		t.Fatalf("failed to parse signed URL: %v", err)
	}

	query = parsedURL.Query()
	if query.Get("X-Amz-Expires") != "600" {
		t.Errorf("expected expires 600, got %s", query.Get("X-Amz-Expires"))
	}
}

func TestPresignHTTPMissingPayloadHash(t *testing.T) {
	signer, err := NewSigner(testConfig)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	req, _ := buildTestRequest(
		"GET",
		"https://example.com/bucket/key",
		"",
	)

	_, _, err = signer.PresignHTTP(req, "", time.Now())
	if err == nil {
		t.Error("expected error for missing payload hash")
	}
}

func TestPresignHTTPDoesNotModifyOriginal(t *testing.T) {
	signer, err := NewSigner(testConfig)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	req, payloadHash := buildTestRequest(
		"GET",
		"https://example.com/bucket/key",
		"",
	)

	originalURL := req.URL.String()
	originalHeaders := make(http.Header)
	for k, v := range req.Header {
		originalHeaders[k] = v
	}

	_, _, err = signer.PresignHTTP(req, payloadHash, time.Now())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Original request should not be modified
	if req.URL.String() != originalURL {
		t.Error("original request URL should not be modified")
	}

	for k, v := range originalHeaders {
		if len(req.Header[k]) != len(v) {
			t.Errorf("original header %s should not be modified", k)
		}
	}
}

func TestComputePayloadHash(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "empty body",
			body:     "",
			expected: EmptyStringSHA256,
		},
		{
			name:     "non-empty body",
			body:     "test data",
			expected: "", // Will compute
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := ComputePayloadHash(strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if tt.expected != "" {
				if hash != tt.expected {
					t.Errorf("expected %s, got %s", tt.expected, hash)
				}
			} else {
				if len(hash) != 64 {
					t.Errorf("expected hash length 64, got %d", len(hash))
				}
			}
		})
	}
}

func TestSignHTTPDifferentTimes(t *testing.T) {
	signer, err := NewSigner(testConfig)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	req1, payloadHash := buildTestRequest(
		"GET",
		"https://example.com/bucket/key",
		"",
	)

	req2, _ := buildTestRequest(
		"GET",
		"https://example.com/bucket/key",
		"",
	)

	t1 := time.Unix(1000, 0)
	t2 := time.Unix(2000, 0)

	err = signer.SignHTTP(req1, payloadHash, t1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = signer.SignHTTP(req2, payloadHash, t2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	date1 := req1.Header.Get(AmzDateKey)
	date2 := req2.Header.Get(AmzDateKey)

	if date1 == date2 {
		t.Error("different times should produce different dates")
	}

	auth1 := req1.Header.Get(AuthorizationHeader)
	auth2 := req2.Header.Get(AuthorizationHeader)

	if auth1 == auth2 {
		t.Error("different times should produce different signatures")
	}
}

