package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Signer applies AWS Signature Version 4 signing to HTTP requests.
// Thread safety is controlled by Config.ThreadSafety:
//   - When ThreadSafety is true, the Signer can be used concurrently from multiple goroutines.
//   - When ThreadSafety is false, the Signer must be used from a single goroutine at a time.
//
// Reference: AWS SDK v4 signer v4.go Signer struct
type Signer struct {
	config       Config
	keyDerivator keyDerivator
}

// NewSigner creates a new Signer with the given config.
// The ThreadSafety field in config determines whether a thread-safe
// or non-thread-safe cache implementation is used.
func NewSigner(config Config) (*Signer, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	var cache derivedKeyCacheInterface
	if config.ThreadSafety {
		cache = newDerivedKeyCacheThr()
	} else {
		cache = newDerivedKeyCacheNoThr()
	}

	return &Signer{
		config:       config,
		keyDerivator: NewSigningKeyDeriver(cache),
	}, nil
}

// httpSigner handles the signing process for a single request.
// Reference: AWS SDK v4 signer v4.go httpSigner struct
type httpSigner struct {
	Request               *http.Request
	ServiceName           string
	Region                string
	Time                  SigningTime
	AccessKeyID           string
	SecretAccessKey       string
	KeyDerivator          keyDerivator
	IsPreSign             bool
	PayloadHash           string
	DisableHeaderHoisting bool
}

// SignHTTP signs an HTTP request using AWS Signature Version 4.
// The request is modified in place with the Authorization header.
// The payloadHash must be provided (hex-encoded SHA256 of request body).
// For requests with no body, use EmptyStringSHA256.
// Reference: AWS SDK v4 signer v4.go SignHTTP method
func (s *Signer) SignHTTP(req *http.Request, payloadHash string, signingTime time.Time) error {
	if payloadHash == "" {
		return fmt.Errorf("payload hash is required")
	}

	signer := &httpSigner{
		Request:               req,
		PayloadHash:           payloadHash,
		ServiceName:           s.config.Service,
		Region:                s.config.Region,
		AccessKeyID:           s.config.AccessKeyID,
		SecretAccessKey:       s.config.SecretAccessKey,
		Time:                  NewSigningTime(signingTime),
		DisableHeaderHoisting: s.config.DisableHeaderHoisting,
		KeyDerivator:          s.keyDerivator,
	}

	return signer.build()
}

// PresignHTTP presigns an HTTP request using AWS Signature Version 4.
// Returns the signed URL, signed headers that must be included, and error.
// The request is cloned and not modified.
// Reference: AWS SDK v4 signer v4.go PresignHTTP method
func (s *Signer) PresignHTTP(req *http.Request, payloadHash string, signingTime time.Time) (string, http.Header, error) {
	if payloadHash == "" {
		return "", nil, fmt.Errorf("payload hash is required")
	}

	// Clone the request to avoid modifying the original
	clonedReq := req.Clone(req.Context())
	if clonedReq == nil {
		clonedReq = &http.Request{
			Method:     req.Method,
			URL:        &url.URL{},
			Header:     make(http.Header),
			Proto:      req.Proto,
			ProtoMajor: req.ProtoMajor,
			ProtoMinor: req.ProtoMinor,
		}
		*clonedReq.URL = *req.URL
		for k, v := range req.Header {
			clonedReq.Header[k] = v
		}
		clonedReq.Host = req.Host
		clonedReq.ContentLength = req.ContentLength
	}

	signer := &httpSigner{
		Request:               clonedReq,
		PayloadHash:           payloadHash,
		ServiceName:           s.config.Service,
		Region:                s.config.Region,
		AccessKeyID:           s.config.AccessKeyID,
		SecretAccessKey:       s.config.SecretAccessKey,
		Time:                  NewSigningTime(signingTime),
		IsPreSign:             true,
		DisableHeaderHoisting: s.config.DisableHeaderHoisting,
		KeyDerivator:          s.keyDerivator,
	}

	signedHeaders, err := signer.buildPresign()
	if err != nil {
		return "", nil, err
	}

	// Canonicalize header keys for return
	resultHeaders := make(http.Header)
	for k, v := range signedHeaders {
		key := CanonicalizeHeaderKey(k)
		resultHeaders[key] = append(resultHeaders[key], v...)
	}

	return clonedReq.URL.String(), resultHeaders, nil
}

// build performs the signing process for SignHTTP.
func (s *httpSigner) build() error {
	req := s.Request
	query := req.URL.Query()
	headers := req.Header

	s.setRequiredSigningFields(headers, query)

	// Sort query values
	for key := range query {
		sort.Strings(query[key])
	}

	SanitizeHostForHeader(req)

	credentialScope := BuildCredentialScope(s.Time, s.Region, s.ServiceName)
	credentialStr := s.AccessKeyID + "/" + credentialScope

	host := req.URL.Host
	if len(req.Host) > 0 {
		host = req.Host
	}

	_, signedHeadersStr, canonicalHeaderStr := BuildCanonicalHeaders(
		host,
		IgnoredHeaders,
		headers,
		req.ContentLength,
	)

	var rawQuery strings.Builder
	rawQuery.WriteString(
		strings.Replace(query.Encode(), "+", "%20", -1),
	)

	canonicalURI := GetURIPath(req.URL)
	// Note: URI path escaping is disabled for S3/R2 compatibility

	canonicalString := BuildCanonicalString(
		req.Method,
		canonicalURI,
		rawQuery.String(),
		signedHeadersStr,
		canonicalHeaderStr,
		s.PayloadHash,
	)

	strToSign := BuildStringToSign(
		SigningAlgorithm,
		s.Time.TimeFormat(),
		credentialScope,
		canonicalString,
	)

	key := s.KeyDerivator.DeriveKey(
		s.AccessKeyID,
		s.SecretAccessKey,
		s.ServiceName,
		s.Region,
		s.Time,
	)

	signature := BuildSignature(key, strToSign)

	authHeader := BuildAuthorizationHeader(
		credentialStr,
		signedHeadersStr,
		signature,
	)

	headers[AuthorizationHeader] = []string{authHeader}
	req.URL.RawQuery = rawQuery.String()

	return nil
}

// buildPresign performs the signing process for PresignHTTP.
func (s *httpSigner) buildPresign() (http.Header, error) {
	req := s.Request
	query := req.URL.Query()
	headers := req.Header

	s.setRequiredSigningFields(headers, query)

	// Sort query values
	for key := range query {
		sort.Strings(query[key])
	}

	SanitizeHostForHeader(req)

	credentialScope := BuildCredentialScope(s.Time, s.Region, s.ServiceName)
	credentialStr := s.AccessKeyID + "/" + credentialScope
	query.Set(AmzCredentialKey, credentialStr)

	unsignedHeaders := headers
	if !s.DisableHeaderHoisting {
		urlValues, uHeaders := BuildQuery(
			AllowedQueryHoisting,
			headers,
		)
		for k := range urlValues {
			query[k] = urlValues[k]
		}
		unsignedHeaders = uHeaders
	}

	host := req.URL.Host
	if len(req.Host) > 0 {
		host = req.Host
	}

	signedHeaders, signedHeadersStr, canonicalHeaderStr := BuildCanonicalHeaders(
		host,
		IgnoredHeaders,
		unsignedHeaders,
		req.ContentLength,
	)

	query.Set(AmzSignedHeadersKey, signedHeadersStr)

	var rawQuery strings.Builder
	rawQuery.WriteString(
		strings.Replace(query.Encode(), "+", "%20", -1),
	)

	canonicalURI := GetURIPath(req.URL)
	// Note: URI path escaping is disabled for S3/R2 compatibility

	canonicalString := BuildCanonicalString(
		req.Method,
		canonicalURI,
		rawQuery.String(),
		signedHeadersStr,
		canonicalHeaderStr,
		s.PayloadHash,
	)

	strToSign := BuildStringToSign(
		SigningAlgorithm,
		s.Time.TimeFormat(),
		credentialScope,
		canonicalString,
	)

	key := s.KeyDerivator.DeriveKey(
		s.AccessKeyID,
		s.SecretAccessKey,
		s.ServiceName,
		s.Region,
		s.Time,
	)

	signature := BuildSignature(key, strToSign)

	rawQuery.WriteString("&")
	rawQuery.WriteString(AmzSignatureKey)
	rawQuery.WriteString("=")
	rawQuery.WriteString(signature)

	req.URL.RawQuery = rawQuery.String()

	return signedHeaders, nil
}

// setRequiredSigningFields sets required signing fields in headers/query.
func (s *httpSigner) setRequiredSigningFields(headers http.Header, query url.Values) {
	amzDate := s.Time.TimeFormat()

	if s.IsPreSign {
		query.Set(AmzAlgorithmKey, SigningAlgorithm)
		query.Set(AmzDateKey, amzDate)
		return
	}

	headers[AmzDateKey] = []string{amzDate}
}

// ComputePayloadHash computes the SHA256 hash of the request body.
// Returns hex-encoded hash string.
func ComputePayloadHash(body io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, body); err != nil {
		return "", fmt.Errorf("failed to compute payload hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
