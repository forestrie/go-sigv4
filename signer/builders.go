package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// BuildCredentialScope builds the SigV4 credential scope.
// Format: date/region/service/aws4_request
// Reference: AWS SDK v4 signer internal/v4/scope.go
func BuildCredentialScope(t SigningTime, region, service string) string {
	return strings.Join([]string{
		t.ShortTimeFormat(),
		region,
		service,
		"aws4_request",
	}, "/")
}

// BuildCanonicalHeaders builds the canonical headers string.
// Returns: signed headers map, signed headers string, canonical headers
// Reference: AWS SDK v4 signer v4.go buildCanonicalHeaders
func BuildCanonicalHeaders(host string, rule Rule, header http.Header, length int64) (signed http.Header, signedHeaders, canonicalHeadersStr string) {
	signed = make(http.Header)

	var headers []string
	const hostHeader = "host"
	headers = append(headers, hostHeader)
	signed[hostHeader] = append(signed[hostHeader], host)

	const contentLengthHeader = "content-length"
	if length > 0 {
		headers = append(headers, contentLengthHeader)
		signed[contentLengthHeader] = append(
			signed[contentLengthHeader],
			strconv.FormatInt(length, 10),
		)
	}

	for k, v := range header {
		if !rule.IsValid(k) {
			continue
		}
		if strings.EqualFold(k, contentLengthHeader) {
			continue
		}

		lowerKey := strings.ToLower(k)
		if _, ok := signed[lowerKey]; ok {
			signed[lowerKey] = append(signed[lowerKey], v...)
			continue
		}

		headers = append(headers, lowerKey)
		signed[lowerKey] = v
	}
	sort.Strings(headers)

	signedHeaders = strings.Join(headers, ";")

	var canonicalHeaders strings.Builder
	n := len(headers)
	const colon = ':'
	for i := 0; i < n; i++ {
		if headers[i] == hostHeader {
			canonicalHeaders.WriteString(hostHeader)
			canonicalHeaders.WriteRune(colon)
			canonicalHeaders.WriteString(
				StripExcessSpaces(host),
			)
		} else {
			canonicalHeaders.WriteString(headers[i])
			canonicalHeaders.WriteRune(colon)
			values := signed[headers[i]]
			for j, val := range values {
				cleaned := strings.TrimSpace(
					StripExcessSpaces(val),
				)
				canonicalHeaders.WriteString(cleaned)
				if j < len(values)-1 {
					canonicalHeaders.WriteRune(',')
				}
			}
		}
		canonicalHeaders.WriteRune('\n')
	}
	canonicalHeadersStr = canonicalHeaders.String()

	return signed, signedHeaders, canonicalHeadersStr
}

// BuildCanonicalString builds the canonical request string.
// Format: METHOD\nURI\nQUERY\nHEADERS\nSIGNED_HEADERS\nPAYLOAD_HASH
// Reference: AWS SDK v4 signer v4.go buildCanonicalString
func BuildCanonicalString(method, uri, query, signedHeaders, canonicalHeaders, payloadHash string) string {
	return strings.Join([]string{
		method,
		uri,
		query,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
}

// BuildStringToSign builds the string to sign.
// Format: ALGORITHM\nTIMESTAMP\nSCOPE\nHASH(CANONICAL_REQUEST)
// Reference: AWS SDK v4 signer v4.go buildStringToSign
func BuildStringToSign(algorithm, timestamp, credentialScope, canonicalRequest string) string {
	hash := sha256.Sum256([]byte(canonicalRequest))
	hashStr := hex.EncodeToString(hash[:])
	return strings.Join([]string{
		algorithm,
		timestamp,
		credentialScope,
		hashStr,
	}, "\n")
}

// BuildSignature computes the signature using HMAC-SHA256.
// Reference: AWS SDK v4 signer v4.go buildSignature
func BuildSignature(key []byte, stringToSign string) string {
	h := HMACSHA256(key, []byte(stringToSign))
	return hex.EncodeToString(h)
}

// BuildAuthorizationHeader builds the Authorization header value.
// Format: ALGORITHM Credential=..., SignedHeaders=..., Signature=...
// Reference: AWS SDK v4 signer v4.go buildAuthorizationHeader
func BuildAuthorizationHeader(credentialStr, signedHeadersStr, signature string) string {
	const credential = "Credential="
	const signedHeaders = "SignedHeaders="
	const signatureKey = "Signature="
	const commaSpace = ", "

	var parts strings.Builder
	parts.Grow(
		len(SigningAlgorithm) + 1 +
			len(credential) + len(credentialStr) + 2 +
			len(signedHeaders) + len(signedHeadersStr) + 2 +
			len(signatureKey) + len(signature),
	)
	parts.WriteString(SigningAlgorithm)
	parts.WriteRune(' ')
	parts.WriteString(credential)
	parts.WriteString(credentialStr)
	parts.WriteString(commaSpace)
	parts.WriteString(signedHeaders)
	parts.WriteString(signedHeadersStr)
	parts.WriteString(commaSpace)
	parts.WriteString(signatureKey)
	parts.WriteString(signature)
	return parts.String()
}

// BuildQuery hoists allowed headers to query parameters.
// Note: This function intentionally converts certain header names to lowercase
// when storing them in unsignedHeaders. This behavior matches the AWS SDK v4
// signer implementation and is required to mitigate S3 limitations. The same
// potentially-lowercased key is used for both query parameters and unsigned
// headers to maintain consistency.
// Reference: AWS SDK v4 signer v4.go:394-417 (buildQuery function)
func BuildQuery(rule Rule, header http.Header) (url.Values, http.Header) {
	query := url.Values{}
	unsignedHeaders := http.Header{}

	// A list of headers to be converted to lower case to mitigate a
	// limitation from S3
	lowerCaseHeaders := map[string]string{
		"X-Amz-Expected-Bucket-Owner": "x-amz-expected-bucket-owner", // see #2508
		"X-Amz-Request-Payer":         "x-amz-request-payer",         // see #2764
	}

	for k, h := range header {
		if newKey, ok := lowerCaseHeaders[k]; ok {
			k = newKey
		}

		if rule.IsValid(k) {
			query[k] = h
		} else {
			unsignedHeaders[k] = h
		}
	}

	return query, unsignedHeaders
}

// CanonicalizeHeaderKey returns the canonical form of a header key.
func CanonicalizeHeaderKey(key string) string {
	return textproto.CanonicalMIMEHeaderKey(key)
}

