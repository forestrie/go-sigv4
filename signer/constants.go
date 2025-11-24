package signer

// Signature Version 4 (SigV4) constants.
// Reference: AWS SDK v4 signer internal/v4/const.go

const (
	// EmptyStringSHA256 is the hex encoded SHA256 hash of an empty string.
	// Used for x-amz-content-sha256 header on requests with no body.
	EmptyStringSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// SigningAlgorithm is the SigV4 signing algorithm identifier.
	SigningAlgorithm = "AWS4-HMAC-SHA256"

	// AuthorizationHeader is the HTTP header name for authorization.
	AuthorizationHeader = "Authorization"

	// AmzAlgorithmKey is the query parameter key for signing algorithm.
	AmzAlgorithmKey = "X-Amz-Algorithm"

	// AmzDateKey is the header/query key for the request timestamp.
	// Format: YYYYMMDDTHHMMSSZ (e.g., 20231201T120000Z)
	AmzDateKey = "X-Amz-Date"

	// AmzCredentialKey is the query parameter key for credentials.
	AmzCredentialKey = "X-Amz-Credential"

	// AmzSignedHeadersKey is the query parameter key for signed headers.
	AmzSignedHeadersKey = "X-Amz-SignedHeaders"

	// AmzSignatureKey is the query parameter key for the signature.
	AmzSignatureKey = "X-Amz-Signature"

	// ContentSHAKey is the header key for request body SHA256 hash.
	ContentSHAKey = "X-Amz-Content-Sha256"

	// TimeFormat is the time format for X-Amz-Date header/query.
	// Format: YYYYMMDDTHHMMSSZ
	TimeFormat = "20060102T150405Z"

	// ShortTimeFormat is the shortened time format for credential scope.
	// Format: YYYYMMDD
	ShortTimeFormat = "20060102"
)

