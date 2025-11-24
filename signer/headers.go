package signer

import "strings"

// Rule defines an interface for header validation rules.
// Reference: AWS SDK v4 signer internal/v4/header_rules.go
type Rule interface {
	IsValid(value string) bool
}

// Rules is a slice of Rule that implements Rule interface.
type Rules []Rule

// IsValid returns true if any rule in the slice validates the value.
func (r Rules) IsValid(value string) bool {
	for _, rule := range r {
		if rule.IsValid(value) {
			return true
		}
	}
	return false
}

// MapRule is a map-based rule.
type MapRule map[string]struct{}

// IsValid returns true if the value exists in the map.
func (m MapRule) IsValid(value string) bool {
	_, ok := m[value]
	return ok
}

// ExcludeList is a rule that excludes values matching the inner rule.
type ExcludeList struct {
	Rule
}

// IsValid returns true if the value does NOT match the inner rule.
func (e ExcludeList) IsValid(value string) bool {
	return !e.Rule.IsValid(value)
}

// Patterns is a rule that matches values with any of the given prefixes.
type Patterns []string

// IsValid returns true if value has any of the pattern prefixes.
func (p Patterns) IsValid(value string) bool {
	for _, pattern := range p {
		if strings.HasPrefix(strings.ToLower(value), strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// InclusiveRules requires all rules to be valid.
type InclusiveRules []Rule

// IsValid returns true if all rules validate the value.
func (r InclusiveRules) IsValid(value string) bool {
	for _, rule := range r {
		if !rule.IsValid(value) {
			return false
		}
	}
	return true
}

// IgnoredHeaders lists headers that are ignored during signing.
// Reference: AWS SDK v4 signer internal/v4/headers.go IgnoredHeaders
var IgnoredHeaders = Rules{
	ExcludeList{
		MapRule{
			"Authorization":     struct{}{},
			"User-Agent":         struct{}{},
			"X-Amzn-Trace-Id":    struct{}{},
			"Expect":             struct{}{},
			"Transfer-Encoding":  struct{}{},
		},
	},
}

// AllowedQueryHoisting lists headers that can be hoisted to query params.
// Reference: AWS SDK v4 signer internal/v4/headers.go AllowedQueryHoisting
var AllowedQueryHoisting = InclusiveRules{
	ExcludeList{RequiredSignedHeaders},
	Patterns{"X-Amz-"},
}

// RequiredSignedHeaders lists headers that must be signed.
// Reference: AWS SDK v4 signer internal/v4/headers.go RequiredSignedHeaders
var RequiredSignedHeaders = Rules{
	MapRule{
		"Cache-Control":                         struct{}{},
		"Content-Disposition":                   struct{}{},
		"Content-Encoding":                      struct{}{},
		"Content-Language":                      struct{}{},
		"Content-Md5":                           struct{}{},
		"Content-Type":                          struct{}{},
		"Expires":                               struct{}{},
		"If-Match":                              struct{}{},
		"If-Modified-Since":                     struct{}{},
		"If-None-Match":                          struct{}{},
		"If-Unmodified-Since":                   struct{}{},
		"Range":                                 struct{}{},
		"X-Amz-Acl":                             struct{}{},
		"X-Amz-Copy-Source":                     struct{}{},
		"X-Amz-Copy-Source-If-Match":            struct{}{},
		"X-Amz-Copy-Source-If-Modified-Since":   struct{}{},
		"X-Amz-Copy-Source-If-None-Match":       struct{}{},
		"X-Amz-Copy-Source-If-Unmodified-Since": struct{}{},
		"X-Amz-Copy-Source-Range":               struct{}{},
		"X-Amz-Copy-Source-Server-Side-Encryption-Customer-Algorithm": struct{}{},
		"X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key":     struct{}{},
		"X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key-Md5":  struct{}{},
		"X-Amz-Grant-Full-control":                                   struct{}{},
		"X-Amz-Grant-Read":                                           struct{}{},
		"X-Amz-Grant-Read-Acp":                                       struct{}{},
		"X-Amz-Grant-Write":                                          struct{}{},
		"X-Amz-Grant-Write-Acp":                                      struct{}{},
		"X-Amz-Metadata-Directive":                                   struct{}{},
		"X-Amz-Mfa":                                                  struct{}{},
		"X-Amz-Server-Side-Encryption":                               struct{}{},
		"X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id":                struct{}{},
		"X-Amz-Server-Side-Encryption-Context":                       struct{}{},
		"X-Amz-Server-Side-Encryption-Customer-Algorithm":            struct{}{},
		"X-Amz-Server-Side-Encryption-Customer-Key":                  struct{}{},
		"X-Amz-Server-Side-Encryption-Customer-Key-Md5":              struct{}{},
		"X-Amz-Storage-Class":                                        struct{}{},
		"X-Amz-Website-Redirect-Location":                             struct{}{},
		"X-Amz-Content-Sha256":                                       struct{}{},
		"X-Amz-Tagging":                                              struct{}{},
	},
	Patterns{"X-Amz-Object-Lock-"},
	Patterns{"X-Amz-Meta-"},
}

