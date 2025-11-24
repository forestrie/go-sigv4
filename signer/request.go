package signer

import "net/http"

// SanitizeHostForHeader removes default port from host.
// Reference: AWS SDK v4 signer internal/v4/host.go SanitizeHostForHeader
func SanitizeHostForHeader(r *http.Request) {
	host := GetHost(r)
	port := PortOnly(host)
	if port != "" && IsDefaultPort(r.URL.Scheme, port) {
		r.Host = StripPort(host)
	}
}

// GetHost returns the host from the request.
func GetHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
}

