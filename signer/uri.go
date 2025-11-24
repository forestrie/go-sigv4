package signer

import (
	"net/url"
	"strings"
)

// GetURIPath returns the URI path from the URL.
// Note: This implementation does NOT perform URI path escaping, as this
// signer is designed for minimal S3/R2 support where escaping is not
// required. For S3-compatible APIs, the path should be used as-is.
// Reference: AWS SDK v4 signer internal/v4/util.go GetURIPath
func GetURIPath(u *url.URL) string {
	var uriPath string

	if len(u.Opaque) > 0 {
		const schemeSep, pathSep, queryStart = "//", "/", "?"
		opaque := u.Opaque

		// Cut off query string if present
		if idx := strings.Index(opaque, queryStart); idx >= 0 {
			opaque = opaque[:idx]
		}

		// Cut out scheme separator if present
		if strings.Index(opaque, schemeSep) == 0 {
			opaque = opaque[len(schemeSep):]
		}

		// Capture URI path starting with first path separator
		if idx := strings.Index(opaque, pathSep); idx >= 0 {
			uriPath = opaque[idx:]
		}
	} else {
		uriPath = u.EscapedPath()
	}

	if len(uriPath) == 0 {
		uriPath = "/"
	}

	return uriPath
}

