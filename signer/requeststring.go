package signer

import "strings"

// StripExcessSpaces removes multiple consecutive spaces from a string.
// Reference: AWS SDK v4 signer internal/v4/util.go StripExcessSpaces
func StripExcessSpaces(str string) string {
	const doubleSpace = "  "

	var j, k, l, m, spaces int

	// Trim trailing spaces
	for j = len(str) - 1; j >= 0 && str[j] == ' '; j-- {
	}

	// Trim leading spaces
	for k = 0; k < j && str[k] == ' '; k++ {
	}
	str = str[k : j+1]

	// Strip multiple spaces
	j = strings.Index(str, doubleSpace)
	if j < 0 {
		return str
	}

	buf := []byte(str)
	for k, m, l = j, j, len(buf); k < l; k++ {
		if buf[k] == ' ' {
			if spaces == 0 {
				buf[m] = buf[k]
				m++
			}
			spaces++
		} else {
			spaces = 0
			buf[m] = buf[k]
			m++
		}
	}

	return string(buf[:m])
}

// StripPort removes the port from a host:port string.
func StripPort(hostport string) string {
	colon := strings.IndexByte(hostport, ':')
	if colon == -1 {
		return hostport
	}
	if i := strings.IndexByte(hostport, ']'); i != -1 {
		return strings.TrimPrefix(hostport[:i], "[")
	}
	return hostport[:colon]
}

// PortOnly returns the port part of a host:port string.
func PortOnly(hostport string) string {
	colon := strings.IndexByte(hostport, ':')
	if colon == -1 {
		return ""
	}
	if i := strings.Index(hostport, "]:"); i != -1 {
		return hostport[i+len("]:"):]
	}
	if strings.Contains(hostport, "]") {
		return ""
	}
	return hostport[colon+len(":"):]
}

// IsDefaultPort checks if port is the default for the scheme.
func IsDefaultPort(scheme, port string) bool {
	if port == "" {
		return true
	}
	lowerScheme := strings.ToLower(scheme)
	return (lowerScheme == "http" && port == "80") ||
		(lowerScheme == "https" && port == "443")
}

