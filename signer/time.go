package signer

import "time"

// SigningTime provides a wrapper around time.Time with cached format strings.
// This avoids repeated formatting operations during signing.
// Reference: AWS SDK v4 signer internal/v4/time.go
type SigningTime struct {
	time.Time
	timeFormat      string
	shortTimeFormat string
}

// NewSigningTime creates a new SigningTime from a time.Time.
// The time is converted to UTC.
func NewSigningTime(t time.Time) SigningTime {
	return SigningTime{
		Time: t.UTC(),
	}
}

// TimeFormat returns the time formatted for X-Amz-Date header/query.
// Format: YYYYMMDDTHHMMSSZ (e.g., 20231201T120000Z)
func (st *SigningTime) TimeFormat() string {
	if st.timeFormat == "" {
		st.timeFormat = st.Time.Format(TimeFormat)
	}
	return st.timeFormat
}

// ShortTimeFormat returns the time formatted for credential scope.
// Format: YYYYMMDD (e.g., 20231201)
func (st *SigningTime) ShortTimeFormat() string {
	if st.shortTimeFormat == "" {
		st.shortTimeFormat = st.Time.Format(ShortTimeFormat)
	}
	return st.shortTimeFormat
}

