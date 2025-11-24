package signer

import "fmt"

// Config holds the configuration for SigV4 signing.
// All fields are required except Service, which defaults to "s3".
type Config struct {
	// Region is the AWS region (e.g., "auto" for Cloudflare R2).
	Region string

	// AccessKeyID is the AWS access key ID.
	AccessKeyID string

	// SecretAccessKey is the AWS secret access key.
	SecretAccessKey string

	// Service is the AWS service name (defaults to "s3").
	// For Cloudflare R2, this should be "s3".
	Service string
}

// Validate checks that all required fields are set.
func (c *Config) Validate() error {
	if c.Region == "" {
		return fmt.Errorf("region is required")
	}
	if c.AccessKeyID == "" {
		return fmt.Errorf("access key ID is required")
	}
	if c.SecretAccessKey == "" {
		return fmt.Errorf("secret access key is required")
	}
	if c.Service == "" {
		c.Service = "s3"
	}
	return nil
}
