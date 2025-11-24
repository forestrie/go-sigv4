# go-sigv4

A minimal AWS Signature Version 4 (SigV4) signing package for Go, designed
for S3-compatible APIs like Cloudflare R2 without AWS SDK dependencies.

## Features

- **SignHTTP**: Signs HTTP requests using Authorization header
- **PresignHTTP**: Creates presigned URLs with query string authentication
- **Minimal dependencies**: Only Go standard library
- **Key caching**: Efficient key derivation with per-day caching
- **S3/R2 optimized**: No URI path escaping (as required for S3-compatible APIs)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
details.

This implementation is based on the AWS SDK for Go v2 signer implementation.
See [NOTICE](NOTICE) for attribution details.
