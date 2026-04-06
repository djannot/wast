// Package httputil provides shared HTTP utilities for the WAST scanner.
package httputil

import (
	"io"
)

// MaxResponseBodySize is the maximum number of bytes read from an HTTP response
// body. Any response larger than this limit is silently truncated to prevent
// memory exhaustion when scanning potentially malicious targets.
const MaxResponseBodySize = 10 * 1024 * 1024 // 10 MiB

// ReadResponseBody reads at most MaxResponseBodySize bytes from r and returns
// the result. It is a safe replacement for io.ReadAll(resp.Body) throughout the
// scanner and its supporting packages.
func ReadResponseBody(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, MaxResponseBodySize))
}
