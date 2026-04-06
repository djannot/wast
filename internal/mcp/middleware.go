package mcp

import (
	"net/http"
	"strconv"

	"github.com/djannot/wast/pkg/ratelimit"
)

// rateLimitMiddleware returns an http.HandlerFunc that rejects requests exceeding
// the configured per-second rate limit with HTTP 429 Too Many Requests.
// It uses the provided ratelimit.Limiter's Allow() method for non-blocking checks.
func rateLimitMiddleware(next http.HandlerFunc, limiter ratelimit.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// concurrencyLimitMiddleware returns an http.HandlerFunc that limits the number
// of concurrently executing requests. When the semaphore is full, the request is
// rejected immediately with HTTP 429 Too Many Requests and a Retry-After header.
func concurrencyLimitMiddleware(next http.HandlerFunc, sem chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			// Acquired a slot; release it when the handler returns.
			defer func() { <-sem }()
			next(w, r)
		default:
			// Semaphore full — reject immediately.
			retryAfter := strconv.Itoa(cap(sem))
			if retryAfter == "0" {
				retryAfter = "1"
			}
			w.Header().Set("Retry-After", retryAfter)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		}
	}
}
