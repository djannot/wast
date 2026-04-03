// Package ratelimit provides rate limiting functionality for HTTP-based operations.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter provides rate limiting functionality for HTTP requests.
type Limiter interface {
	// Wait blocks until the rate limit allows another request, or the context is cancelled.
	Wait(ctx context.Context) error

	// Allow reports whether an event may happen at this moment.
	Allow() bool
}

// TokenBucketLimiter implements a token bucket rate limiter.
type TokenBucketLimiter struct {
	rate       float64    // tokens per second
	burst      int        // maximum bucket size
	tokens     float64    // current number of tokens
	lastUpdate time.Time  // last time tokens were updated
	mu         sync.Mutex // protects tokens and lastUpdate
}

// NewLimiter creates a new rate limiter that allows requestsPerSecond requests per second.
// The burst size defaults to 1 if requestsPerSecond is <= 1, otherwise burst is set to
// allow some burstiness while maintaining the overall rate.
func NewLimiter(requestsPerSecond float64) Limiter {
	if requestsPerSecond <= 0 {
		return &NoopLimiter{}
	}

	burst := 1
	if requestsPerSecond > 1 {
		burst = int(requestsPerSecond)
	}

	return &TokenBucketLimiter{
		rate:       requestsPerSecond,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

// NewLimiterWithBurst creates a new rate limiter with a custom burst size.
func NewLimiterWithBurst(requestsPerSecond float64, burst int) Limiter {
	if requestsPerSecond <= 0 || burst <= 0 {
		return &NoopLimiter{}
	}

	return &TokenBucketLimiter{
		rate:       requestsPerSecond,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

// Wait blocks until the rate limit allows another request.
func (l *TokenBucketLimiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.lastUpdate).Seconds()
		l.tokens += elapsed * l.rate
		if l.tokens > float64(l.burst) {
			l.tokens = float64(l.burst)
		}
		l.lastUpdate = now

		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}

		// Calculate wait time
		waitTime := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
			// Try again
		}
	}
}

// Allow reports whether an event may happen at this moment.
func (l *TokenBucketLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastUpdate).Seconds()
	l.tokens += elapsed * l.rate
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}
	l.lastUpdate = now

	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// DelayLimiter implements a simple delay-based rate limiter.
// TODO: expose via a future --rate-limit-delay-ms CLI flag in mcpscan scan.
type DelayLimiter struct {
	delay     time.Duration
	lastTime  time.Time
	mu        sync.Mutex
	firstCall bool
}

// NewDelayLimiter creates a new delay-based rate limiter that waits delayMs milliseconds between requests.
func NewDelayLimiter(delayMs int) Limiter {
	if delayMs <= 0 {
		return &NoopLimiter{}
	}

	return &DelayLimiter{
		delay:     time.Duration(delayMs) * time.Millisecond,
		firstCall: true,
	}
}

// Wait blocks until the delay has passed since the last request.
// The mutex is released before any sleep so that context cancellation is
// observable by other goroutines that are concurrently calling Wait.
func (l *DelayLimiter) Wait(ctx context.Context) error {
	l.mu.Lock()

	// First call doesn't wait.
	if l.firstCall {
		l.firstCall = false
		l.lastTime = time.Now()
		l.mu.Unlock()
		return nil
	}

	// Calculate how long to wait, then release the lock before sleeping so
	// that other goroutines blocked on l.mu.Lock() can observe ctx.Done().
	elapsed := time.Since(l.lastTime)
	var waitTime time.Duration
	if elapsed < l.delay {
		waitTime = l.delay - elapsed
	}
	l.mu.Unlock()

	if waitTime > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
		}
	}

	l.mu.Lock()
	l.lastTime = time.Now()
	l.mu.Unlock()
	return nil
}

// Allow reports whether an event may happen at this moment.
func (l *DelayLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.firstCall {
		l.firstCall = false
		l.lastTime = time.Now()
		return true
	}

	elapsed := time.Since(l.lastTime)
	if elapsed >= l.delay {
		l.lastTime = time.Now()
		return true
	}
	return false
}

// NoopLimiter is a rate limiter that does nothing (allows all requests).
type NoopLimiter struct{}

// Wait returns immediately, but respects context cancellation so callers can
// use it as a reliable early-out point even when rate limiting is disabled.
func (l *NoopLimiter) Wait(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// Allow always returns true.
func (l *NoopLimiter) Allow() bool {
	return true
}

// Config holds rate limiting configuration.
// TODO: wire this into mcpscan scan via a --rate-limit-config flag or YAML
// config file when more complex rate-limiting scenarios (e.g. delay + RPS)
// are needed.
type Config struct {
	// RequestsPerSecond limits the number of requests per second.
	// Set to 0 to disable rate limiting.
	RequestsPerSecond float64

	// DelayMs specifies a fixed delay between requests in milliseconds.
	// This takes precedence over RequestsPerSecond if both are set.
	// Set to 0 to use RequestsPerSecond instead.
	DelayMs int
}

// NewLimiterFromConfig creates a new rate limiter from a Config.
// If DelayMs is set, a DelayLimiter is created.
// Otherwise, if RequestsPerSecond is set, a TokenBucketLimiter is created.
// If neither is set, a NoopLimiter is returned.
func NewLimiterFromConfig(cfg Config) Limiter {
	if cfg.DelayMs > 0 {
		return NewDelayLimiter(cfg.DelayMs)
	}
	if cfg.RequestsPerSecond > 0 {
		return NewLimiter(cfg.RequestsPerSecond)
	}
	return &NoopLimiter{}
}

// IsEnabled returns true if the config specifies any rate limiting.
func (c Config) IsEnabled() bool {
	return c.RequestsPerSecond > 0 || c.DelayMs > 0
}
