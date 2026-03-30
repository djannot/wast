// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"go.opentelemetry.io/otel/trace"
)

// BaseScanner holds the 6 fields shared by every scanner type. Scanner
// implementations embed this struct instead of redeclaring the fields.
// Fields are unexported to match the existing access pattern (s.client, s.userAgent, etc.)
// which continues to work transparently through Go's embedding promotion.
type BaseScanner struct {
	client      HTTPClient
	userAgent   string
	timeout     time.Duration
	authConfig  *auth.AuthConfig
	rateLimiter ratelimit.Limiter
	tracer      trace.Tracer
}

// BaseOption is a functional option that configures the shared BaseScanner fields.
type BaseOption func(*BaseScanner)

// WithBaseHTTPClient sets a custom HTTP client.
func WithBaseHTTPClient(c HTTPClient) BaseOption {
	return func(b *BaseScanner) {
		b.client = c
	}
}

// WithBaseUserAgent sets the user agent string.
func WithBaseUserAgent(ua string) BaseOption {
	return func(b *BaseScanner) {
		b.userAgent = ua
	}
}

// WithBaseTimeout sets the timeout for HTTP requests.
func WithBaseTimeout(d time.Duration) BaseOption {
	return func(b *BaseScanner) {
		b.timeout = d
	}
}

// WithBaseAuth sets the authentication configuration.
func WithBaseAuth(config *auth.AuthConfig) BaseOption {
	return func(b *BaseScanner) {
		b.authConfig = config
	}
}

// WithBaseRateLimiter sets a rate limiter.
func WithBaseRateLimiter(limiter ratelimit.Limiter) BaseOption {
	return func(b *BaseScanner) {
		b.rateLimiter = limiter
	}
}

// WithBaseRateLimitConfig sets rate limiting from a configuration.
func WithBaseRateLimitConfig(cfg ratelimit.Config) BaseOption {
	return func(b *BaseScanner) {
		b.rateLimiter = ratelimit.NewLimiterFromConfig(cfg)
	}
}

// WithBaseTracer sets the OpenTelemetry tracer.
func WithBaseTracer(tracer trace.Tracer) BaseOption {
	return func(b *BaseScanner) {
		b.tracer = tracer
	}
}

// DefaultBaseScanner returns a BaseScanner initialised with the standard defaults
// (user-agent string and 30-second timeout). Scanners that need different defaults
// (e.g. XXE uses 10 s) can override after calling this.
func DefaultBaseScanner() BaseScanner {
	return BaseScanner{
		userAgent: "WAST/1.0 (Web Application Security Testing)",
		timeout:   30 * time.Second,
	}
}

// ApplyBaseOptions applies a slice of BaseOption to a BaseScanner pointer.
func ApplyBaseOptions(b *BaseScanner, opts []BaseOption) {
	for _, opt := range opts {
		opt(b)
	}
}

// InitDefaultClient sets the HTTP client to a DefaultHTTPClient if none was
// provided via options.
func (b *BaseScanner) InitDefaultClient() {
	if b.client == nil {
		b.client = NewDefaultHTTPClient(b.timeout)
	}
}

// buildBaseOpts constructs the shared BaseOption slice from a CommonScannerConfig.
// This replaces the duplicated per-scanner option builder functions.
func buildBaseOpts(c CommonScannerConfig) []BaseOption {
	opts := []BaseOption{WithBaseTimeout(c.Timeout)}
	if c.AuthConfig != nil && !c.AuthConfig.IsEmpty() {
		opts = append(opts, WithBaseAuth(c.AuthConfig))
	}
	if c.HTTPClient != nil {
		opts = append(opts, WithBaseHTTPClient(c.HTTPClient))
	}
	if c.RateLimitConfig.IsEnabled() {
		opts = append(opts, WithBaseRateLimitConfig(c.RateLimitConfig))
	}
	if c.Tracer != nil {
		opts = append(opts, WithBaseTracer(c.Tracer))
	}
	return opts
}
