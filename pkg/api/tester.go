// Package api provides OpenAPI/Swagger specification parsing and API endpoint testing.
package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
)

// HTTPClient defines the interface for HTTP operations, allowing for mock implementations in tests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DefaultHTTPClient wraps the standard http.Client.
type DefaultHTTPClient struct {
	client *http.Client
}

// NewDefaultHTTPClient creates a new DefaultHTTPClient with the given timeout.
func NewDefaultHTTPClient(timeout time.Duration) *DefaultHTTPClient {
	return &DefaultHTTPClient{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Allow up to 10 redirects
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// Do performs an HTTP request.
func (c *DefaultHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// EndpointTestResult represents the result of testing a single API endpoint.
type EndpointTestResult struct {
	Endpoint      EndpointInfo      `json:"endpoint" yaml:"endpoint"`
	StatusCode    int               `json:"status_code" yaml:"status_code"`
	ResponseTime  int64             `json:"response_time_ms" yaml:"response_time_ms"`
	Headers       map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Error         string            `json:"error,omitempty" yaml:"error,omitempty"`
	Tested        bool              `json:"tested" yaml:"tested"`
	RateLimitInfo *RateLimitInfo    `json:"rate_limit_info,omitempty" yaml:"rate_limit_info,omitempty"`
}

// TestResult represents the result of testing all endpoints.
type TestResult struct {
	BaseURL   string               `json:"base_url" yaml:"base_url"`
	Spec      *APISpec             `json:"spec,omitempty" yaml:"spec,omitempty"`
	Endpoints []EndpointTestResult `json:"endpoints" yaml:"endpoints"`
	Summary   TestSummary          `json:"summary" yaml:"summary"`
	DryRun    bool                 `json:"dry_run" yaml:"dry_run"`
	Errors    []string             `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// TestSummary provides an overview of the test results.
type TestSummary struct {
	TotalEndpoints   int `json:"total_endpoints" yaml:"total_endpoints"`
	TestedEndpoints  int `json:"tested_endpoints" yaml:"tested_endpoints"`
	SuccessCount     int `json:"success_count" yaml:"success_count"`
	ClientErrorCount int `json:"client_error_count" yaml:"client_error_count"`
	ServerErrorCount int `json:"server_error_count" yaml:"server_error_count"`
	ErrorCount       int `json:"error_count" yaml:"error_count"`
	RateLimitedCount int `json:"rate_limited_count" yaml:"rate_limited_count"`
}

// String returns a human-readable representation of the test result.
func (r *TestResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("API Endpoint Test Results\n"))
	sb.WriteString(strings.Repeat("=", 50) + "\n")
	sb.WriteString(fmt.Sprintf("Base URL: %s\n", r.BaseURL))

	if r.DryRun {
		sb.WriteString("Mode: DRY RUN (no requests made)\n")
	}

	sb.WriteString(fmt.Sprintf("\nEndpoints (%d):\n", len(r.Endpoints)))
	for _, ep := range r.Endpoints {
		if r.DryRun {
			sb.WriteString(fmt.Sprintf("  %s %s", ep.Endpoint.Method, ep.Endpoint.Path))
			if ep.Endpoint.Summary != "" {
				sb.WriteString(fmt.Sprintf(" - %s", ep.Endpoint.Summary))
			}
			sb.WriteString("\n")
		} else {
			status := "✓"
			if ep.Error != "" {
				status = "✗"
			} else if ep.StatusCode >= 400 {
				status = "!"
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s %s -> %d (%dms)\n",
				status, ep.Endpoint.Method, ep.Endpoint.Path, ep.StatusCode, ep.ResponseTime))
			if ep.Error != "" {
				sb.WriteString(fmt.Sprintf("      Error: %s\n", ep.Error))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\nSummary:\n"))
	sb.WriteString(fmt.Sprintf("  Total: %d\n", r.Summary.TotalEndpoints))
	if !r.DryRun {
		sb.WriteString(fmt.Sprintf("  Tested: %d\n", r.Summary.TestedEndpoints))
		sb.WriteString(fmt.Sprintf("  Success (2xx): %d\n", r.Summary.SuccessCount))
		sb.WriteString(fmt.Sprintf("  Client Errors (4xx): %d\n", r.Summary.ClientErrorCount))
		sb.WriteString(fmt.Sprintf("  Server Errors (5xx): %d\n", r.Summary.ServerErrorCount))
		sb.WriteString(fmt.Sprintf("  Request Errors: %d\n", r.Summary.ErrorCount))
		if r.Summary.RateLimitedCount > 0 {
			sb.WriteString(fmt.Sprintf("  Rate Limited (429): %d\n", r.Summary.RateLimitedCount))
		}
	}

	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, err := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	return sb.String()
}

// Tester performs API endpoint testing.
type Tester struct {
	client            HTTPClient
	userAgent         string
	timeout           time.Duration
	authConfig        *auth.AuthConfig
	baseURL           string
	dryRun            bool
	respectRateLimits bool
}

// TesterOption is a function that configures a Tester.
type TesterOption func(*Tester)

// WithHTTPClient sets a custom HTTP client for the tester.
func WithHTTPClient(c HTTPClient) TesterOption {
	return func(t *Tester) {
		t.client = c
	}
}

// WithUserAgent sets the user agent string for the tester.
func WithUserAgent(ua string) TesterOption {
	return func(t *Tester) {
		t.userAgent = ua
	}
}

// WithTimeout sets the timeout for HTTP requests.
func WithTimeout(d time.Duration) TesterOption {
	return func(t *Tester) {
		t.timeout = d
	}
}

// WithAuth sets the authentication configuration for the tester.
func WithAuth(config *auth.AuthConfig) TesterOption {
	return func(t *Tester) {
		t.authConfig = config
	}
}

// WithBaseURL sets a custom base URL that overrides the specification's server URL.
func WithBaseURL(url string) TesterOption {
	return func(t *Tester) {
		t.baseURL = url
	}
}

// WithDryRun enables dry run mode (list endpoints without making requests).
func WithDryRun(dryRun bool) TesterOption {
	return func(t *Tester) {
		t.dryRun = dryRun
	}
}

// WithRespectRateLimits enables respecting rate limits by pausing when HTTP 429 is received.
func WithRespectRateLimits(respect bool) TesterOption {
	return func(t *Tester) {
		t.respectRateLimits = respect
	}
}

// NewTester creates a new Tester with the given options.
func NewTester(opts ...TesterOption) *Tester {
	t := &Tester{
		userAgent: "WAST/1.0 (Web Application Security Testing)",
		timeout:   30 * time.Second,
	}

	for _, opt := range opts {
		opt(t)
	}

	// Create default HTTP client if not set
	if t.client == nil {
		t.client = NewDefaultHTTPClient(t.timeout)
	}

	return t
}

// TestAll tests all endpoints in the given API specification.
func (t *Tester) TestAll(ctx context.Context, spec *APISpec) *TestResult {
	result := &TestResult{
		BaseURL:   t.resolveBaseURL(spec),
		Spec:      spec,
		Endpoints: make([]EndpointTestResult, 0, len(spec.Endpoints)),
		DryRun:    t.dryRun,
		Errors:    make([]string, 0),
	}

	if result.BaseURL == "" {
		result.Errors = append(result.Errors, "No base URL available. Use --base-url flag or ensure the specification contains server information.")
		return result
	}

	for _, endpoint := range spec.Endpoints {
		// Check context cancellation
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, "Testing cancelled: "+ctx.Err().Error())
			t.updateSummary(result)
			return result
		default:
		}

		endpointResult := t.TestEndpoint(ctx, result.BaseURL, endpoint)
		result.Endpoints = append(result.Endpoints, endpointResult)

		// If rate limiting is detected and we're respecting rate limits, pause before next request
		if t.respectRateLimits && endpointResult.RateLimitInfo != nil && endpointResult.RateLimitInfo.RateLimitDetected {
			waitDuration := t.parseRetryAfter(endpointResult.RateLimitInfo.RetryAfter)
			// Cap the wait time to prevent excessive delays (max 5 minutes)
			if waitDuration > 5*time.Minute {
				waitDuration = 5 * time.Minute
			}
			select {
			case <-ctx.Done():
				result.Errors = append(result.Errors, "Testing cancelled while respecting rate limit: "+ctx.Err().Error())
				t.updateSummary(result)
				return result
			case <-time.After(waitDuration):
				// Continue after waiting
			}
		}
	}

	t.updateSummary(result)
	return result
}

// TestEndpoint tests a single API endpoint.
func (t *Tester) TestEndpoint(ctx context.Context, baseURL string, endpoint EndpointInfo) EndpointTestResult {
	result := EndpointTestResult{
		Endpoint: endpoint,
		Headers:  make(map[string]string),
		Tested:   !t.dryRun,
	}

	// In dry run mode, just return the endpoint info without testing
	if t.dryRun {
		return result
	}

	// Build the full URL
	fullURL := t.buildURL(baseURL, endpoint.Path)

	// Create request
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(endpoint.Method), fullURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create request: %s", err.Error())
		return result
	}

	// Set headers
	req.Header.Set("User-Agent", t.userAgent)
	req.Header.Set("Accept", "application/json, application/xml, text/plain, */*")

	// Apply authentication configuration
	if t.authConfig != nil {
		t.authConfig.ApplyToRequest(req)
	}

	// Make the request and measure response time
	start := time.Now()
	resp, err := t.client.Do(req)
	result.ResponseTime = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = fmt.Sprintf("Request failed: %s", err.Error())
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Extract security-relevant headers
	result.Headers = t.extractSecurityHeaders(resp.Header)

	// Detect rate limiting
	result.RateLimitInfo = t.detectRateLimit(resp.StatusCode, resp.Header)

	return result
}

// resolveBaseURL determines the base URL to use for requests.
func (t *Tester) resolveBaseURL(spec *APISpec) string {
	// Override takes precedence
	if t.baseURL != "" {
		return strings.TrimSuffix(t.baseURL, "/")
	}

	// Use first server from specification
	if len(spec.Servers) > 0 && spec.Servers[0].URL != "" {
		return strings.TrimSuffix(spec.Servers[0].URL, "/")
	}

	return ""
}

// buildURL constructs the full URL for an endpoint.
func (t *Tester) buildURL(baseURL, path string) string {
	// Remove trailing slash from base URL
	baseURL = strings.TrimSuffix(baseURL, "/")
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return baseURL + path
}

// extractSecurityHeaders extracts security-relevant headers from the response.
func (t *Tester) extractSecurityHeaders(headers http.Header) map[string]string {
	securityHeaders := []string{
		"Content-Type",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"Cache-Control",
		"WWW-Authenticate",
		"Server",
		// Rate limit headers
		"Retry-After",
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"X-RateLimit-Reset",
	}

	result := make(map[string]string)
	for _, name := range securityHeaders {
		if value := headers.Get(name); value != "" {
			result[name] = value
		}
	}
	return result
}

// extractRateLimitHeaders extracts rate-limit specific headers from the response.
func (t *Tester) extractRateLimitHeaders(headers http.Header) map[string]string {
	rateLimitHeaders := []string{
		"Retry-After",
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"X-RateLimit-Reset",
		"RateLimit-Limit",
		"RateLimit-Remaining",
		"RateLimit-Reset",
	}

	result := make(map[string]string)
	for _, name := range rateLimitHeaders {
		if value := headers.Get(name); value != "" {
			result[name] = value
		}
	}
	return result
}

// detectRateLimit checks if the response indicates rate limiting and extracts relevant info.
func (t *Tester) detectRateLimit(statusCode int, headers http.Header) *RateLimitInfo {
	rateLimitHeaders := t.extractRateLimitHeaders(headers)
	retryAfter := headers.Get("Retry-After")

	// Rate limiting detected if status is 429 or if rate limit headers are present
	isRateLimited := statusCode == http.StatusTooManyRequests

	// Only return RateLimitInfo if there's something to report
	if !isRateLimited && len(rateLimitHeaders) == 0 {
		return nil
	}

	return &RateLimitInfo{
		RateLimitDetected: isRateLimited,
		RetryAfter:        retryAfter,
		RateLimitHeaders:  rateLimitHeaders,
	}
}

// parseRetryAfter parses the Retry-After header value and returns the duration to wait.
// Retry-After can be either a number of seconds or an HTTP date.
func (t *Tester) parseRetryAfter(retryAfter string) time.Duration {
	if retryAfter == "" {
		// Default to 1 second if no Retry-After specified
		return time.Second
	}

	// Try to parse as seconds
	var seconds int
	if _, err := fmt.Sscanf(retryAfter, "%d", &seconds); err == nil {
		return time.Duration(seconds) * time.Second
	}

	// Try to parse as HTTP date (RFC 7231)
	formats := []string{
		time.RFC1123,
		time.RFC1123Z,
		time.RFC850,
		time.ANSIC,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, retryAfter); err == nil {
			wait := time.Until(t)
			if wait > 0 {
				return wait
			}
			return 0
		}
	}

	// Default to 1 second if parsing fails
	return time.Second
}

// updateSummary calculates the summary statistics for the test result.
func (t *Tester) updateSummary(result *TestResult) {
	result.Summary.TotalEndpoints = len(result.Endpoints)

	for _, ep := range result.Endpoints {
		if !ep.Tested {
			continue
		}
		result.Summary.TestedEndpoints++

		if ep.Error != "" {
			result.Summary.ErrorCount++
		} else if ep.StatusCode >= 200 && ep.StatusCode < 300 {
			result.Summary.SuccessCount++
		} else if ep.StatusCode >= 400 && ep.StatusCode < 500 {
			result.Summary.ClientErrorCount++
			// Count rate limited responses separately
			if ep.StatusCode == http.StatusTooManyRequests {
				result.Summary.RateLimitedCount++
			}
		} else if ep.StatusCode >= 500 {
			result.Summary.ServerErrorCount++
		}
	}
}
