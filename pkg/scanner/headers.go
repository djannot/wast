// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/telemetry"
	"go.opentelemetry.io/otel/trace"
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

// Severity levels for security findings.
const (
	SeverityInfo   = "info"
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

// HeaderScanResult represents the result of a security headers scan.
type HeaderScanResult struct {
	Target  string          `json:"target" yaml:"target"`
	Headers []HeaderFinding `json:"headers" yaml:"headers"`
	Cookies []CookieFinding `json:"cookies" yaml:"cookies"`
	CORS    []CORSFinding   `json:"cors" yaml:"cors"`
	Summary ScanSummary     `json:"summary" yaml:"summary"`
	Errors  []string        `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// HeaderFinding represents a finding related to an HTTP security header.
type HeaderFinding struct {
	Name        string `json:"name" yaml:"name"`
	Present     bool   `json:"present" yaml:"present"`
	Value       string `json:"value,omitempty" yaml:"value,omitempty"`
	Severity    string `json:"severity" yaml:"severity"`
	Description string `json:"description" yaml:"description"`
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

// CookieFinding represents a finding related to a cookie's security attributes.
type CookieFinding struct {
	Name        string   `json:"name" yaml:"name"`
	HttpOnly    bool     `json:"http_only" yaml:"http_only"`
	Secure      bool     `json:"secure" yaml:"secure"`
	SameSite    string   `json:"same_site" yaml:"same_site"`
	Issues      []string `json:"issues,omitempty" yaml:"issues,omitempty"`
	Severity    string   `json:"severity" yaml:"severity"`
	Remediation string   `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

// CORSFinding represents a finding related to CORS policy configuration.
type CORSFinding struct {
	Header           string   `json:"header" yaml:"header"`
	Value            string   `json:"value,omitempty" yaml:"value,omitempty"`
	Present          bool     `json:"present" yaml:"present"`
	Issues           []string `json:"issues,omitempty" yaml:"issues,omitempty"`
	Severity         string   `json:"severity" yaml:"severity"`
	Description      string   `json:"description" yaml:"description"`
	Remediation      string   `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	OriginReflection bool     `json:"origin_reflection,omitempty" yaml:"origin_reflection,omitempty"`
}

// ScanSummary provides an overview of the scan results.
type ScanSummary struct {
	TotalHeaders        int `json:"total_headers" yaml:"total_headers"`
	MissingHeaders      int `json:"missing_headers" yaml:"missing_headers"`
	TotalCookies        int `json:"total_cookies" yaml:"total_cookies"`
	InsecureCookies     int `json:"insecure_cookies" yaml:"insecure_cookies"`
	CORSIssues          int `json:"cors_issues" yaml:"cors_issues"`
	HighSeverityCount   int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount    int `json:"low_severity_count" yaml:"low_severity_count"`
	InfoCount           int `json:"info_count" yaml:"info_count"`
}

// String returns a human-readable representation of the scan result.
func (r *HeaderScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("HTTP Security Headers Scan for: %s\n", r.Target))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	// Summary
	sb.WriteString("\nSummary:\n")
	sb.WriteString(fmt.Sprintf("  Headers Checked: %d\n", r.Summary.TotalHeaders))
	sb.WriteString(fmt.Sprintf("  Missing Headers: %d\n", r.Summary.MissingHeaders))
	sb.WriteString(fmt.Sprintf("  Cookies Found: %d\n", r.Summary.TotalCookies))
	sb.WriteString(fmt.Sprintf("  Insecure Cookies: %d\n", r.Summary.InsecureCookies))
	sb.WriteString(fmt.Sprintf("  CORS Issues: %d\n", r.Summary.CORSIssues))
	sb.WriteString(fmt.Sprintf("  High Severity: %d\n", r.Summary.HighSeverityCount))
	sb.WriteString(fmt.Sprintf("  Medium Severity: %d\n", r.Summary.MediumSeverityCount))
	sb.WriteString(fmt.Sprintf("  Low Severity: %d\n", r.Summary.LowSeverityCount))
	sb.WriteString(fmt.Sprintf("  Info: %d\n", r.Summary.InfoCount))

	// Header findings
	if len(r.Headers) > 0 {
		sb.WriteString("\nSecurity Headers:\n")
		for _, h := range r.Headers {
			status := "PRESENT"
			if !h.Present {
				status = "MISSING"
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s - %s\n", strings.ToUpper(h.Severity), h.Name, status))
			if h.Value != "" {
				sb.WriteString(fmt.Sprintf("    Value: %s\n", h.Value))
			}
			sb.WriteString(fmt.Sprintf("    %s\n", h.Description))
			if h.Remediation != "" && !h.Present {
				sb.WriteString(fmt.Sprintf("    Remediation: %s\n", h.Remediation))
			}
		}
	}

	// Cookie findings
	if len(r.Cookies) > 0 {
		sb.WriteString("\nCookie Security:\n")
		for _, c := range r.Cookies {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", strings.ToUpper(c.Severity), c.Name))
			sb.WriteString(fmt.Sprintf("    HttpOnly: %t, Secure: %t, SameSite: %s\n",
				c.HttpOnly, c.Secure, c.SameSite))
			if len(c.Issues) > 0 {
				sb.WriteString("    Issues:\n")
				for _, issue := range c.Issues {
					sb.WriteString(fmt.Sprintf("      - %s\n", issue))
				}
			}
			if c.Remediation != "" {
				sb.WriteString(fmt.Sprintf("    Remediation: %s\n", c.Remediation))
			}
		}
	}

	// CORS findings
	if len(r.CORS) > 0 {
		sb.WriteString("\nCORS Policy:\n")
		for _, c := range r.CORS {
			status := "PRESENT"
			if !c.Present {
				status = "NOT SET"
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s - %s\n", strings.ToUpper(c.Severity), c.Header, status))
			if c.Value != "" {
				sb.WriteString(fmt.Sprintf("    Value: %s\n", c.Value))
			}
			sb.WriteString(fmt.Sprintf("    %s\n", c.Description))
			if len(c.Issues) > 0 {
				sb.WriteString("    Issues:\n")
				for _, issue := range c.Issues {
					sb.WriteString(fmt.Sprintf("      - %s\n", issue))
				}
			}
			if c.Remediation != "" {
				sb.WriteString(fmt.Sprintf("    Remediation: %s\n", c.Remediation))
			}
		}
	}

	// Errors
	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, e := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}

	return sb.String()
}

// HasResults returns true if the scan produced any meaningful results.
func (r *HeaderScanResult) HasResults() bool {
	return len(r.Headers) > 0 || len(r.Cookies) > 0 || len(r.CORS) > 0
}

// securityHeader defines the metadata for a security header check.
type securityHeader struct {
	Name        string
	Severity    string // Severity if missing
	Description string
	Remediation string
}

// securityHeaders is the list of security headers to check.
var securityHeaders = []securityHeader{
	{
		Name:        "Strict-Transport-Security",
		Severity:    SeverityHigh,
		Description: "HSTS ensures browsers only connect via HTTPS, preventing downgrade attacks",
		Remediation: "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
	},
	{
		Name:        "X-Content-Type-Options",
		Severity:    SeverityMedium,
		Description: "Prevents MIME type sniffing which can lead to security vulnerabilities",
		Remediation: "Add header: X-Content-Type-Options: nosniff",
	},
	{
		Name:        "X-Frame-Options",
		Severity:    SeverityMedium,
		Description: "Prevents clickjacking attacks by controlling iframe embedding",
		Remediation: "Add header: X-Frame-Options: DENY or SAMEORIGIN",
	},
	{
		Name:        "Content-Security-Policy",
		Severity:    SeverityHigh,
		Description: "CSP helps prevent XSS attacks by controlling resource loading",
		Remediation: "Add a Content-Security-Policy header with appropriate directives",
	},
	{
		Name:        "X-XSS-Protection",
		Severity:    SeverityLow,
		Description: "Legacy XSS filter (deprecated but still useful for older browsers)",
		Remediation: "Add header: X-XSS-Protection: 1; mode=block",
	},
	{
		Name:        "Referrer-Policy",
		Severity:    SeverityLow,
		Description: "Controls how much referrer information is sent with requests",
		Remediation: "Add header: Referrer-Policy: strict-origin-when-cross-origin",
	},
	{
		Name:        "Permissions-Policy",
		Severity:    SeverityLow,
		Description: "Controls which browser features can be used (formerly Feature-Policy)",
		Remediation: "Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()",
	},
}

// HTTPHeadersScanner performs passive security analysis of HTTP response headers.
type HTTPHeadersScanner struct {
	BaseScanner
}

// Option is a function that configures an HTTPHeadersScanner.
type Option func(*HTTPHeadersScanner)

// WithHTTPClient sets a custom HTTP client for the scanner.
func WithHTTPClient(c HTTPClient) Option {
	return func(s *HTTPHeadersScanner) { s.client = c }
}

// WithUserAgent sets the user agent string for the scanner.
func WithUserAgent(ua string) Option {
	return func(s *HTTPHeadersScanner) { s.userAgent = ua }
}

// WithTimeout sets the timeout for HTTP requests.
func WithTimeout(d time.Duration) Option {
	return func(s *HTTPHeadersScanner) { s.timeout = d }
}

// WithAuth sets the authentication configuration for the scanner.
func WithAuth(config *auth.AuthConfig) Option {
	return func(s *HTTPHeadersScanner) { s.authConfig = config }
}

// WithRateLimiter sets a rate limiter for the scanner.
func WithRateLimiter(limiter ratelimit.Limiter) Option {
	return func(s *HTTPHeadersScanner) { s.rateLimiter = limiter }
}

// WithRateLimitConfig sets rate limiting from a configuration.
func WithRateLimitConfig(cfg ratelimit.Config) Option {
	return func(s *HTTPHeadersScanner) { s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg) }
}

// WithTracer sets the OpenTelemetry tracer for the scanner.
func WithTracer(tracer trace.Tracer) Option {
	return func(s *HTTPHeadersScanner) { s.tracer = tracer }
}

// NewHTTPHeadersScanner creates a new HTTPHeadersScanner with the given options.
func NewHTTPHeadersScanner(opts ...Option) *HTTPHeadersScanner {
	s := &HTTPHeadersScanner{BaseScanner: DefaultBaseScanner()}
	for _, opt := range opts {
		opt(s)
	}
	s.InitDefaultClient()
	return s
}

// NewHTTPHeadersScannerFromBase creates a new HTTPHeadersScanner from pre-built
// BaseOptions plus any scanner-specific options. Used by executor to avoid duplication.
func NewHTTPHeadersScannerFromBase(baseOpts []BaseOption, extraOpts ...Option) *HTTPHeadersScanner {
	s := &HTTPHeadersScanner{BaseScanner: DefaultBaseScanner()}
	ApplyBaseOptions(&s.BaseScanner, baseOpts)
	for _, opt := range extraOpts {
		opt(s)
	}
	s.InitDefaultClient()
	return s
}

// Scan performs a security headers scan on the given target URL.
func (s *HTTPHeadersScanner) Scan(ctx context.Context, targetURL string) *HeaderScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanHeaders)
		defer span.End()
	}

	result := &HeaderScanResult{
		Target:  targetURL,
		Headers: make([]HeaderFinding, 0, len(securityHeaders)),
		Cookies: make([]CookieFinding, 0),
		CORS:    make([]CORSFinding, 0),
		Errors:  make([]string, 0),
	}

	// Apply rate limiting before making the request
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
			return result
		}
	}

	// Create and send initial request (without Origin header)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to create request: %s", err.Error()))
		return result
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	// Apply authentication configuration
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to fetch URL: %s", err.Error()))
		return result
	}
	defer resp.Body.Close()

	// Handle rate limiting (HTTP 429)
	if resp.StatusCode == http.StatusTooManyRequests {
		result.Errors = append(result.Errors, "Rate limited by server (HTTP 429)")
		return result
	}

	// Analyze security headers
	result.Headers = s.analyzeHeaders(resp.Header)

	// Analyze cookies
	result.Cookies = s.analyzeCookies(resp.Cookies())

	// Analyze CORS policy (using response headers and a second request with Origin)
	result.CORS = s.analyzeCORS(ctx, targetURL, resp.Header)

	// Calculate summary
	result.Summary = s.calculateSummary(result)

	return result
}

// analyzeHeaders checks for the presence and correctness of security headers.
func (s *HTTPHeadersScanner) analyzeHeaders(headers http.Header) []HeaderFinding {
	findings := make([]HeaderFinding, 0, len(securityHeaders))

	for _, sh := range securityHeaders {
		value := headers.Get(sh.Name)
		present := value != ""

		finding := HeaderFinding{
			Name:        sh.Name,
			Present:     present,
			Description: sh.Description,
		}

		if present {
			finding.Value = value
			finding.Severity = SeverityInfo
			finding.Description = fmt.Sprintf("%s is properly configured", sh.Name)
		} else {
			finding.Severity = sh.Severity
			finding.Remediation = sh.Remediation
		}

		findings = append(findings, finding)
	}

	return findings
}

// analyzeCookies checks the security attributes of cookies.
func (s *HTTPHeadersScanner) analyzeCookies(cookies []*http.Cookie) []CookieFinding {
	findings := make([]CookieFinding, 0, len(cookies))

	for _, cookie := range cookies {
		finding := CookieFinding{
			Name:     cookie.Name,
			HttpOnly: cookie.HttpOnly,
			Secure:   cookie.Secure,
			SameSite: sameSiteToString(cookie.SameSite),
			Issues:   make([]string, 0),
		}

		// Check for security issues
		if !cookie.HttpOnly {
			finding.Issues = append(finding.Issues, "Missing HttpOnly flag - cookie accessible via JavaScript")
		}

		if !cookie.Secure {
			finding.Issues = append(finding.Issues, "Missing Secure flag - cookie can be sent over unencrypted connections")
		}

		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == 0 {
			finding.Issues = append(finding.Issues, "Missing SameSite attribute - vulnerable to CSRF attacks")
		}

		// Determine severity based on issues
		if len(finding.Issues) == 0 {
			finding.Severity = SeverityInfo
		} else if len(finding.Issues) >= 2 {
			finding.Severity = SeverityHigh
			finding.Remediation = "Set all security attributes: HttpOnly, Secure, and SameSite=Strict or Lax"
		} else if !cookie.Secure || !cookie.HttpOnly {
			finding.Severity = SeverityMedium
			finding.Remediation = "Add missing security attributes to the cookie"
		} else {
			finding.Severity = SeverityLow
			finding.Remediation = "Consider adding the SameSite attribute"
		}

		findings = append(findings, finding)
	}

	return findings
}

// sameSiteToString converts http.SameSite to a string representation.
func sameSiteToString(ss http.SameSite) string {
	switch ss {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Not Set"
	}
}

// corsHeader defines the metadata for a CORS header check.
type corsHeader struct {
	Name        string
	Description string
}

// corsHeaders is the list of CORS headers to check.
var corsHeaders = []corsHeader{
	{
		Name:        "Access-Control-Allow-Origin",
		Description: "Specifies which origins can access the resource",
	},
	{
		Name:        "Access-Control-Allow-Credentials",
		Description: "Indicates whether credentials can be included in requests",
	},
	{
		Name:        "Access-Control-Allow-Methods",
		Description: "Specifies the HTTP methods allowed for cross-origin requests",
	},
	{
		Name:        "Access-Control-Allow-Headers",
		Description: "Specifies the headers allowed in cross-origin requests",
	},
	{
		Name:        "Access-Control-Expose-Headers",
		Description: "Specifies which response headers are exposed to the client",
	},
}

// analyzeCORS checks the CORS policy configuration.
func (s *HTTPHeadersScanner) analyzeCORS(ctx context.Context, targetURL string, headers http.Header) []CORSFinding {
	findings := make([]CORSFinding, 0)

	// Extract CORS headers from the response
	acao := headers.Get("Access-Control-Allow-Origin")
	acac := headers.Get("Access-Control-Allow-Credentials")
	acam := headers.Get("Access-Control-Allow-Methods")
	acah := headers.Get("Access-Control-Allow-Headers")
	aceh := headers.Get("Access-Control-Expose-Headers")

	// Check for origin reflection by sending a request with an Origin header
	originReflection := s.checkOriginReflection(ctx, targetURL)

	// Analyze Access-Control-Allow-Origin
	if acao != "" {
		finding := CORSFinding{
			Header:      "Access-Control-Allow-Origin",
			Value:       acao,
			Present:     true,
			Description: "Specifies which origins can access the resource",
			Issues:      make([]string, 0),
		}

		// Check for wildcard with credentials (HIGH severity)
		if acao == "*" && strings.EqualFold(acac, "true") {
			finding.Issues = append(finding.Issues, "Wildcard (*) origin with credentials is invalid and may cause browser errors")
			finding.Severity = SeverityHigh
			finding.Remediation = "Do not use wildcard (*) with Access-Control-Allow-Credentials: true. Specify exact origins instead."
		} else if acao == "*" {
			// Wildcard alone (MEDIUM severity)
			finding.Issues = append(finding.Issues, "Wildcard (*) allows any origin to access resources")
			finding.Severity = SeverityMedium
			finding.Remediation = "Consider restricting to specific trusted origins instead of using wildcard (*)"
		} else {
			finding.Severity = SeverityInfo
			finding.Description = fmt.Sprintf("CORS allows origin: %s", acao)
		}

		findings = append(findings, finding)
	}

	// Analyze Access-Control-Allow-Credentials
	if acac != "" {
		finding := CORSFinding{
			Header:      "Access-Control-Allow-Credentials",
			Value:       acac,
			Present:     true,
			Description: "Indicates whether credentials can be included in requests",
			Issues:      make([]string, 0),
		}

		if strings.EqualFold(acac, "true") {
			if acao == "*" {
				// Already handled above as HIGH severity
				finding.Issues = append(finding.Issues, "Credentials allowed with overly permissive CORS policy")
				finding.Severity = SeverityHigh
				finding.Remediation = "Review the CORS configuration to ensure credentials are only allowed for trusted origins"
			} else if originReflection {
				finding.Issues = append(finding.Issues, "Credentials allowed with potential origin reflection vulnerability")
				finding.Severity = SeverityHigh
				finding.Remediation = "Validate the Origin header against a whitelist of trusted domains"
			} else {
				finding.Severity = SeverityInfo
				finding.Description = "Credentials are allowed for cross-origin requests"
			}
		} else {
			finding.Severity = SeverityInfo
		}

		findings = append(findings, finding)
	}

	// Check for origin reflection
	if originReflection {
		finding := CORSFinding{
			Header:           "Access-Control-Allow-Origin",
			Present:          true,
			OriginReflection: true,
			Description:      "Server reflects the Origin header without validation",
			Issues:           []string{"Origin reflection detected - server may accept any origin"},
			Severity:         SeverityMedium,
			Remediation:      "Validate the Origin header against a whitelist of trusted domains instead of reflecting it",
		}
		// Check if credentials are also allowed
		if strings.EqualFold(acac, "true") {
			finding.Severity = SeverityHigh
			finding.Issues = append(finding.Issues, "Origin reflection combined with credentials allows any origin to make authenticated requests")
		}
		findings = append(findings, finding)
	}

	// Analyze Access-Control-Allow-Methods
	if acam != "" {
		finding := CORSFinding{
			Header:      "Access-Control-Allow-Methods",
			Value:       acam,
			Present:     true,
			Description: "Specifies the HTTP methods allowed for cross-origin requests",
			Issues:      make([]string, 0),
		}

		methods := strings.Split(acam, ",")
		dangerousMethods := []string{}
		for _, m := range methods {
			m = strings.TrimSpace(strings.ToUpper(m))
			// Check for overly permissive methods
			if m == "*" || m == "PUT" || m == "DELETE" || m == "PATCH" {
				dangerousMethods = append(dangerousMethods, m)
			}
		}

		if len(dangerousMethods) > 0 {
			finding.Issues = append(finding.Issues, fmt.Sprintf("Potentially dangerous methods allowed: %s", strings.Join(dangerousMethods, ", ")))
			finding.Severity = SeverityLow
			finding.Remediation = "Only allow the HTTP methods that are actually needed for your API"
		} else {
			finding.Severity = SeverityInfo
		}

		findings = append(findings, finding)
	}

	// Analyze Access-Control-Allow-Headers
	if acah != "" {
		finding := CORSFinding{
			Header:      "Access-Control-Allow-Headers",
			Value:       acah,
			Present:     true,
			Description: "Specifies the headers allowed in cross-origin requests",
			Issues:      make([]string, 0),
		}

		if acah == "*" {
			finding.Issues = append(finding.Issues, "Wildcard (*) allows any header in cross-origin requests")
			finding.Severity = SeverityLow
			finding.Remediation = "Specify only the headers that are actually needed"
		} else {
			finding.Severity = SeverityInfo
		}

		findings = append(findings, finding)
	}

	// Analyze Access-Control-Expose-Headers
	if aceh != "" {
		finding := CORSFinding{
			Header:      "Access-Control-Expose-Headers",
			Value:       aceh,
			Present:     true,
			Description: "Specifies which response headers are exposed to the client",
			Issues:      make([]string, 0),
		}

		if aceh == "*" {
			finding.Issues = append(finding.Issues, "Wildcard (*) exposes all headers to cross-origin requests")
			finding.Severity = SeverityLow
			finding.Remediation = "Specify only the headers that need to be exposed"
		} else {
			finding.Severity = SeverityInfo
		}

		findings = append(findings, finding)
	}

	return findings
}

// checkOriginReflection sends a request with a test Origin header to detect origin reflection.
func (s *HTTPHeadersScanner) checkOriginReflection(ctx context.Context, targetURL string) bool {
	// Apply rate limiting before making the request
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			return false
		}
	}

	// Create a request with a test Origin header
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return false
	}

	// Use a clearly fake origin to test reflection
	testOrigin := "https://malicious-test-origin.example.com"
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Origin", testOrigin)

	// Apply authentication configuration
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Handle rate limiting (HTTP 429)
	if resp.StatusCode == http.StatusTooManyRequests {
		return false
	}

	// Check if the response reflects our test origin
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	return acao == testOrigin
}

// calculateSummary calculates the summary statistics for the scan.
func (s *HTTPHeadersScanner) calculateSummary(result *HeaderScanResult) ScanSummary {
	summary := ScanSummary{
		TotalHeaders: len(result.Headers),
		TotalCookies: len(result.Cookies),
	}

	// Count header statistics
	for _, h := range result.Headers {
		if !h.Present {
			summary.MissingHeaders++
		}
		s.countSeverity(&summary, h.Severity)
	}

	// Count cookie statistics
	for _, c := range result.Cookies {
		if len(c.Issues) > 0 {
			summary.InsecureCookies++
		}
		s.countSeverity(&summary, c.Severity)
	}

	// Count CORS statistics
	for _, c := range result.CORS {
		if len(c.Issues) > 0 {
			summary.CORSIssues++
		}
		s.countSeverity(&summary, c.Severity)
	}

	return summary
}

// countSeverity increments the appropriate severity counter in the summary.
func (s *HTTPHeadersScanner) countSeverity(summary *ScanSummary, severity string) {
	switch severity {
	case SeverityHigh:
		summary.HighSeverityCount++
	case SeverityMedium:
		summary.MediumSeverityCount++
	case SeverityLow:
		summary.LowSeverityCount++
	case SeverityInfo:
		summary.InfoCount++
	}
}
