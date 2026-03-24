// Package scanner provides security scanning functionality for web applications.
package scanner

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

// ScanSummary provides an overview of the scan results.
type ScanSummary struct {
	TotalHeaders        int `json:"total_headers" yaml:"total_headers"`
	MissingHeaders      int `json:"missing_headers" yaml:"missing_headers"`
	TotalCookies        int `json:"total_cookies" yaml:"total_cookies"`
	InsecureCookies     int `json:"insecure_cookies" yaml:"insecure_cookies"`
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
	return len(r.Headers) > 0 || len(r.Cookies) > 0
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
	client     HTTPClient
	userAgent  string
	timeout    time.Duration
	authConfig *auth.AuthConfig
}

// Option is a function that configures an HTTPHeadersScanner.
type Option func(*HTTPHeadersScanner)

// WithHTTPClient sets a custom HTTP client for the scanner.
func WithHTTPClient(c HTTPClient) Option {
	return func(s *HTTPHeadersScanner) {
		s.client = c
	}
}

// WithUserAgent sets the user agent string for the scanner.
func WithUserAgent(ua string) Option {
	return func(s *HTTPHeadersScanner) {
		s.userAgent = ua
	}
}

// WithTimeout sets the timeout for HTTP requests.
func WithTimeout(d time.Duration) Option {
	return func(s *HTTPHeadersScanner) {
		s.timeout = d
	}
}

// WithAuth sets the authentication configuration for the scanner.
func WithAuth(config *auth.AuthConfig) Option {
	return func(s *HTTPHeadersScanner) {
		s.authConfig = config
	}
}

// NewHTTPHeadersScanner creates a new HTTPHeadersScanner with the given options.
func NewHTTPHeadersScanner(opts ...Option) *HTTPHeadersScanner {
	s := &HTTPHeadersScanner{
		userAgent: "WAST/1.0 (Web Application Security Testing)",
		timeout:   30 * time.Second,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Create default HTTP client if not set
	if s.client == nil {
		s.client = NewDefaultHTTPClient(s.timeout)
	}

	return s
}

// Scan performs a security headers scan on the given target URL.
func (s *HTTPHeadersScanner) Scan(ctx context.Context, targetURL string) *HeaderScanResult {
	result := &HeaderScanResult{
		Target:  targetURL,
		Headers: make([]HeaderFinding, 0, len(securityHeaders)),
		Cookies: make([]CookieFinding, 0),
		Errors:  make([]string, 0),
	}

	// Create and send request
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

	// Analyze security headers
	result.Headers = s.analyzeHeaders(resp.Header)

	// Analyze cookies
	result.Cookies = s.analyzeCookies(resp.Cookies())

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
