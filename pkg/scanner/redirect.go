// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// defaultCanaryDomain is the fallback canary domain used in redirect payloads
// when no canary is explicitly configured. Using the IANA-reserved "example.com"
// avoids sending live DNS lookups to a third-party host the project does not control.
const defaultCanaryDomain = "example.com"

// RedirectScanner performs active Open Redirect vulnerability detection.
type RedirectScanner struct {
	BaseScanner
	canaryDomain string // domain substituted for "evil.com" in redirect payloads
}

// RedirectScanResult represents the result of an Open Redirect vulnerability scan.
type RedirectScanResult struct {
	Target   string            `json:"target" yaml:"target"`
	Findings []RedirectFinding `json:"findings" yaml:"findings"`
	Summary  RedirectSummary   `json:"summary" yaml:"summary"`
	Errors   []string          `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// RedirectFinding represents a single Open Redirect vulnerability finding.
type RedirectFinding struct {
	URL                  string `json:"url" yaml:"url"`
	Parameter            string `json:"parameter" yaml:"parameter"`
	Payload              string `json:"payload" yaml:"payload"`
	Evidence             string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Severity             string `json:"severity" yaml:"severity"`
	Type                 string `json:"type" yaml:"type"` // "protocol-relative", "at-symbol", "encoded", "subdomain"
	Description          string `json:"description" yaml:"description"`
	Remediation          string `json:"remediation" yaml:"remediation"`
	Confidence           string `json:"confidence" yaml:"confidence"`
	Verified             bool   `json:"verified" yaml:"verified"`
	VerificationAttempts int    `json:"verification_attempts,omitempty" yaml:"verification_attempts,omitempty"`
}

// RedirectSummary provides an overview of the Open Redirect scan results.
type RedirectSummary struct {
	TotalTests           int `json:"total_tests" yaml:"total_tests"`
	VulnerabilitiesFound int `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	HighSeverityCount    int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount  int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount     int `json:"low_severity_count" yaml:"low_severity_count"`
}

// redirectPayload represents a test payload for Open Redirect detection.
type redirectPayload struct {
	Payload     string
	Type        string // "protocol-relative", "at-symbol", "encoded", "subdomain"
	Severity    string
	Description string
	Target      string // The domain we're testing redirect to
}

// redirectPayloads is the list of payloads to test for Open Redirect vulnerabilities.
var redirectPayloads = []redirectPayload{
	// Protocol-relative URLs
	{
		Payload:     "//evil.com",
		Type:        "protocol-relative",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects to protocol-relative URL",
		Target:      "evil.com",
	},
	{
		Payload:     "///evil.com",
		Type:        "protocol-relative",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects to protocol-relative URL with triple slashes",
		Target:      "evil.com",
	},
	{
		Payload:     "////evil.com",
		Type:        "protocol-relative",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects to protocol-relative URL with quadruple slashes",
		Target:      "evil.com",
	},
	// URL with @ symbol bypass
	{
		Payload:     "https://expected.com@evil.com",
		Type:        "at-symbol",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects using @ symbol URL bypass",
		Target:      "evil.com",
	},
	{
		Payload:     "http://expected.com@evil.com",
		Type:        "at-symbol",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects using @ symbol URL bypass (HTTP)",
		Target:      "evil.com",
	},
	{
		Payload:     "https://trusted@evil.com",
		Type:        "at-symbol",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects using @ symbol with generic username",
		Target:      "evil.com",
	},
	// Encoded payloads
	{
		Payload:     "%2F%2Fevil.com",
		Type:        "encoded",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects to URL-encoded payload",
		Target:      "evil.com",
	},
	{
		Payload:     "%2F%2F%2Fevil.com",
		Type:        "encoded",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects to URL-encoded payload (triple slash)",
		Target:      "evil.com",
	},
	{
		Payload:     "https:%2F%2Fevil.com",
		Type:        "encoded",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects to partially encoded URL",
		Target:      "evil.com",
	},
	{
		Payload:     "%68%74%74%70%73%3A%2F%2Fevil.com",
		Type:        "encoded",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects to fully URL-encoded payload",
		Target:      "evil.com",
	},
	// Subdomain confusion
	{
		Payload:     "https://evil.com.example.com",
		Type:        "subdomain",
		Severity:    SeverityMedium,
		Description: "Potential Open Redirect vulnerability - application may redirect to subdomain that looks like trusted domain",
		Target:      "evil.com",
	},
	{
		Payload:     "https://example.com.evil.com",
		Type:        "subdomain",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects to attacker-controlled domain with subdomain confusion",
		Target:      "evil.com",
	},
	// Backslash bypass attempts
	{
		Payload:     "https://evil.com\\@expected.com",
		Type:        "backslash",
		Severity:    SeverityMedium,
		Description: "Potential Open Redirect vulnerability - application may redirect using backslash bypass",
		Target:      "evil.com",
	},
	{
		Payload:     "\\\\evil.com",
		Type:        "backslash",
		Severity:    SeverityMedium,
		Description: "Potential Open Redirect vulnerability - application may redirect using backslash protocol-relative URL",
		Target:      "evil.com",
	},
	// Data URI scheme (less common but still valid)
	{
		Payload:     "javascript:alert(document.domain)",
		Type:        "javascript",
		Severity:    SeverityHigh,
		Description: "Critical Open Redirect vulnerability - application allows javascript: protocol redirect (XSS)",
		Target:      "javascript",
	},
	// Whitespace bypass attempts
	{
		Payload:     " //evil.com",
		Type:        "whitespace",
		Severity:    SeverityHigh,
		Description: "Open Redirect vulnerability detected - application redirects with leading whitespace bypass",
		Target:      "evil.com",
	},
	{
		Payload:     "https://evil.com%20",
		Type:        "whitespace",
		Severity:    SeverityMedium,
		Description: "Potential Open Redirect vulnerability - application may redirect with trailing whitespace",
		Target:      "evil.com",
	},
}

// RedirectOption is a function that configures a RedirectScanner.
type RedirectOption func(*RedirectScanner)

// WithRedirectHTTPClient sets a custom HTTP client for the redirect scanner.
func WithRedirectHTTPClient(c HTTPClient) RedirectOption {
	return func(s *RedirectScanner) { s.client = c }
}

// WithRedirectUserAgent sets the user agent string for the redirect scanner.
func WithRedirectUserAgent(ua string) RedirectOption {
	return func(s *RedirectScanner) { s.userAgent = ua }
}

// WithRedirectTimeout sets the timeout for HTTP requests.
func WithRedirectTimeout(d time.Duration) RedirectOption {
	return func(s *RedirectScanner) { s.timeout = d }
}

// WithRedirectAuth sets the authentication configuration for the redirect scanner.
func WithRedirectAuth(config *auth.AuthConfig) RedirectOption {
	return func(s *RedirectScanner) { s.authConfig = config }
}

// WithRedirectRateLimiter sets a rate limiter for the redirect scanner.
func WithRedirectRateLimiter(limiter ratelimit.Limiter) RedirectOption {
	return func(s *RedirectScanner) { s.rateLimiter = limiter }
}

// WithRedirectRateLimitConfig sets rate limiting from a configuration.
func WithRedirectRateLimitConfig(cfg ratelimit.Config) RedirectOption {
	return func(s *RedirectScanner) { s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg) }
}

// WithRedirectTracer sets the OpenTelemetry tracer for the redirect scanner.
func WithRedirectTracer(tracer trace.Tracer) RedirectOption {
	return func(s *RedirectScanner) { s.tracer = tracer }
}

// WithRedirectCanaryDomain sets the canary domain substituted into redirect payloads
// instead of the hard-coded "evil.com". All payload Target fields and payload strings
// are rewritten to use this domain at scan time. Detection uses exact hostname matching
// to eliminate substring false positives.
// If d is empty the option is a no-op and the default ("example.com") is used.
func WithRedirectCanaryDomain(d string) RedirectOption {
	return func(s *RedirectScanner) {
		if d != "" {
			s.canaryDomain = d
		}
	}
}

// NewRedirectScanner creates a new RedirectScanner with the given options.
func NewRedirectScanner(opts ...RedirectOption) *RedirectScanner {
	s := &RedirectScanner{BaseScanner: DefaultBaseScanner()}
	for _, opt := range opts {
		opt(s)
	}
	if s.canaryDomain == "" {
		s.canaryDomain = defaultCanaryDomain
	}
	// IMPORTANT: For redirect testing, we need a client that does NOT follow redirects
	if s.client == nil {
		s.client = NewNoRedirectHTTPClient(s.timeout)
	}
	return s
}

// NewRedirectScannerFromBase creates a new RedirectScanner from pre-built BaseOptions
// plus any scanner-specific options.
func NewRedirectScannerFromBase(baseOpts []BaseOption, extraOpts ...RedirectOption) *RedirectScanner {
	s := &RedirectScanner{BaseScanner: DefaultBaseScanner()}
	ApplyBaseOptions(&s.BaseScanner, baseOpts)
	for _, opt := range extraOpts {
		opt(s)
	}
	if s.canaryDomain == "" {
		s.canaryDomain = defaultCanaryDomain
	}
	// IMPORTANT: For redirect testing, we need a client that does NOT follow redirects
	if s.client == nil {
		s.client = NewNoRedirectHTTPClient(s.timeout)
	}
	return s
}

// NewNoRedirectHTTPClient creates an HTTP client that does not follow redirects.
func NewNoRedirectHTTPClient(timeout time.Duration) HTTPClient {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Return error to prevent following redirects
			return http.ErrUseLastResponse
		},
	}
}

// buildActivePayloads returns a copy of the global redirectPayloads slice with
// the canary domain substituted for the hard-coded "evil.com" in both the
// Payload string and the Target field. The javascript: payload is left unchanged
// because its Target ("javascript") is unrelated to the canary domain.
func (s *RedirectScanner) buildActivePayloads() []redirectPayload {
	canary := s.canaryDomain
	active := make([]redirectPayload, len(redirectPayloads))
	for i, p := range redirectPayloads {
		if p.Target != "javascript" {
			p.Payload = strings.ReplaceAll(p.Payload, "evil.com", canary)
			p.Target = canary
		}
		active[i] = p
	}
	return active
}

// Scan performs an Open Redirect vulnerability scan on the given target URL.
func (s *RedirectScanner) Scan(ctx context.Context, targetURL string) *RedirectScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanRedirect)
		defer span.End()
	}

	result := &RedirectScanResult{
		Target:   targetURL,
		Findings: make([]RedirectFinding, 0),
		Errors:   make([]string, 0),
	}

	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid URL: %s", err.Error()))
		return result
	}

	// Extract query parameters to test
	params := parsedURL.Query()

	// If no query parameters exist, test with common redirect parameter names
	if len(params) == 0 {
		params.Set("url", "")
		params.Set("redirect", "")
		params.Set("next", "")
		params.Set("return", "")
		params.Set("goto", "")
		params.Set("target", "")
		params.Set("dest", "")
		params.Set("destination", "")
		params.Set("returnUrl", "")
		params.Set("continue", "")
	}

	// Build payloads with the configured canary domain substituted for "evil.com".
	activePayloads := s.buildActivePayloads()

	// Test each parameter with each payload
	for paramName := range params {
		for _, payload := range activePayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			finding := s.testParameter(ctx, parsedURL, paramName, payload)
			result.Summary.TotalTests++

			if finding != nil {
				result.Findings = append(result.Findings, *finding)
				result.Summary.VulnerabilitiesFound++
			}

			// Check context cancellation
			select {
			case <-ctx.Done():
				result.Errors = append(result.Errors, "Scan cancelled")
				s.calculateSummary(result)
				return result
			default:
			}
		}
	}

	// Calculate final summary
	s.calculateSummary(result)

	return result
}

// ScanPOST performs Open Redirect scanning with POST method using form-encoded parameters.
func (s *RedirectScanner) ScanPOST(ctx context.Context, targetURL string, parameters map[string]string) *RedirectScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanRedirect)
		defer span.End()
	}

	result := &RedirectScanResult{
		Target:   targetURL,
		Findings: make([]RedirectFinding, 0),
		Errors:   make([]string, 0),
	}

	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid URL: %s", err.Error()))
		return result
	}

	// Use provided parameters or fallback to common redirect parameter names
	params := parameters
	if len(params) == 0 {
		params = map[string]string{
			"url":         "",
			"redirect":    "",
			"next":        "",
			"return":      "",
			"goto":        "",
			"target":      "",
			"dest":        "",
			"destination": "",
			"returnUrl":   "",
			"continue":    "",
		}
	}

	// Build payloads with the configured canary domain substituted for "evil.com".
	activePayloads := s.buildActivePayloads()

	// Test each parameter with each payload
	for paramName := range params {
		for _, payload := range activePayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			finding := s.testParameterPOST(ctx, parsedURL, paramName, payload, params)
			result.Summary.TotalTests++

			if finding != nil {
				result.Findings = append(result.Findings, *finding)
				result.Summary.VulnerabilitiesFound++
			}

			// Check context cancellation
			select {
			case <-ctx.Done():
				result.Errors = append(result.Errors, "Scan cancelled")
				s.calculateSummary(result)
				return result
			default:
			}
		}
	}

	// Calculate final summary
	s.calculateSummary(result)

	return result
}

// testParameterPOST tests a single parameter with a specific redirect payload using POST method.
func (s *RedirectScanner) testParameterPOST(ctx context.Context, baseURL *url.URL, paramName string, payload redirectPayload, allParameters map[string]string) *RedirectFinding {
	// Create form data with ALL parameters
	formData := url.Values{}
	for k, v := range allParameters {
		formData.Set(k, v)
	}
	// Override the parameter being tested
	formData.Set(paramName, payload.Payload)

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Apply authentication configuration
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	// Send the request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Handle rate limiting (HTTP 429)
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}

	// Read response body (if any)
	body, err := readResponseBody(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Analyze the response for Open Redirect indicators
	confidence, evidence := s.analyzeRedirectResponse(resp, bodyStr, payload)

	// Only report if there's medium or high confidence
	if confidence != "low" && confidence != "" {
		finding := &RedirectFinding{
			URL:         baseURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    evidence,
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  confidence,
		}
		return finding
	}

	return nil
}

// testParameter tests a single parameter with a specific redirect payload.
func (s *RedirectScanner) testParameter(ctx context.Context, baseURL *url.URL, paramName string, payload redirectPayload) *RedirectFinding {
	// Create a copy of the URL with the test payload
	testURL := *baseURL
	q := testURL.Query()
	q.Set(paramName, payload.Payload)
	testURL.RawQuery = q.Encode()

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	// Apply authentication configuration
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	// Send the request
	resp, err := s.client.Do(req)

	// Handle request errors
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Handle rate limiting (HTTP 429)
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}

	// Read response body (if any)
	body, err := readResponseBody(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Analyze the response for Open Redirect indicators
	confidence, evidence := s.analyzeRedirectResponse(resp, bodyStr, payload)

	// Only report if there's medium or high confidence
	if confidence != "low" && confidence != "" {
		finding := &RedirectFinding{
			URL:         testURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    evidence,
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  confidence,
		}
		return finding
	}

	return nil
}

// analyzeRedirectResponse analyzes the HTTP response to determine if Open Redirect is possible.
func (s *RedirectScanner) analyzeRedirectResponse(resp *http.Response, body string, payload redirectPayload) (confidence string, evidence string) {
	// Check for redirect status codes (3xx)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			// Parse the Location header
			locationURL, err := url.Parse(location)
			if err == nil {
				// Check if the redirect location contains our payload or target domain
				if s.isRedirectToPayload(location, locationURL, payload) {
					return "high", fmt.Sprintf("HTTP %d redirect to: %s", resp.StatusCode, location)
				}

				// Check for partial matches that might indicate vulnerability
				if s.isPartialRedirectMatch(location, payload) {
					return "medium", fmt.Sprintf("HTTP %d redirect contains payload elements: %s", resp.StatusCode, location)
				}
			} else {
				// If we can't parse the location, but it contains our target, it might still be vulnerable
				if strings.Contains(location, payload.Target) {
					return "medium", fmt.Sprintf("HTTP %d redirect with unparseable location containing target: %s", resp.StatusCode, location)
				}
			}
		}
	}

	// Check for client-side redirects in the response body
	bodyLower := strings.ToLower(body)

	// Check for meta refresh redirects
	if strings.Contains(bodyLower, "<meta") && strings.Contains(bodyLower, "http-equiv") && strings.Contains(bodyLower, "refresh") {
		if s.containsPayloadInBody(body, payload) {
			return "high", fmt.Sprintf("Client-side meta refresh redirect found in response body")
		}
	}

	// Check for JavaScript redirects
	if strings.Contains(bodyLower, "window.location") || strings.Contains(bodyLower, "location.href") || strings.Contains(bodyLower, "location.replace") {
		if s.containsPayloadInBody(body, payload) {
			return "medium", "Client-side JavaScript redirect found in response body"
		}
	}

	return "", ""
}

// isRedirectToPayload checks if the redirect location matches our payload target.
// It uses exact hostname matching against the canary domain to avoid substring
// false positives (e.g. "notevil.com" containing "evil.com").
func (s *RedirectScanner) isRedirectToPayload(location string, locationURL *url.URL, payload redirectPayload) bool {
	// For javascript: protocol, check if present
	if payload.Target == "javascript" {
		return strings.HasPrefix(strings.ToLower(location), "javascript:")
	}

	// Use Hostname() (strips port, handles userinfo) for exact matching.
	// url.Parse correctly sets Host for protocol-relative URLs like "//canary.com"
	// and for @ symbol URLs like "https://user@canary.com" (Host = "canary.com").
	hostname := locationURL.Hostname()

	// Exact hostname match: covers protocol-relative, at-symbol, encoded, and most
	// other redirect types without risking substring false positives.
	if hostname == payload.Target {
		return true
	}

	// Subdomain confusion: the redirect hostname ends with the canary domain,
	// e.g. "example.com.canary.com" ends with ".canary.com".
	// Use HasSuffix rather than Contains to avoid false positives like "notcanary.com".
	if payload.Type == "subdomain" {
		if strings.HasSuffix(hostname, "."+payload.Target) {
			return true
		}
	}

	return false
}

// isPartialRedirectMatch checks for partial matches that might indicate vulnerability.
// This is a medium-confidence signal used when exact hostname matching fails — for
// example when the server returns a backslash-prefixed URL that url.Parse cannot
// fully resolve, but the canary domain still appears somewhere in the location.
//
// Like isRedirectToPayload, this function uses Hostname() extraction rather than
// strings.Contains to avoid substring false positives such as "notevil.com" when
// the canary domain is "evil.com".
func (s *RedirectScanner) isPartialRedirectMatch(location string, payload redirectPayload) bool {
	// The javascript: target is already handled by isRedirectToPayload; skip here
	// to avoid spurious medium-confidence findings on ordinary pages that contain
	// the word "javascript" (e.g. <script type="text/javascript">).
	if payload.Target == "javascript" {
		return false
	}

	if payload.Target == "" {
		return false
	}

	// Prefer exact hostname matching via url.Parse to avoid substring false positives.
	u, err := url.Parse(location)
	if err == nil && u.Hostname() != "" {
		h := u.Hostname()
		return h == payload.Target || strings.HasSuffix(h, "."+payload.Target)
	}

	// Fallback for locations that url.Parse cannot resolve (e.g. backslash-prefixed
	// paths like "\\evil.com" where Hostname() returns ""). Use boundary-aware checks
	// to reduce — but not fully eliminate — false positives.
	return strings.Contains(location, "."+payload.Target) || strings.Contains(location, "/"+payload.Target)
}

// containsPayloadInBody checks if the response body contains our payload.
func (s *RedirectScanner) containsPayloadInBody(body string, payload redirectPayload) bool {
	// Check if the payload appears in the body
	if strings.Contains(body, payload.Payload) {
		return true
	}

	// For javascript: payloads, "javascript" is too generic a target to match on
	// (it appears on virtually every web page via <script type="text/javascript"> tags,
	// JavaScript comments, or DOM XSS pages that read window.location to extract URL
	// parameters). Matching on just "javascript" would produce false positives on any
	// page that uses client-side scripting. Only the full payload string match above is
	// used for this payload type to avoid false positives.
	if payload.Target == "javascript" {
		return false
	}

	if strings.Contains(body, payload.Target) {
		return true
	}

	return false
}

// getRemediation returns remediation guidance for Open Redirect vulnerabilities.
func (s *RedirectScanner) getRemediation() string {
	return "Implement strict URL validation before redirecting. Use an allowlist of permitted redirect destinations. " +
		"Validate that redirect URLs are relative paths (not absolute URLs) or belong to trusted domains. " +
		"Avoid using user input directly in redirect operations. " +
		"Use indirect reference maps (e.g., redirect to /page?id=123 where 123 maps to a safe URL server-side). " +
		"If absolute URLs are required, validate the protocol (http/https only), domain (against allowlist), and path. " +
		"Implement CSRF tokens for any redirect functionality. " +
		"Consider using the Referrer-Policy header to control referrer information leakage."
}

// calculateSummary calculates the summary statistics for the scan.
func (s *RedirectScanner) calculateSummary(result *RedirectScanResult) {
	result.Summary.VulnerabilitiesFound = len(result.Findings)

	for _, finding := range result.Findings {
		switch finding.Severity {
		case SeverityHigh:
			result.Summary.HighSeverityCount++
		case SeverityMedium:
			result.Summary.MediumSeverityCount++
		case SeverityLow:
			result.Summary.LowSeverityCount++
		}
	}
}

// String returns a human-readable representation of the scan result.
func (r *RedirectScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Open Redirect Vulnerability Scan for: %s\n", r.Target))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	// Summary
	sb.WriteString("\nSummary:\n")
	sb.WriteString(fmt.Sprintf("  Total Tests: %d\n", r.Summary.TotalTests))
	sb.WriteString(fmt.Sprintf("  Vulnerabilities Found: %d\n", r.Summary.VulnerabilitiesFound))
	sb.WriteString(fmt.Sprintf("  High Severity: %d\n", r.Summary.HighSeverityCount))
	sb.WriteString(fmt.Sprintf("  Medium Severity: %d\n", r.Summary.MediumSeverityCount))
	sb.WriteString(fmt.Sprintf("  Low Severity: %d\n", r.Summary.LowSeverityCount))

	// Findings
	if len(r.Findings) > 0 {
		sb.WriteString("\nVulnerabilities:\n")
		for i, f := range r.Findings {
			sb.WriteString(fmt.Sprintf("\n  %d. [%s] %s Open Redirect\n", i+1, strings.ToUpper(f.Severity), titleCase(f.Type)))
			sb.WriteString(fmt.Sprintf("     Parameter: %s\n", f.Parameter))
			sb.WriteString(fmt.Sprintf("     Payload: %s\n", f.Payload))
			sb.WriteString(fmt.Sprintf("     Description: %s\n", f.Description))
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("     Evidence: %s\n", f.Evidence))
			}
			sb.WriteString(fmt.Sprintf("     Confidence: %s\n", f.Confidence))
			sb.WriteString(fmt.Sprintf("     Remediation: %s\n", f.Remediation))
		}
	} else {
		sb.WriteString("\nNo Open Redirect vulnerabilities detected.\n")
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
func (r *RedirectScanResult) HasResults() bool {
	return len(r.Findings) > 0 || r.Summary.TotalTests > 0
}

// VerifyFinding re-tests an Open Redirect finding with payload variants to confirm it's reproducible.
func (s *RedirectScanner) VerifyFinding(ctx context.Context, finding *RedirectFinding, config VerificationConfig) (*VerificationResult, error) {
	if finding == nil {
		return nil, fmt.Errorf("finding is nil")
	}

	// Parse the original URL to extract parameters
	parsedURL, err := url.Parse(finding.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL in finding: %w", err)
	}

	// Generate payload variants for verification
	variants := s.generateRedirectPayloadVariants(finding.Payload, finding.Type)

	successCount := 0
	totalAttempts := 0
	maxAttempts := config.MaxRetries
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	// Test each variant
	for i, variant := range variants {
		if i >= maxAttempts {
			break
		}

		// Apply rate limiting before making the request
		if s.rateLimiter != nil {
			if err := s.rateLimiter.Wait(ctx); err != nil {
				return nil, fmt.Errorf("rate limiting error: %w", err)
			}
		}

		// Apply delay between attempts if configured
		if i > 0 && config.Delay > 0 {
			time.Sleep(config.Delay)
		}

		totalAttempts++

		// Test with the variant payload
		testURL := *parsedURL
		q := testURL.Query()
		q.Set(finding.Parameter, variant)
		testURL.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", s.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		if s.authConfig != nil {
			s.authConfig.ApplyToRequest(req)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}

		body, err := readResponseBody(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// Check if variant produces similar redirect indicators
		confidence, _ := s.analyzeRedirectResponse(resp, bodyStr, redirectPayload{
			Target: extractTargetFromPayload(variant),
			Type:   finding.Type,
		})
		if confidence == "high" || confidence == "medium" {
			successCount++
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	// Calculate verification result
	confidenceScore := float64(successCount) / float64(totalAttempts)
	verified := confidenceScore >= 0.5 // At least 50% of variants must succeed

	explanation := fmt.Sprintf("Verified %d out of %d payload variants successfully reproduced the vulnerability",
		successCount, totalAttempts)

	if !verified {
		explanation = fmt.Sprintf("Only %d out of %d payload variants reproduced the vulnerability - likely a false positive or WAF protection",
			successCount, totalAttempts)
	}

	return &VerificationResult{
		Verified:    verified,
		Attempts:    totalAttempts,
		Confidence:  confidenceScore,
		Explanation: explanation,
	}, nil
}

// generateRedirectPayloadVariants creates different variations of the redirect payload.
func (s *RedirectScanner) generateRedirectPayloadVariants(originalPayload, payloadType string) []string {
	variants := make([]string, 0)

	// Add the original payload
	variants = append(variants, originalPayload)

	switch payloadType {
	case "protocol-relative":
		// Add variations with different numbers of slashes
		variants = append(variants, "//attacker.com")
		variants = append(variants, "///attacker.com")
		variants = append(variants, "//evil.example.com")

	case "at-symbol":
		// Add variations with different trusted domains
		variants = append(variants, "https://trusted@attacker.com")
		variants = append(variants, "https://example.com@attacker.com")
		variants = append(variants, "http://user@attacker.com")

	case "encoded":
		// Add various encoding levels
		variants = append(variants, "%2F%2Fattacker.com")
		variants = append(variants, "%2F%2F%2Fattacker.com")
		variants = append(variants, "https:%2F%2Fattacker.com")

	case "subdomain":
		// Add subdomain variations
		variants = append(variants, "https://attacker.com.example.com")
		variants = append(variants, "https://example.com.attacker.com")

	case "javascript":
		// Add JavaScript protocol variations
		variants = append(variants, "javascript:alert(1)")
		variants = append(variants, "javascript:void(0)")

	case "whitespace":
		// Add whitespace variations
		variants = append(variants, " //attacker.com")
		variants = append(variants, "//attacker.com ")

	case "backslash":
		// Add backslash variations
		variants = append(variants, "\\\\attacker.com")
		variants = append(variants, "https://attacker.com\\")
	}

	return variants
}

// extractTargetFromPayload extracts the target domain from a payload.
func extractTargetFromPayload(payload string) string {
	// Try to parse as URL
	if u, err := url.Parse(payload); err == nil {
		if u.Host != "" {
			return u.Host
		}
	}

	// Look for common patterns
	if strings.Contains(payload, "evil.com") {
		return "evil.com"
	}
	if strings.Contains(payload, "attacker.com") {
		return "attacker.com"
	}
	if strings.HasPrefix(payload, "javascript:") {
		return "javascript"
	}

	return "unknown"
}
