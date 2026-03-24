// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
)

// XSSScanner performs active XSS vulnerability detection.
type XSSScanner struct {
	client      HTTPClient
	userAgent   string
	timeout     time.Duration
	authConfig  *auth.AuthConfig
	rateLimiter ratelimit.Limiter
}

// XSSScanResult represents the result of an XSS vulnerability scan.
type XSSScanResult struct {
	Target   string       `json:"target" yaml:"target"`
	Findings []XSSFinding `json:"findings" yaml:"findings"`
	Summary  XSSSummary   `json:"summary" yaml:"summary"`
	Errors   []string     `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// XSSFinding represents a single XSS vulnerability finding.
type XSSFinding struct {
	URL         string `json:"url" yaml:"url"`
	Parameter   string `json:"parameter" yaml:"parameter"`
	Payload     string `json:"payload" yaml:"payload"`
	Evidence    string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Severity    string `json:"severity" yaml:"severity"`
	Type        string `json:"type" yaml:"type"` // "reflected", "stored", "dom"
	Description string `json:"description" yaml:"description"`
	Remediation string `json:"remediation" yaml:"remediation"`
	Confidence  string `json:"confidence" yaml:"confidence"` // "high", "medium", "low"
}

// XSSSummary provides an overview of the XSS scan results.
type XSSSummary struct {
	TotalTests           int `json:"total_tests" yaml:"total_tests"`
	VulnerabilitiesFound int `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	HighSeverityCount    int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount  int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount     int `json:"low_severity_count" yaml:"low_severity_count"`
}

// xssPayload represents a test payload for XSS detection.
type xssPayload struct {
	Payload     string
	Type        string // "reflected", "stored", "dom"
	Severity    string
	Description string
	Evidence    string // What to look for in the response
}

// xssPayloads is the list of safe detection payloads to test for XSS.
var xssPayloads = []xssPayload{
	{
		Payload:     "<script>alert('XSS')</script>",
		Type:        "reflected",
		Severity:    SeverityHigh,
		Description: "Unescaped script tag injection detected - allows arbitrary JavaScript execution",
		Evidence:    "<script>alert('XSS')</script>",
	},
	{
		Payload:     "<img src=x onerror=alert('XSS')>",
		Type:        "reflected",
		Severity:    SeverityHigh,
		Description: "Event handler injection detected - allows JavaScript execution via HTML attributes",
		Evidence:    "onerror=alert('XSS')",
	},
	{
		Payload:     "<svg/onload=alert('XSS')>",
		Type:        "reflected",
		Severity:    SeverityHigh,
		Description: "SVG event handler injection detected - allows JavaScript execution",
		Evidence:    "onload=alert('XSS')",
	},
	{
		Payload:     "'\"><script>alert('XSS')</script>",
		Type:        "reflected",
		Severity:    SeverityHigh,
		Description: "Attribute escape and script injection detected - breaks out of HTML attributes",
		Evidence:    "<script>alert('XSS')</script>",
	},
	{
		Payload:     "javascript:alert('XSS')",
		Type:        "reflected",
		Severity:    SeverityMedium,
		Description: "JavaScript protocol handler injection detected",
		Evidence:    "javascript:alert('XSS')",
	},
	{
		Payload:     "<iframe src=\"javascript:alert('XSS')\">",
		Type:        "reflected",
		Severity:    SeverityHigh,
		Description: "Iframe with JavaScript protocol detected",
		Evidence:    "javascript:alert('XSS')",
	},
}

// XSSOption is a function that configures an XSSScanner.
type XSSOption func(*XSSScanner)

// WithXSSHTTPClient sets a custom HTTP client for the XSS scanner.
func WithXSSHTTPClient(c HTTPClient) XSSOption {
	return func(s *XSSScanner) {
		s.client = c
	}
}

// WithXSSUserAgent sets the user agent string for the XSS scanner.
func WithXSSUserAgent(ua string) XSSOption {
	return func(s *XSSScanner) {
		s.userAgent = ua
	}
}

// WithXSSTimeout sets the timeout for HTTP requests.
func WithXSSTimeout(d time.Duration) XSSOption {
	return func(s *XSSScanner) {
		s.timeout = d
	}
}

// WithXSSAuth sets the authentication configuration for the XSS scanner.
func WithXSSAuth(config *auth.AuthConfig) XSSOption {
	return func(s *XSSScanner) {
		s.authConfig = config
	}
}

// WithXSSRateLimiter sets a rate limiter for the XSS scanner.
func WithXSSRateLimiter(limiter ratelimit.Limiter) XSSOption {
	return func(s *XSSScanner) {
		s.rateLimiter = limiter
	}
}

// WithXSSRateLimitConfig sets rate limiting from a configuration.
func WithXSSRateLimitConfig(cfg ratelimit.Config) XSSOption {
	return func(s *XSSScanner) {
		s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg)
	}
}

// NewXSSScanner creates a new XSSScanner with the given options.
func NewXSSScanner(opts ...XSSOption) *XSSScanner {
	s := &XSSScanner{
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

// Scan performs an XSS vulnerability scan on the given target URL.
func (s *XSSScanner) Scan(ctx context.Context, targetURL string) *XSSScanResult {
	result := &XSSScanResult{
		Target:   targetURL,
		Findings: make([]XSSFinding, 0),
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

	// If no query parameters exist, test with a common parameter name
	if len(params) == 0 {
		params.Set("q", "")
		params.Set("search", "")
		params.Set("query", "")
		params.Set("input", "")
	}

	// Test each parameter with each payload
	for paramName := range params {
		for _, payload := range xssPayloads {
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

// XSSContext represents where a payload appears in the HTML/JavaScript context.
type XSSContext int

const (
	ContextUnknown XSSContext = iota
	ContextHTMLBody
	ContextHTMLAttribute
	ContextJavaScript
	ContextURL
)

// analyzeContext determines where the payload appears and if it's executable.
// Returns the context type and whether the payload is in an executable form.
func (s *XSSScanner) analyzeContext(body, payload string) (XSSContext, bool, string) {
	// Check if payload is HTML-encoded (would neutralize XSS)
	htmlEncodedPayload := strings.ReplaceAll(payload, "<", "&lt;")
	htmlEncodedPayload = strings.ReplaceAll(htmlEncodedPayload, ">", "&gt;")
	htmlEncodedPayload = strings.ReplaceAll(htmlEncodedPayload, "\"", "&quot;")
	htmlEncodedPayload = strings.ReplaceAll(htmlEncodedPayload, "'", "&#39;")

	if strings.Contains(body, htmlEncodedPayload) {
		return ContextHTMLBody, false, "low" // Payload is HTML-encoded, not executable
	}

	// Find the index where payload appears
	idx := strings.Index(body, payload)
	if idx == -1 {
		// Try to find evidence instead
		return ContextUnknown, false, "low"
	}

	// Extract context around the payload (200 chars before and after)
	start := idx - 200
	if start < 0 {
		start = 0
	}
	end := idx + len(payload) + 200
	if end > len(body) {
		end = len(body)
	}
	context := body[start:end]

	// Check if payload is inside script tags (high confidence)
	scriptTagPattern := regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?</script>`)
	if scriptTagPattern.MatchString(context) {
		// Check if payload is actually inside the script tags
		beforePayload := body[start:idx]
		if strings.Contains(beforePayload, "<script") && !strings.Contains(beforePayload, "</script>") {
			return ContextJavaScript, true, "high"
		}
	}

	// Check if payload appears in event handlers (high confidence)
	eventHandlerPattern := regexp.MustCompile(`(?i)\bon\w+\s*=\s*["\']?[^"\'>\s]*` + regexp.QuoteMeta(payload))
	if eventHandlerPattern.MatchString(context) {
		return ContextHTMLAttribute, true, "high"
	}

	// Check if payload contains event handlers that are not quoted or escaped
	if strings.Contains(payload, "onerror") || strings.Contains(payload, "onload") || strings.Contains(payload, "onclick") {
		// Check if it's properly rendered as an attribute
		attrPattern := regexp.MustCompile(`(?i)<\w+[^>]*` + regexp.QuoteMeta(payload))
		if attrPattern.MatchString(context) {
			return ContextHTMLAttribute, true, "high"
		}
	}

	// Check if payload is inside an HTML attribute value but not event handler
	attrValuePattern := regexp.MustCompile(`(?i)(\w+)\s*=\s*["\'][^"\']*` + regexp.QuoteMeta(payload))
	if attrValuePattern.MatchString(context) {
		return ContextHTMLAttribute, true, "medium"
	}

	// Check if script/img/svg tags are properly formed
	if strings.Contains(payload, "<script") || strings.Contains(payload, "<img") || strings.Contains(payload, "<svg") {
		tagPattern := regexp.MustCompile(`<(script|img|svg|iframe)[^>]*>`)
		if tagPattern.MatchString(payload) {
			// Check if the tag is actually rendered (not inside a string or comment)
			if !strings.Contains(context, "<!--") && !strings.Contains(context, "*/") {
				return ContextHTMLBody, true, "high"
			}
		}
	}

	// Default: payload is reflected but context is unclear
	return ContextHTMLBody, false, "low"
}

// testParameter tests a single parameter with a specific payload.
func (s *XSSScanner) testParameter(ctx context.Context, baseURL *url.URL, paramName string, payload xssPayload) *XSSFinding {
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
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Handle rate limiting (HTTP 429)
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}

	// Only check successful responses
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Check if the payload or evidence is reflected in the response
	if strings.Contains(bodyStr, payload.Evidence) || strings.Contains(bodyStr, payload.Payload) {
		// Payload is reflected - now verify if it's actually executable
		contextType, isExecutable, confidence := s.analyzeContext(bodyStr, payload.Payload)

		// If payload is HTML-encoded or in a safe context, it's likely a false positive
		if !isExecutable && contextType != ContextUnknown {
			// Don't report low-confidence findings that are clearly encoded
			if confidence == "low" {
				return nil
			}
		}

		// For executable contexts, increase confidence
		if isExecutable {
			if contextType == ContextJavaScript || contextType == ContextHTMLAttribute {
				confidence = "high"
			} else if contextType == ContextHTMLBody {
				// Check if it's actually a complete executable tag
				if strings.Contains(payload.Payload, "<script") ||
					strings.Contains(payload.Payload, "onerror") ||
					strings.Contains(payload.Payload, "onload") {
					confidence = "high"
				} else {
					confidence = "medium"
				}
			}
		}

		// Vulnerability found!
		finding := &XSSFinding{
			URL:         testURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    s.extractEvidence(bodyStr, payload.Evidence, payload.Payload),
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(payload.Type),
			Confidence:  confidence,
		}
		return finding
	}

	return nil
}

// extractEvidence extracts a snippet of the response containing the vulnerability evidence.
func (s *XSSScanner) extractEvidence(body, evidence, payload string) string {
	// Look for the evidence string
	searchStr := evidence
	if !strings.Contains(body, searchStr) {
		searchStr = payload
	}

	idx := strings.Index(body, searchStr)
	if idx == -1 {
		return "Payload reflected in response"
	}

	// Extract context around the evidence (up to 200 characters)
	start := idx - 50
	if start < 0 {
		start = 0
	}
	end := idx + len(searchStr) + 50
	if end > len(body) {
		end = len(body)
	}

	snippet := body[start:end]
	// Clean up the snippet
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	snippet = strings.TrimSpace(snippet)

	return fmt.Sprintf("...%s...", snippet)
}

// getRemediation returns remediation guidance based on the vulnerability type.
func (s *XSSScanner) getRemediation(vulnType string) string {
	remediations := map[string]string{
		"reflected": "Implement proper output encoding/escaping for all user input. Use context-aware encoding (HTML, JavaScript, URL, CSS). Consider implementing Content Security Policy (CSP) headers. Validate and sanitize all input on the server side.",
		"stored":    "Sanitize and validate all user input before storing. Implement proper output encoding when displaying stored data. Use parameterized queries or prepared statements. Consider implementing Content Security Policy (CSP) headers.",
		"dom":       "Avoid using dangerous DOM methods like innerHTML, document.write, eval(). Use safe alternatives like textContent, setAttribute. Implement proper client-side validation and encoding. Review and secure all client-side JavaScript code.",
	}

	if remediation, ok := remediations[vulnType]; ok {
		return remediation
	}

	return "Implement proper input validation and output encoding to prevent XSS attacks."
}

// calculateSummary calculates the summary statistics for the scan.
func (s *XSSScanner) calculateSummary(result *XSSScanResult) {
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
func (r *XSSScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("XSS Vulnerability Scan for: %s\n", r.Target))
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
			sb.WriteString(fmt.Sprintf("\n  %d. [%s] %s XSS\n", i+1, strings.ToUpper(f.Severity), strings.Title(f.Type)))
			sb.WriteString(fmt.Sprintf("     Parameter: %s\n", f.Parameter))
			sb.WriteString(fmt.Sprintf("     Payload: %s\n", f.Payload))
			sb.WriteString(fmt.Sprintf("     Description: %s\n", f.Description))
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("     Evidence: %s\n", f.Evidence))
			}
			sb.WriteString(fmt.Sprintf("     Remediation: %s\n", f.Remediation))
		}
	} else {
		sb.WriteString("\nNo XSS vulnerabilities detected.\n")
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
func (r *XSSScanResult) HasResults() bool {
	return len(r.Findings) > 0 || r.Summary.TotalTests > 0
}
