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
	"github.com/djannot/wast/pkg/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// XSSScanner performs active XSS vulnerability detection.
type XSSScanner struct {
	client      HTTPClient
	userAgent   string
	timeout     time.Duration
	authConfig  *auth.AuthConfig
	rateLimiter ratelimit.Limiter
	tracer      trace.Tracer
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
	URL                  string `json:"url" yaml:"url"`
	Parameter            string `json:"parameter" yaml:"parameter"`
	Payload              string `json:"payload" yaml:"payload"`
	Evidence             string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Severity             string `json:"severity" yaml:"severity"`
	Type                 string `json:"type" yaml:"type"` // "reflected", "stored", "dom"
	Description          string `json:"description" yaml:"description"`
	Remediation          string `json:"remediation" yaml:"remediation"`
	Confidence           string `json:"confidence" yaml:"confidence"` // "high", "medium", "low"
	Verified             bool   `json:"verified" yaml:"verified"`
	VerificationAttempts int    `json:"verification_attempts,omitempty" yaml:"verification_attempts,omitempty"`
}

// XSSSummary provides an overview of the XSS scan results.
type XSSSummary struct {
	TotalTests           int `json:"total_tests" yaml:"total_tests"`
	VulnerabilitiesFound int `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	HighSeverityCount    int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount  int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount     int `json:"low_severity_count" yaml:"low_severity_count"`
}

// VerificationResult represents the result of a finding verification.
type VerificationResult struct {
	Verified    bool    `json:"verified" yaml:"verified"`
	Attempts    int     `json:"attempts" yaml:"attempts"`
	Confidence  float64 `json:"confidence" yaml:"confidence"` // 0.0 to 1.0
	Explanation string  `json:"explanation" yaml:"explanation"`
}

// VerificationConfig controls how finding verification is performed.
type VerificationConfig struct {
	Enabled    bool          `json:"enabled" yaml:"enabled"`
	MaxRetries int           `json:"max_retries" yaml:"max_retries"`
	Delay      time.Duration `json:"delay" yaml:"delay"`
}

// xssPayload represents a test payload for XSS detection.
type xssPayload struct {
	Payload     string
	Type        string // "reflected", "stored", "dom"
	Severity    string
	Description string
	Evidence    string // What to look for in the response
}

// defaultTestParams is the list of common parameter names to test when no parameters are present.
var defaultTestParams = []string{
	"q", "search", "query", "input",
	"name", "username", "email", "id", "user",
	"text", "message", "comment", "title", "content", "value", "data",
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
		Payload:     "<script>alert(1)</script>",
		Type:        "reflected",
		Severity:    SeverityHigh,
		Description: "Unescaped script tag injection detected - allows arbitrary JavaScript execution",
		Evidence:    "<script>alert(1)</script>",
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

// WithXSSTracer sets the OpenTelemetry tracer for the XSS scanner.
func WithXSSTracer(tracer trace.Tracer) XSSOption {
	return func(s *XSSScanner) {
		s.tracer = tracer
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
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanXSS)
		defer span.End()
	}

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

	// If no query parameters exist, test with common parameter names
	if len(params) == 0 {
		for _, paramName := range defaultTestParams {
			params.Set(paramName, "")
		}
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

	// Scan for DOM-based XSS vulnerabilities
	domFindings := s.scanForDOMXSS(ctx, parsedURL)
	result.Findings = append(result.Findings, domFindings...)
	result.Summary.VulnerabilitiesFound += len(domFindings)

	// Calculate final summary
	s.calculateSummary(result)

	return result
}

// ScanPOST scans a URL for XSS vulnerabilities using POST form data.
// Unlike Scan(), which tests GET query parameters, ScanPOST sends payloads in
// the request body as application/x-www-form-urlencoded data.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - targetURL: The URL to test (should not include query parameters)
//   - parameters: Form parameters and their original values. When testing each
//     parameter, all other parameters are included with their original values
//     to ensure proper form validation. If empty, tests common parameter names
//     (q, search, query, input) with empty default values.
//
// Returns:
//   - An XSSScanResult containing all findings, summary statistics, and any errors.
//     The result is never nil, even if errors occur.
//
// This method is typically called by the discovery module when scanning POST forms.
func (s *XSSScanner) ScanPOST(ctx context.Context, targetURL string, parameters map[string]string) *XSSScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanXSS)
		defer span.End()
	}

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

	// Use provided parameters or fallback to common parameter names
	params := parameters
	if len(params) == 0 {
		params = make(map[string]string)
		for _, paramName := range defaultTestParams {
			params[paramName] = ""
		}
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
	// First, check if the exact payload appears verbatim in the response
	// Note: This uses strings.Index which finds only the FIRST occurrence.
	// Known limitation: If the payload appears multiple times in different contexts
	// (e.g., once encoded, once unencoded), we only analyze the first occurrence.
	idx := strings.Index(body, payload)
	if idx == -1 {
		// Payload not found verbatim, try to find evidence instead
		return ContextUnknown, false, "low"
	}

	// Extract context around the payload for early validation
	// (same extraction logic used later)
	start := idx - 200
	if start < 0 {
		start = 0
	}
	end := idx + len(payload) + 200
	if end > len(body) {
		end = len(body)
	}
	contextSnippet := body[start:end]
	beforePayload := body[start:idx]

	// Early detection: If payload contains executable tags and appears verbatim, it's likely executable
	// This handles DVWA-style trivial reflected XSS.
	//
	// IMPORTANT: The <script> check runs FIRST, before the HTML comment heuristic.
	// A verbatim <script>...</script> in the response body is almost always executable.
	// The comment check below guards against edge cases where the script is inside a comment,
	// but we must not let a false-positive comment detection suppress a real finding.
	//
	// HTML comment check uses body[:idx] (full content before the payload) so that comments
	// opened and closed outside the 200-char context window are correctly accounted for.
	// Using only the context window could see a lone "<!--" from a comment that was already
	// closed hundreds of characters earlier, causing a false "inside comment" classification.

	// Check if payload is inside textarea - not directly executable
	if strings.Contains(beforePayload, "<textarea") && !strings.Contains(beforePayload, "</textarea>") {
		// Payload is inside textarea - skip early detection
		goto detailedAnalysis
	}

	if strings.Contains(payload, "<script") {
		// Only suppress if the payload is demonstrably inside an unclosed HTML comment.
		// Use the full body up to the payload position so we don't miss a "-->" that falls
		// outside the 200-char window.
		{
			fullBefore := body[:idx]
			lcStart := strings.LastIndex(fullBefore, "<!--")
			lcEnd := strings.LastIndex(fullBefore, "-->")
			if lcStart >= 0 && lcEnd < lcStart {
				// There is an unclosed comment before the payload — fall through to detailed analysis.
				goto detailedAnalysis
			}
		}
		return ContextHTMLBody, true, "high"
	}
	// Note: Event handler detection is also done in detailed analysis below.
	// We keep both: early detection catches common DVWA-style patterns quickly,
	// while detailed analysis (lines 472-478) provides more accurate context for edge cases.
	// Both return ContextHTMLBody for consistency, though detailed analysis may refine
	// to ContextHTMLAttribute if the payload is detected as an attribute value.
	if (strings.Contains(payload, "onerror") || strings.Contains(payload, "onload")) &&
		(strings.Contains(payload, "<img") || strings.Contains(payload, "<svg")) {
		return ContextHTMLBody, true, "high"
	}
	// iframe with javascript: protocol is also highly suspicious
	if strings.Contains(payload, "<iframe") && strings.Contains(payload, "javascript:") {
		return ContextHTMLBody, true, "high"
	}

	// Check if payload is inside HTML comment - not executable.
	// Use the full body up to the payload (body[:idx]) so that a comment opened and closed
	// far before the 200-char window is not mistakenly treated as unclosed.
	{
		fullBefore := body[:idx]
		lcStart := strings.LastIndex(fullBefore, "<!--")
		lcEnd := strings.LastIndex(fullBefore, "-->")
		if lcStart >= 0 && lcEnd < lcStart {
			goto detailedAnalysis
		}
	}

detailedAnalysis:

	// Now check if payload is HTML-encoded (would neutralize XSS)
	// This check comes AFTER checking for verbatim reflection
	// Note: This only checks common entity encodings (decimal entities like &#39;).
	// Hex entities (&#x27;) and other encodings like &apos; are not checked.
	// This is a conservative approach to avoid false negatives.
	htmlEncodedPayload := strings.ReplaceAll(payload, "<", "&lt;")
	htmlEncodedPayload = strings.ReplaceAll(htmlEncodedPayload, ">", "&gt;")
	htmlEncodedPayload = strings.ReplaceAll(htmlEncodedPayload, "\"", "&quot;")
	htmlEncodedPayload = strings.ReplaceAll(htmlEncodedPayload, "'", "&#39;")

	// IMPORTANT: We need to check if the payload at the specific location (idx) is HTML-encoded,
	// not just if an encoded version exists somewhere else in the body.
	// Check if the found payload instance is actually the encoded version
	encodedIdx := strings.Index(body, htmlEncodedPayload)
	if encodedIdx >= 0 && encodedIdx == idx {
		// The payload at the found location is HTML-encoded, not executable
		return ContextHTMLBody, false, "low"
	}
	// If encoded version exists elsewhere but not at idx, the unencoded version at idx is still vulnerable

	// Use the context snippet we already extracted for early detection
	context := contextSnippet

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
	if strings.Contains(payload, "<script") || strings.Contains(payload, "<img") || strings.Contains(payload, "<svg") || strings.Contains(payload, "<iframe") {
		tagPattern := regexp.MustCompile(`<(script|img|svg|iframe)[^>]*>`)
		if tagPattern.MatchString(payload) {
			// Check if payload is inside textarea (not directly executable)
			if strings.Contains(beforePayload, "<textarea") && !strings.Contains(beforePayload, "</textarea>") {
				// Payload is inside textarea - report as low confidence
				return ContextHTMLBody, false, "low"
			}

			// Check if payload is inside an HTML comment.
			// Use the full body up to the payload position (body[:idx]) so that comments
			// opened and closed outside the 200-char context window are correctly handled.
			{
				fullBefore := body[:idx]
				lastCommentStart := strings.LastIndex(fullBefore, "<!--")
				lastCommentEnd := strings.LastIndex(fullBefore, "-->")
				if lastCommentStart >= 0 && lastCommentEnd < lastCommentStart {
					// Comment is not closed before payload - payload is inside comment
					goto defaultAnalysis
				}
			}

			// Check if payload is inside a JavaScript comment
			// This is a simple check - more comprehensive would require parsing
			if strings.Contains(context, "*/") {
				lastJsCommentStart := strings.LastIndex(beforePayload, "/*")
				lastJsCommentEnd := strings.LastIndex(beforePayload, "*/")
				if lastJsCommentStart >= 0 && lastJsCommentEnd < lastJsCommentStart {
					// Inside JS block comment - skip
					goto defaultAnalysis
				}
			}

			// Tag is properly formed and not in a comment/textarea
			return ContextHTMLBody, true, "high"
		}
	}

defaultAnalysis:

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

	// Check responses in the success range (200-299) and redirect range (300-399)
	// We include redirects because some applications reflect payloads in redirect responses
	// The HTTP client may have followed redirects, but we still want to check the final response
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
	// Note: We check for both the original payload and the URL-encoded version
	// because some applications may reflect the encoded form without decoding
	urlEncodedPayload := url.QueryEscape(payload.Payload)
	payloadFound := strings.Contains(bodyStr, payload.Payload)
	encodedPayloadFound := strings.Contains(bodyStr, urlEncodedPayload)
	evidenceFound := strings.Contains(bodyStr, payload.Evidence)

	if payloadFound || encodedPayloadFound || evidenceFound {
		// If only the URL-encoded version is found, it's likely not executable
		// as it would appear as text rather than actual HTML/JS
		if !payloadFound && encodedPayloadFound {
			return nil
		}

		// If the payload is not found verbatim but only evidence is found,
		// it's likely HTML-encoded and not executable
		if !payloadFound && evidenceFound {
			// Evidence found but not the full payload - likely encoded
			return nil
		}

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

// testParameterPOST tests a single parameter for XSS vulnerability using POST.
func (s *XSSScanner) testParameterPOST(ctx context.Context, baseURL *url.URL, paramName string, payload xssPayload, allParameters map[string]string) *XSSFinding {
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
	// Note: We check for both the original payload and the URL-encoded version
	// because some applications may reflect the encoded form without decoding
	urlEncodedPayload := url.QueryEscape(payload.Payload)
	payloadFound := strings.Contains(bodyStr, payload.Payload)
	encodedPayloadFound := strings.Contains(bodyStr, urlEncodedPayload)
	evidenceFound := strings.Contains(bodyStr, payload.Evidence)

	if payloadFound || encodedPayloadFound || evidenceFound {
		// If only the URL-encoded version is found, it's likely not executable
		// as it would appear as text rather than actual HTML/JS
		if !payloadFound && encodedPayloadFound {
			return nil
		}

		// If the payload is not found verbatim but only evidence is found,
		// it's likely HTML-encoded and not executable
		if !payloadFound && evidenceFound {
			// Evidence found but not the full payload - likely encoded
			return nil
		}

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
			URL:         baseURL.String(),
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

// domSource represents a dangerous source of user-controlled data in client-side JavaScript.
type domSource struct {
	pattern     *regexp.Regexp
	name        string
	description string
}

// domSink represents a dangerous sink that can execute JavaScript code.
type domSink struct {
	pattern     *regexp.Regexp
	name        string
	description string
	severity    string
}

// getDOMSources returns a list of dangerous DOM sources.
func getDOMSources() []domSource {
	return []domSource{
		{
			pattern:     regexp.MustCompile(`location\.hash`),
			name:        "location.hash",
			description: "URL fragment identifier",
		},
		{
			pattern:     regexp.MustCompile(`location\.search`),
			name:        "location.search",
			description: "URL query string",
		},
		{
			pattern:     regexp.MustCompile(`location\.href`),
			name:        "location.href",
			description: "full URL",
		},
		{
			pattern:     regexp.MustCompile(`document\.referrer`),
			name:        "document.referrer",
			description: "referrer URL",
		},
		{
			pattern:     regexp.MustCompile(`window\.name`),
			name:        "window.name",
			description: "window name",
		},
		{
			pattern:     regexp.MustCompile(`document\.URL`),
			name:        "document.URL",
			description: "document URL",
		},
		{
			pattern:     regexp.MustCompile(`document\.documentURI`),
			name:        "document.documentURI",
			description: "document URI",
		},
		{
			pattern:     regexp.MustCompile(`postMessage`),
			name:        "postMessage",
			description: "cross-origin message",
		},
	}
}

// getDOMSinks returns a list of dangerous DOM sinks.
func getDOMSinks() []domSink {
	return []domSink{
		{
			pattern:     regexp.MustCompile(`\.innerHTML\s*=`),
			name:        "innerHTML",
			description: "Direct HTML injection via innerHTML assignment",
			severity:    SeverityHigh,
		},
		{
			pattern:     regexp.MustCompile(`\.outerHTML\s*=`),
			name:        "outerHTML",
			description: "Direct HTML injection via outerHTML assignment",
			severity:    SeverityHigh,
		},
		{
			pattern:     regexp.MustCompile(`document\.write\s*\(`),
			name:        "document.write",
			description: "Direct content injection via document.write",
			severity:    SeverityHigh,
		},
		{
			pattern:     regexp.MustCompile(`document\.writeln\s*\(`),
			name:        "document.writeln",
			description: "Direct content injection via document.writeln",
			severity:    SeverityHigh,
		},
		{
			pattern:     regexp.MustCompile(`\beval\s*\(`),
			name:        "eval",
			description: "Code execution via eval",
			severity:    SeverityHigh,
		},
		{
			pattern:     regexp.MustCompile(`setTimeout\s*\(`),
			name:        "setTimeout",
			description: "Code execution via setTimeout with string argument",
			severity:    SeverityHigh,
		},
		{
			pattern:     regexp.MustCompile(`setInterval\s*\(`),
			name:        "setInterval",
			description: "Code execution via setInterval with string argument",
			severity:    SeverityHigh,
		},
		{
			pattern:     regexp.MustCompile(`new\s+Function\s*\(`),
			name:        "Function constructor",
			description: "Code execution via Function constructor",
			severity:    SeverityHigh,
		},
		{
			pattern:     regexp.MustCompile(`location\.href\s*=`),
			name:        "location.href",
			description: "URL manipulation via location.href assignment",
			severity:    SeverityMedium,
		},
		{
			pattern:     regexp.MustCompile(`location\.assign\s*\(`),
			name:        "location.assign",
			description: "URL manipulation via location.assign",
			severity:    SeverityMedium,
		},
	}
}

// scanForDOMXSS scans for DOM-based XSS vulnerabilities by analyzing JavaScript code.
func (s *XSSScanner) scanForDOMXSS(ctx context.Context, targetURL *url.URL) []XSSFinding {
	findings := make([]XSSFinding, 0)

	// Apply rate limiting before making the request
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			return findings
		}
	}

	// Fetch the target page
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return findings
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
		return findings
	}
	defer resp.Body.Close()

	// Only check successful responses
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return findings
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return findings
	}

	bodyStr := string(body)

	// Extract JavaScript code from the page
	scriptContents := s.extractJavaScript(bodyStr)

	// Analyze each script for DOM XSS vulnerabilities
	for _, script := range scriptContents {
		domFindings := s.analyzeDOMXSS(targetURL.String(), script)
		findings = append(findings, domFindings...)
	}

	return findings
}

// extractJavaScript extracts JavaScript code from HTML content.
func (s *XSSScanner) extractJavaScript(htmlContent string) []string {
	scripts := make([]string, 0)

	// Extract inline script tags
	scriptTagPattern := regexp.MustCompile(`(?i)<script[^>]*>([\s\S]*?)</script>`)
	matches := scriptTagPattern.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			scriptContent := match[1]
			// Skip empty scripts or those that only reference external sources
			if strings.TrimSpace(scriptContent) != "" {
				scripts = append(scripts, scriptContent)
			}
		}
	}

	// Extract event handler attributes (onclick, onerror, onload, etc.)
	eventHandlerPattern := regexp.MustCompile(`(?i)\bon\w+\s*=\s*["']([^"']+)["']`)
	eventMatches := eventHandlerPattern.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range eventMatches {
		if len(match) > 1 {
			eventCode := match[1]
			if strings.TrimSpace(eventCode) != "" {
				scripts = append(scripts, eventCode)
			}
		}
	}

	return scripts
}

// analyzeDOMXSS analyzes JavaScript code for DOM-based XSS vulnerabilities.
func (s *XSSScanner) analyzeDOMXSS(url string, scriptContent string) []XSSFinding {
	findings := make([]XSSFinding, 0)

	sources := getDOMSources()
	sinks := getDOMSinks()

	// Check for dangerous sinks
	for _, sink := range sinks {
		if sink.pattern.MatchString(scriptContent) {
			// Found a dangerous sink, now check for sources
			confidence := "low"
			detectedSources := make([]string, 0)

			for _, source := range sources {
				if source.pattern.MatchString(scriptContent) {
					detectedSources = append(detectedSources, source.name)
				}
			}

			// Determine confidence based on source detection
			if len(detectedSources) > 0 {
				// Check if source and sink appear in close proximity (source-to-sink flow)
				if s.detectSourceToSinkFlow(scriptContent, sources, sink) {
					confidence = "high"
				} else {
					confidence = "medium"
				}
			}

			// Create finding
			evidence := s.extractDOMEvidence(scriptContent, sink.pattern)
			sourcesStr := "Unknown source"
			if len(detectedSources) > 0 {
				sourcesStr = strings.Join(detectedSources, ", ")
			}

			description := fmt.Sprintf("%s - Dangerous sink '%s' detected. User-controlled data from %s may reach this sink.",
				sink.description, sink.name, sourcesStr)

			finding := XSSFinding{
				URL:         url,
				Parameter:   "DOM-based",
				Payload:     fmt.Sprintf("Sink: %s, Sources: %s", sink.name, sourcesStr),
				Evidence:    evidence,
				Severity:    sink.severity,
				Type:        "dom",
				Description: description,
				Remediation: s.getRemediation("dom"),
				Confidence:  confidence,
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// detectSourceToSinkFlow checks if there's a direct flow from source to sink.
func (s *XSSScanner) detectSourceToSinkFlow(scriptContent string, sources []domSource, sink domSink) bool {
	// Split the script into lines for line-by-line analysis
	lines := strings.Split(scriptContent, "\n")

	// Look for patterns like: element.innerHTML = location.hash
	// or var x = location.hash; element.innerHTML = x;
	sinkMatches := sink.pattern.FindAllStringIndex(scriptContent, -1)
	if len(sinkMatches) == 0 {
		return false
	}

	// For each sink occurrence, check if there's a source nearby
	for _, sinkMatch := range sinkMatches {
		// Extract a window of 200 characters before the sink
		start := sinkMatch[0] - 200
		if start < 0 {
			start = 0
		}
		end := sinkMatch[1] + 100
		if end > len(scriptContent) {
			end = len(scriptContent)
		}

		window := scriptContent[start:end]

		// Check if any source appears in this window
		for _, source := range sources {
			if source.pattern.MatchString(window) {
				return true
			}
		}
	}

	// Also check for variable assignment patterns
	for _, line := range lines {
		// Check if a source is assigned to a variable
		for _, source := range sources {
			if source.pattern.MatchString(line) {
				// Extract variable name
				varPattern := regexp.MustCompile(`(\w+)\s*=.*` + regexp.QuoteMeta(source.name))
				if varMatch := varPattern.FindStringSubmatch(line); len(varMatch) > 1 {
					varName := varMatch[1]
					// Check if this variable is used in a sink
					if strings.Contains(scriptContent, varName) && sink.pattern.MatchString(scriptContent) {
						// Simple heuristic: if the variable appears near the sink
						sinkLines := strings.Split(scriptContent, "\n")
						for _, sinkLine := range sinkLines {
							if sink.pattern.MatchString(sinkLine) && strings.Contains(sinkLine, varName) {
								return true
							}
						}
					}
				}
			}
		}
	}

	return false
}

// extractDOMEvidence extracts evidence of the DOM XSS vulnerability.
func (s *XSSScanner) extractDOMEvidence(scriptContent string, pattern *regexp.Regexp) string {
	matches := pattern.FindStringIndex(scriptContent)
	if matches == nil {
		return "Pattern detected in JavaScript code"
	}

	// Extract context around the match (up to 100 characters)
	start := matches[0] - 30
	if start < 0 {
		start = 0
	}
	end := matches[1] + 30
	if end > len(scriptContent) {
		end = len(scriptContent)
	}

	snippet := scriptContent[start:end]
	// Clean up the snippet
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	snippet = strings.ReplaceAll(snippet, "\t", " ")
	// Collapse multiple spaces
	snippet = regexp.MustCompile(`\s+`).ReplaceAllString(snippet, " ")
	snippet = strings.TrimSpace(snippet)

	return fmt.Sprintf("...%s...", snippet)
}

// VerifyFinding re-tests an XSS finding with payload variants to confirm it's reproducible.
func (s *XSSScanner) VerifyFinding(ctx context.Context, finding *XSSFinding, config VerificationConfig) (*VerificationResult, error) {
	if finding == nil {
		return nil, fmt.Errorf("finding is nil")
	}

	// DOM-based findings are not verified through re-testing with payloads
	if finding.Type == "dom" {
		return &VerificationResult{
			Verified:    true,
			Attempts:    1,
			Confidence:  0.7,
			Explanation: "DOM-based XSS findings are verified through static analysis",
		}, nil
	}

	// Generate payload variants for verification
	variants := s.generatePayloadVariants(finding.Payload)

	// Parse the original URL to extract parameters
	parsedURL, err := url.Parse(finding.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL in finding: %w", err)
	}

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

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Check if variant is reflected and executable
		bodyStr := string(body)
		if strings.Contains(bodyStr, variant) {
			_, isExecutable, _ := s.analyzeContext(bodyStr, variant)
			if isExecutable {
				successCount++
			}
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	// Calculate verification result
	confidence := float64(successCount) / float64(totalAttempts)
	verified := confidence >= 0.5 // At least 50% of variants must succeed

	explanation := fmt.Sprintf("Verified %d out of %d payload variants successfully reproduced the vulnerability",
		successCount, totalAttempts)

	if !verified {
		explanation = fmt.Sprintf("Only %d out of %d payload variants reproduced the vulnerability - likely a false positive",
			successCount, totalAttempts)
	}

	return &VerificationResult{
		Verified:    verified,
		Attempts:    totalAttempts,
		Confidence:  confidence,
		Explanation: explanation,
	}, nil
}

// generatePayloadVariants creates different encodings and variations of the original payload.
func (s *XSSScanner) generatePayloadVariants(originalPayload string) []string {
	variants := make([]string, 0)

	// Add the original payload
	variants = append(variants, originalPayload)

	// Case variations
	if strings.Contains(originalPayload, "<script>") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "<script>", "<SCRIPT>"))
		variants = append(variants, strings.ReplaceAll(originalPayload, "<script>", "<ScRiPt>"))
	}

	// Different quote styles
	if strings.Contains(originalPayload, "alert('XSS')") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "alert('XSS')", "alert(\"XSS\")"))
		variants = append(variants, strings.ReplaceAll(originalPayload, "alert('XSS')", "alert(`XSS`)"))
	}

	// URL encoding variations
	if strings.Contains(originalPayload, "<") {
		urlEncoded := strings.ReplaceAll(originalPayload, "<", "%3C")
		urlEncoded = strings.ReplaceAll(urlEncoded, ">", "%3E")
		variants = append(variants, urlEncoded)
	}

	// Alternative event handlers
	if strings.Contains(originalPayload, "onerror") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "onerror", "onload"))
	}
	if strings.Contains(originalPayload, "onload") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "onload", "onerror"))
	}

	// HTML5 variations
	if strings.Contains(originalPayload, "<img") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "<img", "<svg"))
	}
	if strings.Contains(originalPayload, "<svg") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "<svg", "<img"))
	}

	return variants
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
