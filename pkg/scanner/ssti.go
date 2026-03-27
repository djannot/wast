// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// SSTIScanner performs active SSTI (Server-Side Template Injection) vulnerability detection.
type SSTIScanner struct {
	client      HTTPClient
	userAgent   string
	timeout     time.Duration
	authConfig  *auth.AuthConfig
	rateLimiter ratelimit.Limiter
	tracer      trace.Tracer
}

// SSTIScanResult represents the result of an SSTI vulnerability scan.
type SSTIScanResult struct {
	Target   string        `json:"target" yaml:"target"`
	Findings []SSTIFinding `json:"findings" yaml:"findings"`
	Summary  SSTISummary   `json:"summary" yaml:"summary"`
	Errors   []string      `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// SSTIFinding represents a single SSTI vulnerability finding.
type SSTIFinding struct {
	URL            string `json:"url" yaml:"url"`
	Parameter      string `json:"parameter" yaml:"parameter"`
	Payload        string `json:"payload" yaml:"payload"`
	Evidence       string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Severity       string `json:"severity" yaml:"severity"`
	TemplateEngine string `json:"template_engine" yaml:"template_engine"` // "jinja2", "twig", "freemarker", "thymeleaf", "generic"
	Description    string `json:"description" yaml:"description"`
	Remediation    string `json:"remediation" yaml:"remediation"`
	Confidence     string `json:"confidence" yaml:"confidence"` // "high", "medium", "low"
	Verified       bool   `json:"verified" yaml:"verified"`
}

// SSTISummary provides an overview of the SSTI scan results.
type SSTISummary struct {
	TotalTests           int `json:"total_tests" yaml:"total_tests"`
	VulnerabilitiesFound int `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	HighSeverityCount    int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount  int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount     int `json:"low_severity_count" yaml:"low_severity_count"`
}

// sstiPayload represents a test payload for SSTI detection.
type sstiPayload struct {
	Payload        string
	TemplateEngine string // "jinja2", "twig", "freemarker", "thymeleaf", "generic"
	Severity       string
	Description    string
	ExpectedResult string            // What to look for in the response (e.g., "49" for 7*7)
	Validator      func(string) bool // Custom validation function
}

// sstiPayloads is the list of safe detection payloads to test for SSTI.
var sstiPayloads = []sstiPayload{
	// Jinja2/Twig - Mathematical expression
	{
		Payload:        "{{7*7}}",
		TemplateEngine: "jinja2",
		Severity:       SeverityHigh,
		Description:    "Jinja2/Twig template injection detected - mathematical expression evaluated",
		ExpectedResult: "49",
		Validator:      nil,
	},
	// Jinja2 - String multiplication
	{
		Payload:        "{{7*'7'}}",
		TemplateEngine: "jinja2",
		Severity:       SeverityHigh,
		Description:    "Jinja2 template injection detected - string multiplication evaluated",
		ExpectedResult: "7777777",
		Validator:      nil,
	},
	// Freemarker - Mathematical expression
	{
		Payload:        "${7*7}",
		TemplateEngine: "freemarker",
		Severity:       SeverityHigh,
		Description:    "Freemarker template injection detected - mathematical expression evaluated",
		ExpectedResult: "49",
		Validator:      nil,
	},
	// Freemarker - Alternative syntax
	{
		Payload:        "<#assign x=7*7>${x}",
		TemplateEngine: "freemarker",
		Severity:       SeverityHigh,
		Description:    "Freemarker template injection detected - variable assignment and evaluation",
		ExpectedResult: "49",
		Validator:      nil,
	},
	// Velocity - Mathematical expression
	{
		Payload:        "#set($x=7*7)$x",
		TemplateEngine: "velocity",
		Severity:       SeverityHigh,
		Description:    "Velocity template injection detected - mathematical expression evaluated",
		ExpectedResult: "49",
		Validator:      nil,
	},
	// Smarty - Mathematical expression
	{
		Payload:        "{7*7}",
		TemplateEngine: "smarty",
		Severity:       SeverityHigh,
		Description:    "Smarty template injection detected - mathematical expression evaluated",
		ExpectedResult: "49",
		Validator:      nil,
	},
	// Thymeleaf - Mathematical expression
	{
		Payload:        "${7*7}",
		TemplateEngine: "thymeleaf",
		Severity:       SeverityHigh,
		Description:    "Thymeleaf template injection detected - mathematical expression evaluated",
		ExpectedResult: "49",
		Validator:      nil,
	},
	// Generic expression language
	{
		Payload:        "${7+7}",
		TemplateEngine: "generic",
		Severity:       SeverityHigh,
		Description:    "Template injection detected - mathematical expression evaluated",
		ExpectedResult: "14",
		Validator:      nil,
	},
	// ERB (Ruby) - Mathematical expression
	{
		Payload:        "<%= 7*7 %>",
		TemplateEngine: "erb",
		Severity:       SeverityHigh,
		Description:    "ERB (Ruby) template injection detected - mathematical expression evaluated",
		ExpectedResult: "49",
		Validator:      nil,
	},
	// Handlebars - Mathematical expression with helper
	{
		Payload:        "{{7}}{{7}}",
		TemplateEngine: "handlebars",
		Severity:       SeverityMedium,
		Description:    "Handlebars template injection detected - values reflected",
		ExpectedResult: "77",
		Validator:      nil,
	},
}

// SSTIOption is a function that configures an SSTIScanner.
type SSTIOption func(*SSTIScanner)

// WithSSTIHTTPClient sets a custom HTTP client for the SSTI scanner.
func WithSSTIHTTPClient(c HTTPClient) SSTIOption {
	return func(s *SSTIScanner) {
		s.client = c
	}
}

// WithSSTIUserAgent sets the user agent string for the SSTI scanner.
func WithSSTIUserAgent(ua string) SSTIOption {
	return func(s *SSTIScanner) {
		s.userAgent = ua
	}
}

// WithSSTITimeout sets the timeout for HTTP requests.
func WithSSTITimeout(d time.Duration) SSTIOption {
	return func(s *SSTIScanner) {
		s.timeout = d
	}
}

// WithSSTIAuth sets the authentication configuration for the SSTI scanner.
func WithSSTIAuth(config *auth.AuthConfig) SSTIOption {
	return func(s *SSTIScanner) {
		s.authConfig = config
	}
}

// WithSSTIRateLimiter sets a rate limiter for the SSTI scanner.
func WithSSTIRateLimiter(limiter ratelimit.Limiter) SSTIOption {
	return func(s *SSTIScanner) {
		s.rateLimiter = limiter
	}
}

// WithSSTIRateLimitConfig sets rate limiting from a configuration.
func WithSSTIRateLimitConfig(cfg ratelimit.Config) SSTIOption {
	return func(s *SSTIScanner) {
		s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg)
	}
}

// WithSSTITracer sets the OpenTelemetry tracer for the SSTI scanner.
func WithSSTITracer(tracer trace.Tracer) SSTIOption {
	return func(s *SSTIScanner) {
		s.tracer = tracer
	}
}

// NewSSTIScanner creates a new SSTIScanner with the given options.
func NewSSTIScanner(opts ...SSTIOption) *SSTIScanner {
	s := &SSTIScanner{
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

// Scan performs an SSTI vulnerability scan on the given target URL.
func (s *SSTIScanner) Scan(ctx context.Context, targetURL string) *SSTIScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanSSTI)
		defer span.End()
	}

	result := &SSTIScanResult{
		Target:   targetURL,
		Findings: make([]SSTIFinding, 0),
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
		params.Set("q", "")
		params.Set("search", "")
		params.Set("query", "")
		params.Set("input", "")
		params.Set("name", "")
		params.Set("template", "")
	}

	// Test each parameter with each payload
	for paramName := range params {
		for _, payload := range sstiPayloads {
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

// getBaselineResponse fetches a baseline response with a benign value to detect false positives.
func (s *SSTIScanner) getBaselineResponse(ctx context.Context, baseURL *url.URL, paramName string) string {
	// Create a copy of the URL with a benign baseline value
	baselineURL := *baseURL
	q := baselineURL.Query()
	q.Set(paramName, "WAST_BASELINE_12345")
	baselineURL.RawQuery = q.Encode()

	// Create the baseline request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baselineURL.String(), nil)
	if err != nil {
		return ""
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
		return ""
	}
	defer resp.Body.Close()

	// Only read successful responses
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return ""
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return string(body)
}

// testParameter tests a single parameter with a specific payload.
func (s *SSTIScanner) testParameter(ctx context.Context, baseURL *url.URL, paramName string, payload sstiPayload) *SSTIFinding {
	// Step 1: Get baseline response with a benign value
	baselineBody := s.getBaselineResponse(ctx, baseURL, paramName)

	// Step 2: Create a copy of the URL with the test payload
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

	// Step 3: Compare with baseline - only flag if result appears in payload response but NOT in baseline
	if s.detectTemplateInjection(bodyStr, payload, baselineBody) {
		confidence := s.calculateConfidence(bodyStr, payload)

		// Vulnerability found!
		finding := &SSTIFinding{
			URL:            testURL.String(),
			Parameter:      paramName,
			Payload:        payload.Payload,
			Evidence:       s.extractEvidence(bodyStr, payload.ExpectedResult, payload.Payload),
			Severity:       payload.Severity,
			TemplateEngine: payload.TemplateEngine,
			Description:    payload.Description,
			Remediation:    s.getRemediation(),
			Confidence:     confidence,
		}
		return finding
	}

	return nil
}

// detectTemplateInjection checks if the response indicates template injection.
// It compares the payload response with a baseline to avoid false positives.
func (s *SSTIScanner) detectTemplateInjection(body string, payload sstiPayload, baselineBody string) bool {
	// Check for expected result
	if payload.ExpectedResult != "" && strings.Contains(body, payload.ExpectedResult) {
		// If expected result already exists in baseline, it's not injection - it's naturally present in the page
		if baselineBody != "" && strings.Contains(baselineBody, payload.ExpectedResult) {
			return false
		}

		// Make sure it's not just the payload being reflected
		// The expected result should appear without the template syntax
		if !strings.Contains(body, payload.Payload) || s.isEvaluated(body, payload) {
			return true
		}
	}

	// Use custom validator if provided
	if payload.Validator != nil {
		return payload.Validator(body)
	}

	return false
}

// isEvaluated checks if the template was actually evaluated (not just reflected).
func (s *SSTIScanner) isEvaluated(body string, payload sstiPayload) bool {
	// Check if the expected result appears separately from the payload
	// This helps distinguish evaluation from simple reflection

	// Look for the expected result in isolation
	expectedPattern := regexp.MustCompile(`(?:^|[^\d])` + regexp.QuoteMeta(payload.ExpectedResult) + `(?:[^\d]|$)`)
	if expectedPattern.MatchString(body) {
		// Check if the template syntax is NOT present in the same context
		// This would indicate evaluation rather than reflection
		if strings.Contains(body, payload.ExpectedResult) {
			// Count occurrences
			expectedCount := strings.Count(body, payload.ExpectedResult)
			payloadCount := strings.Count(body, payload.Payload)

			// If we see the expected result more times than the payload, or
			// if the expected result appears but the payload doesn't, it's likely evaluated
			if expectedCount > payloadCount {
				return true
			}
		}
	}

	return false
}

// calculateConfidence determines the confidence level of the finding.
func (s *SSTIScanner) calculateConfidence(body string, payload sstiPayload) string {
	// High confidence if expected result is found and payload is not visible
	if strings.Contains(body, payload.ExpectedResult) && !strings.Contains(body, payload.Payload) {
		return "high"
	}

	// Medium confidence if both expected result and payload are visible
	if strings.Contains(body, payload.ExpectedResult) && strings.Contains(body, payload.Payload) {
		// Check if they appear in different contexts (evaluation happened)
		if s.isEvaluated(body, payload) {
			return "high"
		}
		return "medium"
	}

	return "low"
}

// extractEvidence extracts a snippet of the response containing the vulnerability evidence.
func (s *SSTIScanner) extractEvidence(body, evidence, payload string) string {
	// Look for the evidence string (expected result)
	searchStr := evidence
	if !strings.Contains(body, searchStr) {
		searchStr = payload
	}

	idx := strings.Index(body, searchStr)
	if idx == -1 {
		return "Template expression evaluated in response"
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

// getRemediation returns remediation guidance for SSTI vulnerabilities.
func (s *SSTIScanner) getRemediation() string {
	return "Avoid passing user input directly to template engines. If dynamic templating is required, use a sandboxed environment with strict controls. Implement input validation and use template engines in 'safe mode' if available. Consider using logic-less templates (e.g., Mustache). Never allow users to control template selection or content."
}

// calculateSummary calculates the summary statistics for the scan.
func (s *SSTIScanner) calculateSummary(result *SSTIScanResult) {
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

// VerifyFinding re-tests an SSTI finding with payload variants to confirm it's reproducible.
func (s *SSTIScanner) VerifyFinding(ctx context.Context, finding *SSTIFinding, config VerificationConfig) (*VerificationResult, error) {
	if finding == nil {
		return nil, fmt.Errorf("finding is nil")
	}

	// Generate payload variants for verification
	variants := s.generatePayloadVariants(finding.Payload, finding.TemplateEngine)

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
		q.Set(finding.Parameter, variant.payload)
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

		// Check if variant result is in the response
		bodyStr := string(body)
		if strings.Contains(bodyStr, variant.expectedResult) {
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

// payloadVariant represents a variant payload for verification.
type payloadVariant struct {
	payload        string
	expectedResult string
}

// generatePayloadVariants creates different variations of the original payload.
func (s *SSTIScanner) generatePayloadVariants(originalPayload string, engine string) []payloadVariant {
	variants := make([]payloadVariant, 0)

	// Add the original payload
	variants = append(variants, payloadVariant{
		payload:        originalPayload,
		expectedResult: s.getExpectedResult(originalPayload),
	})

	// Generate engine-specific variants
	switch engine {
	case "jinja2", "twig":
		// Add variations with different mathematical operations
		variants = append(variants, payloadVariant{
			payload:        "{{8*8}}",
			expectedResult: "64",
		})
		variants = append(variants, payloadVariant{
			payload:        "{{9*9}}",
			expectedResult: "81",
		})
		variants = append(variants, payloadVariant{
			payload:        "{{7+7}}",
			expectedResult: "14",
		})

	case "freemarker":
		variants = append(variants, payloadVariant{
			payload:        "${8*8}",
			expectedResult: "64",
		})
		variants = append(variants, payloadVariant{
			payload:        "${9*9}",
			expectedResult: "81",
		})

	case "thymeleaf":
		variants = append(variants, payloadVariant{
			payload:        "${8*8}",
			expectedResult: "64",
		})
		variants = append(variants, payloadVariant{
			payload:        "${6+6}",
			expectedResult: "12",
		})

	case "generic":
		// Try multiple expression syntaxes
		variants = append(variants, payloadVariant{
			payload:        "${8+8}",
			expectedResult: "16",
		})
		variants = append(variants, payloadVariant{
			payload:        "{{8+8}}",
			expectedResult: "16",
		})

	case "erb":
		variants = append(variants, payloadVariant{
			payload:        "<%= 8*8 %>",
			expectedResult: "64",
		})
		variants = append(variants, payloadVariant{
			payload:        "<%= 6+6 %>",
			expectedResult: "12",
		})
	}

	return variants
}

// getExpectedResult determines the expected result for a given payload.
func (s *SSTIScanner) getExpectedResult(payload string) string {
	// Simple expression evaluator for common patterns
	// Look for patterns like {{7*7}}, ${7*7}, <%= 7*7 %>, etc.

	// Extract the expression
	exprPattern := regexp.MustCompile(`[\{\<\[].*?(\d+)\s*([*+\-/])\s*(\d+)`)
	matches := exprPattern.FindStringSubmatch(payload)

	if len(matches) >= 4 {
		left, _ := strconv.Atoi(matches[1])
		op := matches[2]
		right, _ := strconv.Atoi(matches[3])

		var result int
		switch op {
		case "*":
			result = left * right
		case "+":
			result = left + right
		case "-":
			result = left - right
		case "/":
			if right != 0 {
				result = left / right
			}
		}

		return strconv.Itoa(result)
	}

	return ""
}

// String returns a human-readable representation of the scan result.
func (r *SSTIScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("SSTI Vulnerability Scan for: %s\n", r.Target))
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
			sb.WriteString(fmt.Sprintf("\n  %d. [%s] %s SSTI\n", i+1, strings.ToUpper(f.Severity), f.TemplateEngine))
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
		sb.WriteString("\nNo SSTI vulnerabilities detected.\n")
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
func (r *SSTIScanResult) HasResults() bool {
	return len(r.Findings) > 0 || r.Summary.TotalTests > 0
}
