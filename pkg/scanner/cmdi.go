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

// CMDiScanner performs active command injection vulnerability detection.
type CMDiScanner struct {
	client         HTTPClient
	userAgent      string
	timeout        time.Duration
	authConfig     *auth.AuthConfig
	rateLimiter    ratelimit.Limiter
	tracer         trace.Tracer
	timeBasedDelay time.Duration // Default 5 seconds
}

// CMDiScanResult represents the result of a command injection vulnerability scan.
type CMDiScanResult struct {
	Target   string        `json:"target" yaml:"target"`
	Findings []CMDiFinding `json:"findings" yaml:"findings"`
	Summary  CMDiSummary   `json:"summary" yaml:"summary"`
	Errors   []string      `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// CMDiFinding represents a single command injection vulnerability finding.
type CMDiFinding struct {
	URL                  string `json:"url" yaml:"url"`
	Parameter            string `json:"parameter" yaml:"parameter"`
	Payload              string `json:"payload" yaml:"payload"`
	Evidence             string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Severity             string `json:"severity" yaml:"severity"`
	Type                 string `json:"type" yaml:"type"`       // "time-based", "error-based", "output-based"
	OSType               string `json:"os_type" yaml:"os_type"` // "unix", "windows", "unknown"
	Description          string `json:"description" yaml:"description"`
	Remediation          string `json:"remediation" yaml:"remediation"`
	Confidence           string `json:"confidence" yaml:"confidence"` // "high", "medium", "low"
	Verified             bool   `json:"verified" yaml:"verified"`
	VerificationAttempts int    `json:"verification_attempts,omitempty" yaml:"verification_attempts,omitempty"`
}

// CMDiSummary provides an overview of the command injection scan results.
type CMDiSummary struct {
	TotalTests           int `json:"total_tests" yaml:"total_tests"`
	VulnerabilitiesFound int `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	HighSeverityCount    int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount  int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount     int `json:"low_severity_count" yaml:"low_severity_count"`
}

// cmdiPayload represents a test payload for command injection detection.
type cmdiPayload struct {
	Payload       string
	Type          string // "time-based", "error-based", "output-based"
	OSType        string // "unix", "windows", "both"
	Severity      string
	Description   string
	ErrorPattern  *regexp.Regexp // Pattern to match in response for error-based detection
	ExpectedDelay time.Duration  // Expected delay for time-based payloads
}

// Common shell error patterns from various operating systems.
var cmdErrorPatterns = []*regexp.Regexp{
	// Unix/Linux shell errors
	regexp.MustCompile(`(?i)/bin/(ba)?sh:`),
	regexp.MustCompile(`(?i)command not found`),
	regexp.MustCompile(`(?i)sh: \d+: .*: not found`),
	regexp.MustCompile(`(?i)bash: .*: command not found`),
	regexp.MustCompile(`(?i)cannot execute`),
	regexp.MustCompile(`(?i)permission denied`),
	regexp.MustCompile(`(?i)/bin/sh: .*: not found`),
	regexp.MustCompile(`(?i)sh: .*: No such file or directory`),

	// Windows command errors
	regexp.MustCompile(`(?i)not recognized as an internal or external command`),
	regexp.MustCompile(`(?i)'.*' is not recognized`),
	regexp.MustCompile(`(?i)The system cannot find the path specified`),
	regexp.MustCompile(`(?i)cmd\.exe`),
	regexp.MustCompile(`(?i)The filename, directory name, or volume label syntax is incorrect`),

	// Generic execution errors
	regexp.MustCompile(`(?i)syntax error near unexpected token`),
	regexp.MustCompile(`(?i)unexpected EOF while looking for matching`),
	regexp.MustCompile(`(?i)command failed`),
	regexp.MustCompile(`(?i)exec format error`),
}

// cmdiPayloads is the list of safe detection payloads to test for command injection.
var cmdiPayloads = []cmdiPayload{
	// Time-based Unix/Linux payloads
	{
		Payload:       ";sleep 5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (semicolon separator)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "|sleep 5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (pipe separator)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "&&sleep 5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (AND separator)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "||sleep 5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (OR separator)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "`sleep 5`",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (backtick substitution)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "$(sleep 5)",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (command substitution)",
		ExpectedDelay: 5 * time.Second,
	},

	// URL-encoded time-based payloads
	{
		Payload:       "%3Bsleep+5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using URL-encoded payload",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "%7Csleep+5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using URL-encoded payload (pipe)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "%26%26sleep+5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using URL-encoded payload (AND)",
		ExpectedDelay: 5 * time.Second,
	},

	// Time-based Windows payloads
	{
		Payload:       "&timeout 5",
		Type:          "time-based",
		OSType:        "windows",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Windows timeout",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "|timeout 5",
		Type:          "time-based",
		OSType:        "windows",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Windows timeout (pipe)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "&&timeout 5",
		Type:          "time-based",
		OSType:        "windows",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Windows timeout (AND)",
		ExpectedDelay: 5 * time.Second,
	},

	// Error-based Unix/Linux payloads
	{
		Payload:      ";id",
		Type:         "error-based",
		OSType:       "unix",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Unix id command separator (semicolon)",
		ErrorPattern: nil, // Will check against all patterns
	},
	{
		Payload:      "|whoami",
		Type:         "error-based",
		OSType:       "unix",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Unix whoami command (pipe)",
		ErrorPattern: nil,
	},
	{
		Payload:      "&&id",
		Type:         "error-based",
		OSType:       "unix",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Unix id command (AND)",
		ErrorPattern: nil,
	},
	{
		Payload:      "`id`",
		Type:         "error-based",
		OSType:       "unix",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Unix id command (backtick)",
		ErrorPattern: nil,
	},
	{
		Payload:      "$(whoami)",
		Type:         "error-based",
		OSType:       "unix",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Unix whoami command (command substitution)",
		ErrorPattern: nil,
	},

	// Error-based Windows payloads
	{
		Payload:      "& dir",
		Type:         "error-based",
		OSType:       "windows",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Windows dir command",
		ErrorPattern: nil,
	},
	{
		Payload:      "| type",
		Type:         "error-based",
		OSType:       "windows",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Windows type command (pipe)",
		ErrorPattern: nil,
	},
	{
		Payload:      "&& whoami",
		Type:         "error-based",
		OSType:       "windows",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Windows whoami command",
		ErrorPattern: nil,
	},
	{
		Payload:      "|| whoami",
		Type:         "error-based",
		OSType:       "windows",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Windows whoami command (OR)",
		ErrorPattern: nil,
	},
}

// Common vulnerable parameter names to test.
var cmdiVulnerableParams = []string{
	"cmd", "exec", "command", "ping", "query", "jump", "code", "reg",
	"do", "func", "arg", "option", "process", "step", "daemon", "dir",
	"download", "log", "ip", "cli", "shell", "sys", "run", "execute",
}

// CMDiOption is a function that configures a CMDiScanner.
type CMDiOption func(*CMDiScanner)

// WithCMDiHTTPClient sets a custom HTTP client for the command injection scanner.
func WithCMDiHTTPClient(c HTTPClient) CMDiOption {
	return func(s *CMDiScanner) {
		s.client = c
	}
}

// WithCMDiUserAgent sets the user agent string for the command injection scanner.
func WithCMDiUserAgent(ua string) CMDiOption {
	return func(s *CMDiScanner) {
		s.userAgent = ua
	}
}

// WithCMDiTimeout sets the timeout for HTTP requests.
func WithCMDiTimeout(d time.Duration) CMDiOption {
	return func(s *CMDiScanner) {
		s.timeout = d
	}
}

// WithCMDiAuth sets the authentication configuration for the command injection scanner.
func WithCMDiAuth(config *auth.AuthConfig) CMDiOption {
	return func(s *CMDiScanner) {
		s.authConfig = config
	}
}

// WithCMDiRateLimiter sets a rate limiter for the command injection scanner.
func WithCMDiRateLimiter(limiter ratelimit.Limiter) CMDiOption {
	return func(s *CMDiScanner) {
		s.rateLimiter = limiter
	}
}

// WithCMDiRateLimitConfig sets rate limiting from a configuration.
func WithCMDiRateLimitConfig(cfg ratelimit.Config) CMDiOption {
	return func(s *CMDiScanner) {
		s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg)
	}
}

// WithCMDiTracer sets the OpenTelemetry tracer for the command injection scanner.
func WithCMDiTracer(tracer trace.Tracer) CMDiOption {
	return func(s *CMDiScanner) {
		s.tracer = tracer
	}
}

// WithCMDiTimeBasedDelay sets the expected delay duration for time-based command injection detection.
func WithCMDiTimeBasedDelay(d time.Duration) CMDiOption {
	return func(s *CMDiScanner) {
		s.timeBasedDelay = d
	}
}

// NewCMDiScanner creates a new CMDiScanner with the given options.
func NewCMDiScanner(opts ...CMDiOption) *CMDiScanner {
	s := &CMDiScanner{
		userAgent:      "WAST/1.0 (Web Application Security Testing)",
		timeout:        30 * time.Second,
		timeBasedDelay: 5 * time.Second, // Default delay for time-based detection
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

// Scan performs a command injection vulnerability scan on the given target URL.
func (s *CMDiScanner) Scan(ctx context.Context, targetURL string) *CMDiScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanCMDi)
		defer span.End()
	}

	result := &CMDiScanResult{
		Target:   targetURL,
		Findings: make([]CMDiFinding, 0),
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

	// If no query parameters exist, test with common vulnerable parameter names
	if len(params) == 0 {
		for _, paramName := range cmdiVulnerableParams {
			params.Set(paramName, "test")
		}
	}

	// Get baseline responses and timing for detection
	baselineResponses := make(map[string]*baselineResponse)
	baselineTiming := make(map[string]time.Duration)
	for paramName := range params {
		baseline, duration := s.getBaselineWithTiming(ctx, parsedURL, paramName)
		if baseline != nil {
			baselineResponses[paramName] = baseline
			baselineTiming[paramName] = duration
		}
	}

	// Test each parameter with each payload
	for paramName := range params {
		for _, payload := range cmdiPayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			var finding *CMDiFinding
			if payload.Type == "time-based" {
				// Time-based detection
				baseline := baselineTiming[paramName]
				finding = s.testTimeBased(ctx, parsedURL, paramName, payload, baseline)
			} else {
				// Error-based detection
				finding = s.testErrorBased(ctx, parsedURL, paramName, payload)
			}

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

// getBaselineWithTiming makes a request with the original parameter value to establish a baseline
// and measures the request duration for time-based detection.
func (s *CMDiScanner) getBaselineWithTiming(ctx context.Context, baseURL *url.URL, paramName string) (*baselineResponse, time.Duration) {
	// Create a copy of the URL with the original parameter value
	testURL := *baseURL
	q := testURL.Query()

	// Use original value if it exists, otherwise use a safe default
	originalValue := q.Get(paramName)
	if originalValue == "" {
		originalValue = "test"
		q.Set(paramName, originalValue)
	}
	testURL.RawQuery = q.Encode()

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return nil, 0
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	// Apply authentication configuration
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	// Measure request time
	startTime := time.Now()
	resp, err := s.client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0
	}

	baseline := &baselineResponse{
		StatusCode:  resp.StatusCode,
		BodyLength:  len(body),
		BodyHash:    fmt.Sprintf("%x", len(body)), // Simple hash for comparison
		ContainsKey: string(body),
	}

	return baseline, duration
}

// testErrorBased tests a single parameter with an error-based command injection payload.
func (s *CMDiScanner) testErrorBased(ctx context.Context, baseURL *url.URL, paramName string, payload cmdiPayload) *CMDiFinding {
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

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Check for shell error patterns in the response
	for _, pattern := range cmdErrorPatterns {
		if pattern.MatchString(bodyStr) {
			// Command error detected!
			match := pattern.FindString(bodyStr)
			finding := &CMDiFinding{
				URL:         testURL.String(),
				Parameter:   paramName,
				Payload:     payload.Payload,
				Evidence:    s.extractEvidence(bodyStr, match),
				Severity:    payload.Severity,
				Type:        payload.Type,
				OSType:      payload.OSType,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "high", // Error-based detection with shell errors is high confidence
			}
			return finding
		}
	}

	return nil
}

// testTimeBased tests a single parameter with a time-based command injection payload.
// It measures request duration and compares with baseline and expected delay.
func (s *CMDiScanner) testTimeBased(ctx context.Context, baseURL *url.URL, paramName string, payload cmdiPayload, baselineDuration time.Duration) *CMDiFinding {
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

	// Measure request time
	startTime := time.Now()
	resp, err := s.client.Do(req)
	requestDuration := time.Since(startTime)

	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Handle rate limiting (HTTP 429)
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}

	// Read response body to check for shell errors (which would indicate even higher confidence)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// First check if there are shell errors - this would be even stronger evidence
	shellErrorFound := false
	var errorMatch string
	for _, pattern := range cmdErrorPatterns {
		if pattern.MatchString(bodyStr) {
			shellErrorFound = true
			errorMatch = pattern.FindString(bodyStr)
			break
		}
	}

	// Determine the expected delay (use payload's expected delay or scanner's default)
	expectedDelay := payload.ExpectedDelay
	if expectedDelay == 0 {
		expectedDelay = s.timeBasedDelay
	}

	// Calculate threshold: baseline + expected delay - tolerance
	// We use a tolerance of 1 second to account for network jitter
	tolerance := 1 * time.Second
	minExpectedDuration := baselineDuration + expectedDelay - tolerance

	// Check if the request took significantly longer than expected
	if requestDuration >= minExpectedDuration {
		confidence := "high"
		evidenceMsg := fmt.Sprintf("Request took %v (baseline: %v, expected delay: %v) - indicates time-based command injection",
			requestDuration, baselineDuration, expectedDelay)

		// If shell error is also present, mention it in evidence
		if shellErrorFound {
			evidenceMsg += fmt.Sprintf("; Shell error also detected: %s", s.extractEvidence(bodyStr, errorMatch))
			confidence = "high" // Both timing and error confirms vulnerability
		}

		return &CMDiFinding{
			URL:         testURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    evidenceMsg,
			Severity:    payload.Severity,
			Type:        payload.Type,
			OSType:      payload.OSType,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  confidence,
		}
	}

	return nil
}

// extractEvidence extracts a snippet of the response containing the shell error.
func (s *CMDiScanner) extractEvidence(body, errorMatch string) string {
	if errorMatch == "" {
		return "Shell error detected in response"
	}

	idx := strings.Index(body, errorMatch)
	if idx == -1 {
		return errorMatch
	}

	// Extract context around the error (up to 200 characters)
	start := idx - 30
	if start < 0 {
		start = 0
	}
	end := idx + len(errorMatch) + 30
	if end > len(body) {
		end = len(body)
	}

	snippet := body[start:end]
	// Clean up the snippet
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	snippet = strings.ReplaceAll(snippet, "\t", " ")
	snippet = strings.TrimSpace(snippet)

	return fmt.Sprintf("...%s...", snippet)
}

// getRemediation returns remediation guidance for command injection vulnerabilities.
func (s *CMDiScanner) getRemediation() string {
	return "Use parameterized system calls or avoid passing user input to system commands. " +
		"Implement strict input validation with allowlists. " +
		"Consider using language-specific APIs instead of shell commands. " +
		"If system commands are necessary, use built-in escaping functions and run with minimal privileges. " +
		"Implement proper error handling that doesn't expose system details to users."
}

// calculateSummary calculates the summary statistics for the scan.
func (s *CMDiScanner) calculateSummary(result *CMDiScanResult) {
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
func (r *CMDiScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Command Injection Vulnerability Scan for: %s\n", r.Target))
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
			sb.WriteString(fmt.Sprintf("\n  %d. [%s] %s Command Injection (%s)\n", i+1, strings.ToUpper(f.Severity), strings.Title(f.Type), f.OSType))
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
		sb.WriteString("\nNo command injection vulnerabilities detected.\n")
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
func (r *CMDiScanResult) HasResults() bool {
	return len(r.Findings) > 0 || r.Summary.TotalTests > 0
}

// VerifyFinding re-tests a command injection finding with payload variants.
func (s *CMDiScanner) VerifyFinding(ctx context.Context, finding *CMDiFinding, config VerificationConfig) (*VerificationResult, error) {
	if finding == nil {
		return nil, fmt.Errorf("finding is nil")
	}

	// Parse the original URL to extract parameters
	parsedURL, err := url.Parse(finding.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL in finding: %w", err)
	}

	// Get baseline for comparison
	baseline, baselineDuration := s.getBaselineWithTiming(ctx, parsedURL, finding.Parameter)
	if baseline == nil {
		return &VerificationResult{
			Verified:    false,
			Attempts:    1,
			Confidence:  0.0,
			Explanation: "Failed to obtain baseline response for verification",
		}, nil
	}

	// Generate payload variants for verification
	variants := s.generateCMDiPayloadVariants(finding.Payload, finding.Type)

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

		// For time-based command injection, measure request duration
		if finding.Type == "time-based" {
			// Create test URL with variant
			testURL := *parsedURL
			q := testURL.Query()
			q.Set(finding.Parameter, variant)
			testURL.RawQuery = q.Encode()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", s.userAgent)
			if s.authConfig != nil {
				s.authConfig.ApplyToRequest(req)
			}

			// Measure request time
			startTime := time.Now()
			resp, err := s.client.Do(req)
			requestDuration := time.Since(startTime)

			if err != nil {
				continue
			}
			resp.Body.Close()

			// Check if request took significantly longer (expected delay is typically 5 seconds)
			expectedDelay := s.timeBasedDelay
			tolerance := 1 * time.Second
			minExpectedDuration := baselineDuration + expectedDelay - tolerance

			if requestDuration >= minExpectedDuration {
				successCount++
			}
		} else {
			// Test the variant for error-based
			testURL := *parsedURL
			q := testURL.Query()
			q.Set(finding.Parameter, variant)
			testURL.RawQuery = q.Encode()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", s.userAgent)
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

			// For error-based command injection, check for shell error patterns
			foundError := false
			for _, pattern := range cmdErrorPatterns {
				if pattern.MatchString(string(body)) {
					foundError = true
					break
				}
			}
			if foundError {
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
		explanation = fmt.Sprintf("Only %d out of %d payload variants reproduced the vulnerability - likely a false positive or WAF interference",
			successCount, totalAttempts)
	}

	return &VerificationResult{
		Verified:    verified,
		Attempts:    totalAttempts,
		Confidence:  confidence,
		Explanation: explanation,
	}, nil
}

// generateCMDiPayloadVariants creates different encodings and variations of the command injection payload.
func (s *CMDiScanner) generateCMDiPayloadVariants(originalPayload, findingType string) []string {
	variants := make([]string, 0)

	// Add the original payload
	variants = append(variants, originalPayload)

	// Case variations for commands
	if strings.Contains(originalPayload, "sleep") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "sleep", "SLEEP"))
	}
	if strings.Contains(originalPayload, "timeout") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "timeout", "TIMEOUT"))
	}

	// Separator variations
	if strings.HasPrefix(originalPayload, ";") {
		variants = append(variants, strings.Replace(originalPayload, ";", "&&", 1))
		variants = append(variants, strings.Replace(originalPayload, ";", "|", 1))
	}
	if strings.HasPrefix(originalPayload, "&") && !strings.HasPrefix(originalPayload, "&&") {
		variants = append(variants, strings.Replace(originalPayload, "&", ";", 1))
		variants = append(variants, strings.Replace(originalPayload, "&", "|", 1))
	}

	// Different time delays for time-based payloads
	if findingType == "time-based" {
		if strings.Contains(originalPayload, "5") {
			variants = append(variants, strings.ReplaceAll(originalPayload, "5", "6"))
			variants = append(variants, strings.ReplaceAll(originalPayload, "5", "4"))
		}
	}

	// URL encoding variations
	if !strings.Contains(originalPayload, "%") {
		// Add URL-encoded version
		urlEncoded := originalPayload
		urlEncoded = strings.ReplaceAll(urlEncoded, ";", "%3B")
		urlEncoded = strings.ReplaceAll(urlEncoded, "|", "%7C")
		urlEncoded = strings.ReplaceAll(urlEncoded, "&", "%26")
		urlEncoded = strings.ReplaceAll(urlEncoded, " ", "+")
		if urlEncoded != originalPayload {
			variants = append(variants, urlEncoded)
		}
	}

	return variants
}
