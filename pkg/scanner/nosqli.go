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

// NoSQLiScanner performs active NoSQL injection vulnerability detection.
type NoSQLiScanner struct {
	BaseScanner
}

// NoSQLiScanResult represents the result of a NoSQL injection vulnerability scan.
type NoSQLiScanResult struct {
	Target   string          `json:"target" yaml:"target"`
	Findings []NoSQLiFinding `json:"findings" yaml:"findings"`
	Summary  NoSQLiSummary   `json:"summary" yaml:"summary"`
	Errors   []string        `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// NoSQLiFinding represents a single NoSQL injection vulnerability finding.
type NoSQLiFinding struct {
	URL                  string `json:"url" yaml:"url"`
	Parameter            string `json:"parameter" yaml:"parameter"`
	Payload              string `json:"payload" yaml:"payload"`
	Evidence             string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Severity             string `json:"severity" yaml:"severity"`
	Type                 string `json:"type" yaml:"type"` // "operator-injection", "javascript-injection", "array-pollution"
	Description          string `json:"description" yaml:"description"`
	Remediation          string `json:"remediation" yaml:"remediation"`
	Confidence           string `json:"confidence" yaml:"confidence"` // "high", "medium", "low"
	Verified             bool   `json:"verified" yaml:"verified"`
	VerificationAttempts int    `json:"verification_attempts,omitempty" yaml:"verification_attempts,omitempty"`
}

// NoSQLiSummary provides an overview of the NoSQL injection scan results.
type NoSQLiSummary struct {
	TotalTests           int `json:"total_tests" yaml:"total_tests"`
	VulnerabilitiesFound int `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	HighSeverityCount    int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount  int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount     int `json:"low_severity_count" yaml:"low_severity_count"`
}

// nosqliPayload represents a test payload for NoSQL injection detection.
type nosqliPayload struct {
	Payload      string
	Type         string // "operator-injection", "javascript-injection", "array-pollution", "error-based"
	Severity     string
	Description  string
	ErrorPattern *regexp.Regexp // Pattern to match in response for error-based detection
	// Whether to compare with baseline for differential analysis
	CompareBaseline bool
}

// Common NoSQL error patterns indicating injection attempts triggered errors.
var nosqlErrorPatterns = []*regexp.Regexp{
	// MongoDB error patterns
	regexp.MustCompile(`(?i)MongoError`),
	regexp.MustCompile(`(?i)MongoServerError`),
	regexp.MustCompile(`(?i)MongoNetworkError`),
	regexp.MustCompile(`(?i)BSONTypeError`),
	regexp.MustCompile(`(?i)Unhandled promise rejection.*mongo`),
	regexp.MustCompile(`(?i)\$where.*is not allowed`),
	regexp.MustCompile(`(?i)unknown operator.*\$`),
	regexp.MustCompile(`(?i)invalid operator.*\$`),
	regexp.MustCompile(`(?i)SyntaxError.*EJSON`),
	regexp.MustCompile(`(?i)Failed to parse.*BSON`),
	regexp.MustCompile(`(?i)mongo.*syntax error`),
	regexp.MustCompile(`(?i)cannot use the \$ prefix`),

	// CouchDB error patterns
	regexp.MustCompile(`(?i)"error":\s*"bad_request"`),
	regexp.MustCompile(`(?i)"reason":\s*"invalid UTF-8 JSON"`),
	regexp.MustCompile(`(?i)compilation_error`),

	// Redis error patterns
	regexp.MustCompile(`(?i)WRONGTYPE Operation`),
	regexp.MustCompile(`(?i)ERR.*syntax error`),
	regexp.MustCompile(`(?i)NOAUTH Authentication required`),
	regexp.MustCompile(`(?i)ERR Protocol error`),

	// Generic NoSQL errors
	regexp.MustCompile(`(?i)invalid json`),
	regexp.MustCompile(`(?i)unexpected token.*json`),
	regexp.MustCompile(`(?i)JSON.*parse.*error`),
}

// nosqliPayloads contains the test payloads for NoSQL injection detection.
//
// SECURITY WARNING: This list contains ONLY non-destructive payloads for responsible
// vulnerability detection. Payloads use read-only MongoDB operators and safe patterns.
// Adding destructive payloads would violate responsible disclosure practices.
var nosqliPayloads = []nosqliPayload{
	// MongoDB operator injection - authentication bypass patterns
	{
		Payload:         `{"$gt": ""}`,
		Type:            "operator-injection",
		Severity:        SeverityHigh,
		Description:     "MongoDB operator injection using $gt (greater-than) operator for authentication bypass",
		CompareBaseline: true,
	},
	{
		Payload:         `{"$ne": ""}`,
		Type:            "operator-injection",
		Severity:        SeverityHigh,
		Description:     "MongoDB operator injection using $ne (not-equal) operator for authentication bypass",
		CompareBaseline: true,
	},
	{
		Payload:         `{"$ne": null}`,
		Type:            "operator-injection",
		Severity:        SeverityHigh,
		Description:     "MongoDB operator injection using $ne null for authentication bypass",
		CompareBaseline: true,
	},
	{
		Payload:         `{"$regex": ".*"}`,
		Type:            "operator-injection",
		Severity:        SeverityHigh,
		Description:     "MongoDB operator injection using $regex to match all values",
		CompareBaseline: true,
	},
	{
		Payload:         `{"$where": "1==1"}`,
		Type:            "operator-injection",
		Severity:        SeverityHigh,
		Description:     "MongoDB $where operator injection with always-true condition",
		CompareBaseline: true,
	},
	{
		Payload:         `{"$or": [{}]}`,
		Type:            "operator-injection",
		Severity:        SeverityHigh,
		Description:     "MongoDB $or operator injection with empty condition (matches all documents)",
		CompareBaseline: true,
	},
	{
		Payload:         `{"$and": [{}]}`,
		Type:            "operator-injection",
		Severity:        SeverityHigh,
		Description:     "MongoDB $and operator injection with empty condition",
		CompareBaseline: true,
	},
	{
		Payload:         `{"$exists": true}`,
		Type:            "operator-injection",
		Severity:        SeverityMedium,
		Description:     "MongoDB $exists operator injection to check field existence",
		CompareBaseline: true,
	},
	// JavaScript injection in $where clause
	{
		Payload:         `'; return true; var dummy='`,
		Type:            "javascript-injection",
		Severity:        SeverityHigh,
		Description:     "JavaScript injection in MongoDB $where clause using return true pattern",
		CompareBaseline: true,
	},
	{
		Payload:         `'; return 1==1; var dummy='`,
		Type:            "javascript-injection",
		Severity:        SeverityHigh,
		Description:     "JavaScript injection in MongoDB $where clause with tautology",
		CompareBaseline: true,
	},
	{
		Payload:         `\'; return true; //`,
		Type:            "javascript-injection",
		Severity:        SeverityHigh,
		Description:     "JavaScript injection in MongoDB $where clause with comment",
		CompareBaseline: true,
	},
	// Array parameter pollution (NoSQLi via HTTP parameter abuse)
	{
		Payload:         `[$ne]=1`,
		Type:            "array-pollution",
		Severity:        SeverityHigh,
		Description:     "Array parameter pollution with $ne operator for NoSQL authentication bypass",
		CompareBaseline: true,
	},
	{
		Payload:         `[$gt]=`,
		Type:            "array-pollution",
		Severity:        SeverityHigh,
		Description:     "Array parameter pollution with $gt operator",
		CompareBaseline: true,
	},
	{
		Payload:         `[$regex]=.*`,
		Type:            "array-pollution",
		Severity:        SeverityHigh,
		Description:     "Array parameter pollution with $regex operator to match all values",
		CompareBaseline: true,
	},
	// Error-based injection probes
	{
		Payload:      `{"$invalidop": "test"}`,
		Type:         "error-based",
		Severity:     SeverityMedium,
		Description:  "Error-based NoSQL probe using invalid operator to trigger error messages",
		ErrorPattern: regexp.MustCompile(`(?i)(unknown operator|invalid operator|MongoError|BSONTypeError)`),
	},
	{
		Payload:     `{$where: "this.x == 1"}`,
		Type:        "error-based",
		Severity:    SeverityMedium,
		Description: "Error-based MongoDB $where probe to detect NoSQL parsing",
		// Note: do NOT include \$where in this pattern — reflection-based pages
		// (e.g. XSS reflection pages) echo back the payload verbatim, which
		// would cause false positives.  Real MongoDB $where errors are caught by
		// the MongoError / SyntaxError patterns, and by the general
		// nosqlErrorPatterns entry `\$where.*is not allowed`.
		ErrorPattern: regexp.MustCompile(`(?i)(MongoError|SyntaxError|parse error)`),
	},
}

// nosqliVulnerableParams lists common parameter names that may be vulnerable to NoSQL injection.
var nosqliVulnerableParams = []string{
	"username", "user", "email", "password", "pass", "passwd",
	"id", "uid", "userid", "user_id",
	"name", "login", "query", "search", "q",
	"filter", "where", "sort", "field", "key",
	"token", "auth", "session", "data",
	"value", "input", "param", "field",
}

// NoSQLiOption is a function that configures a NoSQLiScanner.
type NoSQLiOption func(*NoSQLiScanner)

// WithNoSQLiHTTPClient sets a custom HTTP client for the NoSQL injection scanner.
func WithNoSQLiHTTPClient(c HTTPClient) NoSQLiOption {
	return func(s *NoSQLiScanner) { s.client = c }
}

// WithNoSQLiUserAgent sets the user agent string for the NoSQL injection scanner.
func WithNoSQLiUserAgent(ua string) NoSQLiOption {
	return func(s *NoSQLiScanner) { s.userAgent = ua }
}

// WithNoSQLiTimeout sets the timeout for HTTP requests.
func WithNoSQLiTimeout(d time.Duration) NoSQLiOption {
	return func(s *NoSQLiScanner) { s.timeout = d }
}

// WithNoSQLiAuth sets the authentication configuration for the NoSQL injection scanner.
func WithNoSQLiAuth(config *auth.AuthConfig) NoSQLiOption {
	return func(s *NoSQLiScanner) { s.authConfig = config }
}

// WithNoSQLiRateLimiter sets a rate limiter for the NoSQL injection scanner.
func WithNoSQLiRateLimiter(limiter ratelimit.Limiter) NoSQLiOption {
	return func(s *NoSQLiScanner) { s.rateLimiter = limiter }
}

// WithNoSQLiRateLimitConfig sets rate limiting from a configuration.
func WithNoSQLiRateLimitConfig(cfg ratelimit.Config) NoSQLiOption {
	return func(s *NoSQLiScanner) { s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg) }
}

// WithNoSQLiTracer sets the OpenTelemetry tracer for the NoSQL injection scanner.
func WithNoSQLiTracer(tracer trace.Tracer) NoSQLiOption {
	return func(s *NoSQLiScanner) { s.tracer = tracer }
}

// NewNoSQLiScanner creates a new NoSQLiScanner with the given options.
func NewNoSQLiScanner(opts ...NoSQLiOption) *NoSQLiScanner {
	s := &NoSQLiScanner{BaseScanner: DefaultBaseScanner()}
	for _, opt := range opts {
		opt(s)
	}
	s.InitDefaultClient()
	return s
}

// NewNoSQLiScannerFromBase creates a new NoSQLiScanner from pre-built BaseOptions
// plus any scanner-specific options.
func NewNoSQLiScannerFromBase(baseOpts []BaseOption, extraOpts ...NoSQLiOption) *NoSQLiScanner {
	s := &NoSQLiScanner{BaseScanner: DefaultBaseScanner()}
	ApplyBaseOptions(&s.BaseScanner, baseOpts)
	for _, opt := range extraOpts {
		opt(s)
	}
	s.InitDefaultClient()
	return s
}

// Scan performs a NoSQL injection vulnerability scan on the given target URL.
func (s *NoSQLiScanner) Scan(ctx context.Context, targetURL string) *NoSQLiScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanNoSQLi)
		defer span.End()
	}

	result := &NoSQLiScanResult{
		Target:   targetURL,
		Findings: make([]NoSQLiFinding, 0),
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
		for _, paramName := range nosqliVulnerableParams {
			params.Set(paramName, "test")
		}
	}

	// Get baseline responses for differential analysis
	baselineResponses := make(map[string]*baselineResponse)
	for paramName := range params {
		baseline := s.getBaseline(ctx, parsedURL, paramName)
		if baseline != nil {
			baselineResponses[paramName] = baseline
		}
	}

	// Test each parameter with each payload
	for paramName := range params {
		for _, payload := range nosqliPayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			// Skip array-pollution payloads here; they are handled by a dedicated loop below
			// that constructs the correct URL format (e.g., param[$ne]=1).
			if payload.Type == "array-pollution" {
				continue
			}

			result.Summary.TotalTests++

			var finding *NoSQLiFinding
			if payload.Type == "error-based" {
				finding = s.testErrorBased(ctx, parsedURL, paramName, payload)
			} else if payload.CompareBaseline {
				baseline := baselineResponses[paramName]
				finding = s.testWithBaseline(ctx, parsedURL, paramName, payload, baseline)
			}

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

	// Also test array parameter pollution as a separate form
	for paramName := range params {
		for _, payload := range nosqliPayloads {
			if payload.Type != "array-pollution" {
				continue
			}

			// Apply rate limiting
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			result.Summary.TotalTests++
			finding := s.testArrayPollution(ctx, parsedURL, paramName, payload, baselineResponses[paramName])
			if finding != nil {
				result.Findings = append(result.Findings, *finding)
				result.Summary.VulnerabilitiesFound++
			}

			select {
			case <-ctx.Done():
				result.Errors = append(result.Errors, "Scan cancelled")
				s.calculateSummary(result)
				return result
			default:
			}
		}
	}

	s.calculateSummary(result)
	return result
}

// ScanPOST scans a URL for NoSQL injection vulnerabilities using POST form data.
func (s *NoSQLiScanner) ScanPOST(ctx context.Context, targetURL string, parameters map[string]string) *NoSQLiScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanNoSQLi)
		defer span.End()
	}

	result := &NoSQLiScanResult{
		Target:   targetURL,
		Findings: make([]NoSQLiFinding, 0),
		Errors:   make([]string, 0),
	}

	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid URL: %s", err.Error()))
		return result
	}

	// Use provided parameters or fallback to common vulnerable parameter names
	params := parameters
	if len(params) == 0 {
		params = make(map[string]string)
		for _, paramName := range nosqliVulnerableParams {
			params[paramName] = "test"
		}
	}

	// Filter out non-data parameters (submit buttons, CSRF tokens, etc.) so that
	// the scanner only probes fields that are likely to reach a NoSQL query.
	// The full params map is still passed to each request builder so that fixed
	// form fields (e.g. submit buttons) are included in every POST body.
	paramsToTest := make(map[string]string)
	for paramName, paramValue := range params {
		if !isNonDataParameter(paramName) {
			paramsToTest[paramName] = paramValue
		}
	}

	// Get baseline responses for differential analysis
	baselineResponses := make(map[string]*baselineResponse)
	for paramName := range paramsToTest {
		baseline := s.getBaselinePOST(ctx, parsedURL, paramName, params)
		if baseline != nil {
			baselineResponses[paramName] = baseline
		}
	}

	// Test each parameter with each payload
	for paramName := range paramsToTest {
		for _, payload := range nosqliPayloads {
			// Apply rate limiting
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			// Skip array-pollution payloads in this loop; they are not applicable to POST body params.
			if payload.Type == "array-pollution" {
				continue
			}

			result.Summary.TotalTests++

			var finding *NoSQLiFinding
			if payload.Type == "error-based" {
				finding = s.testErrorBasedPOST(ctx, parsedURL, paramName, payload, params)
			} else if payload.CompareBaseline {
				baseline := baselineResponses[paramName]
				finding = s.testWithBaselinePOST(ctx, parsedURL, paramName, payload, params, baseline)
			}

			if finding != nil {
				result.Findings = append(result.Findings, *finding)
				result.Summary.VulnerabilitiesFound++
			}

			select {
			case <-ctx.Done():
				result.Errors = append(result.Errors, "Scan cancelled")
				s.calculateSummary(result)
				return result
			default:
			}
		}
	}

	s.calculateSummary(result)
	return result
}

// getBaseline makes a request with the original parameter value to establish a baseline.
func (s *NoSQLiScanner) getBaseline(ctx context.Context, baseURL *url.URL, paramName string) *baselineResponse {
	// Create a copy of the URL with the original parameter value
	testURL := *baseURL
	q := testURL.Query()

	originalValue := q.Get(paramName)
	if originalValue == "" {
		originalValue = "test"
		q.Set(paramName, originalValue)
	}
	testURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	return &baselineResponse{
		StatusCode:  resp.StatusCode,
		BodyLength:  len(body),
		BodyHash:    fmt.Sprintf("%x", len(body)),
		ContainsKey: string(body),
	}
}

// getBaselinePOST makes a POST request to establish a baseline.
func (s *NoSQLiScanner) getBaselinePOST(ctx context.Context, baseURL *url.URL, paramName string, allParameters map[string]string) *baselineResponse {
	formData := url.Values{}
	for k, v := range allParameters {
		formData.Set(k, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	return &baselineResponse{
		StatusCode:  resp.StatusCode,
		BodyLength:  len(body),
		BodyHash:    fmt.Sprintf("%x", len(body)),
		ContainsKey: string(body),
	}
}

// testErrorBased tests a parameter with an error-based NoSQL injection payload.
func (s *NoSQLiScanner) testErrorBased(ctx context.Context, baseURL *url.URL, paramName string, payload nosqliPayload) *NoSQLiFinding {
	testURL := *baseURL
	q := testURL.Query()
	q.Set(paramName, payload.Payload)
	testURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Check specific error pattern for this payload
	if payload.ErrorPattern != nil && payload.ErrorPattern.MatchString(bodyStr) {
		match := payload.ErrorPattern.FindString(bodyStr)
		return &NoSQLiFinding{
			URL:         testURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    s.extractEvidence(bodyStr, match),
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  "high",
		}
	}

	// Also check generic NoSQL error patterns
	for _, pattern := range nosqlErrorPatterns {
		if pattern.MatchString(bodyStr) {
			match := pattern.FindString(bodyStr)
			return &NoSQLiFinding{
				URL:         testURL.String(),
				Parameter:   paramName,
				Payload:     payload.Payload,
				Evidence:    s.extractEvidence(bodyStr, match),
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "high",
			}
		}
	}

	return nil
}

// testErrorBasedPOST tests a parameter with an error-based NoSQL injection payload via POST.
func (s *NoSQLiScanner) testErrorBasedPOST(ctx context.Context, baseURL *url.URL, paramName string, payload nosqliPayload, allParameters map[string]string) *NoSQLiFinding {
	formData := url.Values{}
	for k, v := range allParameters {
		formData.Set(k, v)
	}
	formData.Set(paramName, payload.Payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	if payload.ErrorPattern != nil && payload.ErrorPattern.MatchString(bodyStr) {
		match := payload.ErrorPattern.FindString(bodyStr)
		return &NoSQLiFinding{
			URL:         baseURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    s.extractEvidence(bodyStr, match),
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  "high",
		}
	}

	for _, pattern := range nosqlErrorPatterns {
		if pattern.MatchString(bodyStr) {
			match := pattern.FindString(bodyStr)
			return &NoSQLiFinding{
				URL:         baseURL.String(),
				Parameter:   paramName,
				Payload:     payload.Payload,
				Evidence:    s.extractEvidence(bodyStr, match),
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "high",
			}
		}
	}

	return nil
}

// testWithBaseline performs differential analysis to detect NoSQL injection via response changes.
func (s *NoSQLiScanner) testWithBaseline(ctx context.Context, baseURL *url.URL, paramName string, payload nosqliPayload, baseline *baselineResponse) *NoSQLiFinding {
	if baseline == nil {
		return nil
	}

	testURL := *baseURL
	q := testURL.Query()
	q.Set(paramName, payload.Payload)
	testURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Check for NoSQL error patterns in the response
	for _, pattern := range nosqlErrorPatterns {
		if pattern.MatchString(bodyStr) {
			match := pattern.FindString(bodyStr)
			return &NoSQLiFinding{
				URL:         testURL.String(),
				Parameter:   paramName,
				Payload:     payload.Payload,
				Evidence:    s.extractEvidence(bodyStr, match),
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "high",
			}
		}
	}

	// Differential analysis: significant response change may indicate injection.
	// A confirmation request with a benign neutral value is sent to verify the change
	// is injection-specific and not simply natural parameter variance (e.g. a page-router
	// param like ?doc=readme that legitimately returns different content for every value).
	if s.isSignificantResponseChange(baseline, resp.StatusCode, len(body)) {
		if !s.confirmVarianceIsInjection(ctx, baseURL, paramName, baseline) {
			// Benign neutral value also changes the response → parameter naturally varies
			// → this is not injection, skip to avoid false positive.
			return nil
		}
		return &NoSQLiFinding{
			URL:         testURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    fmt.Sprintf("Response changed significantly: baseline status=%d len=%d, injected status=%d len=%d", baseline.StatusCode, baseline.BodyLength, resp.StatusCode, len(body)),
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  "medium",
		}
	}

	return nil
}

// testWithBaselinePOST performs differential analysis for POST requests.
func (s *NoSQLiScanner) testWithBaselinePOST(ctx context.Context, baseURL *url.URL, paramName string, payload nosqliPayload, allParameters map[string]string, baseline *baselineResponse) *NoSQLiFinding {
	if baseline == nil {
		return nil
	}

	formData := url.Values{}
	for k, v := range allParameters {
		formData.Set(k, v)
	}
	formData.Set(paramName, payload.Payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	for _, pattern := range nosqlErrorPatterns {
		if pattern.MatchString(bodyStr) {
			match := pattern.FindString(bodyStr)
			return &NoSQLiFinding{
				URL:         baseURL.String(),
				Parameter:   paramName,
				Payload:     payload.Payload,
				Evidence:    s.extractEvidence(bodyStr, match),
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "high",
			}
		}
	}

	if s.isSignificantResponseChange(baseline, resp.StatusCode, len(body)) {
		// Re-capture the baseline to detect external page modifications (e.g., concurrent
		// scanners storing content on the same page during discovery scans).  If the fresh
		// baseline itself has drifted significantly from the original, the differential
		// analysis is unreliable — skip to avoid false positives on stored-content pages.
		freshBaseline := s.getBaselinePOST(ctx, baseURL, paramName, allParameters)
		if freshBaseline != nil && s.isSignificantResponseChange(baseline, freshBaseline.StatusCode, freshBaseline.BodyLength) {
			return nil
		}

		if !s.confirmVarianceIsInjectionPOST(ctx, baseURL, paramName, allParameters, baseline) {
			return nil
		}
		return &NoSQLiFinding{
			URL:         baseURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    fmt.Sprintf("Response changed significantly: baseline status=%d len=%d, injected status=%d len=%d", baseline.StatusCode, baseline.BodyLength, resp.StatusCode, len(body)),
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  "medium",
		}
	}

	return nil
}

// testArrayPollution tests array parameter pollution for NoSQL injection.
// e.g., param[$ne]=1 instead of param=value
func (s *NoSQLiScanner) testArrayPollution(ctx context.Context, baseURL *url.URL, paramName string, payload nosqliPayload, baseline *baselineResponse) *NoSQLiFinding {
	if baseline == nil {
		return nil
	}

	// Build the polluted query string manually
	// e.g., username[$ne]=1 instead of username=value
	operatorPart := payload.Payload // e.g., "[$ne]=1"

	testURL := *baseURL
	existingQuery := testURL.RawQuery
	if existingQuery != "" {
		testURL.RawQuery = existingQuery + "&" + url.QueryEscape(paramName) + operatorPart
	} else {
		testURL.RawQuery = url.QueryEscape(paramName) + operatorPart
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Check for error patterns
	for _, pattern := range nosqlErrorPatterns {
		if pattern.MatchString(bodyStr) {
			match := pattern.FindString(bodyStr)
			return &NoSQLiFinding{
				URL:         testURL.String(),
				Parameter:   paramName,
				Payload:     paramName + payload.Payload,
				Evidence:    s.extractEvidence(bodyStr, match),
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "high",
			}
		}
	}

	// Differential analysis — with confirmation to eliminate false positives on routing params.
	if s.isSignificantResponseChange(baseline, resp.StatusCode, len(body)) {
		if !s.confirmVarianceIsInjection(ctx, baseURL, paramName, baseline) {
			return nil
		}
		return &NoSQLiFinding{
			URL:         testURL.String(),
			Parameter:   paramName,
			Payload:     paramName + payload.Payload,
			Evidence:    fmt.Sprintf("Response changed significantly: baseline status=%d len=%d, injected status=%d len=%d", baseline.StatusCode, baseline.BodyLength, resp.StatusCode, len(body)),
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  "medium",
		}
	}

	return nil
}

// isSignificantResponseChange determines if the response changed significantly from the baseline.
// A significant change (status code change or large body length change) may indicate injection.
func (s *NoSQLiScanner) isSignificantResponseChange(baseline *baselineResponse, statusCode, bodyLength int) bool {
	if baseline == nil {
		return false
	}

	// Status code change is suspicious.
	// A change from 4xx to 2xx strongly suggests authentication bypass.
	if baseline.StatusCode != statusCode {
		return true
	}

	// Large body length change (more than 30% difference)
	if baseline.BodyLength > 0 {
		pctChange := float64(bodyLength-baseline.BodyLength) / float64(baseline.BodyLength)
		if pctChange > 0.30 || pctChange < -0.30 {
			return true
		}
	}

	return false
}

// nosqliNeutralConfirmValue is a benign value used for confirmation requests.
// It is not a valid NoSQL operator and is unlikely to match real page content or DB entries.
const nosqliNeutralConfirmValue = "nosqlicheckxyz123"

// confirmVarianceIsInjection checks that a detected response change is injection-specific
// and not simply natural parameter variance (e.g. a page-router param like ?doc=readme).
//
// It sends a second GET request with a benign neutral value and compares the response
// length to the baseline. If the benign value ALSO produces a significant change, the
// parameter is inherently variable — the original change was a false positive.
// Returns true when the change is injection-specific (safe to report as a finding).
func (s *NoSQLiScanner) confirmVarianceIsInjection(ctx context.Context, baseURL *url.URL, paramName string, baseline *baselineResponse) bool {
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			// Cannot wait for rate limiter — conservatively assume injection to avoid suppressing real findings.
			return true
		}
	}

	confirmURL := *baseURL
	q := confirmURL.Query()
	q.Set(paramName, nosqliNeutralConfirmValue)
	confirmURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, confirmURL.String(), nil)
	if err != nil {
		// Cannot confirm — assume injection to avoid suppressing real findings
		return true
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return true
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return true
	}

	// If a benign neutral value also produces a significant response change from the
	// baseline, the parameter is a routing/content-selector param (e.g. ?doc=readme).
	// Any injected-payload change is therefore not unique → not injection.
	if s.isSignificantResponseChange(baseline, resp.StatusCode, len(body)) {
		return false
	}

	// Benign confirmation is close to baseline → injected-payload change is unique → injection confirmed.
	return true
}

// confirmVarianceIsInjectionPOST is the POST-body variant of confirmVarianceIsInjection.
func (s *NoSQLiScanner) confirmVarianceIsInjectionPOST(ctx context.Context, baseURL *url.URL, paramName string, allParameters map[string]string, baseline *baselineResponse) bool {
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			// Cannot wait for rate limiter — conservatively assume injection to avoid suppressing real findings.
			return true
		}
	}

	formData := url.Values{}
	for k, v := range allParameters {
		formData.Set(k, v)
	}
	formData.Set(paramName, nosqliNeutralConfirmValue)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return true
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return true
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return true
	}

	if s.isSignificantResponseChange(baseline, resp.StatusCode, len(body)) {
		return false
	}

	return true
}

// extractEvidence extracts context around a match in the response body.
func (s *NoSQLiScanner) extractEvidence(body, match string) string {
	if match == "" {
		return ""
	}

	idx := strings.Index(body, match)
	if idx < 0 {
		return match
	}

	start := idx - 30
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + 30
	if end > len(body) {
		end = len(body)
	}

	snippet := body[start:end]
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	snippet = strings.ReplaceAll(snippet, "\t", " ")
	snippet = strings.TrimSpace(snippet)

	return fmt.Sprintf("...%s...", snippet)
}

// getRemediation returns remediation guidance for NoSQL injection vulnerabilities.
func (s *NoSQLiScanner) getRemediation() string {
	return "Validate and sanitize all user input before using it in NoSQL queries. " +
		"Use parameterized queries or ODM/ORM abstractions that prevent operator injection. " +
		"Disable JavaScript execution in MongoDB ($where, $function) if not required. " +
		"Apply strict schema validation (e.g., JSON Schema) to reject unexpected operators. " +
		"Implement allowlist-based input validation for fields used in queries. " +
		"Use the principle of least privilege for database accounts."
}

// calculateSummary calculates the summary statistics for the scan.
func (s *NoSQLiScanner) calculateSummary(result *NoSQLiScanResult) {
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
func (r *NoSQLiScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("NoSQL Injection Vulnerability Scan for: %s\n", r.Target))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	sb.WriteString("\nSummary:\n")
	sb.WriteString(fmt.Sprintf("  Total Tests: %d\n", r.Summary.TotalTests))
	sb.WriteString(fmt.Sprintf("  Vulnerabilities Found: %d\n", r.Summary.VulnerabilitiesFound))
	sb.WriteString(fmt.Sprintf("  High Severity: %d\n", r.Summary.HighSeverityCount))
	sb.WriteString(fmt.Sprintf("  Medium Severity: %d\n", r.Summary.MediumSeverityCount))
	sb.WriteString(fmt.Sprintf("  Low Severity: %d\n", r.Summary.LowSeverityCount))

	if len(r.Findings) > 0 {
		sb.WriteString("\nVulnerabilities:\n")
		for i, f := range r.Findings {
			sb.WriteString(fmt.Sprintf("\n  %d. [%s] NoSQL Injection (%s)\n", i+1, strings.ToUpper(f.Severity), f.Type))
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
		sb.WriteString("\nNo NoSQL injection vulnerabilities detected.\n")
	}

	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, e := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}

	return sb.String()
}

// HasResults returns true if the scan produced any meaningful results.
func (r *NoSQLiScanResult) HasResults() bool {
	return len(r.Findings) > 0 || r.Summary.TotalTests > 0
}

// VerifyFinding re-tests a NoSQL injection finding with payload variants.
func (s *NoSQLiScanner) VerifyFinding(ctx context.Context, finding *NoSQLiFinding, config VerificationConfig) (*VerificationResult, error) {
	if finding == nil {
		return nil, fmt.Errorf("finding is nil")
	}

	// Parse the original URL to extract parameters
	parsedURL, err := url.Parse(finding.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL in finding: %w", err)
	}

	// Get baseline for comparison
	baseline := s.getBaseline(ctx, parsedURL, finding.Parameter)
	if baseline == nil {
		return &VerificationResult{
			Verified:    false,
			Attempts:    1,
			Confidence:  0.0,
			Explanation: "Failed to obtain baseline response for verification",
		}, nil
	}

	// Generate payload variants
	variants := s.generateNoSQLiPayloadVariants(finding.Payload, finding.Type)

	successCount := 0
	totalAttempts := 0
	maxAttempts := config.MaxRetries
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	for i, variant := range variants {
		if i >= maxAttempts {
			break
		}

		if s.rateLimiter != nil {
			if err := s.rateLimiter.Wait(ctx); err != nil {
				return nil, fmt.Errorf("rate limiting error: %w", err)
			}
		}

		if i > 0 && config.Delay > 0 {
			time.Sleep(config.Delay)
		}

		totalAttempts++

		// Build test URL
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

		bodyStr := string(body)

		// Check for error patterns or significant response change
		foundError := false
		for _, pattern := range nosqlErrorPatterns {
			if pattern.MatchString(bodyStr) {
				foundError = true
				break
			}
		}

		if foundError || s.isSignificantResponseChange(baseline, resp.StatusCode, len(body)) {
			successCount++
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	confidence := float64(successCount) / float64(totalAttempts)
	verified := confidence >= 0.5

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

// generateNoSQLiPayloadVariants creates different variations of the NoSQL injection payload.
func (s *NoSQLiScanner) generateNoSQLiPayloadVariants(originalPayload, findingType string) []string {
	variants := make([]string, 0)

	// Always include the original
	variants = append(variants, originalPayload)

	switch findingType {
	case "operator-injection":
		// Try related operators
		if strings.Contains(originalPayload, `"$gt"`) {
			variants = append(variants, strings.ReplaceAll(originalPayload, `"$gt"`, `"$gte"`))
			variants = append(variants, strings.ReplaceAll(originalPayload, `"$gt"`, `"$ne"`))
		}
		if strings.Contains(originalPayload, `"$ne"`) {
			variants = append(variants, strings.ReplaceAll(originalPayload, `"$ne"`, `"$gt"`))
			variants = append(variants, strings.ReplaceAll(originalPayload, `"$ne"`, `"$exists"`))
		}
		if strings.Contains(originalPayload, `"$regex"`) {
			variants = append(variants, strings.ReplaceAll(originalPayload, `".*"`, `"^"`))
		}
	case "javascript-injection":
		// Try comment variations
		if strings.Contains(originalPayload, "return true") {
			variants = append(variants, strings.ReplaceAll(originalPayload, "return true", "return 1==1"))
			variants = append(variants, strings.ReplaceAll(originalPayload, "return true", "return !false"))
		}
	case "array-pollution":
		// Try different operators
		if strings.Contains(originalPayload, "$ne") {
			variants = append(variants, strings.ReplaceAll(originalPayload, "$ne", "$gt"))
		}
		if strings.Contains(originalPayload, "$gt") {
			variants = append(variants, strings.ReplaceAll(originalPayload, "$gt", "$ne"))
		}
	}

	return variants
}
