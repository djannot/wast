// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/telemetry"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/html"
)

const (
	// maxResponseSize is the maximum response size to analyze (10MB) to prevent memory exhaustion
	maxResponseSize = 10 * 1024 * 1024

	// Content-based detection thresholds - these are baseline values
	// Actual thresholds are adaptive based on response characteristics
	minWordCountDifference         = 2  // Minimum word count difference to consider significant (lowered from 3 for DVWA)
	minStructuralElementDifference = 1  // Minimum structural element difference to consider significant
	lengthDifferenceThresholdPct   = 10 // Minimum percentage difference in length to consider significant (lowered from 20)

	// Adaptive threshold settings
	smallResponseSizeThreshold = 1024 // Responses < 1KB use more sensitive thresholds
	fewStructuralElementsLimit = 10   // Responses with < 10 structural elements use sensitive thresholds
	minWordCountForPercentage  = 5    // If baseline has < 5 words, use absolute difference instead of percentage (lowered from 10 for DVWA detection)
)

// Pre-compiled regex patterns for structural element counting (performance optimization)
var (
	trRegex  = regexp.MustCompile(`(?i)<tr[^>]*>`)
	liRegex  = regexp.MustCompile(`(?i)<li[^>]*>`)
	divRegex = regexp.MustCompile(`(?i)<div[^>]*class=['"][^'"]*(?:item|row|entry|record|result)[^'"]*['"][^>]*>`)
)

// Pre-compiled regex patterns for dynamic content normalization (performance optimization)
var dynamicContentPatterns = []*regexp.Regexp{
	// CSRF tokens - common patterns
	regexp.MustCompile(`(?i)<input[^>]*name=['"]?(csrf_?token|user_?token|token|_token|authenticity_?token)['"]?[^>]*value=['"][^'"]*['"][^>]*>`),
	regexp.MustCompile(`(?i)<input[^>]*value=['"][^'"]*['"][^>]*name=['"]?(csrf_?token|user_?token|token|_token|authenticity_?token)['"]?[^>]*>`),

	// CSRF token meta tags
	regexp.MustCompile(`(?i)<meta[^>]*name=['"]?(csrf-token|csrf_token)['"]?[^>]*content=['"][^'"]*['"][^>]*>`),

	// Nonces and session IDs in attribute values (quoted)
	regexp.MustCompile(`(?i)(nonce|session_?id|sid|jsessionid)=['"][0-9a-f]{8,}['"]`),

	// Nonces and session IDs in URLs (query parameters)
	regexp.MustCompile(`(?i)[?&](nonce|session_?id|sid|jsessionid)=[0-9a-f]{8,}`),

	// Timestamps in attribute values (quoted)
	regexp.MustCompile(`(?i)(timestamp|ts|time|_t)=['"][0-9]{10,}['"]`),

	// Timestamps in URLs (query parameters)
	regexp.MustCompile(`(?i)[?&](timestamp|ts|time|_t)=[0-9]{10,}`),

	// Common token patterns in hidden inputs
	regexp.MustCompile(`(?i)<input[^>]*type=['"]?hidden['"]?[^>]*value=['"][0-9a-fA-F]{16,}['"][^>]*>`),
}

// SQLiScanner performs active SQL injection vulnerability detection.
type SQLiScanner struct {
	client         HTTPClient
	userAgent      string
	timeout        time.Duration
	authConfig     *auth.AuthConfig
	rateLimiter    ratelimit.Limiter
	tracer         trace.Tracer
	timeBasedDelay time.Duration // Delay duration for time-based detection (default 5 seconds)
}

// SQLiScanResult represents the result of a SQL injection vulnerability scan.
type SQLiScanResult struct {
	Target   string        `json:"target" yaml:"target"`
	Findings []SQLiFinding `json:"findings" yaml:"findings"`
	Summary  SQLiSummary   `json:"summary" yaml:"summary"`
	Errors   []string      `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// SQLiFinding represents a single SQL injection vulnerability finding.
type SQLiFinding struct {
	URL                  string `json:"url" yaml:"url"`
	Parameter            string `json:"parameter" yaml:"parameter"`
	Payload              string `json:"payload" yaml:"payload"`
	Evidence             string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Severity             string `json:"severity" yaml:"severity"`
	Type                 string `json:"type" yaml:"type"` // "error-based", "boolean-based", "time-based"
	Description          string `json:"description" yaml:"description"`
	Remediation          string `json:"remediation" yaml:"remediation"`
	Confidence           string `json:"confidence" yaml:"confidence"` // "high", "medium", "low"
	Verified             bool   `json:"verified" yaml:"verified"`
	VerificationAttempts int    `json:"verification_attempts,omitempty" yaml:"verification_attempts,omitempty"`
}

// SQLiSummary provides an overview of the SQL injection scan results.
type SQLiSummary struct {
	TotalTests           int `json:"total_tests" yaml:"total_tests"`
	VulnerabilitiesFound int `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	HighSeverityCount    int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount  int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount     int `json:"low_severity_count" yaml:"low_severity_count"`
}

// sqliPayload represents a test payload for SQL injection detection.
type sqliPayload struct {
	Payload         string
	Type            string // "error-based", "boolean-based", "time-based"
	Severity        string
	Description     string
	ErrorPattern    *regexp.Regexp // Pattern to match in response for error-based detection
	CompareBaseline bool           // Whether to compare with baseline response for boolean-based
	ExpectedDelay   time.Duration  // Expected delay for time-based payloads
}

// Common SQL error patterns from various database systems.
var sqlErrorPatterns = []*regexp.Regexp{
	// MySQL
	regexp.MustCompile(`(?i)SQL syntax.*?MySQL`),
	regexp.MustCompile(`(?i)Warning.*?\Wmysqli?_`),
	regexp.MustCompile(`(?i)MySQLSyntaxErrorException`),
	regexp.MustCompile(`(?i)valid MySQL result`),
	regexp.MustCompile(`(?i)check the manual that corresponds to your (MySQL|MariaDB) server version`),

	// PostgreSQL
	regexp.MustCompile(`(?i)PostgreSQL.*?ERROR`),
	regexp.MustCompile(`(?i)Warning.*?\Wpg_`),
	regexp.MustCompile(`(?i)valid PostgreSQL result`),
	regexp.MustCompile(`(?i)Npgsql\.`),
	regexp.MustCompile(`(?i)PG::SyntaxError`),

	// Microsoft SQL Server
	regexp.MustCompile(`(?i)Driver.*? SQL[\-\_\ ]*Server`),
	regexp.MustCompile(`(?i)OLE DB.*? SQL Server`),
	regexp.MustCompile(`(?i)\[SQL Server\]`),
	regexp.MustCompile(`(?i)\[Microsoft\]\[ODBC SQL Server Driver\]`),
	regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)Microsoft SQL Native Client error`),

	// Oracle
	regexp.MustCompile(`(?i)\bORA-\d{5}`),
	regexp.MustCompile(`(?i)Oracle error`),
	regexp.MustCompile(`(?i)Oracle.*?Driver`),
	regexp.MustCompile(`(?i)Warning.*?\W(oci|ora)_`),

	// SQLite
	regexp.MustCompile(`(?i)SQLite/JDBCDriver`),
	regexp.MustCompile(`(?i)SQLite\.Exception`),
	regexp.MustCompile(`(?i)System\.Data\.SQLite\.SQLiteException`),
	regexp.MustCompile(`(?i)Warning.*?\W(sqlite_|SQLite3::)`),
	regexp.MustCompile(`(?i)SQLite3::SQLException`),

	// Generic SQL errors
	regexp.MustCompile(`(?i)syntax error.*?SQL`),
	regexp.MustCompile(`(?i)unclosed quotation mark`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
	regexp.MustCompile(`(?i)SQL command not properly ended`),
	regexp.MustCompile(`(?i)SQLSTATE\[\w+\]`),
	regexp.MustCompile(`(?i)Incorrect syntax near`),
}

// sqliPayloads is the list of safe detection payloads to test for SQL injection.
var sqliPayloads = []sqliPayload{
	// Error-based detection - single quote
	{
		Payload:      "'",
		Type:         "error-based",
		Severity:     SeverityHigh,
		Description:  "Single quote injection triggers database error - indicates SQL injection vulnerability",
		ErrorPattern: nil, // Will check against all patterns
	},
	// Error-based detection - double quote
	{
		Payload:      "\"",
		Type:         "error-based",
		Severity:     SeverityHigh,
		Description:  "Double quote injection triggers database error - indicates SQL injection vulnerability",
		ErrorPattern: nil,
	},
	// Error-based detection - SQL comment
	{
		Payload:      "' OR '1'='1' --",
		Type:         "error-based",
		Severity:     SeverityHigh,
		Description:  "SQL comment injection detected - allows bypassing authentication and query logic",
		ErrorPattern: nil,
	},
	// Boolean-based blind - always true
	{
		Payload:         "' OR '1'='1",
		Type:            "boolean-based",
		Severity:        SeverityHigh,
		Description:     "Boolean-based SQL injection detected - allows data extraction through logic manipulation",
		CompareBaseline: true,
	},
	// Boolean-based blind - always false
	{
		Payload:         "' OR '1'='2",
		Type:            "boolean-based",
		Severity:        SeverityHigh,
		Description:     "Boolean-based SQL injection detected - response differs from baseline",
		CompareBaseline: true,
	},
	// Boolean-based - AND true
	{
		Payload:         "' AND '1'='1",
		Type:            "boolean-based",
		Severity:        SeverityHigh,
		Description:     "Boolean-based SQL injection with AND condition detected",
		CompareBaseline: true,
	},
	// Union-based detection marker
	{
		Payload:      "' UNION SELECT NULL--",
		Type:         "error-based",
		Severity:     SeverityHigh,
		Description:  "UNION-based SQL injection marker detected - could allow data extraction",
		ErrorPattern: nil,
	},
	// Numeric injection test
	{
		Payload:         "1' OR '1'='1",
		Type:            "boolean-based",
		Severity:        SeverityHigh,
		Description:     "Numeric field SQL injection detected",
		CompareBaseline: true,
	},
	// Time-based detection - MySQL SLEEP
	{
		Payload:       "' OR SLEEP(5)--",
		Type:          "time-based",
		Severity:      SeverityHigh,
		Description:   "Time-based blind SQL injection detected using MySQL SLEEP function",
		ExpectedDelay: 5 * time.Second,
	},
	// Time-based detection - MySQL BENCHMARK
	{
		Payload:       "' AND BENCHMARK(10000000,SHA1('test'))--",
		Type:          "time-based",
		Severity:      SeverityHigh,
		Description:   "Time-based blind SQL injection detected using MySQL BENCHMARK function",
		ExpectedDelay: 5 * time.Second,
	},
	// Time-based detection - PostgreSQL pg_sleep
	{
		Payload:       "'; SELECT pg_sleep(5)--",
		Type:          "time-based",
		Severity:      SeverityHigh,
		Description:   "Time-based blind SQL injection detected using PostgreSQL pg_sleep function",
		ExpectedDelay: 5 * time.Second,
	},
	// Time-based detection - Microsoft SQL Server WAITFOR DELAY
	{
		Payload:       "'; WAITFOR DELAY '00:00:05'--",
		Type:          "time-based",
		Severity:      SeverityHigh,
		Description:   "Time-based blind SQL injection detected using SQL Server WAITFOR DELAY",
		ExpectedDelay: 5 * time.Second,
	},
	// Time-based detection - SQLite heavy computation (no native sleep)
	{
		Payload:       "' AND (SELECT COUNT(*) FROM sqlite_master WHERE tbl_name LIKE '%' || randomblob(100000000))--",
		Type:          "time-based",
		Severity:      SeverityHigh,
		Description:   "Time-based blind SQL injection detected using SQLite heavy computation",
		ExpectedDelay: 3 * time.Second, // Lower threshold for computation-based delays
	},
}

// SQLiOption is a function that configures a SQLiScanner.
type SQLiOption func(*SQLiScanner)

// WithSQLiHTTPClient sets a custom HTTP client for the SQL injection scanner.
func WithSQLiHTTPClient(c HTTPClient) SQLiOption {
	return func(s *SQLiScanner) {
		s.client = c
	}
}

// WithSQLiUserAgent sets the user agent string for the SQL injection scanner.
func WithSQLiUserAgent(ua string) SQLiOption {
	return func(s *SQLiScanner) {
		s.userAgent = ua
	}
}

// WithSQLiTimeout sets the timeout for HTTP requests.
func WithSQLiTimeout(d time.Duration) SQLiOption {
	return func(s *SQLiScanner) {
		s.timeout = d
	}
}

// WithSQLiAuth sets the authentication configuration for the SQL injection scanner.
func WithSQLiAuth(config *auth.AuthConfig) SQLiOption {
	return func(s *SQLiScanner) {
		s.authConfig = config
	}
}

// WithSQLiRateLimiter sets a rate limiter for the SQL injection scanner.
func WithSQLiRateLimiter(limiter ratelimit.Limiter) SQLiOption {
	return func(s *SQLiScanner) {
		s.rateLimiter = limiter
	}
}

// WithSQLiRateLimitConfig sets rate limiting from a configuration.
func WithSQLiRateLimitConfig(cfg ratelimit.Config) SQLiOption {
	return func(s *SQLiScanner) {
		s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg)
	}
}

// WithSQLiTracer sets the OpenTelemetry tracer for the SQL injection scanner.
func WithSQLiTracer(tracer trace.Tracer) SQLiOption {
	return func(s *SQLiScanner) {
		s.tracer = tracer
	}
}

// WithSQLiTimeBasedDelay sets the expected delay duration for time-based SQL injection detection.
func WithSQLiTimeBasedDelay(d time.Duration) SQLiOption {
	return func(s *SQLiScanner) {
		s.timeBasedDelay = d
	}
}

// NewSQLiScanner creates a new SQLiScanner with the given options.
func NewSQLiScanner(opts ...SQLiOption) *SQLiScanner {
	s := &SQLiScanner{
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

// Scan performs a SQL injection vulnerability scan on the given target URL.
func (s *SQLiScanner) Scan(ctx context.Context, targetURL string) *SQLiScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanSQLi)
		defer span.End()
	}

	result := &SQLiScanResult{
		Target:   targetURL,
		Findings: make([]SQLiFinding, 0),
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
		params.Set("id", "1")
		params.Set("user", "1")
		params.Set("page", "1")
		params.Set("product", "1")
	}

	// Filter out non-data parameters (submit buttons, CSRF tokens, etc.)
	paramsToTest := make(map[string]bool)
	for paramName := range params {
		if !isNonDataParameter(paramName) {
			paramsToTest[paramName] = true
		}
	}

	// Get baseline responses for boolean-based detection and baseline timing for time-based detection
	baselineResponses := make(map[string]*baselineResponse)
	baselineTiming := make(map[string]time.Duration)
	for paramName := range paramsToTest {
		baseline, duration := s.getBaselineWithTiming(ctx, parsedURL, paramName)
		if baseline != nil {
			baselineResponses[paramName] = baseline
			baselineTiming[paramName] = duration
		}
	}

	// Test each parameter with each payload
	for paramName := range paramsToTest {
		for _, payload := range sqliPayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			var finding *SQLiFinding
			if payload.Type == "time-based" {
				// Time-based detection
				baseline := baselineTiming[paramName]
				finding = s.testTimeBased(ctx, parsedURL, paramName, payload, baseline)
			} else if payload.CompareBaseline {
				// Boolean-based detection
				baseline := baselineResponses[paramName]
				finding = s.testBooleanBased(ctx, parsedURL, paramName, payload, baseline)
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

	// DVWA-style fallback: If no vulnerabilities found and responses look like empty forms,
	// try adding a Submit parameter. This handles cases where forms require a submit button
	// parameter to process the query (e.g., DVWA's /vulnerabilities/sqli/).
	// This fixes issue #188.
	if result.Summary.VulnerabilitiesFound == 0 && len(paramsToTest) > 0 {
		// Check if baseline responses look like empty forms (no data, just structure)
		looksLikeEmptyForm := false
		for _, baseline := range baselineResponses {
			// If response is small and contains form-like keywords, it might be an unprocessed form
			if baseline.BodyLength < 3000 && strings.Contains(strings.ToLower(baseline.ContainsKey), "form") {
				looksLikeEmptyForm = true
				break
			}
		}

		// Check if URL path suggests it's a form endpoint
		pathLower := strings.ToLower(parsedURL.Path)
		isLikelyFormEndpoint := strings.Contains(pathLower, "sqli") ||
			strings.Contains(pathLower, "sql") ||
			strings.Contains(pathLower, "search") ||
			strings.Contains(pathLower, "query") ||
			strings.Contains(pathLower, "login") ||
			strings.Contains(pathLower, "user")

		// If it looks like an empty form or is a likely form endpoint, try adding Submit parameter
		if looksLikeEmptyForm || isLikelyFormEndpoint {
			// Check if Submit parameter is already present
			hasSubmit := false
			for paramName := range params {
				if strings.ToLower(paramName) == "submit" {
					hasSubmit = true
					break
				}
			}

			if !hasSubmit {
				// Create a new URL with Submit parameter added
				retryURL := *parsedURL
				retryParams := retryURL.Query()
				retryParams.Set("Submit", "Submit")
				retryURL.RawQuery = retryParams.Encode()

				// Get new baselines with Submit parameter
				retryBaselineResponses := make(map[string]*baselineResponse)
				for paramName := range paramsToTest {
					baseline, _ := s.getBaselineWithTiming(ctx, &retryURL, paramName)
					if baseline != nil {
						retryBaselineResponses[paramName] = baseline
					}
				}

				// Re-test with Submit parameter - only boolean-based payloads since those are most affected
				for paramName := range paramsToTest {
					for _, payload := range sqliPayloads {
						if !payload.CompareBaseline {
							continue // Skip non-boolean payloads in retry
						}

						if s.rateLimiter != nil {
							if err := s.rateLimiter.Wait(ctx); err != nil {
								break
							}
						}

						baseline := retryBaselineResponses[paramName]
						finding := s.testBooleanBased(ctx, &retryURL, paramName, payload, baseline)

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
			}
		}
	}

	// Calculate final summary
	s.calculateSummary(result)

	return result
}

// ScanPOST scans a URL for SQL injection vulnerabilities using POST form data.
// Unlike Scan(), which tests GET query parameters, ScanPOST sends payloads in
// the request body as application/x-www-form-urlencoded data.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - targetURL: The URL to test (should not include query parameters)
//   - parameters: Form parameters and their original values. When testing each
//     parameter, all other parameters are included with their original values
//     to ensure proper form validation. If empty, tests common parameter names
//     (id, user, page, product) with default values.
//
// Returns:
//   - A SQLiScanResult containing all findings, summary statistics, and any errors.
//     The result is never nil, even if errors occur.
//
// This method is typically called by the discovery module when scanning POST forms.
func (s *SQLiScanner) ScanPOST(ctx context.Context, targetURL string, parameters map[string]string) *SQLiScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanSQLi)
		defer span.End()
	}

	result := &SQLiScanResult{
		Target:   targetURL,
		Findings: make([]SQLiFinding, 0),
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
		params = map[string]string{
			"id":      "1",
			"user":    "1",
			"page":    "1",
			"product": "1",
		}
	}

	// Filter out non-data parameters (submit buttons, CSRF tokens, etc.)
	paramsToTest := make(map[string]string)
	for paramName, paramValue := range params {
		if !isNonDataParameter(paramName) {
			paramsToTest[paramName] = paramValue
		}
	}

	// Get baseline responses for boolean-based detection and baseline timing for time-based detection
	baselineResponses := make(map[string]*baselineResponse)
	baselineTiming := make(map[string]time.Duration)
	for paramName := range paramsToTest {
		baseline, duration := s.getBaselineWithTimingPOST(ctx, parsedURL, paramName, paramsToTest)
		if baseline != nil {
			baselineResponses[paramName] = baseline
			baselineTiming[paramName] = duration
		}
	}

	// Test each parameter with each payload
	for paramName := range paramsToTest {
		for _, payload := range sqliPayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			var finding *SQLiFinding
			if payload.Type == "time-based" {
				// Time-based detection
				baseline := baselineTiming[paramName]
				finding = s.testTimeBasedPOST(ctx, parsedURL, paramName, payload, baseline, paramsToTest)
			} else if payload.CompareBaseline {
				// Boolean-based detection
				baseline := baselineResponses[paramName]
				finding = s.testBooleanBasedPOST(ctx, parsedURL, paramName, payload, baseline, paramsToTest)
			} else {
				// Error-based detection
				finding = s.testErrorBasedPOST(ctx, parsedURL, paramName, payload, paramsToTest)
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

// baselineResponse stores information about a baseline request for comparison.
type baselineResponse struct {
	StatusCode    int
	BodyLength    int
	BodyHash      string
	ContainsKey   string
	DataWordCount int    // Number of words in data-bearing elements (td, th, pre)
	DataContent   string // Text extracted from data-bearing elements
	DataRowCount  int    // Number of table rows with data cells
}

// getBaseline makes a request with the original parameter value to establish a baseline.
func (s *SQLiScanner) getBaseline(ctx context.Context, baseURL *url.URL, paramName string) *baselineResponse {
	baseline, _ := s.getBaselineWithTiming(ctx, baseURL, paramName)
	return baseline
}

// getBaselineWithTiming makes a request with the original parameter value to establish a baseline
// and measures the request duration for time-based detection.
func (s *SQLiScanner) getBaselineWithTiming(ctx context.Context, baseURL *url.URL, paramName string) (*baselineResponse, time.Duration) {
	// Create a copy of the URL with the original parameter value
	testURL := *baseURL
	q := testURL.Query()

	// Use original value if it exists, otherwise use a safe default
	originalValue := q.Get(paramName)
	if originalValue == "" {
		originalValue = "1"
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

	bodyStr := string(body)
	_, _, _, dataContent, dataWordCount, dataRowCount := analyzeResponse(bodyStr)

	baseline := &baselineResponse{
		StatusCode:    resp.StatusCode,
		BodyLength:    len(body),
		BodyHash:      fmt.Sprintf("%x", len(body)), // Simple hash for comparison
		ContainsKey:   bodyStr,
		DataWordCount: dataWordCount,
		DataContent:   dataContent,
		DataRowCount:  dataRowCount,
	}

	return baseline, duration
}

// getBaselineWithTimingPOST makes a POST request with the original parameter value to establish a baseline
// and measures the request duration for time-based detection.
func (s *SQLiScanner) getBaselineWithTimingPOST(ctx context.Context, baseURL *url.URL, paramName string, allParameters map[string]string) (*baselineResponse, time.Duration) {
	// Create form data with ALL parameters
	formData := url.Values{}
	for k, v := range allParameters {
		formData.Set(k, v)
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, 0
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

	bodyStr := string(body)
	_, _, _, dataContent, dataWordCount, dataRowCount := analyzeResponse(bodyStr)

	// Calculate proper hash of response body
	hash := md5.Sum(body)

	baseline := &baselineResponse{
		StatusCode:    resp.StatusCode,
		BodyLength:    len(body),
		BodyHash:      fmt.Sprintf("%x", hash),
		ContainsKey:   bodyStr,
		DataWordCount: dataWordCount,
		DataContent:   dataContent,
		DataRowCount:  dataRowCount,
	}

	return baseline, duration
}

// testErrorBased tests a single parameter with an error-based SQL injection payload.
func (s *SQLiScanner) testErrorBased(ctx context.Context, baseURL *url.URL, paramName string, payload sqliPayload) *SQLiFinding {
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

	// Check for SQL error patterns in the response
	for _, pattern := range sqlErrorPatterns {
		if pattern.MatchString(bodyStr) {
			// SQL error detected!
			match := pattern.FindString(bodyStr)
			finding := &SQLiFinding{
				URL:         testURL.String(),
				Parameter:   paramName,
				Payload:     payload.Payload,
				Evidence:    s.extractEvidence(bodyStr, match),
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "high", // Error-based detection with SQL errors is high confidence
			}
			return finding
		}
	}

	return nil
}

// responseCharacteristics holds response data for comparison
type responseCharacteristics struct {
	StatusCode         int
	BodyLength         int
	Body               string
	ContentHash        string // MD5 hash of extracted body content
	WordCount          int    // Number of words in the response
	StructuralElements int    // Count of structural HTML elements (tr, li, etc.)
	DataContent        string // Text extracted from data-bearing elements (td, th, pre)
	DataWordCount      int    // Number of words in data content
	DataRowCount       int    // Number of table rows in data regions (for DVWA-style detection)
}

// extractBodyContent strips non-content elements and extracts meaningful text from HTML
// Uses golang.org/x/net/html parser to avoid ReDoS vulnerabilities from regex patterns

// normalizeResponseContent removes dynamic content (CSRF tokens, nonces, timestamps)
// from HTML responses before comparison to reduce false positives in differential analysis
func normalizeResponseContent(htmlStr string) string {
	normalized := htmlStr
	for _, pattern := range dynamicContentPatterns {
		normalized = pattern.ReplaceAllString(normalized, "")
	}
	return normalized
}

// isNonDataParameter checks if a parameter name indicates it's not a data field
// (e.g., submit buttons, action selectors, known non-data fields)
func isNonDataParameter(paramName string) bool {
	paramLower := strings.ToLower(paramName)

	// Submit button patterns — matched as substrings (case-insensitive via ToLower above).
	// "change" is included to catch DVWA's Change submit button on /csrf/. As with the
	// pre-existing "go" entry (which also matches "cargo", "category"), this introduces
	// known false-negative surface: "exchange", "last_changed", "changelog" etc. will
	// also be suppressed. This is an acceptable trade-off given the low prevalence of such
	// parameter names on real injection targets; see TestIsNonDataParameter for the
	// documented collisions.
	submitPatterns := []string{"submit", "button", "btn", "send", "go", "action", "change"}
	for _, pattern := range submitPatterns {
		if strings.Contains(paramLower, pattern) {
			return true
		}
	}

	// DVWA-specific non-data fields (submit buttons and action selectors in the DVWA app)
	dvwaPatterns := []string{"seclev_submit", "upload", "security", "phpids", "login"}
	for _, pattern := range dvwaPatterns {
		if paramLower == pattern {
			return true
		}
	}

	// Common non-data form fields
	nonDataFields := []string{"csrf", "token", "_token", "nonce", "session"}
	for _, field := range nonDataFields {
		if strings.Contains(paramLower, field) {
			return true
		}
	}

	return false
}

func extractBodyContent(htmlStr string) string {
	// Limit input size to prevent memory exhaustion
	if len(htmlStr) > maxResponseSize {
		htmlStr = htmlStr[:maxResponseSize]
	}

	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		// If parsing fails, fall back to simple whitespace normalization
		return strings.Join(strings.Fields(htmlStr), " ")
	}

	var textBuilder strings.Builder
	var extractText func(*html.Node)

	extractText = func(n *html.Node) {
		// Skip script and style elements entirely
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style") {
			return
		}

		// Extract text from text nodes
		if n.Type == html.TextNode {
			text := strings.TrimSpace(n.Data)
			if text != "" {
				if textBuilder.Len() > 0 {
					textBuilder.WriteString(" ")
				}
				textBuilder.WriteString(text)
			}
		}

		// Recursively process child nodes
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractText(c)
		}
	}

	extractText(doc)

	// Normalize whitespace
	content := strings.Join(strings.Fields(textBuilder.String()), " ")
	return content
}

// extractDataContent extracts text content specifically from data-bearing elements (td, th, pre)
// This is more targeted than extractBodyContent and helps detect DVWA-style responses
// where the difference is only in the actual data cells, not the overall page structure
func extractDataContent(htmlStr string) string {
	// Normalize to remove dynamic content like CSRF tokens
	htmlStr = normalizeResponseContent(htmlStr)

	// Limit input size to prevent memory exhaustion
	if len(htmlStr) > maxResponseSize {
		htmlStr = htmlStr[:maxResponseSize]
	}

	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		// If parsing fails, return empty string
		return ""
	}

	var textBuilder strings.Builder
	var extractFromDataElements func(*html.Node)

	extractFromDataElements = func(n *html.Node) {
		// Only extract text from data-bearing elements
		if n.Type == html.ElementNode && (n.Data == "td" || n.Data == "th" || n.Data == "pre") {
			// Extract all text within this element
			var innerText strings.Builder
			var extractInnerText func(*html.Node)

			extractInnerText = func(inner *html.Node) {
				if inner.Type == html.TextNode {
					text := strings.TrimSpace(inner.Data)
					if text != "" {
						if innerText.Len() > 0 {
							innerText.WriteString(" ")
						}
						innerText.WriteString(text)
					}
				}
				for c := inner.FirstChild; c != nil; c = c.NextSibling {
					extractInnerText(c)
				}
			}

			extractInnerText(n)

			if innerText.Len() > 0 {
				if textBuilder.Len() > 0 {
					textBuilder.WriteString(" ")
				}
				textBuilder.WriteString(innerText.String())
			}
		}

		// Continue traversing the tree
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractFromDataElements(c)
		}
	}

	extractFromDataElements(doc)

	// Normalize whitespace
	content := strings.Join(strings.Fields(textBuilder.String()), " ")
	return content
}

// computeContentHash calculates MD5 hash of extracted body content
// Note: MD5 is intentionally used here for performance in a non-cryptographic context.
// This is for content fingerprinting/comparison only, not security or authentication.
func computeContentHash(html string) string {
	// Normalize to remove dynamic content like CSRF tokens before hashing
	normalized := normalizeResponseContent(html)
	content := extractBodyContent(normalized)
	hash := md5.Sum([]byte(content))
	return fmt.Sprintf("%x", hash)
}

// countWords counts the number of words in the response body
func countWords(body string) int {
	// Normalize to remove dynamic content like CSRF tokens before counting
	normalized := normalizeResponseContent(body)
	content := extractBodyContent(normalized)
	if content == "" {
		return 0
	}
	return len(strings.Fields(content))
}

// countStructuralElements counts HTML elements that typically contain data rows
// Uses pre-compiled regex patterns for performance
func countStructuralElements(htmlStr string) int {
	// Limit input size to prevent excessive processing
	if len(htmlStr) > maxResponseSize {
		htmlStr = htmlStr[:maxResponseSize]
	}

	count := 0

	// Count table rows using pre-compiled regex
	count += len(trRegex.FindAllString(htmlStr, -1))

	// Count list items using pre-compiled regex
	count += len(liRegex.FindAllString(htmlStr, -1))

	// Count divs with common data classes using pre-compiled regex
	count += len(divRegex.FindAllString(htmlStr, -1))

	return count
}

// countDataRows counts table rows that contain actual data (td elements)
// This is more specific than countStructuralElements and helps detect DVWA-style
// responses where the difference is in the number of data rows returned
func countDataRows(htmlStr string) int {
	// Limit input size to prevent excessive processing
	if len(htmlStr) > maxResponseSize {
		htmlStr = htmlStr[:maxResponseSize]
	}

	// Parse HTML to count rows with data cells
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		// Fallback: use simple string counting if parsing fails
		// Count <tr> tags that have at least one <td> child
		trMatches := trRegex.FindAllStringIndex(htmlStr, -1)
		count := 0
		for _, trMatch := range trMatches {
			// Look for a <td> tag after this <tr> and before the next </tr>
			trStart := trMatch[1]
			trEndIndex := strings.Index(htmlStr[trStart:], "</tr>")
			if trEndIndex == -1 {
				trEndIndex = len(htmlStr) - trStart
			}
			rowContent := htmlStr[trStart : trStart+trEndIndex]
			if strings.Contains(rowContent, "<td") {
				count++
			}
		}
		return count
	}

	// Use HTML parser to accurately count data rows
	dataRowCount := 0
	var countRows func(*html.Node)

	countRows = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "tr" {
			// Check if this tr has any td children
			hasTD := false
			var checkForTD func(*html.Node)
			checkForTD = func(child *html.Node) {
				if child.Type == html.ElementNode && child.Data == "td" {
					hasTD = true
					return
				}
				for c := child.FirstChild; c != nil; c = c.NextSibling {
					if hasTD {
						return
					}
					checkForTD(c)
				}
			}

			for c := n.FirstChild; c != nil; c = c.NextSibling {
				checkForTD(c)
				if hasTD {
					break
				}
			}

			if hasTD {
				dataRowCount++
			}
		}

		// Continue traversing
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			countRows(c)
		}
	}

	countRows(doc)
	return dataRowCount
}

// detectNoResultsPattern checks if the response indicates "no results" or empty data
func detectNoResultsPattern(body string) bool {
	bodyLower := strings.ToLower(body)

	// Common "no results" patterns
	noResultsPatterns := []string{
		"no results",
		"no records",
		"0 results",
		"no data",
		"not found",
		"no matches",
		"no entries",
		"empty",
		"no user", // DVWA-specific pattern
	}

	for _, pattern := range noResultsPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	// Check for empty table bodies (table with header but no data rows)
	// This is common in DVWA when no results are returned
	if strings.Contains(body, "<table") {
		// Extract content between table tags
		tableStart := strings.Index(body, "<table")
		if tableStart != -1 {
			tableEnd := strings.Index(body[tableStart:], "</table>")
			if tableEnd != -1 {
				tableContent := body[tableStart : tableStart+tableEnd]

				// Check if table has headers but no data cells
				// Count <th> vs <td> tags
				thCount := strings.Count(tableContent, "<th")
				tdCount := strings.Count(tableContent, "<td")

				// If we have headers but no data cells, it's empty
				if thCount > 0 && tdCount == 0 {
					return true
				}

				// Count tr tags in the table
				trCount := len(trRegex.FindAllString(tableContent, -1))
				// If table has 0-1 rows and no td tags, it might indicate no results
				// But if it has td tags, it has data regardless of tr count
				if trCount <= 1 && tdCount == 0 {
					return true
				}
			}
		}
	}

	return false
}

// hasResultsData checks if the response contains actual data/results
func hasResultsData(body string, structuralElements int) bool {
	// If there are multiple structural elements, likely has data
	// Lowered threshold from 2 to 1 to better detect DVWA-style responses
	if structuralElements > 1 {
		return true
	}

	// Check for "no results" pattern first
	if detectNoResultsPattern(body) {
		return false
	}

	// Check for presence of data-like content (table cells with data)
	// DVWA often returns data in <td> tags or <pre> tags
	if strings.Contains(body, "<td") {
		// Has table data cells - likely contains results
		// Even a single td with content indicates data
		return true
	}

	if strings.Contains(body, "<pre") {
		// Extract text content to see if there's actual data in pre tags
		content := extractBodyContent(body)
		// If we have any meaningful content, it's data
		if len(content) > 5 {
			return true
		}
	}

	// Check word count - very few words might indicate no data
	wordCount := countWords(body)
	if wordCount < 3 {
		return false
	}

	return true
}

// analyzeResponse extracts all characteristics from a response
// Optimized to extract body content only once
func analyzeResponse(body string) (contentHash string, wordCount int, structuralElements int, dataContent string, dataWordCount int, dataRowCount int) {
	// Normalize to remove dynamic content (CSRF tokens, nonces, timestamps)
	// before computing ContentHash and WordCount to avoid false positives caused
	// by per-request token changes (e.g. DVWA user_token hidden field).
	normalizedBody := normalizeResponseContent(body)
	extractedContent := extractBodyContent(normalizedBody)

	// Compute hash from normalized extracted content
	hash := md5.Sum([]byte(extractedContent))
	contentHash = fmt.Sprintf("%x", hash)

	// Count words from normalized extracted content
	if extractedContent == "" {
		wordCount = 0
	} else {
		wordCount = len(strings.Fields(extractedContent))
	}

	// Count structural elements from raw HTML (needs tags)
	structuralElements = countStructuralElements(body)

	// Extract data content from data-bearing elements (td, th, pre)
	dataContent = extractDataContent(body)
	if dataContent == "" {
		dataWordCount = 0
	} else {
		dataWordCount = len(strings.Fields(dataContent))
	}

	// Count data rows (rows with td elements) for DVWA-style detection
	dataRowCount = countDataRows(body)

	return
}

// makeRequest is a helper to make a request with a specific payload
func (s *SQLiScanner) makeRequest(ctx context.Context, baseURL *url.URL, paramName string, payloadValue string) (*responseCharacteristics, error) {
	testURL := *baseURL
	q := testURL.Query()
	q.Set(paramName, payloadValue)
	testURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bodyStr := string(body)
	contentHash, wordCount, structuralElements, dataContent, dataWordCount, dataRowCount := analyzeResponse(bodyStr)

	return &responseCharacteristics{
		StatusCode:         resp.StatusCode,
		BodyLength:         len(body),
		Body:               bodyStr,
		ContentHash:        contentHash,
		WordCount:          wordCount,
		StructuralElements: structuralElements,
		DataContent:        dataContent,
		DataWordCount:      dataWordCount,
		DataRowCount:       dataRowCount,
	}, nil
}

// makeRequestPOST is a helper to make a POST request with a specific payload
func (s *SQLiScanner) makeRequestPOST(ctx context.Context, baseURL *url.URL, paramName string, payloadValue string, allParameters map[string]string) (*responseCharacteristics, error) {
	// Create form data with ALL parameters
	formData := url.Values{}
	for k, v := range allParameters {
		formData.Set(k, v)
	}
	// Override the parameter being tested
	formData.Set(paramName, payloadValue)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bodyStr := string(body)
	contentHash, wordCount, structuralElements, dataContent, dataWordCount, dataRowCount := analyzeResponse(bodyStr)

	return &responseCharacteristics{
		StatusCode:         resp.StatusCode,
		BodyLength:         len(body),
		Body:               bodyStr,
		ContentHash:        contentHash,
		WordCount:          wordCount,
		StructuralElements: structuralElements,
		DataContent:        dataContent,
		DataWordCount:      dataWordCount,
		DataRowCount:       dataRowCount,
	}, nil
}

// isContentRouting checks whether a GET parameter is used for content routing rather than
// SQL injection. It sends a random non-SQL string and compares the response against the
// baseline. If the random value also produces a significantly different response, the
// parameter routes to different content pages and should not be tested for boolean-based SQLi.
func (s *SQLiScanner) isContentRouting(ctx context.Context, baseURL *url.URL, paramName string, baseline *baselineResponse) bool {
	randomValue := fmt.Sprintf("randomstring_%d", rand.Intn(99999))
	resp, err := s.makeRequest(ctx, baseURL, paramName, randomValue)
	if err != nil {
		return false // On error, assume not content-routing and proceed with testing
	}
	return responseSignificantlyDiffers(resp, baseline)
}

// isContentRoutingPOST checks whether a POST parameter is used for content routing rather than
// SQL injection. Same logic as isContentRouting but for POST requests.
func (s *SQLiScanner) isContentRoutingPOST(ctx context.Context, baseURL *url.URL, paramName string, baseline *baselineResponse, allParameters map[string]string) bool {
	randomValue := fmt.Sprintf("randomstring_%d", rand.Intn(99999))
	resp, err := s.makeRequestPOST(ctx, baseURL, paramName, randomValue, allParameters)
	if err != nil {
		return false
	}
	return responseSignificantlyDiffers(resp, baseline)
}

// responseSignificantlyDiffers returns true if the response differs significantly from the
// baseline, using the same thresholds as the boolean-based differential analysis.
func responseSignificantlyDiffers(resp *responseCharacteristics, baseline *baselineResponse) bool {
	// Status code difference
	if resp.StatusCode != baseline.StatusCode {
		return true
	}

	// Length difference using the same 10% threshold used in single-payload analysis
	if baseline.BodyLength > 0 {
		lengthDiff := abs(resp.BodyLength - baseline.BodyLength)
		if lengthDiff > baseline.BodyLength/10 {
			return true
		}
	}

	return false
}

// testBooleanBased tests a single parameter with a boolean-based SQL injection payload.
// It now performs differential analysis with complementary payloads to reduce false positives.
func (s *SQLiScanner) testBooleanBased(ctx context.Context, baseURL *url.URL, paramName string, payload sqliPayload, baseline *baselineResponse) *SQLiFinding {
	if baseline == nil {
		return nil
	}

	// Content-routing pre-check: send a random non-SQL string and compare against the baseline.
	// If a random value also produces a significantly different response, the parameter is used
	// for content routing (e.g., switching between documentation pages), not SQL injection.
	if s.isContentRouting(ctx, baseURL, paramName, baseline) {
		return nil
	}

	// For boolean-based detection, we need to test complementary conditions
	// to confirm it's actually SQL injection and not just application behavior
	var truePayload, falsePayload string
	confidence := "medium"

	// Identify the payload type and determine complementary payloads
	if strings.Contains(payload.Payload, "'1'='1") {
		truePayload = payload.Payload
		// Create a complementary false condition
		falsePayload = strings.ReplaceAll(payload.Payload, "'1'='1", "'1'='2")
	} else if strings.Contains(payload.Payload, "'1'='2") {
		falsePayload = payload.Payload
		// Create a complementary true condition
		truePayload = strings.ReplaceAll(payload.Payload, "'1'='2", "'1'='1")
	} else {
		// For other payloads, just do single test (backward compatibility)
		testResp, err := s.makeRequest(ctx, baseURL, paramName, payload.Payload)
		if err != nil {
			return nil
		}

		// Check for SQL errors first (high confidence)
		for _, pattern := range sqlErrorPatterns {
			if pattern.MatchString(testResp.Body) {
				match := pattern.FindString(testResp.Body)
				return &SQLiFinding{
					URL:         baseURL.String(),
					Parameter:   paramName,
					Payload:     payload.Payload,
					Evidence:    s.extractEvidence(testResp.Body, match),
					Severity:    payload.Severity,
					Type:        payload.Type,
					Description: payload.Description,
					Remediation: s.getRemediation(),
					Confidence:  "high", // SQL errors are high confidence
				}
			}
		}

		// Compare with baseline for significant differences
		significantDifference := false
		evidenceMsg := ""

		if testResp.StatusCode != baseline.StatusCode {
			significantDifference = true
			evidenceMsg = fmt.Sprintf("Status code changed from %d to %d", baseline.StatusCode, testResp.StatusCode)
		}

		lengthDiff := abs(testResp.BodyLength - baseline.BodyLength)
		if baseline.BodyLength > 0 && lengthDiff > baseline.BodyLength/10 {
			significantDifference = true
			if evidenceMsg != "" {
				evidenceMsg += "; "
			}
			evidenceMsg += fmt.Sprintf("Response length changed from %d to %d bytes", baseline.BodyLength, testResp.BodyLength)
		}

		if significantDifference {
			return &SQLiFinding{
				URL:         baseURL.String(),
				Parameter:   paramName,
				Payload:     payload.Payload,
				Evidence:    evidenceMsg,
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "low", // Without differential analysis, confidence is low
			}
		}

		return nil
	}

	// Perform differential analysis with true and false conditions
	trueResp, err := s.makeRequest(ctx, baseURL, paramName, truePayload)
	if err != nil {
		return nil
	}

	falseResp, err := s.makeRequest(ctx, baseURL, paramName, falsePayload)
	if err != nil {
		return nil
	}

	// Check if either response has SQL errors (indicates vulnerability)
	for _, pattern := range sqlErrorPatterns {
		if pattern.MatchString(trueResp.Body) || pattern.MatchString(falseResp.Body) {
			var match string
			if pattern.MatchString(trueResp.Body) {
				match = pattern.FindString(trueResp.Body)
			} else {
				match = pattern.FindString(falseResp.Body)
			}
			return &SQLiFinding{
				URL:         baseURL.String(),
				Parameter:   paramName,
				Payload:     payload.Payload,
				Evidence:    s.extractEvidence(trueResp.Body+falseResp.Body, match),
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "high", // SQL errors are always high confidence
			}
		}
	}

	// Differential analysis: compare true vs false responses
	// For SQL injection: true and false conditions should produce different responses
	trueDiffFromBaseline := abs(trueResp.BodyLength - baseline.BodyLength)
	falseDiffFromBaseline := abs(falseResp.BodyLength - baseline.BodyLength)
	trueFalseDiff := abs(trueResp.BodyLength - falseResp.BodyLength)

	// Adaptive thresholds based on baseline characteristics
	isSmallResponse := baseline.BodyLength < smallResponseSizeThreshold
	hasFewStructuralElements := trueResp.StructuralElements < fewStructuralElementsLimit || falseResp.StructuralElements < fewStructuralElementsLimit
	hasLowWordCount := trueResp.WordCount < minWordCountForPercentage || falseResp.WordCount < minWordCountForPercentage

	// Adjust thresholds for small responses or pages with few elements
	adaptiveLengthThreshold := lengthDifferenceThresholdPct
	adaptiveWordCountThreshold := minWordCountDifference

	if isSmallResponse || hasFewStructuralElements {
		// For small responses, use more sensitive thresholds
		adaptiveLengthThreshold = 5    // 5% for small responses (was 10%)
		adaptiveWordCountThreshold = 2 // 2 words minimum (was 3)
	}

	// For very low word counts, use absolute difference instead of percentage
	if hasLowWordCount {
		adaptiveWordCountThreshold = 1 // Any word difference is significant
	}

	// For DVWA-style responses: if baseline is moderate size, be more sensitive
	// DVWA typically returns 2-5KB responses with subtle differences
	if baseline.BodyLength > 1024 && baseline.BodyLength < 10240 {
		adaptiveLengthThreshold = 15 // Use 15% threshold for medium-sized responses
	}

	// Check if responses differ significantly between true and false conditions
	statusDiffers := trueResp.StatusCode != falseResp.StatusCode
	lengthDiffersSignificantly := false

	// True and false should differ from each other (using adaptive threshold)
	if baseline.BodyLength > 0 && trueFalseDiff > baseline.BodyLength/adaptiveLengthThreshold {
		lengthDiffersSignificantly = true
	}

	// Additionally, at least one should differ from baseline
	// Made more sensitive to catch DVWA-style differences
	baselineDiffers := false
	if baseline.BodyLength > 0 && (trueDiffFromBaseline > baseline.BodyLength/adaptiveLengthThreshold || falseDiffFromBaseline > baseline.BodyLength/adaptiveLengthThreshold) {
		baselineDiffers = true
	}

	// Content-based differential analysis using adaptive thresholds
	contentHashDiffers := trueResp.ContentHash != falseResp.ContentHash
	wordCountDiff := abs(trueResp.WordCount - falseResp.WordCount)
	wordCountDiffersSignificantly := wordCountDiff >= adaptiveWordCountThreshold
	structuralDiff := abs(trueResp.StructuralElements - falseResp.StructuralElements)
	structuralDiffersSignificantly := structuralDiff >= minStructuralElementDifference

	// Detect "no results" vs "has results" pattern (common in DVWA)
	trueHasResults := hasResultsData(trueResp.Body, trueResp.StructuralElements)
	falseHasResults := hasResultsData(falseResp.Body, falseResp.StructuralElements)
	resultsPatternDiffers := trueHasResults != falseHasResults

	// Build evidence message with all detection methods
	var detectionMethods []string
	detectedVulnerability := false

	if statusDiffers {
		detectionMethods = append(detectionMethods, fmt.Sprintf("status code differs (true: %d, false: %d)", trueResp.StatusCode, falseResp.StatusCode))
		detectedVulnerability = true
	}

	if lengthDiffersSignificantly {
		detectionMethods = append(detectionMethods, fmt.Sprintf("response length differs significantly (true: %d, false: %d, diff: %d bytes)", trueResp.BodyLength, falseResp.BodyLength, trueFalseDiff))
		detectedVulnerability = true
	}

	if contentHashDiffers {
		detectionMethods = append(detectionMethods, fmt.Sprintf("content hash differs (indicating different content)"))
		// Content hash difference with word count or structural difference indicates SQLi
		if wordCountDiffersSignificantly || structuralDiffersSignificantly {
			detectedVulnerability = true
		}
	}

	if wordCountDiffersSignificantly {
		detectionMethods = append(detectionMethods, fmt.Sprintf("word count differs (true: %d, false: %d, diff: %d words)", trueResp.WordCount, falseResp.WordCount, wordCountDiff))
		detectedVulnerability = true
	}

	if structuralDiffersSignificantly {
		detectionMethods = append(detectionMethods, fmt.Sprintf("structural elements differ (true: %d, false: %d, diff: %d elements)", trueResp.StructuralElements, falseResp.StructuralElements, structuralDiff))
		detectedVulnerability = true
	}

	// Check for "no results" vs "has results" pattern (DVWA-style detection)
	if resultsPatternDiffers {
		if trueHasResults && !falseHasResults {
			detectionMethods = append(detectionMethods, "true condition returns data while false returns no results (classic boolean SQLi)")
			detectedVulnerability = true
		} else if !trueHasResults && falseHasResults {
			detectionMethods = append(detectionMethods, "false condition returns data while true returns no results (inverted boolean SQLi)")
			detectedVulnerability = true
		}
	}

	// DVWA-style detection: Compare data content from data-bearing elements (td, th, pre)
	// This catches cases where the overall page structure is identical but the actual data differs
	dataContentDiffers := trueResp.DataContent != falseResp.DataContent
	dataWordCountDiff := abs(trueResp.DataWordCount - falseResp.DataWordCount)
	dataWordCountDiffersSignificantly := dataWordCountDiff >= adaptiveWordCountThreshold

	// Enhanced DVWA-style detection: If data content differs at all, even with low word count, flag it
	// DVWA often has minimal differences (e.g., "ID: 1, First name: admin" vs no data)
	if dataContentDiffers {
		if dataWordCountDiffersSignificantly {
			detectionMethods = append(detectionMethods, fmt.Sprintf("data content differs (true: %d words, false: %d words, diff: %d words in data elements)", trueResp.DataWordCount, falseResp.DataWordCount, dataWordCountDiff))
			detectedVulnerability = true
		} else if dataWordCountDiff > 0 {
			// Even a small difference in data content is suspicious for SQLi
			detectionMethods = append(detectionMethods, fmt.Sprintf("data content differs subtly (true: %d words, false: %d words in data elements)", trueResp.DataWordCount, falseResp.DataWordCount))
			detectedVulnerability = true
		}
	}

	// Row-count differential detection (DVWA-style): Compare number of table rows with data
	// This catches cases where true condition returns more rows than false condition
	dataRowCountDiff := abs(trueResp.DataRowCount - falseResp.DataRowCount)
	if dataRowCountDiff > 0 {
		detectionMethods = append(detectionMethods, fmt.Sprintf("data row count differs (true: %d rows, false: %d rows, diff: %d rows)", trueResp.DataRowCount, falseResp.DataRowCount, dataRowCountDiff))
		detectedVulnerability = true
	}

	// 3-way baseline comparison for numeric parameter detection:
	// If the true payload returns significantly MORE data than the baseline AND the false
	// payload stays near the baseline, that is a strong boolean-SQLi signal.
	// This catches the canonical DVWA id=1 case where:
	//   baseline → 1 row, true (1' OR '1'='1) → 5 rows, false (1' OR '1'='2) → 1 row
	// The two-way true/false diff is only ~28 words which is caught above, but the
	// three-way comparison provides a dedicated, higher-confidence detection path and
	// ensures correct detection even when the true/false diff happens to be small.
	// Only run the 3-way check when the baseline itself has measurable data content
	// (i.e. the endpoint is known to return data rows). A baseline with DataWordCount == 0
	// means the page has no <pre>/<td> elements, so the comparison would be meaningless
	// and could produce false positives on pages that naturally return varying content.
	if baseline.DataWordCount > 0 {
		trueExceedsBaseline := trueResp.DataWordCount > baseline.DataWordCount+adaptiveWordCountThreshold
		falseWithinBaseline := falseResp.DataWordCount <= baseline.DataWordCount+adaptiveWordCountThreshold
		if trueExceedsBaseline && falseWithinBaseline {
			detectionMethods = append(detectionMethods, fmt.Sprintf(
				"true payload returns more data than baseline while false stays near baseline (true: %d words, baseline: %d words, false: %d words)",
				trueResp.DataWordCount, baseline.DataWordCount, falseResp.DataWordCount))
			detectedVulnerability = true
		}
	}

	// For high confidence: true/false must behave differently via multiple methods
	// OR show strong content-based differences
	if detectedVulnerability {
		// Determine confidence based on detection method strength
		if statusDiffers || (lengthDiffersSignificantly && baselineDiffers) {
			confidence = "high"
		} else if contentHashDiffers && (wordCountDiffersSignificantly || structuralDiffersSignificantly) {
			confidence = "high"
		} else {
			confidence = "medium"
		}

		evidenceMsg := fmt.Sprintf("Differential analysis detected SQL injection via: %s. Baseline: %d bytes (status %d)",
			strings.Join(detectionMethods, "; "),
			baseline.BodyLength, baseline.StatusCode)

		return &SQLiFinding{
			URL:         baseURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    evidenceMsg,
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description + " (confirmed via differential analysis)",
			Remediation: s.getRemediation(),
			Confidence:  confidence,
		}
	}

	// If responses are identical or don't show SQL-like behavior, it's not vulnerable
	return nil
}

// testTimeBased tests a single parameter with a time-based SQL injection payload.
// It measures request duration and compares with baseline and expected delay.
func (s *SQLiScanner) testTimeBased(ctx context.Context, baseURL *url.URL, paramName string, payload sqliPayload, baselineDuration time.Duration) *SQLiFinding {
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

	// Read response body to check for SQL errors (which would indicate even higher confidence)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// First check if there are SQL errors - this would be even stronger evidence
	sqlErrorFound := false
	var errorMatch string
	for _, pattern := range sqlErrorPatterns {
		if pattern.MatchString(bodyStr) {
			sqlErrorFound = true
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
		evidenceMsg := fmt.Sprintf("Request took %v (baseline: %v, expected delay: %v) - indicates time-based SQL injection",
			requestDuration, baselineDuration, expectedDelay)

		// If SQL error is also present, mention it in evidence
		if sqlErrorFound {
			evidenceMsg += fmt.Sprintf("; SQL error also detected: %s", s.extractEvidence(bodyStr, errorMatch))
			confidence = "high" // Both timing and error confirms vulnerability
		}

		return &SQLiFinding{
			URL:         testURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    evidenceMsg,
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  confidence,
		}
	}

	return nil
}

// testErrorBasedPOST tests a single parameter with an error-based SQL injection payload using POST.
func (s *SQLiScanner) testErrorBasedPOST(ctx context.Context, baseURL *url.URL, paramName string, payload sqliPayload, allParameters map[string]string) *SQLiFinding {
	testResp, err := s.makeRequestPOST(ctx, baseURL, paramName, payload.Payload, allParameters)
	if err != nil {
		return nil
	}

	// Check for SQL error patterns in the response
	for _, pattern := range sqlErrorPatterns {
		if pattern.MatchString(testResp.Body) {
			// SQL error detected!
			match := pattern.FindString(testResp.Body)
			finding := &SQLiFinding{
				URL:         baseURL.String(),
				Parameter:   paramName,
				Payload:     payload.Payload,
				Evidence:    s.extractEvidence(testResp.Body, match),
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "high", // Error-based detection with SQL errors is high confidence
			}
			return finding
		}
	}

	return nil
}

// testBooleanBasedPOST tests a single parameter with a boolean-based SQL injection payload using POST.
func (s *SQLiScanner) testBooleanBasedPOST(ctx context.Context, baseURL *url.URL, paramName string, payload sqliPayload, baseline *baselineResponse, allParameters map[string]string) *SQLiFinding {
	if baseline == nil {
		return nil
	}

	// Content-routing pre-check: send a random non-SQL string and compare against the baseline.
	// If a random value also produces a significantly different response, the parameter is used
	// for content routing (e.g., switching between documentation pages), not SQL injection.
	if s.isContentRoutingPOST(ctx, baseURL, paramName, baseline, allParameters) {
		return nil
	}

	// For boolean-based detection, we need to test complementary conditions
	var truePayload, falsePayload string
	confidence := "medium"

	// Identify the payload type and determine complementary payloads
	if strings.Contains(payload.Payload, "'1'='1") {
		truePayload = payload.Payload
		falsePayload = strings.ReplaceAll(payload.Payload, "'1'='1", "'1'='2")
	} else if strings.Contains(payload.Payload, "'1'='2") {
		falsePayload = payload.Payload
		truePayload = strings.ReplaceAll(payload.Payload, "'1'='2", "'1'='1")
	} else {
		// For other payloads, just do single test
		testResp, err := s.makeRequestPOST(ctx, baseURL, paramName, payload.Payload, allParameters)
		if err != nil {
			return nil
		}

		// Check for SQL errors first (high confidence)
		for _, pattern := range sqlErrorPatterns {
			if pattern.MatchString(testResp.Body) {
				match := pattern.FindString(testResp.Body)
				return &SQLiFinding{
					URL:         baseURL.String(),
					Parameter:   paramName,
					Payload:     payload.Payload,
					Evidence:    s.extractEvidence(testResp.Body, match),
					Severity:    payload.Severity,
					Type:        payload.Type,
					Description: payload.Description,
					Remediation: s.getRemediation(),
					Confidence:  "high",
				}
			}
		}

		// Compare with baseline for significant differences
		significantDifference := false
		evidenceMsg := ""

		if testResp.StatusCode != baseline.StatusCode {
			significantDifference = true
			evidenceMsg = fmt.Sprintf("Status code changed from %d to %d", baseline.StatusCode, testResp.StatusCode)
		}

		lengthDiff := abs(testResp.BodyLength - baseline.BodyLength)
		if baseline.BodyLength > 0 && lengthDiff > baseline.BodyLength/10 {
			significantDifference = true
			if evidenceMsg != "" {
				evidenceMsg += "; "
			}
			evidenceMsg += fmt.Sprintf("Response length changed from %d to %d bytes (%.1f%% difference)",
				baseline.BodyLength, testResp.BodyLength, float64(lengthDiff)/float64(baseline.BodyLength)*100)
		}

		if significantDifference {
			return &SQLiFinding{
				URL:         baseURL.String(),
				Parameter:   paramName,
				Payload:     payload.Payload,
				Evidence:    evidenceMsg,
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "low",
			}
		}

		return nil
	}

	// Test both true and false conditions
	trueResp, err := s.makeRequestPOST(ctx, baseURL, paramName, truePayload, allParameters)
	if err != nil {
		return nil
	}

	falseResp, err := s.makeRequestPOST(ctx, baseURL, paramName, falsePayload, allParameters)
	if err != nil {
		return nil
	}

	// Check for SQL errors in either response
	for _, pattern := range sqlErrorPatterns {
		if pattern.MatchString(trueResp.Body) {
			match := pattern.FindString(trueResp.Body)
			return &SQLiFinding{
				URL:         baseURL.String(),
				Parameter:   paramName,
				Payload:     truePayload,
				Evidence:    s.extractEvidence(trueResp.Body, match),
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "high",
			}
		}
		if pattern.MatchString(falseResp.Body) {
			match := pattern.FindString(falseResp.Body)
			return &SQLiFinding{
				URL:         baseURL.String(),
				Parameter:   paramName,
				Payload:     falsePayload,
				Evidence:    s.extractEvidence(falseResp.Body, match),
				Severity:    payload.Severity,
				Type:        payload.Type,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  "high",
			}
		}
	}

	// Adaptive thresholds based on baseline characteristics
	isSmallResponse := baseline.BodyLength < smallResponseSizeThreshold
	hasFewStructuralElements := trueResp.StructuralElements < fewStructuralElementsLimit || falseResp.StructuralElements < fewStructuralElementsLimit
	hasLowWordCount := trueResp.WordCount < minWordCountForPercentage || falseResp.WordCount < minWordCountForPercentage

	// Adjust thresholds for small responses or pages with few elements
	adaptiveLengthThreshold := lengthDifferenceThresholdPct
	adaptiveWordCountThreshold := minWordCountDifference

	if isSmallResponse || hasFewStructuralElements {
		// For small responses, use more sensitive thresholds
		adaptiveLengthThreshold = 5    // 5% for small responses
		adaptiveWordCountThreshold = 2 // 2 words minimum
	}

	// For very low word counts, use absolute difference instead of percentage
	if hasLowWordCount {
		adaptiveWordCountThreshold = 1 // Any word difference is significant
	}

	// Compare true vs false responses for differential behavior (using adaptive threshold)
	lengthDiff := abs(trueResp.BodyLength - falseResp.BodyLength)
	statusDiff := trueResp.StatusCode != falseResp.StatusCode
	lengthDiffersSignificantly := lengthDiff > 0 && baseline.BodyLength > 0 && lengthDiff > baseline.BodyLength/adaptiveLengthThreshold

	// Content-based differential analysis using adaptive thresholds
	contentHashDiffers := trueResp.ContentHash != falseResp.ContentHash
	wordCountDiff := abs(trueResp.WordCount - falseResp.WordCount)
	wordCountDiffersSignificantly := wordCountDiff >= adaptiveWordCountThreshold
	structuralDiff := abs(trueResp.StructuralElements - falseResp.StructuralElements)
	structuralDiffersSignificantly := structuralDiff >= minStructuralElementDifference

	// Detect "no results" vs "has results" pattern (common in DVWA)
	trueHasResults := hasResultsData(trueResp.Body, trueResp.StructuralElements)
	falseHasResults := hasResultsData(falseResp.Body, falseResp.StructuralElements)
	resultsPatternDiffers := trueHasResults != falseHasResults

	// Build evidence message with all detection methods
	var detectionMethods []string
	detectedVulnerability := false

	if statusDiff {
		detectionMethods = append(detectionMethods, fmt.Sprintf("status code differs (true: %d, false: %d)", trueResp.StatusCode, falseResp.StatusCode))
		detectedVulnerability = true
	}

	if lengthDiffersSignificantly {
		detectionMethods = append(detectionMethods, fmt.Sprintf("response length differs significantly (true: %d, false: %d, diff: %d bytes)", trueResp.BodyLength, falseResp.BodyLength, lengthDiff))
		detectedVulnerability = true
	}

	if contentHashDiffers {
		detectionMethods = append(detectionMethods, fmt.Sprintf("content hash differs (indicating different content)"))
		// Content hash difference with word count or structural difference indicates SQLi
		if wordCountDiffersSignificantly || structuralDiffersSignificantly {
			detectedVulnerability = true
		}
	}

	if wordCountDiffersSignificantly {
		detectionMethods = append(detectionMethods, fmt.Sprintf("word count differs (true: %d, false: %d, diff: %d words)", trueResp.WordCount, falseResp.WordCount, wordCountDiff))
		detectedVulnerability = true
	}

	if structuralDiffersSignificantly {
		detectionMethods = append(detectionMethods, fmt.Sprintf("structural elements differ (true: %d, false: %d, diff: %d elements)", trueResp.StructuralElements, falseResp.StructuralElements, structuralDiff))
		detectedVulnerability = true
	}

	// Check for "no results" vs "has results" pattern (DVWA-style detection)
	if resultsPatternDiffers {
		if trueHasResults && !falseHasResults {
			detectionMethods = append(detectionMethods, "true condition returns data while false returns no results (classic boolean SQLi)")
			detectedVulnerability = true
		} else if !trueHasResults && falseHasResults {
			detectionMethods = append(detectionMethods, "false condition returns data while true returns no results (inverted boolean SQLi)")
			detectedVulnerability = true
		}
	}

	// DVWA-style detection: Compare data content from data-bearing elements (td, th, pre)
	// This catches cases where the overall page structure is identical but the actual data differs
	dataContentDiffers := trueResp.DataContent != falseResp.DataContent
	dataWordCountDiff := abs(trueResp.DataWordCount - falseResp.DataWordCount)
	dataWordCountDiffersSignificantly := dataWordCountDiff >= adaptiveWordCountThreshold

	if dataContentDiffers && dataWordCountDiffersSignificantly {
		detectionMethods = append(detectionMethods, fmt.Sprintf("data content differs (true: %d words, false: %d words, diff: %d words in data elements)", trueResp.DataWordCount, falseResp.DataWordCount, dataWordCountDiff))
		detectedVulnerability = true
	}

	// 3-way baseline comparison for numeric parameter detection (POST):
	// Mirrors the GET-path logic in testBooleanBased. Only runs when the baseline has
	// measurable data content (DataWordCount > 0), preventing false positives on pages
	// with no data-bearing elements.
	if baseline.DataWordCount > 0 {
		trueExceedsBaseline := trueResp.DataWordCount > baseline.DataWordCount+adaptiveWordCountThreshold
		falseWithinBaseline := falseResp.DataWordCount <= baseline.DataWordCount+adaptiveWordCountThreshold
		if trueExceedsBaseline && falseWithinBaseline {
			detectionMethods = append(detectionMethods, fmt.Sprintf(
				"true payload returns more data than baseline while false stays near baseline (true: %d words, baseline: %d words, false: %d words)",
				trueResp.DataWordCount, baseline.DataWordCount, falseResp.DataWordCount))
			detectedVulnerability = true
		}
	}

	// If true and false produce different responses, it's likely SQL injection
	if detectedVulnerability {
		// Determine confidence based on detection method strength
		if statusDiff || lengthDiffersSignificantly {
			confidence = "high"
		} else if contentHashDiffers && (wordCountDiffersSignificantly || structuralDiffersSignificantly) {
			confidence = "high"
		} else {
			confidence = "medium"
		}

		evidenceMsg := fmt.Sprintf("Differential analysis detected SQL injection via: %s",
			strings.Join(detectionMethods, "; "))

		return &SQLiFinding{
			URL:         baseURL.String(),
			Parameter:   paramName,
			Payload:     truePayload,
			Evidence:    evidenceMsg,
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  confidence,
		}
	}

	return nil
}

// testTimeBasedPOST tests a single parameter with a time-based SQL injection payload using POST.
func (s *SQLiScanner) testTimeBasedPOST(ctx context.Context, baseURL *url.URL, paramName string, payload sqliPayload, baselineDuration time.Duration, allParameters map[string]string) *SQLiFinding {
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

	// Read response body to check for SQL errors
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Check if there are SQL errors
	sqlErrorFound := false
	var errorMatch string
	for _, pattern := range sqlErrorPatterns {
		if pattern.MatchString(bodyStr) {
			sqlErrorFound = true
			errorMatch = pattern.FindString(bodyStr)
			break
		}
	}

	// Determine the expected delay
	expectedDelay := payload.ExpectedDelay
	if expectedDelay == 0 {
		expectedDelay = s.timeBasedDelay
	}

	// Calculate threshold
	tolerance := 1 * time.Second
	minExpectedDuration := baselineDuration + expectedDelay - tolerance

	// Check if the request took significantly longer than expected
	if requestDuration >= minExpectedDuration {
		confidence := "high"
		evidenceMsg := fmt.Sprintf("Request took %v (baseline: %v, expected delay: %v) - indicates time-based SQL injection",
			requestDuration, baselineDuration, expectedDelay)

		if sqlErrorFound {
			evidenceMsg += fmt.Sprintf("; SQL error also detected: %s", s.extractEvidence(bodyStr, errorMatch))
			confidence = "high"
		}

		return &SQLiFinding{
			URL:         baseURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    evidenceMsg,
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  confidence,
		}
	}

	return nil
}

// extractEvidence extracts a snippet of the response containing the SQL error.
func (s *SQLiScanner) extractEvidence(body, errorMatch string) string {
	if errorMatch == "" {
		return "SQL error detected in response"
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

// getRemediation returns remediation guidance for SQL injection vulnerabilities.
func (s *SQLiScanner) getRemediation() string {
	return "Use parameterized queries (prepared statements) for all database operations. " +
		"Never concatenate user input directly into SQL queries. " +
		"Implement input validation and sanitization on the server side. " +
		"Use an ORM (Object-Relational Mapping) framework that handles parameterization automatically. " +
		"Apply the principle of least privilege for database accounts. " +
		"Enable error handling that doesn't expose database details to users."
}

// calculateSummary calculates the summary statistics for the scan.
func (s *SQLiScanner) calculateSummary(result *SQLiScanResult) {
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
func (r *SQLiScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("SQL Injection Vulnerability Scan for: %s\n", r.Target))
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
			sb.WriteString(fmt.Sprintf("\n  %d. [%s] %s SQL Injection\n", i+1, strings.ToUpper(f.Severity), titleCase(f.Type)))
			sb.WriteString(fmt.Sprintf("     Parameter: %s\n", f.Parameter))
			sb.WriteString(fmt.Sprintf("     Payload: %s\n", f.Payload))
			sb.WriteString(fmt.Sprintf("     Description: %s\n", f.Description))
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("     Evidence: %s\n", f.Evidence))
			}
			sb.WriteString(fmt.Sprintf("     Remediation: %s\n", f.Remediation))
		}
	} else {
		sb.WriteString("\nNo SQL injection vulnerabilities detected.\n")
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
func (r *SQLiScanResult) HasResults() bool {
	return len(r.Findings) > 0 || r.Summary.TotalTests > 0
}

// abs returns the absolute value of an integer.
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// VerifyFinding re-tests a SQLi finding with payload variants using differential analysis.
func (s *SQLiScanner) VerifyFinding(ctx context.Context, finding *SQLiFinding, config VerificationConfig) (*VerificationResult, error) {
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

	// Generate payload variants for verification
	variants := s.generateSQLiPayloadVariants(finding.Payload, finding.Type)

	successCount := 0
	totalAttempts := 0
	maxAttempts := config.MaxRetries
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	// Get baseline timing for time-based verification
	var baselineDuration time.Duration
	if finding.Type == "time-based" {
		// For time-based, we need a clean baseline without the payload
		// Create a clean URL with safe parameter value
		cleanURL := *parsedURL
		q := cleanURL.Query()
		q.Set(finding.Parameter, "1") // Use safe default value
		cleanURL.RawQuery = q.Encode()
		_, baselineDuration = s.getBaselineWithTiming(ctx, &cleanURL, finding.Parameter)
	}

	// Test each variant using differential analysis
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

		// For time-based SQLi, measure request duration
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
			// Test the variant for error-based and boolean-based
			testResp, err := s.makeRequest(ctx, parsedURL, finding.Parameter, variant)
			if err != nil {
				continue
			}

			// For error-based SQLi, check for SQL error patterns
			if finding.Type == "error-based" {
				foundError := false
				for _, pattern := range sqlErrorPatterns {
					if pattern.MatchString(testResp.Body) {
						foundError = true
						break
					}
				}
				if foundError {
					successCount++
				}
			} else if finding.Type == "boolean-based" {
				// For boolean-based, use differential analysis
				// Generate complementary payload
				complementary := s.generateComplementaryPayload(variant)
				if complementary != "" {
					trueResp := testResp
					falseResp, err := s.makeRequest(ctx, parsedURL, finding.Parameter, complementary)
					if err != nil {
						continue
					}

					// Check if responses differ significantly
					trueFalseDiff := abs(trueResp.BodyLength - falseResp.BodyLength)
					if baseline.BodyLength > 0 && trueFalseDiff > baseline.BodyLength/20 {
						successCount++
					} else if trueResp.StatusCode != falseResp.StatusCode {
						successCount++
					}
				}
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

// generateSQLiPayloadVariants creates different encodings and variations of the SQL injection payload.
func (s *SQLiScanner) generateSQLiPayloadVariants(originalPayload, findingType string) []string {
	variants := make([]string, 0)

	// Add the original payload
	variants = append(variants, originalPayload)

	// Case variations
	if strings.Contains(originalPayload, "OR") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "OR", "or"))
		variants = append(variants, strings.ReplaceAll(originalPayload, "OR", "Or"))
	}

	// Space variations (tab, multiple spaces)
	if strings.Contains(originalPayload, " ") {
		variants = append(variants, strings.ReplaceAll(originalPayload, " ", "  "))
		variants = append(variants, strings.ReplaceAll(originalPayload, " ", "\t"))
	}

	// Comment style variations
	if strings.Contains(originalPayload, "--") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "--", "#"))
		variants = append(variants, strings.ReplaceAll(originalPayload, "--", "/**/"))
	}

	// Quote variations
	if strings.Contains(originalPayload, "'") {
		// Double quote variant
		doubleQuote := strings.ReplaceAll(originalPayload, "'", "\"")
		variants = append(variants, doubleQuote)
		// Escaped single quote
		variants = append(variants, strings.ReplaceAll(originalPayload, "'", "\\'"))
	}

	// Boolean condition variations
	if strings.Contains(originalPayload, "1'='1") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "1'='1", "2'='2"))
		variants = append(variants, strings.ReplaceAll(originalPayload, "1'='1", "'a'='a"))
	}

	// UNION variations
	if strings.Contains(originalPayload, "UNION") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "UNION", "union"))
		variants = append(variants, strings.ReplaceAll(originalPayload, "UNION", "UnIoN"))
	}

	// Time-based payload variations
	if findingType == "time-based" {
		// MySQL SLEEP variations
		if strings.Contains(originalPayload, "SLEEP(5)") {
			variants = append(variants, strings.ReplaceAll(originalPayload, "SLEEP(5)", "sleep(5)"))
			variants = append(variants, strings.ReplaceAll(originalPayload, "SLEEP(5)", "SLEEP(6)"))
		}
		// PostgreSQL pg_sleep variations
		if strings.Contains(originalPayload, "pg_sleep(5)") {
			variants = append(variants, strings.ReplaceAll(originalPayload, "pg_sleep(5)", "pg_sleep(6)"))
			variants = append(variants, strings.ReplaceAll(originalPayload, "pg_sleep(5)", "PG_SLEEP(5)"))
		}
		// SQL Server WAITFOR variations
		if strings.Contains(originalPayload, "WAITFOR DELAY") {
			variants = append(variants, strings.ReplaceAll(originalPayload, "WAITFOR DELAY", "waitfor delay"))
			variants = append(variants, strings.ReplaceAll(originalPayload, "'00:00:05'", "'00:00:06'"))
		}
	}

	return variants
}

// generateComplementaryPayload creates a complementary payload for differential analysis.
func (s *SQLiScanner) generateComplementaryPayload(payload string) string {
	// For true conditions, generate false conditions and vice versa
	if strings.Contains(payload, "'1'='1") {
		return strings.ReplaceAll(payload, "'1'='1", "'1'='2")
	}
	if strings.Contains(payload, "'1'='2") {
		return strings.ReplaceAll(payload, "'1'='2", "'1'='1")
	}
	if strings.Contains(payload, "'a'='a") {
		return strings.ReplaceAll(payload, "'a'='a", "'a'='b")
	}
	if strings.Contains(payload, "2'='2") {
		return strings.ReplaceAll(payload, "2'='2", "2'='3")
	}

	// For AND conditions
	if strings.Contains(payload, "AND") || strings.Contains(payload, "and") {
		// Swap AND with OR to get different behavior
		result := strings.ReplaceAll(payload, "AND", "OR")
		result = strings.ReplaceAll(result, "and", "or")
		return result
	}

	return ""
}
