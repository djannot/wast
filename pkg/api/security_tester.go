// Package api provides security testing functionality for API endpoints.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/httputil"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/scanner"
)

// SecurityTester performs comprehensive security testing on API endpoints.
type SecurityTester struct {
	client      HTTPClient
	userAgent   string
	timeout     time.Duration
	authConfig  *auth.AuthConfig
	rateLimiter ratelimit.Limiter
	sqliScanner *scanner.SQLiScanner
	xssScanner  *scanner.XSSScanner
}

// SecurityTesterOption is a function that configures a SecurityTester.
type SecurityTesterOption func(*SecurityTester)

// WithSecurityHTTPClient sets a custom HTTP client for the security tester.
func WithSecurityHTTPClient(c HTTPClient) SecurityTesterOption {
	return func(s *SecurityTester) {
		s.client = c
	}
}

// WithSecurityUserAgent sets the user agent string for the security tester.
func WithSecurityUserAgent(ua string) SecurityTesterOption {
	return func(s *SecurityTester) {
		s.userAgent = ua
	}
}

// WithSecurityTimeout sets the timeout for HTTP requests.
func WithSecurityTimeout(d time.Duration) SecurityTesterOption {
	return func(s *SecurityTester) {
		s.timeout = d
	}
}

// WithSecurityAuth sets the authentication configuration for the security tester.
func WithSecurityAuth(config *auth.AuthConfig) SecurityTesterOption {
	return func(s *SecurityTester) {
		s.authConfig = config
	}
}

// WithSecurityRateLimiter sets a rate limiter for the security tester.
func WithSecurityRateLimiter(limiter ratelimit.Limiter) SecurityTesterOption {
	return func(s *SecurityTester) {
		s.rateLimiter = limiter
	}
}

// NewSecurityTester creates a new SecurityTester with the given options.
func NewSecurityTester(opts ...SecurityTesterOption) *SecurityTester {
	s := &SecurityTester{
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

	// Initialize scanners
	sqliOpts := []scanner.SQLiOption{
		scanner.WithSQLiHTTPClient(s.client),
		scanner.WithSQLiUserAgent(s.userAgent),
		scanner.WithSQLiTimeout(s.timeout),
	}
	if s.authConfig != nil {
		sqliOpts = append(sqliOpts, scanner.WithSQLiAuth(s.authConfig))
	}
	if s.rateLimiter != nil {
		sqliOpts = append(sqliOpts, scanner.WithSQLiRateLimiter(s.rateLimiter))
	}
	s.sqliScanner = scanner.NewSQLiScanner(sqliOpts...)

	xssOpts := []scanner.XSSOption{
		scanner.WithXSSHTTPClient(s.client),
		scanner.WithXSSUserAgent(s.userAgent),
		scanner.WithXSSTimeout(s.timeout),
	}
	if s.authConfig != nil {
		xssOpts = append(xssOpts, scanner.WithXSSAuth(s.authConfig))
	}
	if s.rateLimiter != nil {
		xssOpts = append(xssOpts, scanner.WithXSSRateLimiter(s.rateLimiter))
	}
	s.xssScanner = scanner.NewXSSScanner(xssOpts...)

	return s
}

// TestEndpointSecurity performs comprehensive security testing on an API endpoint.
func (s *SecurityTester) TestEndpointSecurity(ctx context.Context, baseURL string, endpoint EndpointInfo) *SecurityTestResult {
	result := &SecurityTestResult{
		Endpoint:        endpoint,
		Vulnerabilities: make([]SecurityVulnerability, 0),
		AuthTests:       make([]AuthTestResult, 0),
		Tested:          true,
	}

	// Build the full URL
	fullURL := s.buildURL(baseURL, endpoint.Path)

	// Test for BOLA/IDOR vulnerabilities
	if s.hasPathParameters(endpoint) {
		bolaVulns := s.testBOLA(ctx, fullURL, endpoint)
		result.Vulnerabilities = append(result.Vulnerabilities, bolaVulns...)
	}

	// Test for SQL injection in query parameters
	if len(endpoint.Parameters) > 0 {
		sqliVulns := s.testSQLInjection(ctx, fullURL, endpoint)
		result.Vulnerabilities = append(result.Vulnerabilities, sqliVulns...)
	}

	// Test for mass assignment vulnerabilities
	if endpoint.RequestBody != nil && (endpoint.Method == "POST" || endpoint.Method == "PUT" || endpoint.Method == "PATCH") {
		massAssignVulns := s.testMassAssignment(ctx, fullURL, endpoint)
		result.Vulnerabilities = append(result.Vulnerabilities, massAssignVulns...)
	}

	// Test for authentication bypass
	if len(endpoint.Security) > 0 {
		authBypassTests := s.testAuthBypass(ctx, fullURL, endpoint)
		result.AuthTests = append(result.AuthTests, authBypassTests...)
	}

	// Analyze JWT tokens from response headers
	jwtAnalysis := s.analyzeJWTInResponse(ctx, fullURL, endpoint)
	if jwtAnalysis != nil {
		result.JWTAnalysis = jwtAnalysis
	}

	return result
}

// buildURL constructs the full URL for an endpoint.
func (s *SecurityTester) buildURL(baseURL, path string) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return baseURL + path
}

// hasPathParameters checks if the endpoint has path parameters.
func (s *SecurityTester) hasPathParameters(endpoint EndpointInfo) bool {
	for _, param := range endpoint.Parameters {
		if param.In == "path" {
			return true
		}
	}
	return false
}

// testBOLA tests for Broken Object Level Authorization (BOLA/IDOR) vulnerabilities.
func (s *SecurityTester) testBOLA(ctx context.Context, fullURL string, endpoint EndpointInfo) []SecurityVulnerability {
	vulns := make([]SecurityVulnerability, 0)

	// Extract path parameters
	pathParams := make([]ParameterInfo, 0)
	for _, param := range endpoint.Parameters {
		if param.In == "path" {
			pathParams = append(pathParams, param)
		}
	}

	// For each path parameter, try different values
	for _, param := range pathParams {
		// Extract the current value from the URL (if it's a template)
		testURLs := s.generateBOLATestURLs(fullURL, param.Name)

		for _, testURL := range testURLs {
			// Apply rate limiting
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					continue
				}
			}

			// Make request without authentication
			req, err := http.NewRequestWithContext(ctx, endpoint.Method, testURL, nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", s.userAgent)

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}
			statusCode := resp.StatusCode
			resp.Body.Close()

			// If we get 200 without auth, it may be a BOLA vulnerability
			if statusCode == http.StatusOK {
				// Determine confidence based on endpoint security requirements
				confidence := "medium"
				description := fmt.Sprintf("Broken Object Level Authorization detected - endpoint accessible without proper authorization for parameter '%s'", param.Name)

				if len(endpoint.Security) > 0 {
					// Endpoint explicitly requires authentication, so this is high confidence
					confidence = "high"
				} else {
					// No explicit security requirement - could be a public endpoint
					confidence = "low"
					description = fmt.Sprintf("Potential BOLA - endpoint accessible without authentication for parameter '%s'. Note: May be a legitimate public endpoint if no security is required.", param.Name)
				}

				vulns = append(vulns, SecurityVulnerability{
					Type:        "bola",
					Severity:    "high",
					Parameter:   param.Name,
					Evidence:    fmt.Sprintf("Endpoint returned HTTP %d without authentication", statusCode),
					Description: description,
					Remediation: "Implement proper authorization checks to ensure users can only access their own resources. Verify object ownership before returning data. If this is a public endpoint, consider documenting it as such.",
					Confidence:  confidence,
				})
			}

			// Check for context cancellation
			select {
			case <-ctx.Done():
				return vulns
			default:
			}
		}
	}

	return vulns
}

// generateBOLATestURLs generates test URLs for BOLA testing.
func (s *SecurityTester) generateBOLATestURLs(urlStr string, paramName string) []string {
	testURLs := make([]string, 0)

	// Find the parameter in the URL using regex
	// Common patterns: /users/{id}, /users/:id, /users/123
	patterns := []string{
		`\{` + paramName + `\}`,
		`:` + paramName,
		`/\d+`,
		`/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, // UUID
	}

	// Test different ID values
	testValues := []string{"1", "2", "999", "0", "admin"}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(urlStr) {
			for _, testValue := range testValues {
				testURL := re.ReplaceAllString(urlStr, testValue)
				if testURL != urlStr {
					testURLs = append(testURLs, testURL)
				}
			}
		}
	}

	return testURLs
}

// testSQLInjection tests for SQL injection vulnerabilities in query parameters.
func (s *SecurityTester) testSQLInjection(ctx context.Context, fullURL string, endpoint EndpointInfo) []SecurityVulnerability {
	vulns := make([]SecurityVulnerability, 0)

	// Get query parameters
	queryParams := make([]ParameterInfo, 0)
	for _, param := range endpoint.Parameters {
		if param.In == "query" {
			queryParams = append(queryParams, param)
		}
	}

	if len(queryParams) == 0 {
		return vulns
	}

	// Use the existing SQLi scanner
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return vulns
	}

	// Add dummy values for query parameters if not present
	q := parsedURL.Query()
	for _, param := range queryParams {
		if !q.Has(param.Name) {
			q.Set(param.Name, "test")
		}
	}
	parsedURL.RawQuery = q.Encode()

	// Run SQL injection scan
	sqliResult := s.sqliScanner.Scan(ctx, parsedURL.String())

	// Convert scanner findings to our vulnerability format
	for _, finding := range sqliResult.Findings {
		vulns = append(vulns, SecurityVulnerability{
			Type:        "sqli",
			Severity:    finding.Severity,
			Parameter:   finding.Parameter,
			Payload:     finding.Payload,
			Evidence:    finding.Evidence,
			Description: finding.Description,
			Remediation: finding.Remediation,
			Confidence:  finding.Confidence,
		})
	}

	return vulns
}

// testMassAssignment tests for mass assignment vulnerabilities.
func (s *SecurityTester) testMassAssignment(ctx context.Context, fullURL string, endpoint EndpointInfo) []SecurityVulnerability {
	vulns := make([]SecurityVulnerability, 0)

	// Apply rate limiting
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			return vulns
		}
	}

	// Prepare test payload with extra fields
	basePayload := make(map[string]interface{})

	// Add required fields from schema
	if endpoint.RequestBody != nil && endpoint.RequestBody.Properties != nil {
		for field := range endpoint.RequestBody.Properties {
			basePayload[field] = "test"
		}
	}

	// Add sensitive fields that shouldn't be accepted
	sensitiveFields := []string{"role", "admin", "is_admin", "is_superuser", "permissions", "password", "email_verified"}
	testPayload := make(map[string]interface{})
	for k, v := range basePayload {
		testPayload[k] = v
	}
	for _, field := range sensitiveFields {
		testPayload[field] = "malicious_value"
	}

	// Make request with extra fields
	jsonData, err := json.Marshal(testPayload)
	if err != nil {
		return vulns
	}

	req, err := http.NewRequestWithContext(ctx, endpoint.Method, fullURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return vulns
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Content-Type", "application/json")

	// Apply authentication
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()

	// Read response to check if extra fields were accepted
	body, err := httputil.ReadResponseBody(resp.Body)
	if err != nil {
		return vulns
	}

	// If the request succeeded (2xx), check if response contains the extra fields
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		bodyStr := string(body)
		for _, field := range sensitiveFields {
			if strings.Contains(bodyStr, field) && strings.Contains(bodyStr, "malicious_value") {
				vulns = append(vulns, SecurityVulnerability{
					Type:        "mass_assignment",
					Severity:    "high",
					Parameter:   field,
					Evidence:    fmt.Sprintf("Extra field '%s' was accepted and reflected in response", field),
					Description: fmt.Sprintf("Potential mass assignment vulnerability - sensitive field '%s' appears in response with test value. Note: Field may be accepted but not stored, or may be transformed. Manual verification required.", field),
					Remediation: "Use a whitelist approach to explicitly define which fields can be updated. Never allow direct binding of user input to internal model fields. Use Data Transfer Objects (DTOs) or similar patterns. Verify that the field was actually persisted by checking database/storage.",
					Confidence:  "low",
				})
			}
		}
	}

	return vulns
}

// testAuthBypass tests for authentication bypass vulnerabilities.
func (s *SecurityTester) testAuthBypass(ctx context.Context, fullURL string, endpoint EndpointInfo) []AuthTestResult {
	results := make([]AuthTestResult, 0)

	// Apply rate limiting
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			return results
		}
	}

	// Test 1: Request without authentication
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, fullURL, nil)
	if err != nil {
		return results
	}

	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return results
	}
	statusCode := resp.StatusCode
	resp.Body.Close()

	// If we get 200 for a protected endpoint, it's a bypass
	if statusCode == http.StatusOK {
		results = append(results, AuthTestResult{
			TestType:    "bypass",
			Success:     true,
			StatusCode:  statusCode,
			Description: "Endpoint accessible without authentication",
		})
	} else {
		results = append(results, AuthTestResult{
			TestType:    "bypass",
			Success:     false,
			StatusCode:  statusCode,
			Description: "Endpoint properly requires authentication",
		})
	}

	return results
}

// analyzeJWTInResponse attempts to extract and analyze JWT tokens from response headers.
func (s *SecurityTester) analyzeJWTInResponse(ctx context.Context, fullURL string, endpoint EndpointInfo) *JWTAnalysis {
	// Apply rate limiting
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			return nil
		}
	}

	// Make a request to get response headers
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, fullURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)

	// Apply authentication
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Extract headers
	headers := make(map[string]string)
	for name, values := range resp.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}

	// Try to extract JWT from headers
	tokens := ExtractJWTFromHeaders(headers)
	if len(tokens) == 0 {
		return nil
	}

	// Analyze the first JWT token found
	analysis, err := AnalyzeJWT(tokens[0])
	if err != nil {
		return nil
	}

	return analysis
}
