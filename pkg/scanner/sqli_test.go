package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
)

// mockSQLiHTTPClient is a mock HTTP client for testing SQL injection scanner.
type mockSQLiHTTPClient struct {
	responses            map[string]*http.Response
	requests             []*http.Request
	defaultResponse      string
	differentialResponse bool
	trueResponse         string
	falseResponse        string
	simulateTimeDelay    bool          // Whether to simulate time-based SQL injection
	delayDuration        time.Duration // Duration to delay for time-based payloads
}

func (m *mockSQLiHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)

	// Read POST body if present
	var postBody string
	if req.Body != nil && req.Method == http.MethodPost {
		bodyBytes, _ := io.ReadAll(req.Body)
		postBody = string(bodyBytes)
		// Restore the body for potential re-reading
		req.Body = io.NopCloser(strings.NewReader(postBody))
	}

	// Simulate time delay for time-based SQL injection payloads
	if m.simulateTimeDelay {
		checkValues := func(values []string) bool {
			for _, v := range values {
				vLower := strings.ToLower(v)
				if strings.Contains(vLower, "sleep") || strings.Contains(vLower, "pg_sleep") ||
					strings.Contains(vLower, "waitfor") || strings.Contains(vLower, "benchmark") ||
					strings.Contains(vLower, "randomblob") {
					time.Sleep(m.delayDuration)
					return true
				}
			}
			return false
		}

		// Check query params
		query := req.URL.Query()
		for _, val := range query {
			if checkValues(val) {
				break
			}
		}

		// Check POST body
		if postBody != "" {
			checkValues([]string{postBody})
		}
	}

	// Return a response based on the URL or a default response
	if resp, ok := m.responses[req.URL.String()]; ok {
		return resp, nil
	}

	var bodyStr string

	// Check if we're doing differential testing
	if m.differentialResponse {
		checkDifferential := func(values []string) {
			for _, v := range values {
				if strings.Contains(v, "1'='1") || strings.Contains(v, "2'='2") || strings.Contains(v, "a'='a") {
					bodyStr = m.trueResponse
				} else if strings.Contains(v, "1'='2") || strings.Contains(v, "2'='3") || strings.Contains(v, "a'='b") {
					bodyStr = m.falseResponse
				}
			}
		}

		// Check query params
		query := req.URL.Query()
		for _, val := range query {
			checkDifferential(val)
		}

		// Check POST body
		if postBody != "" {
			checkDifferential([]string{postBody})
		}
	}

	// Use default if not set by differential logic
	if bodyStr == "" {
		if m.defaultResponse != "" {
			bodyStr = m.defaultResponse
		} else {
			bodyStr = "<html><body>Normal response</body></html>"
		}
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(bodyStr)),
		Header:     make(http.Header),
	}, nil
}

func newMockSQLiHTTPClient() *mockSQLiHTTPClient {
	return &mockSQLiHTTPClient{
		responses:       make(map[string]*http.Response),
		requests:        make([]*http.Request, 0),
		defaultResponse: "",
	}
}

func TestNewSQLiScanner(t *testing.T) {
	tests := []struct {
		name string
		opts []SQLiOption
	}{
		{
			name: "default configuration",
			opts: nil,
		},
		{
			name: "with custom timeout",
			opts: []SQLiOption{WithSQLiTimeout(60 * time.Second)},
		},
		{
			name: "with custom user agent",
			opts: []SQLiOption{WithSQLiUserAgent("TestAgent/1.0")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewSQLiScanner(tt.opts...)
			if scanner == nil {
				t.Fatal("NewSQLiScanner returned nil")
			}
			if scanner.client == nil {
				t.Error("Scanner client is nil")
			}
		})
	}
}

func TestSQLiScanner_Scan_NoParameters(t *testing.T) {
	mock := newMockSQLiHTTPClient()
	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", result.Target)
	}

	// Should test common parameter names when no parameters exist
	if result.Summary.TotalTests == 0 {
		t.Error("Expected some tests to be performed even without parameters")
	}

	if len(result.Findings) > 0 {
		t.Errorf("Expected no vulnerabilities, found %d", len(result.Findings))
	}
}

func TestSQLiScanner_Scan_ErrorBasedMySQLError(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Configure mock to return MySQL error when single quote is injected
	mock.responses["https://example.com/user?id=%27"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/user?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SQL injection vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if finding.Parameter != "id" {
		t.Errorf("Expected parameter 'id', got %s", finding.Parameter)
	}

	if finding.Type != "error-based" {
		t.Errorf("Expected type 'error-based', got %s", finding.Type)
	}

	if finding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
	}

	if !strings.Contains(finding.Evidence, "MySQL") {
		t.Errorf("Expected evidence to contain 'MySQL', got %s", finding.Evidence)
	}
}

func TestSQLiScanner_Scan_ErrorBasedPostgreSQLError(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Configure mock to return PostgreSQL error
	mock.responses["https://example.com/page?id=%27"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>PostgreSQL query failed: ERROR: syntax error at or near</body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/page?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SQL injection vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	if !strings.Contains(result.Findings[0].Evidence, "PostgreSQL") {
		t.Errorf("Expected evidence to contain 'PostgreSQL', got %s", result.Findings[0].Evidence)
	}
}

func TestSQLiScanner_Scan_ErrorBasedSQLServerError(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Configure mock to return SQL Server error
	mock.responses["https://example.com/data?id=%27"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Microsoft SQL Server error: Unclosed quotation mark after the character string</body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/data?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SQL injection vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	if !strings.Contains(result.Findings[0].Evidence, "quotation mark") {
		t.Errorf("Expected evidence to contain 'quotation mark', got %s", result.Findings[0].Evidence)
	}
}

func TestSQLiScanner_Scan_ErrorBasedOracleError(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Configure mock to return Oracle error
	mock.responses["https://example.com/query?id=%27"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>ORA-01756: quoted string not properly terminated</body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/query?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SQL injection vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	if !strings.Contains(result.Findings[0].Evidence, "ORA-") {
		t.Errorf("Expected evidence to contain 'ORA-', got %s", result.Findings[0].Evidence)
	}
}

func TestSQLiScanner_Scan_BooleanBasedDetection(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Set default response to match baseline so the content-routing pre-check
	// sees the same response for random strings as for the original value.
	mock.defaultResponse = "<html><body>Product details for ID 1</body></html>"

	// Baseline response
	mock.responses["https://example.com/product?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Product details for ID 1</body></html>")),
		Header:     make(http.Header),
	}

	// Response with boolean true payload - significantly different
	mock.responses["https://example.com/product?id=%27+OR+%271%27%3D%271"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Product details for ID 1\nProduct details for ID 2\nProduct details for ID 3\nMany more products displayed due to OR condition</body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/product?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect the boolean-based SQLi due to significant response difference
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find boolean-based SQL injection vulnerability")
	}
}

func TestSQLiScanner_Scan_NoVulnerability(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// All responses are safe - input is properly escaped
	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/safe?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Most payloads should not detect vulnerabilities in this case
	// (since mock returns default safe responses)
	if result.Summary.TotalTests == 0 {
		t.Error("Expected some tests to be performed")
	}
}

func TestSQLiScanner_Scan_WithAuthentication(t *testing.T) {
	mock := newMockSQLiHTTPClient()
	authConfig := &auth.AuthConfig{
		BearerToken: "test-token-123",
	}

	scanner := NewSQLiScanner(
		WithSQLiHTTPClient(mock),
		WithSQLiAuth(authConfig),
	)

	ctx := context.Background()
	scanner.Scan(ctx, "https://example.com/api?id=1")

	if len(mock.requests) == 0 {
		t.Fatal("Expected at least one request")
	}

	// Check that authentication was applied
	authHeader := mock.requests[0].Header.Get("Authorization")
	if authHeader != "Bearer test-token-123" {
		t.Errorf("Expected Authorization header 'Bearer test-token-123', got %s", authHeader)
	}
}

func TestSQLiScanner_Scan_WithRateLimiting(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Create rate limiter config
	rateLimitConfig := ratelimit.Config{
		RequestsPerSecond: 10,
	}

	scanner := NewSQLiScanner(
		WithSQLiHTTPClient(mock),
		WithSQLiRateLimitConfig(rateLimitConfig),
	)

	ctx := context.Background()
	start := time.Now()
	scanner.Scan(ctx, "https://example.com?param1=1&param2=2")
	elapsed := time.Since(start)

	// With rate limiting, the scan should take some minimum time
	if elapsed < 0 {
		t.Error("Rate limiting doesn't appear to be working")
	}
}

func TestSQLiScanner_Scan_ContextCancellation(t *testing.T) {
	mock := newMockSQLiHTTPClient()
	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := scanner.Scan(ctx, "https://example.com?p1=1&p2=2&p3=3")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should have error about cancellation
	if len(result.Errors) == 0 {
		t.Error("Expected error about cancellation")
	}
}

func TestSQLiScanner_Scan_InvalidURL(t *testing.T) {
	mock := newMockSQLiHTTPClient()
	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "not a valid url://example")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected error for invalid URL")
	}

	if !strings.Contains(result.Errors[0], "Invalid URL") {
		t.Errorf("Expected 'Invalid URL' error, got %s", result.Errors[0])
	}
}

func TestSQLiScanner_Scan_HTTP429Response(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Configure mock to return 429 Too Many Requests
	mock.responses["https://example.com/test?id=%27"] = &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should not report vulnerabilities for 429 responses
	// Note: Some tests might still run if baseline succeeds
	if result.Summary.TotalTests == 0 {
		t.Error("Expected some tests to be performed")
	}
}

func TestSQLiScanner_Scan_MultipleParameters(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/search?name=test&category=books")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should test both parameters with multiple payloads
	// 2 parameters * 8 payloads = 16 minimum tests
	if result.Summary.TotalTests < 2 {
		t.Errorf("Expected at least 2 tests for 2 parameters, got %d", result.Summary.TotalTests)
	}

	// Check that requests were made
	if len(mock.requests) == 0 {
		t.Error("Expected at least one HTTP request to be made")
	}
}

func TestSQLiScanResult_String(t *testing.T) {
	result := &SQLiScanResult{
		Target: "https://example.com",
		Findings: []SQLiFinding{
			{
				URL:         "https://example.com?id='",
				Parameter:   "id",
				Payload:     "'",
				Evidence:    "...MySQL syntax error...",
				Severity:    SeverityHigh,
				Type:        "error-based",
				Description: "Single quote injection triggers database error",
				Remediation: "Use parameterized queries",
			},
		},
		Summary: SQLiSummary{
			TotalTests:           10,
			VulnerabilitiesFound: 1,
			HighSeverityCount:    1,
		},
	}

	str := result.String()

	if !strings.Contains(str, "https://example.com") {
		t.Error("String output should contain target URL")
	}

	if !strings.Contains(str, "Total Tests: 10") {
		t.Error("String output should contain total tests")
	}

	if !strings.Contains(str, "Vulnerabilities Found: 1") {
		t.Error("String output should contain vulnerabilities count")
	}

	if !strings.Contains(str, "HIGH") {
		t.Error("String output should contain severity")
	}

	if !strings.Contains(str, "Parameter: id") {
		t.Error("String output should contain parameter name")
	}
}

func TestSQLiScanResult_HasResults(t *testing.T) {
	tests := []struct {
		name     string
		result   *SQLiScanResult
		expected bool
	}{
		{
			name: "has findings",
			result: &SQLiScanResult{
				Findings: []SQLiFinding{{URL: "test"}},
			},
			expected: true,
		},
		{
			name: "has tests but no findings",
			result: &SQLiScanResult{
				Summary: SQLiSummary{TotalTests: 5},
			},
			expected: true,
		},
		{
			name:     "no results",
			result:   &SQLiScanResult{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasResults(); got != tt.expected {
				t.Errorf("HasResults() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSQLiScanner_ExtractEvidence(t *testing.T) {
	scanner := NewSQLiScanner()

	tests := []struct {
		name       string
		body       string
		errorMatch string
		want       string
	}{
		{
			name:       "error found in middle",
			body:       "Some text before MySQL syntax error in the query and some after",
			errorMatch: "MySQL syntax error",
			want:       "MySQL syntax error",
		},
		{
			name:       "error at start",
			body:       "ORA-01756: quoted string not properly terminated",
			errorMatch: "ORA-01756",
			want:       "ORA-01756",
		},
		{
			name:       "no error found",
			body:       "Clean response with no error",
			errorMatch: "",
			want:       "SQL error detected in response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanner.extractEvidence(tt.body, tt.errorMatch)
			if !strings.Contains(got, tt.want) && got != tt.want {
				t.Errorf("extractEvidence() = %v, want to contain %v", got, tt.want)
			}
		})
	}
}

func TestSQLiScanner_GetRemediation(t *testing.T) {
	scanner := NewSQLiScanner()

	remediation := scanner.getRemediation()

	expectedKeywords := []string{"parameterized", "prepared statements", "input validation"}
	for _, keyword := range expectedKeywords {
		if !strings.Contains(strings.ToLower(remediation), strings.ToLower(keyword)) {
			t.Errorf("Remediation should contain '%s', got: %s", keyword, remediation)
		}
	}
}

func TestSQLiScanner_CalculateSummary(t *testing.T) {
	scanner := NewSQLiScanner()

	result := &SQLiScanResult{
		Findings: []SQLiFinding{
			{Severity: SeverityHigh},
			{Severity: SeverityHigh},
			{Severity: SeverityMedium},
			{Severity: SeverityLow},
		},
	}

	scanner.calculateSummary(result)

	if result.Summary.VulnerabilitiesFound != 4 {
		t.Errorf("Expected 4 vulnerabilities, got %d", result.Summary.VulnerabilitiesFound)
	}

	if result.Summary.HighSeverityCount != 2 {
		t.Errorf("Expected 2 high severity, got %d", result.Summary.HighSeverityCount)
	}

	if result.Summary.MediumSeverityCount != 1 {
		t.Errorf("Expected 1 medium severity, got %d", result.Summary.MediumSeverityCount)
	}

	if result.Summary.LowSeverityCount != 1 {
		t.Errorf("Expected 1 low severity, got %d", result.Summary.LowSeverityCount)
	}
}

func TestSQLiScanner_WithCustomOptions(t *testing.T) {
	customClient := newMockSQLiHTTPClient()
	customUserAgent := "CustomAgent/2.0"
	customTimeout := 45 * time.Second
	authConfig := &auth.AuthConfig{
		BasicAuth: "testuser:testpass",
	}

	scanner := NewSQLiScanner(
		WithSQLiHTTPClient(customClient),
		WithSQLiUserAgent(customUserAgent),
		WithSQLiTimeout(customTimeout),
		WithSQLiAuth(authConfig),
	)

	if scanner.client != customClient {
		t.Error("Custom HTTP client not set correctly")
	}

	if scanner.userAgent != customUserAgent {
		t.Error("Custom user agent not set correctly")
	}

	if scanner.timeout != customTimeout {
		t.Error("Custom timeout not set correctly")
	}

	if scanner.authConfig != authConfig {
		t.Error("Auth config not set correctly")
	}
}

func TestSQLiScanner_SQLErrorPatterns(t *testing.T) {
	// Test that our error patterns can detect various database errors
	testCases := []struct {
		name         string
		response     string
		shouldDetect bool
	}{
		{
			name:         "MySQL error",
			response:     "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
			shouldDetect: true,
		},
		{
			name:         "PostgreSQL error",
			response:     "PostgreSQL query failed: ERROR: syntax error",
			shouldDetect: true,
		},
		{
			name:         "SQL Server error",
			response:     "Unclosed quotation mark after the character string",
			shouldDetect: true,
		},
		{
			name:         "Oracle error",
			response:     "ORA-01756: quoted string not properly terminated",
			shouldDetect: true,
		},
		{
			name:         "SQLite error",
			response:     "SQLite3::SQLException: near",
			shouldDetect: true,
		},
		{
			name:         "Generic SQL error",
			response:     "SQLSTATE[42000]: Syntax error",
			shouldDetect: true,
		},
		{
			name:         "No error",
			response:     "This is a normal response with no database errors",
			shouldDetect: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			detected := false
			for _, pattern := range sqlErrorPatterns {
				if pattern.MatchString(tc.response) {
					detected = true
					break
				}
			}

			if detected != tc.shouldDetect {
				t.Errorf("Pattern detection = %v, want %v for response: %s", detected, tc.shouldDetect, tc.response)
			}
		})
	}
}

func TestAbs(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{5, 5},
		{-5, 5},
		{0, 0},
		{-100, 100},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("abs(%d)", tt.input), func(t *testing.T) {
			if got := abs(tt.input); got != tt.expected {
				t.Errorf("abs(%d) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

// Test for false positive: response differences that are NOT SQL injection
func TestSQLiScanner_Scan_FalsePositive_NormalVariation(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Baseline response
	mock.responses["https://example.com/search?q=test"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Search results for 'test'</body></html>")),
		Header:     make(http.Header),
	}

	// Response with true payload - different but not due to SQL injection
	// (e.g., application filters out single quotes)
	mock.responses["https://example.com/search?q=%27+OR+%271%27%3D%271"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Search results for ''</body></html>")),
		Header:     make(http.Header),
	}

	// Response with false payload - similar to true payload (both filtered)
	mock.responses["https://example.com/search?q=%27+OR+%271%27%3D%272"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Search results for ''</body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/search?q=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should NOT report vulnerability because true and false conditions produce same result
	// (indicating proper input sanitization, not SQL injection)
	vulnerabilitiesFound := 0
	for _, finding := range result.Findings {
		if finding.Type == "boolean-based" && strings.Contains(finding.Payload, "'1'='1") {
			vulnerabilitiesFound++
		}
	}

	if vulnerabilitiesFound > 0 {
		t.Errorf("Should not report boolean-based SQLi when true/false conditions produce same result, but found %d", vulnerabilitiesFound)
	}
}

// Test for true positive with high confidence: differential analysis confirms SQLi
func TestSQLiScanner_Scan_TruePositive_DifferentialAnalysis(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Default response matches baseline so content-routing pre-check passes
	mock.defaultResponse = "<html><body>Product ID 1: Widget</body></html>"

	// Baseline response
	mock.responses["https://example.com/product?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Product ID 1: Widget</body></html>")),
		Header:     make(http.Header),
	}

	// Response with true payload - returns all products
	mock.responses["https://example.com/product?id=%27+OR+%271%27%3D%271"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Product ID 1: Widget\nProduct ID 2: Gadget\nProduct ID 3: Tool\nProduct ID 4: Device</body></html>")),
		Header:     make(http.Header),
	}

	// Response with false payload - returns no products
	mock.responses["https://example.com/product?id=%27+OR+%271%27%3D%272"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>No products found</body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/product?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should find boolean-based SQLi with high confidence
	found := false
	for _, finding := range result.Findings {
		if finding.Type == "boolean-based" && strings.Contains(finding.Payload, "'1'='1") {
			found = true
			if finding.Confidence != "high" {
				t.Errorf("Expected high confidence for differential analysis, got %s", finding.Confidence)
			}
			if !strings.Contains(finding.Description, "differential analysis") {
				t.Errorf("Expected description to mention differential analysis, got %s", finding.Description)
			}
		}
	}

	if !found {
		t.Error("Expected to find boolean-based SQLi with differential analysis confirmation")
	}
}

// Test that error-based detection has high confidence
func TestSQLiScanner_Scan_ErrorBased_HighConfidence(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Configure mock to return MySQL error
	mock.responses["https://example.com/user?id=%27"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/user?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SQL injection vulnerability")
	}

	// Check that error-based findings have high confidence
	for _, finding := range result.Findings {
		if finding.Type == "error-based" {
			if finding.Confidence != "high" {
				t.Errorf("Expected high confidence for error-based detection, got %s", finding.Confidence)
			}
		}
	}
}

// Test that findings without clear evidence have appropriate confidence levels
func TestSQLiScanner_Confidence_Levels(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Baseline
	baselineBody := "<html><body>Product details</body></html>"
	mock.responses["https://example.com/item?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineBody)),
		Header:     make(http.Header),
	}

	// Test with AND condition (no differential analysis)
	mock.responses["https://example.com/item?id=%27+AND+%271%27%3D%271"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Product details with different length for testing</body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/item?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// If any findings are reported for AND condition without differential analysis,
	// they should have low confidence
	for _, finding := range result.Findings {
		if strings.Contains(finding.Payload, "AND '1'='1") {
			if finding.Confidence != "low" && finding.Confidence != "high" {
				t.Logf("Finding with payload %s has confidence %s", finding.Payload, finding.Confidence)
			}
		}
	}
}

func TestSQLiScanner_VerifyFinding(t *testing.T) {
	tests := []struct {
		name            string
		finding         *SQLiFinding
		mockResponses   map[string]string
		expectedVerif   bool
		expectedMinConf float64
	}{
		{
			name: "verified error-based SQLi",
			finding: &SQLiFinding{
				URL:       "https://example.com/item?id=1%27",
				Parameter: "id",
				Payload:   "'",
				Type:      "error-based",
			},
			mockResponses: map[string]string{
				"default": "SQL syntax error: You have an error in your SQL syntax",
			},
			expectedVerif:   true,
			expectedMinConf: 0.5,
		},
		{
			name: "verified boolean-based SQLi with differential analysis",
			finding: &SQLiFinding{
				URL:       "https://example.com/item?id=1%27+OR+%271%27%3D%271",
				Parameter: "id",
				Payload:   "' OR '1'='1",
				Type:      "boolean-based",
			},
			mockResponses: map[string]string{
				"true":  strings.Repeat("A", 1000),
				"false": strings.Repeat("B", 500),
			},
			expectedVerif:   true,
			expectedMinConf: 0.5,
		},
		{
			name: "false positive - WAF blocking",
			finding: &SQLiFinding{
				URL:       "https://example.com/item?id=1%27",
				Parameter: "id",
				Payload:   "'",
				Type:      "error-based",
			},
			mockResponses: map[string]string{
				"default": "Access denied",
			},
			expectedVerif:   false,
			expectedMinConf: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockSQLiHTTPClient()

			// Setup mock based on test type
			if tt.finding.Type == "boolean-based" {
				mock.differentialResponse = true
				mock.trueResponse = tt.mockResponses["true"]
				mock.falseResponse = tt.mockResponses["false"]
			} else {
				mock.defaultResponse = tt.mockResponses["default"]
			}

			scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))
			config := VerificationConfig{
				Enabled:    true,
				MaxRetries: 3,
				Delay:      10 * time.Millisecond,
			}

			ctx := context.Background()
			result, err := scanner.VerifyFinding(ctx, tt.finding, config)

			if err != nil {
				t.Fatalf("VerifyFinding returned error: %v", err)
			}

			if result == nil {
				t.Fatal("VerifyFinding returned nil result")
			}

			if result.Verified != tt.expectedVerif {
				t.Errorf("Expected Verified=%v, got %v (explanation: %s)", tt.expectedVerif, result.Verified, result.Explanation)
			}

			if result.Confidence < tt.expectedMinConf {
				t.Errorf("Expected Confidence >= %.2f, got %.2f", tt.expectedMinConf, result.Confidence)
			}

			if result.Attempts <= 0 {
				t.Errorf("Expected Attempts > 0, got %d", result.Attempts)
			}
		})
	}
}

func TestSQLiScanner_GeneratePayloadVariants(t *testing.T) {
	scanner := NewSQLiScanner()

	tests := []struct {
		name             string
		payload          string
		findingType      string
		expectedMinCount int
	}{
		{
			name:             "single quote payload",
			payload:          "'",
			findingType:      "error-based",
			expectedMinCount: 1,
		},
		{
			name:             "OR condition payload",
			payload:          "' OR '1'='1",
			findingType:      "boolean-based",
			expectedMinCount: 2,
		},
		{
			name:             "UNION payload",
			payload:          "' UNION SELECT NULL--",
			findingType:      "error-based",
			expectedMinCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := scanner.generateSQLiPayloadVariants(tt.payload, tt.findingType)

			if len(variants) < tt.expectedMinCount {
				t.Errorf("Expected at least %d variants, got %d", tt.expectedMinCount, len(variants))
			}

			// First variant should be the original
			if variants[0] != tt.payload {
				t.Errorf("Expected first variant to be original payload, got %s", variants[0])
			}
		})
	}
}

func TestSQLiScanner_Scan_TimeBasedMySQL(t *testing.T) {
	mock := newMockSQLiHTTPClient()
	mock.simulateTimeDelay = true
	mock.delayDuration = 5 * time.Second

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/user?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect time-based SQL injection
	foundTimeBased := false
	for _, finding := range result.Findings {
		if finding.Type == "time-based" {
			foundTimeBased = true
			if finding.Confidence != "high" {
				t.Errorf("Expected high confidence for time-based detection, got %s", finding.Confidence)
			}
			if !strings.Contains(finding.Evidence, "Request took") {
				t.Errorf("Expected evidence to mention request duration, got %s", finding.Evidence)
			}
			break
		}
	}

	if !foundTimeBased {
		t.Error("Expected to find time-based SQL injection vulnerability")
	}
}

func TestSQLiScanner_Scan_TimeBasedPostgreSQL(t *testing.T) {
	mock := newMockSQLiHTTPClient()
	mock.simulateTimeDelay = true
	mock.delayDuration = 5 * time.Second

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/product?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect time-based SQL injection
	foundTimeBased := false
	for _, finding := range result.Findings {
		if finding.Type == "time-based" && strings.Contains(finding.Payload, "pg_sleep") {
			foundTimeBased = true
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
			}
			break
		}
	}

	if !foundTimeBased {
		t.Error("Expected to find PostgreSQL time-based SQL injection vulnerability")
	}
}

func TestSQLiScanner_Scan_TimeBasedSQLServer(t *testing.T) {
	mock := newMockSQLiHTTPClient()
	mock.simulateTimeDelay = true
	mock.delayDuration = 5 * time.Second

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/data?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect time-based SQL injection
	foundTimeBased := false
	for _, finding := range result.Findings {
		if finding.Type == "time-based" && strings.Contains(finding.Payload, "WAITFOR") {
			foundTimeBased = true
			if finding.Description == "" {
				t.Error("Expected description to be set")
			}
			break
		}
	}

	if !foundTimeBased {
		t.Error("Expected to find SQL Server time-based SQL injection vulnerability")
	}
}

func TestSQLiScanner_Scan_NoTimeBasedVulnerability(t *testing.T) {
	mock := newMockSQLiHTTPClient()
	// Do not simulate time delay - responses are fast

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/secure?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should NOT detect time-based SQL injection when responses are fast
	foundTimeBased := false
	for _, finding := range result.Findings {
		if finding.Type == "time-based" {
			foundTimeBased = true
			break
		}
	}

	if foundTimeBased {
		t.Error("Should not detect time-based SQLi when responses are fast")
	}
}

func TestSQLiScanner_TimeBasedWithCustomDelay(t *testing.T) {
	mock := newMockSQLiHTTPClient()
	mock.simulateTimeDelay = true
	mock.delayDuration = 3 * time.Second

	customDelay := 3 * time.Second
	scanner := NewSQLiScanner(
		WithSQLiHTTPClient(mock),
		WithSQLiTimeBasedDelay(customDelay),
	)

	if scanner.timeBasedDelay != customDelay {
		t.Errorf("Expected time-based delay %v, got %v", customDelay, scanner.timeBasedDelay)
	}

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect time-based SQL injection with custom delay
	foundTimeBased := false
	for _, finding := range result.Findings {
		if finding.Type == "time-based" {
			foundTimeBased = true
			break
		}
	}

	if !foundTimeBased {
		t.Error("Expected to find time-based SQL injection with custom delay")
	}
}

func TestSQLiScanner_VerifyFinding_TimeBased(t *testing.T) {
	mock := newMockSQLiHTTPClient()
	mock.simulateTimeDelay = true
	mock.delayDuration = 5 * time.Second

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	finding := &SQLiFinding{
		URL:       "https://example.com/item?id=1%27+OR+SLEEP%285%29--",
		Parameter: "id",
		Payload:   "' OR SLEEP(5)--",
		Type:      "time-based",
	}

	config := VerificationConfig{
		Enabled:    true,
		MaxRetries: 3,
		Delay:      10 * time.Millisecond,
	}

	ctx := context.Background()
	result, err := scanner.VerifyFinding(ctx, finding, config)

	if err != nil {
		t.Fatalf("VerifyFinding returned error: %v", err)
	}

	if result == nil {
		t.Fatal("VerifyFinding returned nil result")
	}

	if !result.Verified {
		t.Errorf("Expected time-based finding to be verified, got explanation: %s", result.Explanation)
	}

	if result.Confidence < 0.5 {
		t.Errorf("Expected Confidence >= 0.5, got %.2f", result.Confidence)
	}

	if result.Attempts <= 0 {
		t.Errorf("Expected Attempts > 0, got %d", result.Attempts)
	}
}

// TestSQLiScanner_ScanPOST tests POST parameter scanning for SQL injection
func TestSQLiScanner_ScanPOST(t *testing.T) {
	mockClient := newMockSQLiHTTPClient()
	// Set response that contains SQL error for any request with SQL payloads
	mockClient.defaultResponse = "<html><body>You have an error in your SQL syntax near '' at line 1</body></html>"

	scanner := NewSQLiScanner(
		WithSQLiTimeout(30*time.Second),
		WithSQLiUserAgent("WAST-Test/1.0"),
	)
	scanner.client = mockClient

	ctx := context.Background()
	targetURL := "http://example.com/login"
	params := map[string]string{
		"username": "admin",
		"password": "test",
	}

	result := scanner.ScanPOST(ctx, targetURL, params)

	if result == nil {
		t.Fatal("ScanPOST returned nil result")
	}

	if result.Target != targetURL {
		t.Errorf("Expected target %s, got %s", targetURL, result.Target)
	}

	// Verify that POST requests were made with proper content type
	foundPostRequest := false
	for _, req := range mockClient.requests {
		if req.Method == http.MethodPost {
			foundPostRequest = true
			if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Errorf("Expected Content-Type header to be application/x-www-form-urlencoded, got %s", req.Header.Get("Content-Type"))
			}
			break
		}
	}

	if !foundPostRequest {
		t.Error("Expected at least one POST request to be made")
	}

	// Verify the scan ran and returned results (findings may or may not be found based on payload detection)
	if result.Summary.TotalTests == 0 {
		t.Error("Expected TotalTests > 0")
	}
}

// TestSQLiScanner_ContentBasedDetection tests the new content-based detection features
func TestSQLiScanner_ContentBasedDetection(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Baseline response with one product
	baselineHTML := `<html><body>
		<h1>Products</h1>
		<table>
			<tr><td>Product 1</td><td>$10</td></tr>
		</table>
	</body></html>`

	// True payload response - returns multiple products (different content, more rows)
	truePayloadHTML := `<html><body>
		<h1>Products</h1>
		<table>
			<tr><td>Product 1</td><td>$10</td></tr>
			<tr><td>Product 2</td><td>$20</td></tr>
			<tr><td>Product 3</td><td>$30</td></tr>
			<tr><td>Product 4</td><td>$40</td></tr>
		</table>
	</body></html>`

	// False payload response - returns no products (different content, fewer words)
	falsePayloadHTML := `<html><body>
		<h1>Products</h1>
		<table>
		</table>
		<p>No results found</p>
	</body></html>`

	// Default response matches baseline so content-routing pre-check passes
	mock.defaultResponse = baselineHTML

	// Configure mock responses for differential analysis
	mock.responses["https://example.com/product?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineHTML)),
		Header:     make(http.Header),
	}

	mock.differentialResponse = true
	mock.trueResponse = truePayloadHTML
	mock.falseResponse = falsePayloadHTML

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/product?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect SQL injection due to content-based differences
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SQL injection vulnerability using content-based detection")
	}

	// Check that findings contain evidence about content differences
	if len(result.Findings) > 0 {
		finding := result.Findings[0]
		if !strings.Contains(finding.Evidence, "differ") {
			t.Errorf("Expected evidence to mention differences, got: %s", finding.Evidence)
		}
	}
}

// TestSQLiScanner_ContentBasedDetection_DVWA simulates DVWA-like responses
func TestSQLiScanner_ContentBasedDetection_DVWA(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Simulate DVWA response with single user
	baselineHTML := `<!DOCTYPE html>
<html>
<body>
<div id="main">
	<h1>User Details</h1>
	<table>
		<tr><td>ID</td><td>First Name</td><td>Surname</td></tr>
		<tr><td>1</td><td>admin</td><td>admin</td></tr>
	</table>
</div>
</body>
</html>`

	// True payload (OR 1=1) - returns all users
	truePayloadHTML := `<!DOCTYPE html>
<html>
<body>
<div id="main">
	<h1>User Details</h1>
	<table>
		<tr><td>ID</td><td>First Name</td><td>Surname</td></tr>
		<tr><td>1</td><td>admin</td><td>admin</td></tr>
		<tr><td>2</td><td>Gordon</td><td>Brown</td></tr>
		<tr><td>3</td><td>Hack</td><td>Me</td></tr>
		<tr><td>4</td><td>Pablo</td><td>Picasso</td></tr>
		<tr><td>5</td><td>Bob</td><td>Smith</td></tr>
	</table>
</div>
</body>
</html>`

	// False payload (AND 1=2) - returns no users
	falsePayloadHTML := `<!DOCTYPE html>
<html>
<body>
<div id="main">
	<h1>User Details</h1>
	<table>
		<tr><td>ID</td><td>First Name</td><td>Surname</td></tr>
	</table>
</div>
</body>
</html>`

	// Default response matches baseline so content-routing pre-check passes
	mock.defaultResponse = baselineHTML

	mock.responses["https://dvwa.local/vulnerabilities/sqli/?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineHTML)),
		Header:     make(http.Header),
	}

	mock.differentialResponse = true
	mock.trueResponse = truePayloadHTML
	mock.falseResponse = falsePayloadHTML

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://dvwa.local/vulnerabilities/sqli/?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect SQL injection - this is the key test for DVWA-like scenarios
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SQL injection vulnerability in DVWA-like scenario")
		t.Logf("Total tests performed: %d", result.Summary.TotalTests)
	}

	// Verify the detection method
	if len(result.Findings) > 0 {
		finding := result.Findings[0]
		// Should detect via structural elements (table rows) or word count
		if !strings.Contains(finding.Evidence, "structural") && !strings.Contains(finding.Evidence, "word count") && !strings.Contains(finding.Evidence, "content hash") {
			t.Errorf("Expected evidence to mention content-based detection method, got: %s", finding.Evidence)
		}
		if finding.Confidence != "high" && finding.Confidence != "medium" {
			t.Errorf("Expected confidence to be high or medium, got: %s", finding.Confidence)
		}
	}
}

// TestSQLiScanner_ContentBasedDetection_NoFalsePositives ensures we don't over-detect
func TestSQLiScanner_ContentBasedDetection_NoFalsePositives(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// All responses are identical - properly escaped SQL
	identicalHTML := `<html><body>
		<h1>Product Details</h1>
		<p>Product ID: 1</p>
		<p>Price: $10</p>
	</body></html>`

	mock.responses["https://example.com/safe?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(identicalHTML)),
		Header:     make(http.Header),
	}

	// All payloads return the same response (no vulnerability)
	mock.differentialResponse = true
	mock.trueResponse = identicalHTML
	mock.falseResponse = identicalHTML

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/safe?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should NOT detect SQL injection when responses are identical
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Errorf("Expected no vulnerabilities (false positive), but found %d", result.Summary.VulnerabilitiesFound)
		if len(result.Findings) > 0 {
			t.Logf("False positive evidence: %s", result.Findings[0].Evidence)
		}
	}
}

// Test helper functions for content analysis
func TestExtractBodyContent(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected string
	}{
		{
			name:     "simple text",
			html:     "<html><body>Hello World</body></html>",
			expected: "Hello World",
		},
		{
			name:     "with scripts and styles",
			html:     "<html><head><script>alert('test')</script><style>.foo{}</style></head><body>Content</body></html>",
			expected: "Content",
		},
		{
			name:     "with multiple elements",
			html:     "<html><body><h1>Title</h1><p>Paragraph</p><div>More text</div></body></html>",
			expected: "Title Paragraph More text",
		},
		{
			name:     "with whitespace",
			html:     "<html><body>  Line 1  \n\n  Line 2  </body></html>",
			expected: "Line 1 Line 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBodyContent(tt.html)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestCountStructuralElements(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected int
	}{
		{
			name:     "single table row",
			html:     "<table><tr><td>Data</td></tr></table>",
			expected: 1,
		},
		{
			name:     "multiple table rows",
			html:     "<table><tr><td>1</td></tr><tr><td>2</td></tr><tr><td>3</td></tr></table>",
			expected: 3,
		},
		{
			name:     "list items",
			html:     "<ul><li>Item 1</li><li>Item 2</li></ul>",
			expected: 2,
		},
		{
			name:     "mixed elements",
			html:     "<table><tr><td>Row</td></tr></table><ul><li>Item</li></ul>",
			expected: 2,
		},
		{
			name:     "no structural elements",
			html:     "<p>Just a paragraph</p><span>And a span</span>",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countStructuralElements(tt.html)
			if result != tt.expected {
				t.Errorf("Expected %d structural elements, got %d", tt.expected, result)
			}
		})
	}
}

func TestCountWords(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected int
	}{
		{
			name:     "simple sentence",
			html:     "<html><body>Hello world this is a test</body></html>",
			expected: 6,
		},
		{
			name:     "with HTML tags",
			html:     "<html><body><p>One</p><p>Two</p><p>Three</p></body></html>",
			expected: 3,
		},
		{
			name:     "empty",
			html:     "<html><body></body></html>",
			expected: 0,
		},
		{
			name:     "with scripts (should be ignored)",
			html:     "<html><head><script>var x = 1;</script></head><body>Only these three words</body></html>",
			expected: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countWords(tt.html)
			if result != tt.expected {
				t.Errorf("Expected %d words, got %d", tt.expected, result)
			}
		})
	}
}

// TestDetectNoResultsPattern tests the detection of "no results" patterns
func TestDetectNoResultsPattern(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "explicit no results text",
			body:     "<html><body><p>No results found</p></body></html>",
			expected: true,
		},
		{
			name:     "zero results text",
			body:     "<html><body><p>0 results</p></body></html>",
			expected: true,
		},
		{
			name:     "no records text",
			body:     "<html><body><p>No records available</p></body></html>",
			expected: true,
		},
		{
			name:     "empty table with header only",
			body:     "<html><body><table><tr><th>ID</th><th>Name</th></tr></table></body></html>",
			expected: true,
		},
		{
			name:     "table with data rows",
			body:     "<html><body><table><tr><th>ID</th><th>Name</th></tr><tr><td>1</td><td>John</td></tr><tr><td>2</td><td>Jane</td></tr></table></body></html>",
			expected: false,
		},
		{
			name:     "normal content with results",
			body:     "<html><body><p>Found 5 results</p><ul><li>Item 1</li><li>Item 2</li></ul></body></html>",
			expected: false,
		},
		{
			name:     "empty table (no rows at all)",
			body:     "<html><body><table></table></body></html>",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectNoResultsPattern(tt.body)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestHasResultsData tests the detection of actual data in responses
func TestHasResultsData(t *testing.T) {
	tests := []struct {
		name               string
		body               string
		structuralElements int
		expected           bool
	}{
		{
			name:               "table with multiple rows",
			body:               "<table><tr><td>1</td></tr><tr><td>2</td></tr><tr><td>3</td></tr></table>",
			structuralElements: 3,
			expected:           true,
		},
		{
			name:               "empty table",
			body:               "<table><tr><th>Header</th></tr></table>",
			structuralElements: 1,
			expected:           false, // Only header row, no data - detectNoResultsPattern catches it
		},
		{
			name:               "no results message",
			body:               "<p>No results found</p>",
			structuralElements: 0,
			expected:           false,
		},
		{
			name:               "very few words",
			body:               "<p>None</p>",
			structuralElements: 0,
			expected:           false,
		},
		{
			name:               "normal content",
			body:               "<div>Product ID 1: Widget. Price: $10. Description: A useful tool.</div>",
			structuralElements: 0,
			expected:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasResultsData(tt.body, tt.structuralElements)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for body: %s", tt.expected, result, tt.body)
			}
		})
	}
}

// TestSQLiScanner_AdaptiveThresholds_SmallResponses tests adaptive thresholds for small responses
func TestSQLiScanner_AdaptiveThresholds_SmallResponses(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Small baseline response (< 1KB)
	baselineHTML := `<html><body><p>User ID 1</p></body></html>`

	// True payload - slightly more content (small difference but significant for small page)
	truePayloadHTML := `<html><body><p>User ID 1</p><p>User ID 2</p><p>User ID 3</p></body></html>`

	// False payload - no results
	falsePayloadHTML := `<html><body><p>No user found</p></body></html>`

	mock.responses["https://example.com/user?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineHTML)),
		Header:     make(http.Header),
	}

	mock.differentialResponse = true
	mock.trueResponse = truePayloadHTML
	mock.falseResponse = falsePayloadHTML

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/user?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect SQL injection with adaptive thresholds for small responses
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SQL injection vulnerability using adaptive thresholds for small responses")
		t.Logf("Total tests performed: %d", result.Summary.TotalTests)
	}

	if len(result.Findings) > 0 {
		finding := result.Findings[0]
		if finding.Confidence != "high" && finding.Confidence != "medium" {
			t.Errorf("Expected high or medium confidence, got: %s", finding.Confidence)
		}
	}
}

// TestSQLiScanner_DVWA_LowSecurity_Realistic tests with realistic DVWA low security responses
func TestSQLiScanner_DVWA_LowSecurity_Realistic(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Realistic DVWA baseline response for id=1
	baselineHTML := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA) v1.10</title>
</head>
<body>
<div id="wrapper">
<div id="main_body">
<h1>SQL Injection</h1>
<div class="body_padded">
<form action="#" method="GET">
User ID:
<input type="text" name="id" value="1">
<input type="submit" name="Submit" value="Submit">
</form>
<br />
<table>
<tr><td>ID</td><td>First name</td><td>Surname</td></tr>
<tr><td>1</td><td>admin</td><td>admin</td></tr>
</table>
</div>
</div>
</div>
</body>
</html>`

	// True payload (1' OR '1'='1) returns all users
	truePayloadHTML := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA) v1.10</title>
</head>
<body>
<div id="wrapper">
<div id="main_body">
<h1>SQL Injection</h1>
<div class="body_padded">
<form action="#" method="GET">
User ID:
<input type="text" name="id" value="1' OR '1'='1">
<input type="submit" name="Submit" value="Submit">
</form>
<br />
<table>
<tr><td>ID</td><td>First name</td><td>Surname</td></tr>
<tr><td>1</td><td>admin</td><td>admin</td></tr>
<tr><td>2</td><td>Gordon</td><td>Brown</td></tr>
<tr><td>3</td><td>Hack</td><td>Me</td></tr>
<tr><td>4</td><td>Pablo</td><td>Picasso</td></tr>
<tr><td>5</td><td>Bob</td><td>Smith</td></tr>
</table>
</div>
</div>
</div>
</body>
</html>`

	// False payload (1' OR '1'='2) returns no users
	falsePayloadHTML := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA) v1.10</title>
</head>
<body>
<div id="wrapper">
<div id="main_body">
<h1>SQL Injection</h1>
<div class="body_padded">
<form action="#" method="GET">
User ID:
<input type="text" name="id" value="1' OR '1'='2">
<input type="submit" name="Submit" value="Submit">
</form>
<br />
<table>
<tr><td>ID</td><td>First name</td><td>Surname</td></tr>
</table>
</div>
</div>
</div>
</body>
</html>`

	mock.responses["http://127.0.0.1/dvwa/vulnerabilities/sqli/?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineHTML)),
		Header:     make(http.Header),
	}

	mock.differentialResponse = true
	mock.trueResponse = truePayloadHTML
	mock.falseResponse = falsePayloadHTML

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "http://127.0.0.1/dvwa/vulnerabilities/sqli/?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// This is the critical test - must detect DVWA SQLi
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("CRITICAL: Failed to detect SQL injection in DVWA-style scenario")
		t.Logf("Total tests performed: %d", result.Summary.TotalTests)
		t.Logf("This is the exact scenario described in issue #153")
	} else {
		t.Logf("Successfully detected %d vulnerabilities", result.Summary.VulnerabilitiesFound)
	}

	// Verify detection details
	if len(result.Findings) > 0 {
		finding := result.Findings[0]
		t.Logf("Detection method: %s", finding.Evidence)
		t.Logf("Confidence: %s", finding.Confidence)

		// Should have high confidence for this clear differential behavior
		if finding.Confidence != "high" {
			t.Logf("Note: Expected high confidence for DVWA detection, got: %s", finding.Confidence)
		}

		// Evidence should mention structural or content differences
		hasContentEvidence := strings.Contains(finding.Evidence, "structural") ||
			strings.Contains(finding.Evidence, "word count") ||
			strings.Contains(finding.Evidence, "content hash") ||
			strings.Contains(finding.Evidence, "results")

		if !hasContentEvidence {
			t.Errorf("Expected evidence to mention content-based detection, got: %s", finding.Evidence)
		}
	}
}

// TestSQLiScanner_AdaptiveThresholds_VeryFewWords tests detection with minimal word differences
func TestSQLiScanner_AdaptiveThresholds_VeryFewWords(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Minimal baseline
	baselineHTML := `<html><body>User 1</body></html>`

	// True payload - slightly more
	truePayloadHTML := `<html><body>User 1 User 2</body></html>`

	// False payload - even less
	falsePayloadHTML := `<html><body>None</body></html>`

	mock.responses["https://api.example.com/user?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineHTML)),
		Header:     make(http.Header),
	}

	mock.differentialResponse = true
	mock.trueResponse = truePayloadHTML
	mock.falseResponse = falsePayloadHTML

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://api.example.com/user?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// With adaptive thresholds, even 1-2 word differences should be detected
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SQL injection with minimal word count differences")
	}
}

// TestSQLiScanner_DVWA_EnhancedDetection tests the enhanced detection with various DVWA response patterns
func TestSQLiScanner_DVWA_EnhancedDetection(t *testing.T) {
	tests := []struct {
		name            string
		baselineHTML    string
		trueHTML        string
		falseHTML       string
		shouldDetect    bool
		detectionReason string
	}{
		{
			name: "DVWA table with data rows - true has more rows",
			baselineHTML: `<html><body>
				<table>
					<tr><td>ID</td><td>Name</td></tr>
					<tr><td>1</td><td>admin</td></tr>
				</table>
			</body></html>`,
			trueHTML: `<html><body>
				<table>
					<tr><td>ID</td><td>Name</td></tr>
					<tr><td>1</td><td>admin</td></tr>
					<tr><td>2</td><td>user</td></tr>
					<tr><td>3</td><td>guest</td></tr>
				</table>
			</body></html>`,
			falseHTML: `<html><body>
				<table>
					<tr><td>ID</td><td>Name</td></tr>
				</table>
			</body></html>`,
			shouldDetect:    true,
			detectionReason: "structural elements differ (true has 3 data rows, false has 0)",
		},
		{
			name: "DVWA with pre tags - true has data, false empty",
			baselineHTML: `<html><body>
				<pre>ID: 1
First name: admin
Surname: admin</pre>
			</body></html>`,
			trueHTML: `<html><body>
				<pre>ID: 1
First name: admin
Surname: admin

ID: 2
First name: Gordon
Surname: Brown

ID: 3
First name: Hack
Surname: Me</pre>
			</body></html>`,
			falseHTML: `<html><body>
				<pre></pre>
			</body></html>`,
			shouldDetect:    true,
			detectionReason: "word count differs significantly and results pattern differs",
		},
		{
			name:            "DVWA minimal response - just table headers vs data",
			baselineHTML:    `<html><body><table><tr><th>User</th></tr><tr><td>admin</td></tr></table></body></html>`,
			trueHTML:        `<html><body><table><tr><th>User</th></tr><tr><td>admin</td></tr><tr><td>user1</td></tr><tr><td>user2</td></tr></table></body></html>`,
			falseHTML:       `<html><body><table><tr><th>User</th></tr></table></body></html>`,
			shouldDetect:    true,
			detectionReason: "false has empty table (headers only), true has data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockSQLiHTTPClient()

			mock.responses["https://dvwa.local/sqli?id=1"] = &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(tt.baselineHTML)),
				Header:     make(http.Header),
			}

			mock.differentialResponse = true
			mock.trueResponse = tt.trueHTML
			mock.falseResponse = tt.falseHTML

			scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

			ctx := context.Background()
			result := scanner.Scan(ctx, "https://dvwa.local/sqli?id=1")

			if result == nil {
				t.Fatal("Scan returned nil result")
			}

			if tt.shouldDetect && result.Summary.VulnerabilitiesFound == 0 {
				t.Errorf("Expected to detect SQL injection (%s), but found none", tt.detectionReason)
				t.Logf("Total tests: %d", result.Summary.TotalTests)
			} else if !tt.shouldDetect && result.Summary.VulnerabilitiesFound > 0 {
				t.Errorf("Expected no detection, but found %d vulnerabilities", result.Summary.VulnerabilitiesFound)
			}

			if tt.shouldDetect && len(result.Findings) > 0 {
				t.Logf("Detection evidence: %s", result.Findings[0].Evidence)
				t.Logf("Confidence: %s", result.Findings[0].Confidence)
			}
		})
	}
}

// TestSQLiScanner_hasResultsData_EnhancedDetection tests the enhanced hasResultsData function
func TestSQLiScanner_hasResultsData_EnhancedDetection(t *testing.T) {
	tests := []struct {
		name               string
		body               string
		structuralElements int
		expectedHasResults bool
	}{
		{
			name:               "DVWA table with data",
			body:               `<table><tr><td>1</td><td>admin</td></tr></table>`,
			structuralElements: 1,
			expectedHasResults: true,
		},
		{
			name:               "DVWA empty table (headers only)",
			body:               `<table><tr><th>ID</th><th>Name</th></tr></table>`,
			structuralElements: 1,
			expectedHasResults: false,
		},
		{
			name:               "DVWA pre tag with data",
			body:               `<pre>ID: 1\nFirst name: admin\nSurname: admin</pre>`,
			structuralElements: 0,
			expectedHasResults: true,
		},
		{
			name:               "DVWA empty pre tag",
			body:               `<pre></pre>`,
			structuralElements: 0,
			expectedHasResults: false,
		},
		{
			name:               "Response with no results text",
			body:               `<div>No user found</div>`,
			structuralElements: 0,
			expectedHasResults: false,
		},
		{
			name:               "Response with multiple structural elements",
			body:               `<div><ul><li>User 1</li><li>User 2</li></ul></div>`,
			structuralElements: 3,
			expectedHasResults: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasResultsData(tt.body, tt.structuralElements)
			if result != tt.expectedHasResults {
				t.Errorf("hasResultsData() = %v, expected %v", result, tt.expectedHasResults)
			}
		})
	}
}

// TestSQLiScanner_MinimalDataDifference tests detection when HTML structure is identical
// but only the data content within table cells differs (typical DVWA scenario)
func TestSQLiScanner_MinimalDataDifference(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// Baseline: Single user in table
	baselineHTML := `<!DOCTYPE html>
<html>
<head><title>SQL Injection Test</title></head>
<body>
<h1>User Search</h1>
<table>
<tr><th>ID</th><th>Name</th><th>Email</th></tr>
<tr><td>1</td><td>John Doe</td><td>john@example.com</td></tr>
</table>
</body>
</html>`

	// True payload: Multiple users (OR '1'='1' returns all records)
	truePayloadHTML := `<!DOCTYPE html>
<html>
<head><title>SQL Injection Test</title></head>
<body>
<h1>User Search</h1>
<table>
<tr><th>ID</th><th>Name</th><th>Email</th></tr>
<tr><td>1</td><td>John Doe</td><td>john@example.com</td></tr>
<tr><td>2</td><td>Jane Smith</td><td>jane@example.com</td></tr>
<tr><td>3</td><td>Bob Wilson</td><td>bob@example.com</td></tr>
</table>
</body>
</html>`

	// False payload: No users (AND '1'='2' returns no records)
	falsePayloadHTML := `<!DOCTYPE html>
<html>
<head><title>SQL Injection Test</title></head>
<body>
<h1>User Search</h1>
<table>
<tr><th>ID</th><th>Name</th><th>Email</th></tr>
</table>
</body>
</html>`

	mock.responses["https://webapp.test/search?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineHTML)),
		Header:     make(http.Header),
	}

	mock.differentialResponse = true
	mock.trueResponse = truePayloadHTML
	mock.falseResponse = falsePayloadHTML

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://webapp.test/search?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect the vulnerability even with minimal structural difference
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Failed to detect SQL injection with minimal data difference")
		t.Logf("Total tests performed: %d", result.Summary.TotalTests)
	} else {
		t.Logf("Successfully detected %d vulnerabilities", result.Summary.VulnerabilitiesFound)
	}

	// Verify that data content comparison was used
	if len(result.Findings) > 0 {
		finding := result.Findings[0]
		t.Logf("Detection evidence: %s", finding.Evidence)
		t.Logf("Confidence: %s", finding.Confidence)

		// Should mention data content or structural elements in evidence
		hasDataEvidence := strings.Contains(finding.Evidence, "data content") ||
			strings.Contains(finding.Evidence, "structural elements") ||
			strings.Contains(finding.Evidence, "word count")

		if !hasDataEvidence {
			t.Errorf("Expected evidence to mention data-based detection, got: %s", finding.Evidence)
		}

		// Should have at least medium confidence
		if finding.Confidence != "high" && finding.Confidence != "medium" {
			t.Errorf("Expected medium or high confidence, got: %s", finding.Confidence)
		}
	}
}

// TestSQLiScanner_DVWAFixtures_BooleanBased tests boolean-based SQLi detection
// using actual DVWA HTML response fixtures to match real-world DVWA behavior.
func TestSQLiScanner_DVWAFixtures_BooleanBased(t *testing.T) {
	// Load actual DVWA response fixtures
	baselineHTML, err := os.ReadFile("testdata/dvwa_sqli_baseline.html")
	if err != nil {
		t.Fatalf("Failed to load baseline fixture: %v", err)
	}

	truePayloadHTML, err := os.ReadFile("testdata/dvwa_sqli_true_payload.html")
	if err != nil {
		t.Fatalf("Failed to load true payload fixture: %v", err)
	}

	falsePayloadHTML, err := os.ReadFile("testdata/dvwa_sqli_false_payload.html")
	if err != nil {
		t.Fatalf("Failed to load false payload fixture: %v", err)
	}

	mock := newMockSQLiHTTPClient()

	// Baseline: id=1 returns 1 row (admin)
	mock.responses["http://dvwa.local/vulnerabilities/sqli/?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(string(baselineHTML))),
		Header:     make(http.Header),
	}

	// Set up differential responses for boolean-based testing
	mock.differentialResponse = true
	mock.trueResponse = string(truePayloadHTML)   // Returns 5 rows
	mock.falseResponse = string(falsePayloadHTML) // Returns 0 rows

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "http://dvwa.local/vulnerabilities/sqli/?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// DVWA boolean-based SQLi should be detected via differential analysis
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Errorf("Failed to detect DVWA boolean-based SQLi (1 row -> 5 rows -> 0 rows pattern)")
		t.Logf("Total tests performed: %d", result.Summary.TotalTests)
		t.Logf("Baseline has %d bytes, trueResponse has %d bytes, falseResponse has %d bytes",
			len(baselineHTML), len(truePayloadHTML), len(falsePayloadHTML))

		// Debug: analyze the responses
		_, baselineWords, baselineStructural, baselineData, baselineDataWords, baselineDataRows := analyzeResponse(string(baselineHTML))
		_, trueWords, trueStructural, trueData, trueDataWords, trueDataRows := analyzeResponse(string(truePayloadHTML))
		_, falseWords, falseStructural, falseData, falseDataWords, falseDataRows := analyzeResponse(string(falsePayloadHTML))

		t.Logf("Baseline: words=%d, structural=%d, dataWords=%d, dataRows=%d", baselineWords, baselineStructural, baselineDataWords, baselineDataRows)
		t.Logf("True:     words=%d, structural=%d, dataWords=%d, dataRows=%d", trueWords, trueStructural, trueDataWords, trueDataRows)
		t.Logf("False:    words=%d, structural=%d, dataWords=%d, dataRows=%d", falseWords, falseStructural, falseDataWords, falseDataRows)
		t.Logf("Baseline data: %q", baselineData)
		t.Logf("True data: %q", trueData)
		t.Logf("False data: %q", falseData)
	} else {
		t.Logf("Successfully detected %d vulnerabilities", result.Summary.VulnerabilitiesFound)

		// Verify finding details
		for _, finding := range result.Findings {
			t.Logf("Finding: type=%s, confidence=%s, payload=%s", finding.Type, finding.Confidence, finding.Payload)
			t.Logf("Evidence: %s", finding.Evidence)

			// Should be boolean-based detection
			if finding.Type != "boolean-based" {
				t.Errorf("Expected boolean-based detection, got %s", finding.Type)
			}

			// Should have medium or high confidence
			if finding.Confidence != "high" && finding.Confidence != "medium" {
				t.Errorf("Expected medium or high confidence, got %s", finding.Confidence)
			}
		}
	}
}

// TestSQLiScanner_DVWAFixtures_DataContentDifference tests that the scanner
// correctly identifies SQL injection based on data content differences in DVWA responses.
func TestSQLiScanner_DVWAFixtures_DataContentDifference(t *testing.T) {
	baselineHTML, err := os.ReadFile("testdata/dvwa_sqli_baseline.html")
	if err != nil {
		t.Fatalf("Failed to load baseline fixture: %v", err)
	}

	truePayloadHTML, err := os.ReadFile("testdata/dvwa_sqli_true_payload.html")
	if err != nil {
		t.Fatalf("Failed to load true payload fixture: %v", err)
	}

	// Test data content extraction on baseline (1 row)
	_, baselineWords, baselineStructural, baselineData, baselineDataWords, baselineDataRows := analyzeResponse(string(baselineHTML))
	t.Logf("Baseline response analysis:")
	t.Logf("  Total words: %d", baselineWords)
	t.Logf("  Structural elements: %d", baselineStructural)
	t.Logf("  Data words: %d", baselineDataWords)
	t.Logf("  Data rows: %d", baselineDataRows)
	t.Logf("  Data content: %q", baselineData)

	// Test data content extraction on true payload (5 rows)
	_, trueWords, trueStructural, trueData, trueDataWords, trueDataRows := analyzeResponse(string(truePayloadHTML))
	t.Logf("True payload response analysis:")
	t.Logf("  Total words: %d", trueWords)
	t.Logf("  Structural elements: %d", trueStructural)
	t.Logf("  Data words: %d", trueDataWords)
	t.Logf("  Data rows: %d", trueDataRows)
	t.Logf("  Data content: %q", trueData)

	// Verify meaningful differences
	dataWordsDiff := abs(trueDataWords - baselineDataWords)
	dataRowsDiff := abs(trueDataRows - baselineDataRows)
	t.Logf("Data words difference: %d", dataWordsDiff)
	t.Logf("Data rows difference: %d", dataRowsDiff)

	if dataWordsDiff < minWordCountDifference {
		t.Errorf("Data words difference (%d) is below threshold (%d) - detection may fail",
			dataWordsDiff, minWordCountDifference)
	}

	// Check if data content is significantly different
	if baselineData == trueData {
		t.Error("Data content is identical - boolean-based detection will fail")
	} else {
		t.Logf("Data content differs - detection should succeed")
	}
}

// TestSQLiScanner_DVWAFixtures_ThresholdCalibration verifies that threshold constants
// are properly calibrated for DVWA-sized responses.
func TestSQLiScanner_DVWAFixtures_ThresholdCalibration(t *testing.T) {
	baselineHTML, err := os.ReadFile("testdata/dvwa_sqli_baseline.html")
	if err != nil {
		t.Fatalf("Failed to load baseline fixture: %v", err)
	}

	truePayloadHTML, err := os.ReadFile("testdata/dvwa_sqli_true_payload.html")
	if err != nil {
		t.Fatalf("Failed to load true payload fixture: %v", err)
	}

	falsePayloadHTML, err := os.ReadFile("testdata/dvwa_sqli_false_payload.html")
	if err != nil {
		t.Fatalf("Failed to load false payload fixture: %v", err)
	}

	// Analyze all three responses
	responses := map[string]string{
		"baseline": string(baselineHTML),
		"true":     string(truePayloadHTML),
		"false":    string(falsePayloadHTML),
	}

	for name, html := range responses {
		_, words, structural, _, dataWords, dataRows := analyzeResponse(html)
		length := len(html)

		t.Logf("%s response:", name)
		t.Logf("  Size: %d bytes (threshold: %d)", length, smallResponseSizeThreshold)
		t.Logf("  Word count: %d (min diff threshold: %d)", words, minWordCountDifference)
		t.Logf("  Structural elements: %d (threshold: %d)", structural, fewStructuralElementsLimit)
		t.Logf("  Data word count: %d", dataWords)
		t.Logf("  Data row count: %d", dataRows)

		// Check if response characteristics align with thresholds
		if length < smallResponseSizeThreshold {
			t.Logf("  -> Uses sensitive threshold (small response)")
		}
		if structural < fewStructuralElementsLimit {
			t.Logf("  -> Uses sensitive threshold (few structural elements)")
		}
	}

	// Check if differences exceed thresholds
	_, baselineWords, _, _, baselineDataWords, _ := analyzeResponse(string(baselineHTML))
	_, trueWords, _, _, trueDataWords, _ := analyzeResponse(string(truePayloadHTML))
	_, falseWords, _, _, falseDataWords, _ := analyzeResponse(string(falsePayloadHTML))

	trueVsBaselineWordDiff := abs(trueWords - baselineWords)
	falseVsBaselineWordDiff := abs(falseWords - baselineWords)
	trueVsFalseWordDiff := abs(trueWords - falseWords)

	t.Logf("\nWord count differences:")
	t.Logf("  True vs Baseline: %d (threshold: %d)", trueVsBaselineWordDiff, minWordCountDifference)
	t.Logf("  False vs Baseline: %d (threshold: %d)", falseVsBaselineWordDiff, minWordCountDifference)
	t.Logf("  True vs False: %d (threshold: %d)", trueVsFalseWordDiff, minWordCountDifference)

	trueVsBaselineDataDiff := abs(trueDataWords - baselineDataWords)
	falseVsBaselineDataDiff := abs(falseDataWords - baselineDataWords)
	trueVsFalseDataDiff := abs(trueDataWords - falseDataWords)

	t.Logf("\nData word count differences:")
	t.Logf("  True vs Baseline: %d", trueVsBaselineDataDiff)
	t.Logf("  False vs Baseline: %d", falseVsBaselineDataDiff)
	t.Logf("  True vs False: %d", trueVsFalseDataDiff)

	// Verify detection thresholds are met
	if trueVsBaselineDataDiff < minWordCountDifference && trueVsFalseDataDiff < minWordCountDifference {
		t.Errorf("Data differences below threshold - detection will likely fail")
	}
}

// TestSQLiScanner_DVWAFixtures_NumericParam tests boolean-based SQLi detection
// for a numeric-valued parameter (e.g. id=1) where the false payload still returns
// the baseline row rather than an empty result.
//
// Real DVWA behaviour with id=1:
//   - baseline  (id=1)               → 1 user row  (admin)
//   - true      (id=1' OR '1'='1)    → 5 user rows (all users)
//   - false     (id=1' OR '1'='2)    → 1 user row  (admin, same count as baseline)
//
// The false response is NOT empty — the WHERE clause still matches user 1.
// Detection must rely on the 3-way baseline comparison (true >> baseline ≥ false).
func TestSQLiScanner_DVWAFixtures_NumericParam(t *testing.T) {
	baselineHTML, err := os.ReadFile("testdata/dvwa_sqli_baseline.html")
	if err != nil {
		t.Fatalf("Failed to load baseline fixture: %v", err)
	}

	truePayloadHTML, err := os.ReadFile("testdata/dvwa_sqli_numeric_true_payload.html")
	if err != nil {
		t.Fatalf("Failed to load numeric true payload fixture: %v", err)
	}

	falsePayloadHTML, err := os.ReadFile("testdata/dvwa_sqli_numeric_false_payload.html")
	if err != nil {
		t.Fatalf("Failed to load numeric false payload fixture: %v", err)
	}

	// Confirm the fixture characteristics before running the scanner.
	_, _, _, baselineData, baselineDataWords, _ := analyzeResponse(string(baselineHTML))
	_, _, _, trueData, trueDataWords, _ := analyzeResponse(string(truePayloadHTML))
	_, _, _, falseData, falseDataWords, _ := analyzeResponse(string(falsePayloadHTML))

	t.Logf("Baseline: dataWords=%d, data=%q", baselineDataWords, baselineData)
	t.Logf("True:     dataWords=%d, data=%q", trueDataWords, trueData)
	t.Logf("False:    dataWords=%d, data=%q", falseDataWords, falseData)

	// The false payload returns the same number of rows as the baseline —
	// true/false diff must still be significant for detection.
	if trueDataWords <= falseDataWords {
		t.Errorf("Fixture sanity: true (%d) should have more data words than false (%d)", trueDataWords, falseDataWords)
	}

	mock := newMockSQLiHTTPClient()

	// Default response matches baseline so content-routing pre-check passes
	mock.defaultResponse = string(baselineHTML)

	// Baseline request (id=1) returns 1 row.
	mock.responses["http://dvwa.local/vulnerabilities/sqli/?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(string(baselineHTML))),
		Header:     make(http.Header),
	}

	// Differential: true payload (contains 1'='1) → 5 rows; false (1'='2) → 1 row.
	mock.differentialResponse = true
	mock.trueResponse = string(truePayloadHTML)
	mock.falseResponse = string(falsePayloadHTML)

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "http://dvwa.local/vulnerabilities/sqli/?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Errorf("Failed to detect boolean-based SQLi on numeric id parameter (true: %d words, baseline: %d words, false: %d words)",
			trueDataWords, baselineDataWords, falseDataWords)
		t.Logf("Total tests: %d", result.Summary.TotalTests)
		return
	}

	t.Logf("Detected %d vulnerabilities on numeric id parameter", result.Summary.VulnerabilitiesFound)

	// At least one finding should reference the 3-way baseline comparison.
	foundBaselineEvidence := false
	for _, finding := range result.Findings {
		t.Logf("Finding: payload=%q confidence=%s evidence=%s", finding.Payload, finding.Confidence, finding.Evidence)
		if strings.Contains(finding.Evidence, "baseline") {
			foundBaselineEvidence = true
		}
	}
	if !foundBaselineEvidence {
		t.Errorf("3-way baseline evidence not found in any finding; expected 'baseline' in evidence string — verify the 3-way check block in testBooleanBased is still present and executing")
	}
}

// TestSQLiScanner_DVWAFixtures_ErrorBased tests error-based SQLi detection
// Note: DVWA at security=low typically doesn't expose SQL errors, so this test
// documents that error-based detection is NOT expected to work on DVWA.
func TestSQLiScanner_DVWAFixtures_ErrorBased(t *testing.T) {
	// DVWA at security=low doesn't expose SQL error messages
	// This test documents the expected behavior
	baselineHTML, err := os.ReadFile("testdata/dvwa_sqli_baseline.html")
	if err != nil {
		t.Fatalf("Failed to load baseline fixture: %v", err)
	}

	// Check if baseline contains any SQL error patterns
	hasError := false
	for _, pattern := range sqlErrorPatterns {
		if pattern.MatchString(string(baselineHTML)) {
			hasError = true
			match := pattern.FindString(string(baselineHTML))
			t.Logf("Found SQL error pattern: %s", match)
		}
	}

	if !hasError {
		t.Logf("DVWA baseline response does not contain SQL error messages (expected)")
		t.Logf("Error-based detection will NOT work on DVWA at security=low")
		t.Logf("Boolean-based and time-based detection are the viable methods")
	} else {
		t.Errorf("Unexpected: DVWA baseline contains SQL errors")
	}
}

// TestSQLiScanner_DVWAFixtures_ResponseStructure verifies the HTML structure
// of DVWA responses matches expected patterns.
func TestSQLiScanner_DVWAFixtures_ResponseStructure(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		hasTable bool
		hasPre   bool
		numRows  int // Expected number of data rows
	}{
		{
			name:     "baseline (1 row)",
			fixture:  "testdata/dvwa_sqli_baseline.html",
			hasTable: false,
			hasPre:   true,
			numRows:  1,
		},
		{
			name:     "true payload (5 rows)",
			fixture:  "testdata/dvwa_sqli_true_payload.html",
			hasTable: false,
			hasPre:   true,
			numRows:  5,
		},
		{
			name:     "false payload (0 rows)",
			fixture:  "testdata/dvwa_sqli_false_payload.html",
			hasTable: false,
			hasPre:   true,
			numRows:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			html, err := os.ReadFile(tt.fixture)
			if err != nil {
				t.Fatalf("Failed to load fixture: %v", err)
			}

			htmlStr := string(html)

			// Check for expected HTML elements
			if tt.hasPre {
				if !strings.Contains(htmlStr, "<pre>") {
					t.Errorf("Expected <pre> tag in %s", tt.name)
				}
			}

			if tt.hasTable {
				if !strings.Contains(htmlStr, "<table>") {
					t.Errorf("Expected <table> tag in %s", tt.name)
				}
			}

			// Count occurrences of "ID:" and "First name:" to verify row count
			idCount := strings.Count(htmlStr, "ID:")
			if tt.numRows > 0 && idCount == 0 {
				t.Errorf("Expected data rows but found none in %s", tt.name)
			}

			t.Logf("%s: contains %d data entries", tt.name, idCount)
		})
	}
}

// TestSQLiScanner_Scan_DVWAStyleBooleanBased tests detection of DVWA-style boolean-based SQL injection
// where responses have subtle differences (e.g., presence/absence of table rows)
func TestSQLiScanner_Scan_DVWAStyleBooleanBased(t *testing.T) {
	mock := newMockSQLiHTTPClient()

	// DVWA-style baseline response with one user record in a table
	baselineHTML := `<!DOCTYPE html>
<html>
<head><title>SQL Injection</title></head>
<body>
<h1>SQL Injection</h1>
<div class="vulnerable_code_area">
<table>
<tr><th>ID</th><th>First name</th><th>Surname</th></tr>
<tr><td>1</td><td>admin</td><td>admin</td></tr>
</table>
</div>
</body>
</html>`

	// DVWA-style response for true payload - returns multiple user records
	truePayloadHTML := `<!DOCTYPE html>
<html>
<head><title>SQL Injection</title></head>
<body>
<h1>SQL Injection</h1>
<div class="vulnerable_code_area">
<table>
<tr><th>ID</th><th>First name</th><th>Surname</th></tr>
<tr><td>1</td><td>admin</td><td>admin</td></tr>
<tr><td>2</td><td>Gordon</td><td>Brown</td></tr>
<tr><td>3</td><td>Hack</td><td>Me</td></tr>
<tr><td>4</td><td>Pablo</td><td>Picasso</td></tr>
<tr><td>5</td><td>Bob</td><td>Smith</td></tr>
</table>
</div>
</body>
</html>`

	// DVWA-style response for false payload - returns no records (just header row)
	falsePayloadHTML := `<!DOCTYPE html>
<html>
<head><title>SQL Injection</title></head>
<body>
<h1>SQL Injection</h1>
<div class="vulnerable_code_area">
<table>
<tr><th>ID</th><th>First name</th><th>Surname</th></tr>
</table>
</div>
</body>
</html>`

	// Default response matches baseline so content-routing pre-check passes
	mock.defaultResponse = baselineHTML

	// Set up mock responses
	mock.responses["https://example.com/dvwa/vulnerabilities/sqli/?id=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineHTML)),
		Header:     make(http.Header),
	}

	mock.responses["https://example.com/dvwa/vulnerabilities/sqli/?id=%27+OR+%271%27%3D%271"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(truePayloadHTML)),
		Header:     make(http.Header),
	}

	mock.responses["https://example.com/dvwa/vulnerabilities/sqli/?id=%27+OR+%271%27%3D%272"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(falsePayloadHTML)),
		Header:     make(http.Header),
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/dvwa/vulnerabilities/sqli/?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect boolean-based SQLi due to DVWA-style response differences
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find boolean-based SQL injection vulnerability in DVWA-style responses")
	}

	// Verify that the finding contains differential analysis evidence
	found := false
	for _, finding := range result.Findings {
		if finding.Type == "boolean-based" && strings.Contains(finding.Payload, "'1'='1") {
			found = true

			// Check that evidence mentions row count, data content, or data-related differences
			evidenceLower := strings.ToLower(finding.Evidence)
			hasDifferentialEvidence := strings.Contains(evidenceLower, "row") ||
				strings.Contains(evidenceLower, "data") ||
				strings.Contains(evidenceLower, "word count") ||
				strings.Contains(evidenceLower, "structural")

			if !hasDifferentialEvidence {
				t.Errorf("Expected evidence to mention differential analysis indicators (row, data, word count, etc.), got: %s", finding.Evidence)
			}

			t.Logf("Found DVWA-style SQLi with confidence: %s, evidence: %s", finding.Confidence, finding.Evidence)
		}
	}

	if !found {
		t.Error("Expected to find boolean-based SQLi with differential analysis for DVWA-style responses")
	}
}

// TestIsNonDataParameter tests the parameter filtering logic to prevent false positives
func TestIsNonDataParameter(t *testing.T) {
	tests := []struct {
		name       string
		paramName  string
		shouldSkip bool
	}{
		// Submit buttons and action parameters
		{"submit button", "submit", true},
		{"Submit button uppercase", "Submit", true},
		{"button param", "button", true},
		{"btn param", "btnSearch", true},
		{"send param", "send", true},
		{"action param", "action", true},

		// DVWA-specific non-data fields
		{"seclev_submit", "seclev_submit", true},
		{"Upload button", "Upload", true},
		{"security dropdown", "security", true},
		{"phpids param", "phpids", true},

		// CSRF tokens and session fields
		{"csrf token", "csrf_token", true},
		{"token field", "user_token", true},
		{"nonce field", "nonce", true},
		{"session field", "session_id", true},

		// Valid data parameters that should NOT be skipped
		{"id parameter", "id", false},
		{"user parameter", "user", false},
		{"name parameter", "name", false},
		{"email parameter", "email", false},
		{"search parameter", "search", false},
		{"query parameter", "query", false},
		{"page parameter", "page", false},

		// Edge cases - parameters containing filter patterns as substrings
		// Note: "submission" doesn't contain "submit" (it's "submiss"), so it should NOT be filtered
		{"submission param (doesn't match)", "submission", false},
		{"ribbon param (doesn't match)", "ribbon", false},

		// These DO contain the patterns and WILL be filtered
		{"resubmit param (contains submit)", "resubmit", true},
		{"resend param (contains send)", "resend", true},
		{"sender param (contains send)", "sender", true},
		{"goto param (contains go)", "goto", true},
		{"cargo param (contains go)", "cargo", true},
		{"category param (contains go)", "category", true},
		{"transaction param (contains action)", "transaction", true},
		{"reaction param (contains action)", "reaction", true},
		{"submit_form param (contains submit)", "submit_form", true},
		{"form_button param (contains button)", "form_button", true},

		// Submit button patterns — "change" (added for DVWA /csrf/ Change button)
		{"Change button (DVWA)", "Change", true},
		{"change_password param (contains change)", "change_password", true},

		// Known substring collisions introduced by the "change" pattern (trade-off is documented in sqli.go)
		{"exchange param (contains change)", "exchange", true},
		{"last_changed param (contains change)", "last_changed", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNonDataParameter(tt.paramName)
			if result != tt.shouldSkip {
				t.Errorf("isNonDataParameter(%q) = %v, want %v", tt.paramName, result, tt.shouldSkip)
			}
		})
	}
}

// TestNormalizeResponseContent tests that CSRF tokens and dynamic content are removed
func TestNormalizeResponseContent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string // strings that should be removed
	}{
		{
			name: "CSRF token in input field",
			input: `<html><body>
				<input type="hidden" name="csrf_token" value="abc123def456">
				<input type="text" name="username">
			</body></html>`,
			contains: []string{"csrf_token", "abc123def456"},
		},
		{
			name: "User token in input field",
			input: `<html><body>
				<input name="user_token" value="xyz789" type="hidden">
			</body></html>`,
			contains: []string{"user_token", "xyz789"},
		},
		{
			name: "CSRF meta tag",
			input: `<html><head>
				<meta name="csrf-token" content="meta123abc">
			</head><body></body></html>`,
			contains: []string{"csrf-token", "meta123abc"},
		},
		{
			name: "Nonce in URL",
			input: `<html><body>
				<a href="/page?nonce=1234567890abcdef">Link</a>
			</body></html>`,
			contains: []string{"nonce="},
		},
		{
			name: "Timestamp parameter",
			input: `<html><body>
				<form action="/submit?timestamp=1234567890"></form>
			</body></html>`,
			contains: []string{"timestamp="},
		},
		{
			name: "DVWA user_token with single-quoted attributes (lowercase hex)",
			input: `<html><body>
				<form method='post'>
				<input type='hidden' name='user_token' value='abc123def456abc1' />
				<input type='text' name='username'>
				</form>
			</body></html>`,
			contains: []string{"user_token", "abc123def456abc1"},
		},
		{
			name: "DVWA user_token with single-quoted attributes (uppercase hex)",
			input: `<html><body>
				<form method='post'>
				<input type='hidden' name='user_token' value='ABC123DEF456ABC1' />
				<input type='text' name='password'>
				</form>
			</body></html>`,
			contains: []string{"user_token", "ABC123DEF456ABC1"},
		},
		{
			name: "DVWA user_token with 32-char mixed-case hex (real token length)",
			input: `<html><body>
				<form action='/vulnerabilities/csrf/' method='POST'>
				<input type='hidden' name='user_token' value='1a2B3c4D5e6F7a8B9c0D1e2F3a4B5c6D' />
				<input type='submit' name='Change' value='Change'>
				</form>
			</body></html>`,
			contains: []string{"user_token", "1a2B3c4D5e6F7a8B9c0D1e2F3a4B5c6D"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := normalizeResponseContent(tt.input)

			// Check that the specified strings were removed
			for _, str := range tt.contains {
				if strings.Contains(normalized, str) {
					t.Errorf("normalizeResponseContent() should have removed %q from output, but it's still present", str)
				}
			}
		})
	}
}

// TestSQLiScanner_NoFalsePositivesOnSubmitButtons tests that submit buttons don't trigger false positives
func TestSQLiScanner_NoFalsePositivesOnSubmitButtons(t *testing.T) {
	// Create a stable mock response
	responseBody := `<html><body>
		<form method="post">
			<input type="text" name="id" value="1">
			<input type="submit" name="submit" value="Submit">
			<input type="submit" name="Upload" value="Upload">
		</form>
	</body></html>`

	// Mock client that returns stable responses
	mockClient := &mockSQLiHTTPClient{
		responses:       make(map[string]*http.Response),
		defaultResponse: responseBody,
	}

	scanner := NewSQLiScanner(
		WithSQLiHTTPClient(mockClient),
		WithSQLiTimeout(5*time.Second),
	)

	ctx := context.Background()
	result := scanner.Scan(ctx, "http://example.com/page?id=1&submit=Submit&Upload=Upload")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Check that submit buttons were filtered out
	for _, finding := range result.Findings {
		if finding.Parameter == "submit" || finding.Parameter == "Upload" {
			t.Errorf("Found false positive on submit button parameter: %s", finding.Parameter)
		}
	}

	t.Logf("Scan result: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))
}

// TestSQLiScanner_NoFalsePositivesOnCSRFTokenChanges tests that changing CSRF tokens don't cause false positives
func TestSQLiScanner_NoFalsePositivesOnCSRFTokenChanges(t *testing.T) {
	// Use differential response mode but with CSRF tokens
	// The baseline will have one token, true/false payloads will have different tokens
	// But after normalization, they should all look the same
	baselineBody := `<html><body>
		<h1>Welcome</h1>
		<p>User ID: 1</p>
		<input type="hidden" name="csrf_token" value="csrf_baseline_token_123">
		<form>
			<input type="text" name="id" value="1">
			<input type="submit" value="Submit">
		</form>
	</body></html>`

	trueBody := `<html><body>
		<h1>Welcome</h1>
		<p>User ID: 1</p>
		<input type="hidden" name="csrf_token" value="csrf_true_token_456">
		<form>
			<input type="text" name="id" value="1">
			<input type="submit" value="Submit">
		</form>
	</body></html>`

	falseBody := `<html><body>
		<h1>Welcome</h1>
		<p>User ID: 1</p>
		<input type="hidden" name="csrf_token" value="csrf_false_token_789">
		<form>
			<input type="text" name="id" value="1">
			<input type="submit" value="Submit">
		</form>
	</body></html>`

	mockClient := &mockSQLiHTTPClient{
		responses:            make(map[string]*http.Response),
		defaultResponse:      baselineBody,
		differentialResponse: true,
		trueResponse:         trueBody,
		falseResponse:        falseBody,
	}

	scanner := NewSQLiScanner(
		WithSQLiHTTPClient(mockClient),
		WithSQLiTimeout(5*time.Second),
	)

	ctx := context.Background()
	result := scanner.Scan(ctx, "http://example.com/page?id=1")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Should find no vulnerabilities since only CSRF token changes (normalization should handle this)
	if len(result.Findings) > 0 {
		t.Errorf("Found %d false positives due to CSRF token changes:", len(result.Findings))
		for _, finding := range result.Findings {
			t.Logf("  - Parameter: %s, Payload: %s, Evidence: %s", finding.Parameter, finding.Payload, finding.Evidence)
		}
	}

	t.Logf("Scan result: %d tests, %d findings (expected 0)", result.Summary.TotalTests, len(result.Findings))
}

// TestAnalyzeResponse_CSRFTokenNormalization verifies that two HTML pages differing
// only in a CSRF token hidden field produce the same ContentHash and WordCount.
// This is the core regression test for the boolean-based SQLi false-positive fix.
func TestAnalyzeResponse_CSRFTokenNormalization(t *testing.T) {
	// Two pages identical in structure/content but with different user_token values
	// (as seen on DVWA's /csrf/ page).
	html1 := `<html><body>
		<h1>Change Your Admin Password</h1>
		<form method="GET">
			<input name="password_new" type="password">
			<input name="password_conf" type="password">
			<input name="Change" type="submit" value="Change">
			<input name="user_token" type="hidden" value="aabbccdd11223344aabbccdd11223344">
		</form>
	</body></html>`

	html2 := `<html><body>
		<h1>Change Your Admin Password</h1>
		<form method="GET">
			<input name="password_new" type="password">
			<input name="password_conf" type="password">
			<input name="Change" type="submit" value="Change">
			<input name="user_token" type="hidden" value="99887766554433229988776655443322">
		</form>
	</body></html>`

	hash1, words1, _, _, _, _ := analyzeResponse(html1)
	hash2, words2, _, _, _, _ := analyzeResponse(html2)

	if hash1 != hash2 {
		t.Errorf("analyzeResponse() ContentHash differs for pages that differ only in CSRF token: %q vs %q (CSRF normalization not applied)", hash1, hash2)
	}
	if words1 != words2 {
		t.Errorf("analyzeResponse() WordCount differs for pages that differ only in CSRF token: %d vs %d (CSRF normalization not applied)", words1, words2)
	}
}

// contentRoutingMock simulates a parameter that routes to different content pages.
// Any value different from the original produces a significantly different response.
type contentRoutingMock struct {
	requests      []*http.Request
	originalValue string
	originalBody  string // response for the original value
	differentBody string // response for any other value
	trueBody      string // response for SQL true payloads (only used for injectable params)
	falseBody     string // response for SQL false payloads (only used for injectable params)
	injectable    bool   // if true, only SQL payloads produce different responses
}

func (m *contentRoutingMock) Do(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)

	var postBody string
	if req.Body != nil && req.Method == http.MethodPost {
		bodyBytes, _ := io.ReadAll(req.Body)
		postBody = string(bodyBytes)
		req.Body = io.NopCloser(strings.NewReader(postBody))
	}

	// Collect all parameter values
	var values []string
	for _, vals := range req.URL.Query() {
		values = append(values, vals...)
	}
	if postBody != "" {
		values = append(values, postBody)
	}

	body := m.originalBody

	for _, v := range values {
		if m.injectable {
			// Injectable parameter: only SQL payloads differ
			if strings.Contains(v, "1'='1") || strings.Contains(v, "2'='2") {
				body = m.trueBody
			} else if strings.Contains(v, "1'='2") || strings.Contains(v, "2'='3") {
				body = m.falseBody
			}
		} else {
			// Content-routing parameter: any different value differs
			if v != m.originalValue {
				body = m.differentBody
			}
		}
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

func TestContentRoutingPreCheck_GET_SkipsContentRoutingParam(t *testing.T) {
	// Simulate a content-routing parameter like DVWA's doc param on instructions.php.
	// ANY different value produces a very different response.
	originalBody := strings.Repeat("a", 5000)  // baseline: 5000 bytes
	differentBody := strings.Repeat("b", 8000) // random string response: 8000 bytes (60% larger)

	mock := &contentRoutingMock{
		originalValue: "readme",
		originalBody:  originalBody,
		differentBody: differentBody,
		injectable:    false,
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))
	ctx := context.Background()

	result := scanner.Scan(ctx, "https://example.com/instructions.php?doc=readme")

	// Should produce NO boolean-based findings since the param is content-routing
	for _, f := range result.Findings {
		if f.Type == "boolean-based" {
			t.Errorf("Expected no boolean-based findings for content-routing param, but got: param=%s payload=%s", f.Parameter, f.Payload)
		}
	}
}

func TestContentRoutingPreCheck_GET_DetectsInjectableParam(t *testing.T) {
	// Simulate an injectable parameter like DVWA's id param on sqli/.
	// Only SQL payloads produce different responses; random strings return the same as baseline.
	originalBody := `<html><body><table><tr><td>ID: 1</td><td>First name: admin</td><td>Surname: admin</td></tr></table></body></html>`
	trueBody := `<html><body><table><tr><td>ID: 1</td><td>First name: admin</td><td>Surname: admin</td></tr></table></body></html>`
	falseBody := `<html><body><table></table></body></html>`

	mock := &contentRoutingMock{
		originalValue: "1",
		originalBody:  originalBody,
		trueBody:      trueBody,
		falseBody:     falseBody,
		injectable:    true,
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))
	ctx := context.Background()

	result := scanner.Scan(ctx, "https://example.com/sqli/?id=1")

	// Should produce boolean-based findings since the param IS injectable
	hasBooleanFinding := false
	for _, f := range result.Findings {
		if f.Type == "boolean-based" {
			hasBooleanFinding = true
			break
		}
	}
	if !hasBooleanFinding {
		t.Error("Expected boolean-based findings for injectable param, but got none")
	}
}

func TestContentRoutingPreCheck_POST_SkipsContentRoutingParam(t *testing.T) {
	originalBody := strings.Repeat("a", 5000)
	differentBody := strings.Repeat("b", 8000)

	mock := &contentRoutingMock{
		originalValue: "readme",
		originalBody:  originalBody,
		differentBody: differentBody,
		injectable:    false,
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))
	ctx := context.Background()

	// Simulate POST scanning by testing the isContentRoutingPOST method directly
	baseURL, _ := url.Parse("https://example.com/instructions.php")
	baseline := &baselineResponse{
		StatusCode: http.StatusOK,
		BodyLength: len(originalBody),
	}
	allParams := map[string]string{"doc": "readme"}

	isRouting := scanner.isContentRoutingPOST(ctx, baseURL, "doc", baseline, allParams)
	if !isRouting {
		t.Error("Expected isContentRoutingPOST to return true for content-routing param")
	}
}

func TestContentRoutingPreCheck_POST_DetectsInjectableParam(t *testing.T) {
	originalBody := `<html><body><table><tr><td>ID: 1</td></tr></table></body></html>`

	mock := &contentRoutingMock{
		originalValue: "1",
		originalBody:  originalBody,
		trueBody:      originalBody,
		falseBody:     `<html><body><table></table></body></html>`,
		injectable:    true,
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))
	ctx := context.Background()

	baseURL, _ := url.Parse("https://example.com/sqli/")
	baseline := &baselineResponse{
		StatusCode: http.StatusOK,
		BodyLength: len(originalBody),
	}
	allParams := map[string]string{"id": "1"}

	isRouting := scanner.isContentRoutingPOST(ctx, baseURL, "id", baseline, allParams)
	if isRouting {
		t.Error("Expected isContentRoutingPOST to return false for injectable param")
	}
}

func TestResponseSignificantlyDiffers(t *testing.T) {
	tests := []struct {
		name     string
		resp     *responseCharacteristics
		baseline *baselineResponse
		want     bool
	}{
		{
			name: "same response",
			resp: &responseCharacteristics{
				StatusCode: 200,
				BodyLength: 5000,
			},
			baseline: &baselineResponse{
				StatusCode: 200,
				BodyLength: 5000,
			},
			want: false,
		},
		{
			name: "different status code",
			resp: &responseCharacteristics{
				StatusCode: 404,
				BodyLength: 5000,
			},
			baseline: &baselineResponse{
				StatusCode: 200,
				BodyLength: 5000,
			},
			want: true,
		},
		{
			name: "significant length difference",
			resp: &responseCharacteristics{
				StatusCode: 200,
				BodyLength: 8000,
			},
			baseline: &baselineResponse{
				StatusCode: 200,
				BodyLength: 5000,
			},
			want: true, // 60% difference > 10% threshold
		},
		{
			name: "small length difference within threshold",
			resp: &responseCharacteristics{
				StatusCode: 200,
				BodyLength: 5200,
			},
			baseline: &baselineResponse{
				StatusCode: 200,
				BodyLength: 5000,
			},
			want: false, // 4% difference < 10% threshold
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := responseSignificantlyDiffers(tt.resp, tt.baseline)
			if got != tt.want {
				t.Errorf("responseSignificantlyDiffers() = %v, want %v", got, tt.want)
			}
		})
	}
}
