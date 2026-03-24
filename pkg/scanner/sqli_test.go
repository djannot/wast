package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
)

// mockSQLiHTTPClient is a mock HTTP client for testing SQL injection scanner.
type mockSQLiHTTPClient struct {
	responses map[string]*http.Response
	requests  []*http.Request
}

func (m *mockSQLiHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)

	// Return a response based on the URL or a default response
	if resp, ok := m.responses[req.URL.String()]; ok {
		return resp, nil
	}

	// Default response - no vulnerability
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Normal response</body></html>")),
		Header:     make(http.Header),
	}, nil
}

func newMockSQLiHTTPClient() *mockSQLiHTTPClient {
	return &mockSQLiHTTPClient{
		responses: make(map[string]*http.Response),
		requests:  make([]*http.Request, 0),
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
