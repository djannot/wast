package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
)

// MockHTTPClient implements the HTTPClient interface for testing.
type MockHTTPClient struct {
	Responses map[string]*http.Response
	Errors    map[string]error
	Requests  []*http.Request
}

// NewMockHTTPClient creates a new MockHTTPClient.
func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{
		Responses: make(map[string]*http.Response),
		Errors:    make(map[string]error),
		Requests:  make([]*http.Request, 0),
	}
}

// AddResponse adds a mock response for a URL with headers.
func (m *MockHTTPClient) AddResponse(url string, statusCode int, body string, headers http.Header) {
	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     headers,
	}
	if headers == nil {
		resp.Header = make(http.Header)
	}
	m.Responses[url] = resp
}

// AddError adds a mock error for a URL.
func (m *MockHTTPClient) AddError(url string, err error) {
	m.Errors[url] = err
}

// Do performs the mock HTTP request.
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.Requests = append(m.Requests, req)
	url := req.URL.String()

	if err, ok := m.Errors[url]; ok {
		return nil, err
	}

	if resp, ok := m.Responses[url]; ok {
		// Create a fresh body for each request (since bodies can only be read once)
		if originalResp, exists := m.Responses[url]; exists {
			body, _ := io.ReadAll(originalResp.Body)
			resp.Body = io.NopCloser(strings.NewReader(string(body)))
			// Reset the original response body for future calls
			m.Responses[url].Body = io.NopCloser(strings.NewReader(string(body)))
		}
		return resp, nil
	}

	// Default: 404
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("Not Found")),
		Header:     make(http.Header),
	}, nil
}

type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

func TestTester_TestAll_Success(t *testing.T) {
	mockClient := NewMockHTTPClient()

	// Add responses for test endpoints
	headers := http.Header{
		"Content-Type":           []string{"application/json"},
		"X-Content-Type-Options": []string{"nosniff"},
	}
	mockClient.AddResponse("https://api.example.com/users", 200, `{"users":[]}`, headers)
	mockClient.AddResponse("https://api.example.com/users/1", 200, `{"id":1}`, headers)
	mockClient.AddResponse("https://api.example.com/health", 200, `{"status":"ok"}`, headers)

	spec := &APISpec{
		Title:   "Test API",
		Version: "1.0.0",
		Servers: []ServerInfo{
			{URL: "https://api.example.com"},
		},
		Endpoints: []EndpointInfo{
			{Path: "/users", Method: "GET", Summary: "List users"},
			{Path: "/users/1", Method: "GET", Summary: "Get user"},
			{Path: "/health", Method: "GET", Summary: "Health check"},
		},
	}

	tester := NewTester(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := tester.TestAll(ctx, spec)

	// Check base URL
	if result.BaseURL != "https://api.example.com" {
		t.Errorf("Expected base URL https://api.example.com, got %s", result.BaseURL)
	}

	// Check that all endpoints were tested
	if len(result.Endpoints) != 3 {
		t.Fatalf("Expected 3 endpoints, got %d", len(result.Endpoints))
	}

	// Check all returned 200
	for _, ep := range result.Endpoints {
		if ep.StatusCode != 200 {
			t.Errorf("Expected status code 200 for %s, got %d", ep.Endpoint.Path, ep.StatusCode)
		}
		if ep.Error != "" {
			t.Errorf("Unexpected error for %s: %s", ep.Endpoint.Path, ep.Error)
		}
		if !ep.Tested {
			t.Errorf("Expected endpoint %s to be tested", ep.Endpoint.Path)
		}
	}

	// Check summary
	if result.Summary.TotalEndpoints != 3 {
		t.Errorf("Expected 3 total endpoints in summary, got %d", result.Summary.TotalEndpoints)
	}
	if result.Summary.TestedEndpoints != 3 {
		t.Errorf("Expected 3 tested endpoints, got %d", result.Summary.TestedEndpoints)
	}
	if result.Summary.SuccessCount != 3 {
		t.Errorf("Expected 3 success count, got %d", result.Summary.SuccessCount)
	}

	// Check that requests were actually made
	if len(mockClient.Requests) != 3 {
		t.Errorf("Expected 3 requests, got %d", len(mockClient.Requests))
	}
}

func TestTester_TestAll_DryRun(t *testing.T) {
	mockClient := NewMockHTTPClient()

	spec := &APISpec{
		Title:   "Test API",
		Version: "1.0.0",
		Servers: []ServerInfo{
			{URL: "https://api.example.com"},
		},
		Endpoints: []EndpointInfo{
			{Path: "/users", Method: "GET", Summary: "List users"},
			{Path: "/users", Method: "POST", Summary: "Create user"},
			{Path: "/health", Method: "GET", Summary: "Health check"},
		},
	}

	tester := NewTester(
		WithHTTPClient(mockClient),
		WithDryRun(true),
	)
	ctx := context.Background()
	result := tester.TestAll(ctx, spec)

	// Check that dry run is set
	if !result.DryRun {
		t.Error("Expected dry run to be true")
	}

	// Check that all endpoints are listed
	if len(result.Endpoints) != 3 {
		t.Fatalf("Expected 3 endpoints, got %d", len(result.Endpoints))
	}

	// Check that endpoints were NOT tested (no HTTP requests made)
	for _, ep := range result.Endpoints {
		if ep.Tested {
			t.Errorf("Expected endpoint %s to NOT be tested in dry run", ep.Endpoint.Path)
		}
		if ep.StatusCode != 0 {
			t.Errorf("Expected no status code for %s in dry run, got %d", ep.Endpoint.Path, ep.StatusCode)
		}
	}

	// Check that no requests were made
	if len(mockClient.Requests) != 0 {
		t.Errorf("Expected 0 requests in dry run, got %d", len(mockClient.Requests))
	}

	// Check summary
	if result.Summary.TotalEndpoints != 3 {
		t.Errorf("Expected 3 total endpoints, got %d", result.Summary.TotalEndpoints)
	}
	if result.Summary.TestedEndpoints != 0 {
		t.Errorf("Expected 0 tested endpoints in dry run, got %d", result.Summary.TestedEndpoints)
	}
}

func TestTester_TestAll_BaseURLOverride(t *testing.T) {
	mockClient := NewMockHTTPClient()

	headers := http.Header{}
	mockClient.AddResponse("https://staging.example.com/users", 200, `{}`, headers)

	spec := &APISpec{
		Title:   "Test API",
		Version: "1.0.0",
		Servers: []ServerInfo{
			{URL: "https://api.example.com"}, // This should be overridden
		},
		Endpoints: []EndpointInfo{
			{Path: "/users", Method: "GET"},
		},
	}

	tester := NewTester(
		WithHTTPClient(mockClient),
		WithBaseURL("https://staging.example.com"),
	)
	ctx := context.Background()
	result := tester.TestAll(ctx, spec)

	// Check that base URL was overridden
	if result.BaseURL != "https://staging.example.com" {
		t.Errorf("Expected base URL https://staging.example.com, got %s", result.BaseURL)
	}

	// Check that request was made to the overridden URL
	if len(mockClient.Requests) != 1 {
		t.Fatalf("Expected 1 request, got %d", len(mockClient.Requests))
	}

	requestURL := mockClient.Requests[0].URL.String()
	if requestURL != "https://staging.example.com/users" {
		t.Errorf("Expected request to https://staging.example.com/users, got %s", requestURL)
	}
}

func TestTester_TestAll_NoBaseURL(t *testing.T) {
	mockClient := NewMockHTTPClient()

	spec := &APISpec{
		Title:   "Test API",
		Version: "1.0.0",
		Servers: []ServerInfo{}, // No servers defined
		Endpoints: []EndpointInfo{
			{Path: "/users", Method: "GET"},
		},
	}

	tester := NewTester(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := tester.TestAll(ctx, spec)

	// Check that an error was returned
	if len(result.Errors) == 0 {
		t.Error("Expected error when no base URL is available")
	}

	// Check that no requests were made
	if len(mockClient.Requests) != 0 {
		t.Errorf("Expected 0 requests when no base URL, got %d", len(mockClient.Requests))
	}
}

func TestTester_TestAll_MixedStatusCodes(t *testing.T) {
	mockClient := NewMockHTTPClient()

	mockClient.AddResponse("https://api.example.com/success", 200, `{}`, nil)
	mockClient.AddResponse("https://api.example.com/created", 201, `{}`, nil)
	mockClient.AddResponse("https://api.example.com/not-found", 404, `{}`, nil)
	mockClient.AddResponse("https://api.example.com/forbidden", 403, `{}`, nil)
	mockClient.AddResponse("https://api.example.com/error", 500, `{}`, nil)

	spec := &APISpec{
		Title:   "Test API",
		Version: "1.0.0",
		Servers: []ServerInfo{{URL: "https://api.example.com"}},
		Endpoints: []EndpointInfo{
			{Path: "/success", Method: "GET"},
			{Path: "/created", Method: "POST"},
			{Path: "/not-found", Method: "GET"},
			{Path: "/forbidden", Method: "GET"},
			{Path: "/error", Method: "GET"},
		},
	}

	tester := NewTester(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := tester.TestAll(ctx, spec)

	// Check summary counts
	if result.Summary.SuccessCount != 2 {
		t.Errorf("Expected 2 success (2xx), got %d", result.Summary.SuccessCount)
	}
	if result.Summary.ClientErrorCount != 2 {
		t.Errorf("Expected 2 client errors (4xx), got %d", result.Summary.ClientErrorCount)
	}
	if result.Summary.ServerErrorCount != 1 {
		t.Errorf("Expected 1 server error (5xx), got %d", result.Summary.ServerErrorCount)
	}
}

func TestTester_TestAll_RequestError(t *testing.T) {
	mockClient := NewMockHTTPClient()
	mockClient.AddError("https://api.example.com/timeout", &testError{message: "connection timeout"})
	mockClient.AddResponse("https://api.example.com/success", 200, `{}`, nil)

	spec := &APISpec{
		Title:   "Test API",
		Version: "1.0.0",
		Servers: []ServerInfo{{URL: "https://api.example.com"}},
		Endpoints: []EndpointInfo{
			{Path: "/timeout", Method: "GET"},
			{Path: "/success", Method: "GET"},
		},
	}

	tester := NewTester(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := tester.TestAll(ctx, spec)

	// Check that one endpoint has an error
	var errorEndpoint *EndpointTestResult
	for i, ep := range result.Endpoints {
		if ep.Endpoint.Path == "/timeout" {
			errorEndpoint = &result.Endpoints[i]
			break
		}
	}

	if errorEndpoint == nil {
		t.Fatal("Expected to find /timeout endpoint")
	}

	if errorEndpoint.Error == "" {
		t.Error("Expected error for /timeout endpoint")
	}

	if !strings.Contains(errorEndpoint.Error, "connection timeout") {
		t.Errorf("Expected error to contain 'connection timeout', got %s", errorEndpoint.Error)
	}

	// Check summary
	if result.Summary.ErrorCount != 1 {
		t.Errorf("Expected 1 error count, got %d", result.Summary.ErrorCount)
	}
	if result.Summary.SuccessCount != 1 {
		t.Errorf("Expected 1 success count, got %d", result.Summary.SuccessCount)
	}
}

func TestTester_TestEndpoint_WithAuth(t *testing.T) {
	mockClient := NewMockHTTPClient()
	mockClient.AddResponse("https://api.example.com/protected", 200, `{}`, nil)

	authConfig := &auth.AuthConfig{
		BearerToken: "test-token",
	}

	tester := NewTester(
		WithHTTPClient(mockClient),
		WithAuth(authConfig),
		WithBaseURL("https://api.example.com"),
	)

	endpoint := EndpointInfo{Path: "/protected", Method: "GET"}
	ctx := context.Background()
	result := tester.TestEndpoint(ctx, "https://api.example.com", endpoint)

	if result.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", result.StatusCode)
	}

	// Check that the auth was applied
	if len(mockClient.Requests) != 1 {
		t.Fatalf("Expected 1 request, got %d", len(mockClient.Requests))
	}

	authHeader := mockClient.Requests[0].Header.Get("Authorization")
	if authHeader != "Bearer test-token" {
		t.Errorf("Expected Authorization header 'Bearer test-token', got '%s'", authHeader)
	}
}

func TestTester_TestEndpoint_ExtractsSecurityHeaders(t *testing.T) {
	mockClient := NewMockHTTPClient()

	headers := http.Header{
		"Content-Type":              []string{"application/json"},
		"X-Content-Type-Options":    []string{"nosniff"},
		"X-Frame-Options":           []string{"DENY"},
		"Strict-Transport-Security": []string{"max-age=31536000"},
		"Server":                    []string{"nginx"},
		"X-Custom-Header":           []string{"ignored"},
	}
	mockClient.AddResponse("https://api.example.com/test", 200, `{}`, headers)

	tester := NewTester(WithHTTPClient(mockClient))
	endpoint := EndpointInfo{Path: "/test", Method: "GET"}
	ctx := context.Background()
	result := tester.TestEndpoint(ctx, "https://api.example.com", endpoint)

	// Check that security headers were extracted
	expectedHeaders := map[string]string{
		"Content-Type":              "application/json",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "max-age=31536000",
		"Server":                    "nginx",
	}

	for name, expected := range expectedHeaders {
		if result.Headers[name] != expected {
			t.Errorf("Expected header %s=%s, got %s", name, expected, result.Headers[name])
		}
	}

	// Check that non-security header was NOT included
	if _, exists := result.Headers["X-Custom-Header"]; exists {
		t.Error("Non-security header X-Custom-Header should not be included")
	}
}

func TestTester_TestEndpoint_ResponseTime(t *testing.T) {
	mockClient := NewMockHTTPClient()
	mockClient.AddResponse("https://api.example.com/test", 200, `{}`, nil)

	tester := NewTester(WithHTTPClient(mockClient))
	endpoint := EndpointInfo{Path: "/test", Method: "GET"}
	ctx := context.Background()
	result := tester.TestEndpoint(ctx, "https://api.example.com", endpoint)

	// Response time should be >= 0 (it was measured)
	if result.ResponseTime < 0 {
		t.Errorf("Expected non-negative response time, got %d", result.ResponseTime)
	}
}

func TestTester_WithOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		tester := NewTester()
		if tester.userAgent == "" {
			t.Error("Expected default user agent to be set")
		}
		if tester.timeout != 30*time.Second {
			t.Errorf("Expected default timeout of 30s, got %v", tester.timeout)
		}
		if tester.client == nil {
			t.Error("Expected default client to be set")
		}
		if tester.dryRun {
			t.Error("Expected dry run to be false by default")
		}
	})

	t.Run("custom user agent", func(t *testing.T) {
		tester := NewTester(WithUserAgent("CustomTester/1.0"))
		if tester.userAgent != "CustomTester/1.0" {
			t.Errorf("Expected custom user agent, got %s", tester.userAgent)
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		tester := NewTester(WithTimeout(60 * time.Second))
		if tester.timeout != 60*time.Second {
			t.Errorf("Expected timeout of 60s, got %v", tester.timeout)
		}
	})

	t.Run("custom http client", func(t *testing.T) {
		mock := NewMockHTTPClient()
		tester := NewTester(WithHTTPClient(mock))
		if tester.client != mock {
			t.Error("Expected custom HTTP client to be set")
		}
	})

	t.Run("base URL override", func(t *testing.T) {
		tester := NewTester(WithBaseURL("https://staging.example.com"))
		if tester.baseURL != "https://staging.example.com" {
			t.Errorf("Expected base URL to be set, got %s", tester.baseURL)
		}
	})

	t.Run("dry run", func(t *testing.T) {
		tester := NewTester(WithDryRun(true))
		if !tester.dryRun {
			t.Error("Expected dry run to be true")
		}
	})
}

func TestTester_buildURL(t *testing.T) {
	tester := NewTester()

	tests := []struct {
		baseURL  string
		path     string
		expected string
	}{
		{"https://api.example.com", "/users", "https://api.example.com/users"},
		{"https://api.example.com", "users", "https://api.example.com/users"},
		{"https://api.example.com/", "/users", "https://api.example.com/users"},
		{"https://api.example.com/v1", "/users", "https://api.example.com/v1/users"},
		{"https://api.example.com", "/users/{id}", "https://api.example.com/users/{id}"},
	}

	for _, tt := range tests {
		result := tester.buildURL(tt.baseURL, tt.path)
		if result != tt.expected {
			t.Errorf("buildURL(%s, %s) = %s, expected %s", tt.baseURL, tt.path, result, tt.expected)
		}
	}
}

func TestTester_resolveBaseURL(t *testing.T) {
	t.Run("uses override when provided", func(t *testing.T) {
		tester := NewTester(WithBaseURL("https://staging.example.com"))
		spec := &APISpec{
			Servers: []ServerInfo{{URL: "https://api.example.com"}},
		}
		result := tester.resolveBaseURL(spec)
		if result != "https://staging.example.com" {
			t.Errorf("Expected override URL, got %s", result)
		}
	})

	t.Run("uses spec server when no override", func(t *testing.T) {
		tester := NewTester()
		spec := &APISpec{
			Servers: []ServerInfo{{URL: "https://api.example.com/"}},
		}
		result := tester.resolveBaseURL(spec)
		if result != "https://api.example.com" {
			t.Errorf("Expected spec URL without trailing slash, got %s", result)
		}
	})

	t.Run("returns empty when no URL available", func(t *testing.T) {
		tester := NewTester()
		spec := &APISpec{
			Servers: []ServerInfo{},
		}
		result := tester.resolveBaseURL(spec)
		if result != "" {
			t.Errorf("Expected empty string, got %s", result)
		}
	})
}

func TestTestResult_String(t *testing.T) {
	result := &TestResult{
		BaseURL: "https://api.example.com",
		Endpoints: []EndpointTestResult{
			{
				Endpoint:     EndpointInfo{Path: "/users", Method: "GET", Summary: "List users"},
				StatusCode:   200,
				ResponseTime: 45,
				Tested:       true,
			},
			{
				Endpoint:   EndpointInfo{Path: "/error", Method: "GET"},
				StatusCode: 0,
				Error:      "connection refused",
				Tested:     true,
			},
		},
		Summary: TestSummary{
			TotalEndpoints:  2,
			TestedEndpoints: 2,
			SuccessCount:    1,
			ErrorCount:      1,
		},
	}

	str := result.String()

	checks := []string{
		"api.example.com",
		"GET /users",
		"200",
		"connection refused",
		"Total: 2",
	}

	for _, check := range checks {
		if !strings.Contains(str, check) {
			t.Errorf("String should contain %q", check)
		}
	}
}

func TestTestResult_String_DryRun(t *testing.T) {
	result := &TestResult{
		BaseURL: "https://api.example.com",
		DryRun:  true,
		Endpoints: []EndpointTestResult{
			{
				Endpoint: EndpointInfo{Path: "/users", Method: "GET", Summary: "List users"},
				Tested:   false,
			},
		},
		Summary: TestSummary{
			TotalEndpoints: 1,
		},
	}

	str := result.String()

	if !strings.Contains(str, "DRY RUN") {
		t.Error("String should contain 'DRY RUN' for dry run mode")
	}
}

func TestTester_TestAll_ContextCancellation(t *testing.T) {
	mockClient := &slowMockClient{delay: 100 * time.Millisecond}

	spec := &APISpec{
		Title:   "Test API",
		Version: "1.0.0",
		Servers: []ServerInfo{{URL: "https://api.example.com"}},
		Endpoints: []EndpointInfo{
			{Path: "/endpoint1", Method: "GET"},
			{Path: "/endpoint2", Method: "GET"},
			{Path: "/endpoint3", Method: "GET"},
		},
	}

	tester := NewTester(WithHTTPClient(mockClient))

	// Create a context that we'll cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := tester.TestAll(ctx, spec)

	// Should have an error about cancellation
	if len(result.Errors) == 0 {
		t.Error("Expected error for cancelled context")
	}

	foundCancelError := false
	for _, err := range result.Errors {
		if strings.Contains(err, "cancelled") {
			foundCancelError = true
			break
		}
	}
	if !foundCancelError {
		t.Errorf("Expected cancellation error, got: %v", result.Errors)
	}
}

// slowMockClient is a mock that respects context cancellation
type slowMockClient struct {
	delay time.Duration
}

func (c *slowMockClient) Do(req *http.Request) (*http.Response, error) {
	// Check if context is cancelled
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`{}`)),
		Header:     make(http.Header),
	}, nil
}

func TestTester_RateLimitDetection_429Response(t *testing.T) {
	mockClient := NewMockHTTPClient()

	// Set up a 429 response with rate limit headers
	// Use Header.Set() to ensure proper canonicalization
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("Retry-After", "30")
	headers.Set("X-RateLimit-Limit", "100")
	headers.Set("X-RateLimit-Remaining", "0")
	headers.Set("X-RateLimit-Reset", "1625140800")
	mockClient.AddResponse("https://api.example.com/rate-limited", 429, `{"error":"too many requests"}`, headers)

	spec := &APISpec{
		Title:   "Test API",
		Version: "1.0.0",
		Servers: []ServerInfo{{URL: "https://api.example.com"}},
		Endpoints: []EndpointInfo{
			{Path: "/rate-limited", Method: "GET"},
		},
	}

	tester := NewTester(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := tester.TestAll(ctx, spec)

	// Check that we got one endpoint result
	if len(result.Endpoints) != 1 {
		t.Fatalf("Expected 1 endpoint, got %d", len(result.Endpoints))
	}

	ep := result.Endpoints[0]

	// Check status code
	if ep.StatusCode != 429 {
		t.Errorf("Expected status code 429, got %d", ep.StatusCode)
	}

	// Check RateLimitInfo is populated
	if ep.RateLimitInfo == nil {
		t.Fatal("Expected RateLimitInfo to be populated")
	}

	if !ep.RateLimitInfo.RateLimitDetected {
		t.Error("Expected RateLimitDetected to be true")
	}

	if ep.RateLimitInfo.RetryAfter != "30" {
		t.Errorf("Expected RetryAfter to be '30', got '%s'", ep.RateLimitInfo.RetryAfter)
	}

	// Check rate limit headers
	expectedHeaders := map[string]string{
		"Retry-After":           "30",
		"X-RateLimit-Limit":     "100",
		"X-RateLimit-Remaining": "0",
		"X-RateLimit-Reset":     "1625140800",
	}

	for name, expected := range expectedHeaders {
		if ep.RateLimitInfo.RateLimitHeaders[name] != expected {
			t.Errorf("Expected RateLimitHeaders[%s] to be '%s', got '%s'", name, expected, ep.RateLimitInfo.RateLimitHeaders[name])
		}
	}

	// Check summary
	if result.Summary.RateLimitedCount != 1 {
		t.Errorf("Expected RateLimitedCount to be 1, got %d", result.Summary.RateLimitedCount)
	}
	if result.Summary.ClientErrorCount != 1 {
		t.Errorf("Expected ClientErrorCount to be 1, got %d", result.Summary.ClientErrorCount)
	}
}

func TestTester_RateLimitDetection_NoRateLimit(t *testing.T) {
	mockClient := NewMockHTTPClient()

	headers := http.Header{
		"Content-Type": []string{"application/json"},
	}
	mockClient.AddResponse("https://api.example.com/normal", 200, `{"status":"ok"}`, headers)

	spec := &APISpec{
		Title:   "Test API",
		Version: "1.0.0",
		Servers: []ServerInfo{{URL: "https://api.example.com"}},
		Endpoints: []EndpointInfo{
			{Path: "/normal", Method: "GET"},
		},
	}

	tester := NewTester(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := tester.TestAll(ctx, spec)

	ep := result.Endpoints[0]

	// Check that RateLimitInfo is nil when no rate limiting
	if ep.RateLimitInfo != nil {
		t.Error("Expected RateLimitInfo to be nil for normal response")
	}

	// Check summary
	if result.Summary.RateLimitedCount != 0 {
		t.Errorf("Expected RateLimitedCount to be 0, got %d", result.Summary.RateLimitedCount)
	}
}

func TestTester_RateLimitDetection_WithRateLimitHeadersButNot429(t *testing.T) {
	mockClient := NewMockHTTPClient()

	// Response with rate limit headers but not 429
	// Use Header.Set() to ensure proper canonicalization
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("X-RateLimit-Limit", "100")
	headers.Set("X-RateLimit-Remaining", "50")
	headers.Set("X-RateLimit-Reset", "1625140800")
	mockClient.AddResponse("https://api.example.com/with-headers", 200, `{"status":"ok"}`, headers)

	spec := &APISpec{
		Title:   "Test API",
		Version: "1.0.0",
		Servers: []ServerInfo{{URL: "https://api.example.com"}},
		Endpoints: []EndpointInfo{
			{Path: "/with-headers", Method: "GET"},
		},
	}

	tester := NewTester(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := tester.TestAll(ctx, spec)

	ep := result.Endpoints[0]

	// Check that RateLimitInfo is populated with headers
	if ep.RateLimitInfo == nil {
		t.Fatal("Expected RateLimitInfo to be populated when rate limit headers present")
	}

	// But RateLimitDetected should be false since status is not 429
	if ep.RateLimitInfo.RateLimitDetected {
		t.Error("Expected RateLimitDetected to be false for non-429 response")
	}

	// Headers should still be captured
	if ep.RateLimitInfo.RateLimitHeaders["X-RateLimit-Limit"] != "100" {
		t.Errorf("Expected X-RateLimit-Limit to be '100', got '%s'", ep.RateLimitInfo.RateLimitHeaders["X-RateLimit-Limit"])
	}

	// Summary should not count this as rate limited
	if result.Summary.RateLimitedCount != 0 {
		t.Errorf("Expected RateLimitedCount to be 0, got %d", result.Summary.RateLimitedCount)
	}
}

func TestTester_WithRespectRateLimits(t *testing.T) {
	tester := NewTester(WithRespectRateLimits(true))
	if !tester.respectRateLimits {
		t.Error("Expected respectRateLimits to be true")
	}

	tester2 := NewTester(WithRespectRateLimits(false))
	if tester2.respectRateLimits {
		t.Error("Expected respectRateLimits to be false")
	}
}

func TestTester_parseRetryAfter(t *testing.T) {
	tester := NewTester()

	tests := []struct {
		name     string
		input    string
		expected time.Duration
	}{
		{"empty", "", time.Second},
		{"seconds", "30", 30 * time.Second},
		{"zero", "0", 0},
		{"invalid", "invalid", time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tester.parseRetryAfter(tt.input)
			if result != tt.expected {
				t.Errorf("parseRetryAfter(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTester_extractRateLimitHeaders(t *testing.T) {
	tester := NewTester()

	// Use Header.Set() to ensure proper canonicalization
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("Retry-After", "60")
	headers.Set("X-RateLimit-Limit", "1000")
	headers.Set("X-RateLimit-Remaining", "999")
	headers.Set("X-RateLimit-Reset", "1625140800")
	headers.Set("RateLimit-Limit", "500")
	headers.Set("RateLimit-Remaining", "499")
	headers.Set("RateLimit-Reset", "1625140900")
	headers.Set("X-Custom-Header", "ignored")

	result := tester.extractRateLimitHeaders(headers)

	expectedHeaders := map[string]string{
		"Retry-After":           "60",
		"X-RateLimit-Limit":     "1000",
		"X-RateLimit-Remaining": "999",
		"X-RateLimit-Reset":     "1625140800",
		"RateLimit-Limit":       "500",
		"RateLimit-Remaining":   "499",
		"RateLimit-Reset":       "1625140900",
	}

	for name, expected := range expectedHeaders {
		if result[name] != expected {
			t.Errorf("Expected header %s=%s, got %s", name, expected, result[name])
		}
	}

	// Check that non-rate-limit header was NOT included
	if _, exists := result["Content-Type"]; exists {
		t.Error("Content-Type should not be included in rate limit headers")
	}

	if _, exists := result["X-Custom-Header"]; exists {
		t.Error("X-Custom-Header should not be included in rate limit headers")
	}
}

func TestTester_detectRateLimit(t *testing.T) {
	tester := NewTester()

	t.Run("429 with headers", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Retry-After", "30")
		headers.Set("X-RateLimit-Limit", "100")

		result := tester.detectRateLimit(429, headers)

		if result == nil {
			t.Fatal("Expected non-nil result")
		}
		if !result.RateLimitDetected {
			t.Error("Expected RateLimitDetected to be true")
		}
		if result.RetryAfter != "30" {
			t.Errorf("Expected RetryAfter to be '30', got '%s'", result.RetryAfter)
		}
	})

	t.Run("200 with no headers", func(t *testing.T) {
		headers := http.Header{}

		result := tester.detectRateLimit(200, headers)

		if result != nil {
			t.Error("Expected nil result for 200 with no rate limit headers")
		}
	})

	t.Run("200 with rate limit headers", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("X-RateLimit-Remaining", "50")

		result := tester.detectRateLimit(200, headers)

		if result == nil {
			t.Fatal("Expected non-nil result when headers present")
		}
		if result.RateLimitDetected {
			t.Error("Expected RateLimitDetected to be false for 200 status")
		}
	})
}

func TestTestResult_String_WithRateLimited(t *testing.T) {
	result := &TestResult{
		BaseURL: "https://api.example.com",
		Endpoints: []EndpointTestResult{
			{
				Endpoint:     EndpointInfo{Path: "/rate-limited", Method: "GET"},
				StatusCode:   429,
				ResponseTime: 10,
				Tested:       true,
				RateLimitInfo: &RateLimitInfo{
					RateLimitDetected: true,
					RetryAfter:        "30",
				},
			},
		},
		Summary: TestSummary{
			TotalEndpoints:   1,
			TestedEndpoints:  1,
			ClientErrorCount: 1,
			RateLimitedCount: 1,
		},
	}

	str := result.String()

	if !strings.Contains(str, "Rate Limited (429): 1") {
		t.Error("String should contain rate limited count")
	}
}
