package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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

// AddResponse adds a mock response for a URL with headers and cookies.
func (m *MockHTTPClient) AddResponse(url string, statusCode int, body string, headers http.Header, cookies []*http.Cookie) {
	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     headers,
	}
	if headers == nil {
		resp.Header = make(http.Header)
	}
	// Add cookies to Set-Cookie header for proper parsing
	for _, c := range cookies {
		resp.Header.Add("Set-Cookie", c.String())
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

func TestHTTPHeadersScanner_Scan_AllHeadersPresent(t *testing.T) {
	mockClient := NewMockHTTPClient()

	headers := http.Header{
		"Strict-Transport-Security": []string{"max-age=31536000; includeSubDomains"},
		"X-Content-Type-Options":    []string{"nosniff"},
		"X-Frame-Options":           []string{"DENY"},
		"Content-Security-Policy":   []string{"default-src 'self'"},
		"X-Xss-Protection":          []string{"1; mode=block"},
		"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
		"Permissions-Policy":        []string{"geolocation=()"},
	}

	mockClient.AddResponse("https://secure.example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://secure.example.com")

	// All headers should be present
	for _, h := range result.Headers {
		if !h.Present {
			t.Errorf("Expected header %s to be present", h.Name)
		}
		if h.Severity != SeverityInfo {
			t.Errorf("Expected header %s to have info severity when present, got %s", h.Name, h.Severity)
		}
	}

	// Summary should reflect all headers present
	if result.Summary.MissingHeaders != 0 {
		t.Errorf("Expected 0 missing headers, got %d", result.Summary.MissingHeaders)
	}

	if result.Summary.TotalHeaders != 7 {
		t.Errorf("Expected 7 total headers, got %d", result.Summary.TotalHeaders)
	}

	// Should have no errors
	if len(result.Errors) != 0 {
		t.Errorf("Expected no errors, got %v", result.Errors)
	}
}

func TestHTTPHeadersScanner_Scan_NoSecurityHeaders(t *testing.T) {
	mockClient := NewMockHTTPClient()

	headers := http.Header{
		"Content-Type": []string{"text/html"},
	}

	mockClient.AddResponse("https://insecure.example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://insecure.example.com")

	// All security headers should be missing
	for _, h := range result.Headers {
		if h.Present {
			t.Errorf("Expected header %s to be missing", h.Name)
		}
	}

	// Summary should reflect all headers missing
	if result.Summary.MissingHeaders != 7 {
		t.Errorf("Expected 7 missing headers, got %d", result.Summary.MissingHeaders)
	}

	// Should have high severity findings for HSTS and CSP
	if result.Summary.HighSeverityCount < 2 {
		t.Errorf("Expected at least 2 high severity findings, got %d", result.Summary.HighSeverityCount)
	}
}

func TestHTTPHeadersScanner_Scan_SecureCookies(t *testing.T) {
	mockClient := NewMockHTTPClient()

	cookies := []*http.Cookie{
		{
			Name:     "session",
			Value:    "abc123",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", nil, cookies)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if len(result.Cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(result.Cookies))
	}

	cookie := result.Cookies[0]
	if cookie.Name != "session" {
		t.Errorf("Expected cookie name 'session', got %s", cookie.Name)
	}

	if !cookie.HttpOnly {
		t.Error("Expected cookie to have HttpOnly flag")
	}

	if !cookie.Secure {
		t.Error("Expected cookie to have Secure flag")
	}

	if cookie.SameSite != "Strict" {
		t.Errorf("Expected SameSite=Strict, got %s", cookie.SameSite)
	}

	if len(cookie.Issues) != 0 {
		t.Errorf("Expected no issues for secure cookie, got %v", cookie.Issues)
	}

	if cookie.Severity != SeverityInfo {
		t.Errorf("Expected info severity for secure cookie, got %s", cookie.Severity)
	}
}

func TestHTTPHeadersScanner_Scan_InsecureCookies(t *testing.T) {
	mockClient := NewMockHTTPClient()

	cookies := []*http.Cookie{
		{
			Name:     "insecure_session",
			Value:    "abc123",
			HttpOnly: false,
			Secure:   false,
			SameSite: http.SameSiteDefaultMode,
		},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", nil, cookies)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if len(result.Cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(result.Cookies))
	}

	cookie := result.Cookies[0]

	if cookie.HttpOnly {
		t.Error("Expected cookie to NOT have HttpOnly flag")
	}

	if cookie.Secure {
		t.Error("Expected cookie to NOT have Secure flag")
	}

	// Should have multiple issues
	if len(cookie.Issues) < 2 {
		t.Errorf("Expected at least 2 issues for insecure cookie, got %d", len(cookie.Issues))
	}

	// Should have high severity for multiple issues
	if cookie.Severity != SeverityHigh {
		t.Errorf("Expected high severity for insecure cookie, got %s", cookie.Severity)
	}

	// Summary should reflect insecure cookie
	if result.Summary.InsecureCookies != 1 {
		t.Errorf("Expected 1 insecure cookie, got %d", result.Summary.InsecureCookies)
	}
}

func TestHTTPHeadersScanner_Scan_MultipleCookies(t *testing.T) {
	mockClient := NewMockHTTPClient()

	cookies := []*http.Cookie{
		{
			Name:     "secure_cookie",
			Value:    "value1",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		},
		{
			Name:     "insecure_cookie",
			Value:    "value2",
			HttpOnly: false,
			Secure:   false,
		},
		{
			Name:     "partial_secure",
			Value:    "value3",
			HttpOnly: true,
			Secure:   false,
		},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", nil, cookies)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if len(result.Cookies) != 3 {
		t.Errorf("Expected 3 cookies, got %d", len(result.Cookies))
	}

	if result.Summary.TotalCookies != 3 {
		t.Errorf("Expected 3 total cookies in summary, got %d", result.Summary.TotalCookies)
	}

	if result.Summary.InsecureCookies != 2 {
		t.Errorf("Expected 2 insecure cookies, got %d", result.Summary.InsecureCookies)
	}
}

func TestHTTPHeadersScanner_Scan_RequestError(t *testing.T) {
	mockClient := NewMockHTTPClient()
	mockClient.AddError("https://error.example.com", &testError{message: "connection refused"})

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://error.example.com")

	if len(result.Errors) == 0 {
		t.Error("Expected error in result")
	}

	if !strings.Contains(result.Errors[0], "connection refused") {
		t.Errorf("Expected connection error, got %s", result.Errors[0])
	}
}

type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

func TestHTTPHeadersScanner_Scan_InvalidURL(t *testing.T) {
	scanner := NewHTTPHeadersScanner()
	ctx := context.Background()
	result := scanner.Scan(ctx, "://invalid-url")

	if len(result.Errors) == 0 {
		t.Error("Expected error for invalid URL")
	}
}

func TestHTTPHeadersScanner_WithOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		s := NewHTTPHeadersScanner()
		if s.userAgent == "" {
			t.Error("Expected default user agent to be set")
		}
		if s.timeout != 30*time.Second {
			t.Errorf("Expected default timeout of 30s, got %v", s.timeout)
		}
		if s.client == nil {
			t.Error("Expected default client to be set")
		}
	})

	t.Run("custom user agent", func(t *testing.T) {
		s := NewHTTPHeadersScanner(WithUserAgent("CustomScanner/1.0"))
		if s.userAgent != "CustomScanner/1.0" {
			t.Errorf("Expected custom user agent, got %s", s.userAgent)
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		s := NewHTTPHeadersScanner(WithTimeout(60 * time.Second))
		if s.timeout != 60*time.Second {
			t.Errorf("Expected timeout of 60s, got %v", s.timeout)
		}
	})

	t.Run("custom http client", func(t *testing.T) {
		mock := NewMockHTTPClient()
		s := NewHTTPHeadersScanner(WithHTTPClient(mock))
		if s.client != mock {
			t.Error("Expected custom HTTP client to be set")
		}
	})
}

func TestHeaderScanResult_String(t *testing.T) {
	result := &HeaderScanResult{
		Target: "https://example.com",
		Headers: []HeaderFinding{
			{
				Name:        "Strict-Transport-Security",
				Present:     true,
				Value:       "max-age=31536000",
				Severity:    SeverityInfo,
				Description: "HSTS is properly configured",
			},
			{
				Name:        "Content-Security-Policy",
				Present:     false,
				Severity:    SeverityHigh,
				Description: "CSP helps prevent XSS attacks by controlling resource loading",
				Remediation: "Add a Content-Security-Policy header",
			},
		},
		Cookies: []CookieFinding{
			{
				Name:     "session",
				HttpOnly: true,
				Secure:   true,
				SameSite: "Strict",
				Severity: SeverityInfo,
				Issues:   []string{},
			},
		},
		Summary: ScanSummary{
			TotalHeaders:        2,
			MissingHeaders:      1,
			TotalCookies:        1,
			InsecureCookies:     0,
			HighSeverityCount:   1,
			MediumSeverityCount: 0,
			LowSeverityCount:    0,
			InfoCount:           2,
		},
	}

	str := result.String()

	// Check that all sections are present
	checks := []string{
		"example.com",
		"Summary",
		"Security Headers",
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"Cookie Security",
		"session",
		"MISSING",
		"PRESENT",
	}

	for _, check := range checks {
		if !strings.Contains(str, check) {
			t.Errorf("String should contain %q", check)
		}
	}
}

func TestHeaderScanResult_HasResults(t *testing.T) {
	tests := []struct {
		name   string
		result *HeaderScanResult
		want   bool
	}{
		{
			name:   "no results",
			result: &HeaderScanResult{Target: "https://example.com"},
			want:   false,
		},
		{
			name: "with headers",
			result: &HeaderScanResult{
				Target:  "https://example.com",
				Headers: []HeaderFinding{{Name: "X-Frame-Options"}},
			},
			want: true,
		},
		{
			name: "with cookies",
			result: &HeaderScanResult{
				Target:  "https://example.com",
				Cookies: []CookieFinding{{Name: "session"}},
			},
			want: true,
		},
		{
			name: "only errors",
			result: &HeaderScanResult{
				Target: "https://example.com",
				Errors: []string{"error"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasResults(); got != tt.want {
				t.Errorf("HasResults() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSameSiteToString(t *testing.T) {
	tests := []struct {
		input    http.SameSite
		expected string
	}{
		{http.SameSiteLaxMode, "Lax"},
		{http.SameSiteStrictMode, "Strict"},
		{http.SameSiteNoneMode, "None"},
		{http.SameSiteDefaultMode, "Not Set"},
		{0, "Not Set"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := sameSiteToString(tt.input); got != tt.expected {
				t.Errorf("sameSiteToString(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestHTTPHeadersScanner_Scan_PartialSecurityHeaders(t *testing.T) {
	mockClient := NewMockHTTPClient()

	// Only some security headers present
	headers := http.Header{
		"Strict-Transport-Security": []string{"max-age=31536000"},
		"X-Content-Type-Options":    []string{"nosniff"},
		"X-Frame-Options":           []string{"SAMEORIGIN"},
	}

	mockClient.AddResponse("https://partial.example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://partial.example.com")

	// Check that 3 headers are present and 4 are missing
	presentCount := 0
	missingCount := 0
	for _, h := range result.Headers {
		if h.Present {
			presentCount++
		} else {
			missingCount++
		}
	}

	if presentCount != 3 {
		t.Errorf("Expected 3 present headers, got %d", presentCount)
	}

	if missingCount != 4 {
		t.Errorf("Expected 4 missing headers, got %d", missingCount)
	}

	if result.Summary.MissingHeaders != 4 {
		t.Errorf("Expected 4 missing headers in summary, got %d", result.Summary.MissingHeaders)
	}
}

func TestHTTPHeadersScanner_Scan_ContextCancellation(t *testing.T) {
	// Use a mock client that respects context cancellation
	mockClient := &contextAwareMockClient{}

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))

	// Create an already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := scanner.Scan(ctx, "https://example.com")

	// Should have an error about cancellation
	if len(result.Errors) == 0 {
		t.Error("Expected error for cancelled context")
	}
}

// contextAwareMockClient is a mock that respects context cancellation.
type contextAwareMockClient struct{}

func (c *contextAwareMockClient) Do(req *http.Request) (*http.Response, error) {
	// Check if context is cancelled
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("<html></html>")),
		Header:     make(http.Header),
	}, nil
}

func TestHTTPHeadersScanner_Scan_CookieSameSiteVariants(t *testing.T) {
	testCases := []struct {
		name        string
		sameSite    http.SameSite
		expectedStr string
		expectIssue bool
	}{
		{"Lax", http.SameSiteLaxMode, "Lax", false},
		{"Strict", http.SameSiteStrictMode, "Strict", false},
		{"None", http.SameSiteNoneMode, "None", false},
		{"Default", http.SameSiteDefaultMode, "Not Set", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := NewMockHTTPClient()

			cookies := []*http.Cookie{
				{
					Name:     "test_cookie",
					Value:    "value",
					HttpOnly: true,
					Secure:   true,
					SameSite: tc.sameSite,
				},
			}

			mockClient.AddResponse("https://example.com", 200, "<html></html>", nil, cookies)

			scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
			ctx := context.Background()
			result := scanner.Scan(ctx, "https://example.com")

			if len(result.Cookies) != 1 {
				t.Fatalf("Expected 1 cookie, got %d", len(result.Cookies))
			}

			cookie := result.Cookies[0]
			if cookie.SameSite != tc.expectedStr {
				t.Errorf("Expected SameSite=%s, got %s", tc.expectedStr, cookie.SameSite)
			}

			hasIssue := len(cookie.Issues) > 0
			if hasIssue != tc.expectIssue {
				t.Errorf("Expected issue=%v, got issue=%v (issues: %v)", tc.expectIssue, hasIssue, cookie.Issues)
			}
		})
	}
}

// CORSMockHTTPClient is a mock that supports CORS testing with origin reflection.
type CORSMockHTTPClient struct {
	Responses     map[string]*http.Response
	Errors        map[string]error
	Requests      []*http.Request
	ReflectOrigin bool // If true, the mock will reflect the Origin header
}

// NewCORSMockHTTPClient creates a new CORSMockHTTPClient.
func NewCORSMockHTTPClient() *CORSMockHTTPClient {
	return &CORSMockHTTPClient{
		Responses:     make(map[string]*http.Response),
		Errors:        make(map[string]error),
		Requests:      make([]*http.Request, 0),
		ReflectOrigin: false,
	}
}

// AddResponse adds a mock response for a URL with headers and cookies.
func (m *CORSMockHTTPClient) AddResponse(url string, statusCode int, body string, headers http.Header, cookies []*http.Cookie) {
	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     headers,
	}
	if headers == nil {
		resp.Header = make(http.Header)
	}
	// Add cookies to Set-Cookie header for proper parsing
	for _, c := range cookies {
		resp.Header.Add("Set-Cookie", c.String())
	}
	m.Responses[url] = resp
}

// Do performs the mock HTTP request with optional origin reflection.
func (m *CORSMockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.Requests = append(m.Requests, req)
	url := req.URL.String()

	if err, ok := m.Errors[url]; ok {
		return nil, err
	}

	if resp, ok := m.Responses[url]; ok {
		// Create a fresh body for each request (since bodies can only be read once)
		body := "<html></html>"
		newResp := &http.Response{
			StatusCode: resp.StatusCode,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}
		// Copy headers
		for k, v := range resp.Header {
			newResp.Header[k] = v
		}
		// Reflect origin if configured
		if m.ReflectOrigin {
			origin := req.Header.Get("Origin")
			if origin != "" {
				newResp.Header.Set("Access-Control-Allow-Origin", origin)
			}
		}
		return newResp, nil
	}

	// Default: 404
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("Not Found")),
		Header:     make(http.Header),
	}, nil
}

func TestHTTPHeadersScanner_Scan_CORSWildcardWithCredentials(t *testing.T) {
	mockClient := NewCORSMockHTTPClient()

	headers := http.Header{
		"Access-Control-Allow-Origin":      []string{"*"},
		"Access-Control-Allow-Credentials": []string{"true"},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	// Should have CORS findings
	if len(result.CORS) == 0 {
		t.Fatal("Expected CORS findings")
	}

	// Check for high severity finding for wildcard with credentials
	foundHighSeverity := false
	for _, c := range result.CORS {
		if c.Header == "Access-Control-Allow-Origin" && c.Value == "*" && c.Severity == SeverityHigh {
			foundHighSeverity = true
			if len(c.Issues) == 0 {
				t.Error("Expected issues for wildcard with credentials")
			}
		}
	}

	if !foundHighSeverity {
		t.Error("Expected high severity finding for wildcard with credentials")
	}

	// Check summary
	if result.Summary.HighSeverityCount == 0 {
		t.Error("Expected high severity count > 0")
	}
}

func TestHTTPHeadersScanner_Scan_CORSWildcardWithoutCredentials(t *testing.T) {
	mockClient := NewCORSMockHTTPClient()

	headers := http.Header{
		"Access-Control-Allow-Origin": []string{"*"},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	// Should have CORS findings
	if len(result.CORS) == 0 {
		t.Fatal("Expected CORS findings")
	}

	// Check for medium severity finding for wildcard without credentials
	foundMediumSeverity := false
	for _, c := range result.CORS {
		if c.Header == "Access-Control-Allow-Origin" && c.Value == "*" && c.Severity == SeverityMedium {
			foundMediumSeverity = true
			if len(c.Issues) == 0 {
				t.Error("Expected issues for wildcard origin")
			}
		}
	}

	if !foundMediumSeverity {
		t.Error("Expected medium severity finding for wildcard origin")
	}
}

func TestHTTPHeadersScanner_Scan_CORSOriginReflection(t *testing.T) {
	mockClient := NewCORSMockHTTPClient()
	mockClient.ReflectOrigin = true

	headers := http.Header{
		"Access-Control-Allow-Origin": []string{"https://trusted.example.com"},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	// Should have CORS findings including origin reflection
	foundOriginReflection := false
	for _, c := range result.CORS {
		if c.OriginReflection {
			foundOriginReflection = true
			if c.Severity != SeverityMedium && c.Severity != SeverityHigh {
				t.Errorf("Expected medium or high severity for origin reflection, got %s", c.Severity)
			}
		}
	}

	if !foundOriginReflection {
		t.Error("Expected origin reflection finding")
	}
}

func TestHTTPHeadersScanner_Scan_CORSOriginReflectionWithCredentials(t *testing.T) {
	mockClient := NewCORSMockHTTPClient()
	mockClient.ReflectOrigin = true

	headers := http.Header{
		"Access-Control-Allow-Origin":      []string{"https://trusted.example.com"},
		"Access-Control-Allow-Credentials": []string{"true"},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	// Should have CORS findings including origin reflection with high severity
	foundHighSeverityReflection := false
	for _, c := range result.CORS {
		if c.OriginReflection && c.Severity == SeverityHigh {
			foundHighSeverityReflection = true
		}
	}

	if !foundHighSeverityReflection {
		t.Error("Expected high severity finding for origin reflection with credentials")
	}
}

func TestHTTPHeadersScanner_Scan_CORSAllowMethods(t *testing.T) {
	mockClient := NewCORSMockHTTPClient()

	headers := http.Header{
		"Access-Control-Allow-Origin":  []string{"https://trusted.example.com"},
		"Access-Control-Allow-Methods": []string{"GET, POST, PUT, DELETE"},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	// Should have finding for methods
	foundMethodsFinding := false
	for _, c := range result.CORS {
		if c.Header == "Access-Control-Allow-Methods" {
			foundMethodsFinding = true
			if c.Severity != SeverityLow {
				t.Errorf("Expected low severity for dangerous methods, got %s", c.Severity)
			}
			if len(c.Issues) == 0 {
				t.Error("Expected issues for dangerous methods (PUT, DELETE)")
			}
		}
	}

	if !foundMethodsFinding {
		t.Error("Expected methods finding")
	}
}

func TestHTTPHeadersScanner_Scan_CORSAllowHeaders(t *testing.T) {
	mockClient := NewCORSMockHTTPClient()

	headers := http.Header{
		"Access-Control-Allow-Origin":  []string{"https://trusted.example.com"},
		"Access-Control-Allow-Headers": []string{"*"},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	// Should have finding for wildcard headers
	foundHeadersFinding := false
	for _, c := range result.CORS {
		if c.Header == "Access-Control-Allow-Headers" && c.Value == "*" {
			foundHeadersFinding = true
			if c.Severity != SeverityLow {
				t.Errorf("Expected low severity for wildcard headers, got %s", c.Severity)
			}
			if len(c.Issues) == 0 {
				t.Error("Expected issues for wildcard headers")
			}
		}
	}

	if !foundHeadersFinding {
		t.Error("Expected headers finding for wildcard")
	}
}

func TestHTTPHeadersScanner_Scan_CORSExposeHeaders(t *testing.T) {
	mockClient := NewCORSMockHTTPClient()

	headers := http.Header{
		"Access-Control-Allow-Origin":   []string{"https://trusted.example.com"},
		"Access-Control-Expose-Headers": []string{"*"},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	// Should have finding for wildcard expose headers
	foundExposeFinding := false
	for _, c := range result.CORS {
		if c.Header == "Access-Control-Expose-Headers" && c.Value == "*" {
			foundExposeFinding = true
			if c.Severity != SeverityLow {
				t.Errorf("Expected low severity for wildcard expose headers, got %s", c.Severity)
			}
			if len(c.Issues) == 0 {
				t.Error("Expected issues for wildcard expose headers")
			}
		}
	}

	if !foundExposeFinding {
		t.Error("Expected expose headers finding for wildcard")
	}
}

func TestHTTPHeadersScanner_Scan_CORSSecureConfiguration(t *testing.T) {
	mockClient := NewCORSMockHTTPClient()

	headers := http.Header{
		"Access-Control-Allow-Origin":  []string{"https://trusted.example.com"},
		"Access-Control-Allow-Methods": []string{"GET, POST"},
		"Access-Control-Allow-Headers": []string{"Content-Type, Authorization"},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	// All CORS findings should have info severity (secure configuration)
	for _, c := range result.CORS {
		if c.Severity != SeverityInfo {
			t.Errorf("Expected info severity for secure CORS config, got %s for %s", c.Severity, c.Header)
		}
	}

	// Summary should reflect no CORS issues
	if result.Summary.CORSIssues != 0 {
		t.Errorf("Expected 0 CORS issues, got %d", result.Summary.CORSIssues)
	}
}

func TestHTTPHeadersScanner_Scan_NoCORSHeaders(t *testing.T) {
	mockClient := NewCORSMockHTTPClient()

	headers := http.Header{
		"Content-Type": []string{"text/html"},
	}

	mockClient.AddResponse("https://example.com", 200, "<html></html>", headers, nil)

	scanner := NewHTTPHeadersScanner(WithHTTPClient(mockClient))
	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	// Should have no CORS findings when no CORS headers are present
	if len(result.CORS) != 0 {
		t.Errorf("Expected no CORS findings when no CORS headers present, got %d", len(result.CORS))
	}
}

func TestHeaderScanResult_HasResults_WithCORS(t *testing.T) {
	result := &HeaderScanResult{
		Target: "https://example.com",
		CORS:   []CORSFinding{{Header: "Access-Control-Allow-Origin"}},
	}

	if !result.HasResults() {
		t.Error("Expected HasResults to return true when CORS findings present")
	}
}

func TestHeaderScanResult_String_WithCORS(t *testing.T) {
	result := &HeaderScanResult{
		Target: "https://example.com",
		CORS: []CORSFinding{
			{
				Header:      "Access-Control-Allow-Origin",
				Value:       "*",
				Present:     true,
				Severity:    SeverityMedium,
				Description: "Specifies which origins can access the resource",
				Issues:      []string{"Wildcard (*) allows any origin to access resources"},
				Remediation: "Consider restricting to specific trusted origins",
			},
		},
		Summary: ScanSummary{
			CORSIssues:          1,
			MediumSeverityCount: 1,
		},
	}

	str := result.String()

	// Check that CORS section is present
	checks := []string{
		"CORS Policy",
		"Access-Control-Allow-Origin",
		"MEDIUM",
		"Wildcard",
		"Remediation",
		"CORS Issues: 1",
	}

	for _, check := range checks {
		if !strings.Contains(str, check) {
			t.Errorf("String should contain %q", check)
		}
	}
}
