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
	"github.com/djannot/wast/pkg/crawler"
	"github.com/djannot/wast/pkg/ratelimit"
)

// mockCSRFHTTPClient is a mock HTTP client for testing CSRF scanner.
type mockCSRFHTTPClient struct {
	responses map[string]*http.Response
	requests  []*http.Request
}

func (m *mockCSRFHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)

	// Return a response based on the URL or a default response
	if resp, ok := m.responses[req.URL.String()]; ok {
		return resp, nil
	}

	// Default response - no forms
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>No forms</body></html>")),
		Header:     make(http.Header),
	}, nil
}

func newMockCSRFHTTPClient() *mockCSRFHTTPClient {
	return &mockCSRFHTTPClient{
		responses: make(map[string]*http.Response),
		requests:  make([]*http.Request, 0),
	}
}

func TestNewCSRFScanner(t *testing.T) {
	tests := []struct {
		name string
		opts []CSRFOption
	}{
		{
			name: "default configuration",
			opts: nil,
		},
		{
			name: "with custom timeout",
			opts: []CSRFOption{WithCSRFTimeout(60 * time.Second)},
		},
		{
			name: "with custom user agent",
			opts: []CSRFOption{WithCSRFUserAgent("TestAgent/1.0")},
		},
		{
			name: "with auth config",
			opts: []CSRFOption{WithCSRFAuth(&auth.AuthConfig{})},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewCSRFScanner(tt.opts...)
			if scanner == nil {
				t.Fatal("NewCSRFScanner returned nil")
			}
			if scanner.client == nil {
				t.Error("Scanner client is nil")
			}
		})
	}
}

func TestCSRFScanner_Scan_InvalidURL(t *testing.T) {
	mock := newMockCSRFHTTPClient()
	scanner := NewCSRFScanner(WithCSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "://not a valid url")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected errors for invalid URL")
	}
}

func TestCSRFScanner_Scan_NoForms(t *testing.T) {
	mock := newMockCSRFHTTPClient()
	mock.responses["https://example.com"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body><p>No forms here</p></body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewCSRFScanner(WithCSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", result.Target)
	}

	if result.Summary.TotalFormsTested != 0 {
		t.Errorf("Expected 0 forms tested, got %d", result.Summary.TotalFormsTested)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected no findings, got %d", len(result.Findings))
	}
}

func TestCSRFScanner_Scan_FormWithoutCSRFToken(t *testing.T) {
	htmlContent := `
		<html>
		<body>
			<form action="/login" method="POST">
				<input type="text" name="username" />
				<input type="password" name="password" />
				<button type="submit">Login</button>
			</form>
		</body>
		</html>
	`

	mock := newMockCSRFHTTPClient()
	mock.responses["https://example.com"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(htmlContent)),
		Header:     make(http.Header),
	}

	scanner := NewCSRFScanner(WithCSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.TotalFormsTested != 1 {
		t.Errorf("Expected 1 form tested, got %d", result.Summary.TotalFormsTested)
	}

	if result.Summary.VulnerableForms != 1 {
		t.Errorf("Expected 1 vulnerable form, got %d", result.Summary.VulnerableForms)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(result.Findings))
	}

	finding := result.Findings[0]
	if finding.Type != "missing_token" {
		t.Errorf("Expected type 'missing_token', got %s", finding.Type)
	}
	if finding.Severity != SeverityHigh {
		t.Errorf("Expected high severity, got %s", finding.Severity)
	}
	if finding.FormAction != "/login" {
		t.Errorf("Expected form action '/login', got %s", finding.FormAction)
	}
	if finding.FormMethod != "POST" {
		t.Errorf("Expected form method 'POST', got %s", finding.FormMethod)
	}
}

func TestCSRFScanner_Scan_FormWithCSRFToken(t *testing.T) {
	tests := []struct {
		name      string
		tokenName string
	}{
		{"csrf_token", "csrf_token"},
		{"_csrf", "_csrf"},
		{"_token", "_token"},
		{"authenticity_token", "authenticity_token"},
		{"csrfmiddlewaretoken", "csrfmiddlewaretoken"},
		{"__RequestVerificationToken", "__RequestVerificationToken"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			htmlContent := fmt.Sprintf(`
				<html>
				<body>
					<form action="/login" method="POST">
						<input type="hidden" name="%s" value="abc123" />
						<input type="text" name="username" />
						<input type="password" name="password" />
						<button type="submit">Login</button>
					</form>
				</body>
				</html>
			`, tt.tokenName)

			mock := newMockCSRFHTTPClient()
			mock.responses["https://example.com"] = &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(htmlContent)),
				Header:     make(http.Header),
			}

			scanner := NewCSRFScanner(WithCSRFHTTPClient(mock))

			ctx := context.Background()
			result := scanner.Scan(ctx, "https://example.com")

			if result == nil {
				t.Fatal("Scan returned nil result")
			}

			if result.Summary.TotalFormsTested != 1 {
				t.Errorf("Expected 1 form tested, got %d", result.Summary.TotalFormsTested)
			}

			// Should have no vulnerable forms since token is present
			if result.Summary.VulnerableForms != 0 {
				t.Errorf("Expected 0 vulnerable forms, got %d", result.Summary.VulnerableForms)
			}

			// Check that we don't have a missing_token finding
			for _, finding := range result.Findings {
				if finding.Type == "missing_token" {
					t.Errorf("Unexpected missing_token finding when token '%s' is present", tt.tokenName)
				}
			}
		})
	}
}

func TestCSRFScanner_Scan_GetFormIgnored(t *testing.T) {
	htmlContent := `
		<html>
		<body>
			<form action="/search" method="GET">
				<input type="text" name="q" />
				<button type="submit">Search</button>
			</form>
		</body>
		</html>
	`

	mock := newMockCSRFHTTPClient()
	mock.responses["https://example.com"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(htmlContent)),
		Header:     make(http.Header),
	}

	scanner := NewCSRFScanner(WithCSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// GET forms should be counted but not flagged as vulnerable
	if result.Summary.VulnerableForms != 0 {
		t.Errorf("Expected 0 vulnerable forms for GET method, got %d", result.Summary.VulnerableForms)
	}

	// Should have no missing_token findings for GET forms
	for _, finding := range result.Findings {
		if finding.Type == "missing_token" {
			t.Error("GET forms should not generate missing_token findings")
		}
	}
}

func TestCSRFScanner_Scan_MultipleForms(t *testing.T) {
	htmlContent := `
		<html>
		<body>
			<form action="/search" method="GET">
				<input type="text" name="q" />
			</form>
			<form action="/login" method="POST">
				<input type="text" name="username" />
				<input type="password" name="password" />
			</form>
			<form action="/update" method="POST">
				<input type="hidden" name="_csrf" value="token123" />
				<input type="text" name="data" />
			</form>
			<form action="/delete" method="POST">
				<input type="text" name="id" />
			</form>
		</body>
		</html>
	`

	mock := newMockCSRFHTTPClient()
	mock.responses["https://example.com"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(htmlContent)),
		Header:     make(http.Header),
	}

	scanner := NewCSRFScanner(WithCSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should find 2 vulnerable forms (/login and /delete), but not /search (GET) or /update (has token)
	if result.Summary.VulnerableForms != 2 {
		t.Errorf("Expected 2 vulnerable forms, got %d", result.Summary.VulnerableForms)
	}

	// Check specific findings
	vulnerableActions := make(map[string]bool)
	for _, finding := range result.Findings {
		if finding.Type == "missing_token" {
			vulnerableActions[finding.FormAction] = true
		}
	}

	if !vulnerableActions["/login"] {
		t.Error("Expected /login form to be flagged as vulnerable")
	}
	if !vulnerableActions["/delete"] {
		t.Error("Expected /delete form to be flagged as vulnerable")
	}
	if vulnerableActions["/search"] {
		t.Error("GET form /search should not be flagged as vulnerable")
	}
	if vulnerableActions["/update"] {
		t.Error("Form /update with CSRF token should not be flagged as vulnerable")
	}
}

func TestCSRFScanner_Scan_CookiesWithoutSameSite(t *testing.T) {
	mock := newMockCSRFHTTPClient()

	// Create a response with cookies that lack SameSite attribute
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Test</body></html>")),
		Header:     make(http.Header),
	}
	resp.Header.Add("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly; Secure")
	resp.Header.Add("Set-Cookie", "tracking=xyz789; Path=/")

	mock.responses["https://example.com"] = resp

	scanner := NewCSRFScanner(WithCSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect cookies without SameSite
	if result.Summary.CookiesChecked != 2 {
		t.Errorf("Expected 2 cookies checked, got %d", result.Summary.CookiesChecked)
	}

	if result.Summary.InsecureCookies != 2 {
		t.Errorf("Expected 2 insecure cookies, got %d", result.Summary.InsecureCookies)
	}

	// Check for SameSite findings
	sameSiteFindings := 0
	for _, finding := range result.Findings {
		if finding.Type == "missing_samesite" {
			sameSiteFindings++
		}
	}

	if sameSiteFindings != 2 {
		t.Errorf("Expected 2 missing_samesite findings, got %d", sameSiteFindings)
	}
}

func TestCSRFScanner_Scan_RateLimiting(t *testing.T) {
	mock := newMockCSRFHTTPClient()
	mock.responses["https://example.com"] = &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}

	scanner := NewCSRFScanner(WithCSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected error for rate limiting")
	}
}

func TestCSRFScanner_Scan_WithAuth(t *testing.T) {
	mock := newMockCSRFHTTPClient()
	mock.responses["https://example.com"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Test</body></html>")),
		Header:     make(http.Header),
	}

	authConfig := &auth.AuthConfig{
		BearerToken: "test-token",
	}

	scanner := NewCSRFScanner(
		WithCSRFHTTPClient(mock),
		WithCSRFAuth(authConfig),
	)

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Check that the request was made with auth
	if len(mock.requests) == 0 {
		t.Fatal("No requests were made")
	}

	authHeader := mock.requests[0].Header.Get("Authorization")
	if authHeader == "" {
		t.Error("Expected Authorization header to be set")
	}
}

func TestCSRFScanner_Scan_WithRateLimiter(t *testing.T) {
	mock := newMockCSRFHTTPClient()
	mock.responses["https://example.com"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Test</body></html>")),
		Header:     make(http.Header),
	}

	config := ratelimit.Config{
		RequestsPerSecond: 1,
		DelayMs:           100,
	}

	scanner := NewCSRFScanner(
		WithCSRFHTTPClient(mock),
		WithCSRFRateLimitConfig(config),
	)

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Just verify the scan completed successfully with rate limiting
	if len(result.Errors) > 0 {
		t.Errorf("Unexpected errors: %v", result.Errors)
	}
}

func TestCSRFScanResult_String(t *testing.T) {
	result := &CSRFScanResult{
		Target: "https://example.com",
		Findings: []CSRFFinding{
			{
				FormAction:  "/login",
				FormMethod:  "POST",
				Type:        "missing_token",
				Severity:    SeverityHigh,
				Description: "Form lacks CSRF token",
				Remediation: "Add CSRF token",
			},
		},
		Summary: CSRFSummary{
			TotalFormsTested: 1,
			VulnerableForms:  1,
		},
	}

	str := result.String()
	if str == "" {
		t.Error("String() returned empty string")
	}

	if !strings.Contains(str, "https://example.com") {
		t.Error("String() should contain target URL")
	}

	if !strings.Contains(str, "missing_token") {
		t.Error("String() should contain finding type")
	}
}

func TestCSRFScanResult_HasResults(t *testing.T) {
	tests := []struct {
		name     string
		result   *CSRFScanResult
		expected bool
	}{
		{
			name: "with findings",
			result: &CSRFScanResult{
				Findings: []CSRFFinding{{Type: "missing_token"}},
			},
			expected: true,
		},
		{
			name: "with forms tested",
			result: &CSRFScanResult{
				Summary: CSRFSummary{TotalFormsTested: 1},
			},
			expected: true,
		},
		{
			name:     "no results",
			result:   &CSRFScanResult{},
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

func TestCSRFScanner_hasCSRFToken(t *testing.T) {
	scanner := NewCSRFScanner()

	tests := []struct {
		name     string
		fields   []FormFieldInfo
		expected bool
	}{
		{
			name: "has csrf_token",
			fields: []FormFieldInfo{
				{Name: "csrf_token", Type: "hidden"},
			},
			expected: true,
		},
		{
			name: "has _csrf",
			fields: []FormFieldInfo{
				{Name: "_csrf", Type: "hidden"},
			},
			expected: true,
		},
		{
			name: "has authenticity_token",
			fields: []FormFieldInfo{
				{Name: "authenticity_token", Type: "hidden"},
			},
			expected: true,
		},
		{
			name: "case insensitive __RequestVerificationToken",
			fields: []FormFieldInfo{
				{Name: "__RequestVerificationToken", Type: "hidden"},
			},
			expected: true,
		},
		{
			name: "no CSRF token",
			fields: []FormFieldInfo{
				{Name: "username", Type: "text"},
				{Name: "password", Type: "password"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to crawler.FormFieldInfo for testing
			crawlerFields := make([]crawler.FormFieldInfo, len(tt.fields))
			for i, f := range tt.fields {
				crawlerFields[i] = crawler.FormFieldInfo{
					Name:  f.Name,
					Type:  f.Type,
					Value: f.Value,
				}
			}

			if got := scanner.hasCSRFToken(crawlerFields); got != tt.expected {
				t.Errorf("hasCSRFToken() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// FormFieldInfo is a test helper struct
type FormFieldInfo struct {
	Name  string
	Type  string
	Value string
}
