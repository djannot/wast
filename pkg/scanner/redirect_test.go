package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
)

// mockRedirectHTTPClient is a mock HTTP client for testing redirect scanner.
type mockRedirectHTTPClient struct {
	responses map[string]*http.Response
	requests  []*http.Request
}

func (m *mockRedirectHTTPClient) Do(req *http.Request) (*http.Response, error) {
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

func newMockRedirectHTTPClient() *mockRedirectHTTPClient {
	return &mockRedirectHTTPClient{
		responses: make(map[string]*http.Response),
		requests:  make([]*http.Request, 0),
	}
}

func TestNewRedirectScanner(t *testing.T) {
	tests := []struct {
		name string
		opts []RedirectOption
	}{
		{
			name: "default configuration",
			opts: nil,
		},
		{
			name: "with custom timeout",
			opts: []RedirectOption{WithRedirectTimeout(60 * time.Second)},
		},
		{
			name: "with custom user agent",
			opts: []RedirectOption{WithRedirectUserAgent("TestAgent/1.0")},
		},
		{
			name: "with auth",
			opts: []RedirectOption{WithRedirectAuth(&auth.AuthConfig{
				BearerToken: "test-token",
			})},
		},
		{
			name: "with rate limiter",
			opts: []RedirectOption{WithRedirectRateLimiter(ratelimit.NewLimiter(10))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewRedirectScanner(tt.opts...)
			if scanner == nil {
				t.Fatal("NewRedirectScanner returned nil")
			}
			if scanner.client == nil {
				t.Error("Scanner client is nil")
			}
		})
	}
}

func TestRedirectScanner_Scan_NoParameters(t *testing.T) {
	mock := newMockRedirectHTTPClient()
	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock))

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

func TestRedirectScanner_Scan_ProtocolRelativeRedirect(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Configure mock to return redirect to protocol-relative URL
	headers := make(http.Header)
	headers.Set("Location", "//evil.com")
	mock.responses["https://example.com/redirect?url=%2F%2Fevil.com"] = &http.Response{
		StatusCode: http.StatusFound,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     headers,
	}

	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock), WithRedirectCanaryDomain("evil.com"))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/redirect?url=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find Open Redirect vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	// Find the protocol-relative redirect finding
	var prFinding *RedirectFinding
	for i := range result.Findings {
		if result.Findings[i].Type == "protocol-relative" {
			prFinding = &result.Findings[i]
			break
		}
	}

	if prFinding == nil {
		t.Fatal("Expected to find protocol-relative redirect vulnerability")
	}

	if prFinding.Parameter != "url" {
		t.Errorf("Expected parameter 'url', got %s", prFinding.Parameter)
	}

	if prFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, prFinding.Severity)
	}

	if prFinding.Confidence != "high" {
		t.Errorf("Expected high confidence, got %s", prFinding.Confidence)
	}

	if !strings.Contains(prFinding.Evidence, "302") {
		t.Errorf("Expected evidence to mention redirect status code, got %s", prFinding.Evidence)
	}
}

func TestRedirectScanner_Scan_AtSymbolBypass(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Configure mock to return redirect with @ symbol bypass
	headers := make(http.Header)
	headers.Set("Location", "https://expected.com@evil.com")
	mock.responses["https://example.com/goto?next=https%3A%2F%2Fexpected.com%40evil.com"] = &http.Response{
		StatusCode: http.StatusFound,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     headers,
	}

	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock), WithRedirectCanaryDomain("evil.com"))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/goto?next=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find Open Redirect vulnerability")
	}

	// Find the @ symbol bypass finding
	var atFinding *RedirectFinding
	for i := range result.Findings {
		if result.Findings[i].Type == "at-symbol" {
			atFinding = &result.Findings[i]
			break
		}
	}

	if atFinding == nil {
		t.Fatal("Expected to find @ symbol bypass redirect vulnerability")
	}

	if atFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, atFinding.Severity)
	}
}

func TestRedirectScanner_Scan_EncodedPayload(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Configure mock to return redirect to decoded URL
	headers := make(http.Header)
	headers.Set("Location", "//evil.com")
	mock.responses["https://example.com/return?returnUrl=%252F%252Fevil.com"] = &http.Response{
		StatusCode: http.StatusMovedPermanently,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     headers,
	}

	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock), WithRedirectCanaryDomain("evil.com"))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/return?returnUrl=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find Open Redirect vulnerability")
	}

	// Find the encoded payload finding
	var encodedFinding *RedirectFinding
	for i := range result.Findings {
		if result.Findings[i].Type == "encoded" {
			encodedFinding = &result.Findings[i]
			break
		}
	}

	if encodedFinding == nil {
		t.Fatal("Expected to find encoded payload redirect vulnerability")
	}

	if encodedFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, encodedFinding.Severity)
	}

	if encodedFinding.Confidence != "high" {
		t.Errorf("Expected high confidence, got %s", encodedFinding.Confidence)
	}
}

func TestRedirectScanner_Scan_SubdomainConfusion(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Configure mock to return redirect to subdomain
	headers := make(http.Header)
	headers.Set("Location", "https://example.com.evil.com")
	mock.responses["https://example.com/continue?continue=https%3A%2F%2Fexample.com.evil.com"] = &http.Response{
		StatusCode: http.StatusTemporaryRedirect,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     headers,
	}

	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock), WithRedirectCanaryDomain("evil.com"))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/continue?continue=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find Open Redirect vulnerability")
	}

	// Find the subdomain confusion finding
	var subdomainFinding *RedirectFinding
	for i := range result.Findings {
		if result.Findings[i].Type == "subdomain" {
			subdomainFinding = &result.Findings[i]
			break
		}
	}

	if subdomainFinding == nil {
		t.Fatal("Expected to find subdomain confusion redirect vulnerability")
	}

	if subdomainFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, subdomainFinding.Severity)
	}
}

func TestRedirectScanner_Scan_JavaScriptProtocol(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Configure mock to return redirect to javascript: protocol
	headers := make(http.Header)
	headers.Set("Location", "javascript:alert(document.domain)")
	mock.responses["https://example.com/redir?target=javascript%3Aalert%28document.domain%29"] = &http.Response{
		StatusCode: http.StatusFound,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     headers,
	}

	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/redir?target=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find Open Redirect vulnerability")
	}

	// Find the javascript protocol finding
	var jsFinding *RedirectFinding
	for i := range result.Findings {
		if result.Findings[i].Type == "javascript" {
			jsFinding = &result.Findings[i]
			break
		}
	}

	if jsFinding == nil {
		t.Fatal("Expected to find javascript: protocol redirect vulnerability")
	}

	if jsFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, jsFinding.Severity)
	}
}

func TestRedirectScanner_Scan_ClientSideMetaRefresh(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Configure mock to return meta refresh redirect
	htmlWithMetaRefresh := `<html><head><meta http-equiv="refresh" content="0; url=//evil.com"></head><body>Redirecting...</body></html>`
	mock.responses["https://example.com/page?dest=%2F%2Fevil.com"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(htmlWithMetaRefresh)),
		Header:     make(http.Header),
	}

	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock), WithRedirectCanaryDomain("evil.com"))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/page?dest=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find Open Redirect vulnerability via meta refresh")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	// Check that we detected the meta refresh redirect
	foundMetaRefresh := false
	for _, finding := range result.Findings {
		if strings.Contains(finding.Evidence, "meta refresh") {
			foundMetaRefresh = true
			break
		}
	}

	if !foundMetaRefresh {
		t.Error("Expected to find meta refresh redirect in evidence")
	}
}

func TestRedirectScanner_Scan_ClientSideJavaScript(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Configure mock to return JavaScript redirect
	htmlWithJSRedirect := `<html><body><script>window.location = "//evil.com";</script></body></html>`
	mock.responses["https://example.com/go?redirect=%2F%2Fevil.com"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(htmlWithJSRedirect)),
		Header:     make(http.Header),
	}

	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock), WithRedirectCanaryDomain("evil.com"))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/go?redirect=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find Open Redirect vulnerability via JavaScript")
	}
}

func TestRedirectScanner_Scan_NoVulnerability(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Configure mock to return safe redirect (same domain)
	headers := make(http.Header)
	headers.Set("Location", "/login")
	mock.responses["https://example.com/auth?next=%2F%2Fevil.com"] = &http.Response{
		StatusCode: http.StatusFound,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     headers,
	}

	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/auth?next=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should not detect vulnerability for relative URL redirect
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Errorf("Expected no vulnerabilities for relative URL redirect, found %d", result.Summary.VulnerabilitiesFound)
	}
}

func TestRedirectScanner_Scan_InvalidURL(t *testing.T) {
	scanner := NewRedirectScanner()

	ctx := context.Background()
	result := scanner.Scan(ctx, "://invalid-url")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected error for invalid URL")
	}
}

func TestRedirectScanner_Scan_ContextCancellation(t *testing.T) {
	mock := newMockRedirectHTTPClient()
	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := scanner.Scan(ctx, "https://example.com?url=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should handle cancellation gracefully
	if len(result.Errors) == 0 {
		t.Error("Expected error message about cancellation")
	}
}

func TestRedirectScanner_VerifyFinding(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Configure mock to consistently return redirect
	headers := make(http.Header)
	headers.Set("Location", "//attacker.com")

	// Add responses for various verification attempts
	urls := []string{
		"https://example.com/redir?url=%2F%2Fattacker.com",
		"https://example.com/redir?url=%2F%2F%2Fattacker.com",
		"https://example.com/redir?url=%2F%2Fevil.example.com",
	}

	for _, url := range urls {
		mock.responses[url] = &http.Response{
			StatusCode: http.StatusFound,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     headers,
		}
	}

	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock))

	finding := &RedirectFinding{
		URL:        "https://example.com/redir?url=%2F%2Fevil.com",
		Parameter:  "url",
		Payload:    "//evil.com",
		Type:       "protocol-relative",
		Severity:   SeverityHigh,
		Confidence: "high",
	}

	config := VerificationConfig{
		Enabled:    true,
		MaxRetries: 3,
		Delay:      0,
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
		t.Error("Expected finding to be verified")
	}

	if result.Confidence < 0.5 {
		t.Errorf("Expected confidence >= 0.5, got %f", result.Confidence)
	}

	if result.Attempts == 0 {
		t.Error("Expected at least one verification attempt")
	}
}

func TestRedirectScanner_VerifyFinding_NilFinding(t *testing.T) {
	scanner := NewRedirectScanner()

	config := VerificationConfig{
		Enabled:    true,
		MaxRetries: 3,
	}

	ctx := context.Background()
	_, err := scanner.VerifyFinding(ctx, nil, config)

	if err == nil {
		t.Error("Expected error for nil finding")
	}
}

func TestRedirectScanner_String(t *testing.T) {
	result := &RedirectScanResult{
		Target: "https://example.com",
		Findings: []RedirectFinding{
			{
				URL:         "https://example.com/redirect?url=%2F%2Fevil.com",
				Parameter:   "url",
				Payload:     "//evil.com",
				Severity:    SeverityHigh,
				Type:        "protocol-relative",
				Description: "Test finding",
				Evidence:    "HTTP 302 redirect to: //evil.com",
				Confidence:  "high",
			},
		},
		Summary: RedirectSummary{
			TotalTests:           10,
			VulnerabilitiesFound: 1,
			HighSeverityCount:    1,
		},
	}

	str := result.String()

	if !strings.Contains(str, "Open Redirect Vulnerability Scan") {
		t.Error("Expected string to contain 'Open Redirect Vulnerability Scan'")
	}

	if !strings.Contains(str, "https://example.com") {
		t.Error("Expected string to contain target URL")
	}

	if !strings.Contains(str, "Total Tests: 10") {
		t.Error("Expected string to contain total tests count")
	}

	if !strings.Contains(str, "Vulnerabilities Found: 1") {
		t.Error("Expected string to contain vulnerabilities count")
	}

	if !strings.Contains(str, "Protocol-Relative") && !strings.Contains(str, "protocol-relative") {
		t.Error("Expected string to contain vulnerability type")
	}
}

func TestRedirectScanner_HasResults(t *testing.T) {
	tests := []struct {
		name     string
		result   *RedirectScanResult
		expected bool
	}{
		{
			name: "has findings",
			result: &RedirectScanResult{
				Findings: []RedirectFinding{{}},
			},
			expected: true,
		},
		{
			name: "has tests but no findings",
			result: &RedirectScanResult{
				Summary: RedirectSummary{TotalTests: 10},
			},
			expected: true,
		},
		{
			name:     "no results",
			result:   &RedirectScanResult{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasResults(); got != tt.expected {
				t.Errorf("HasResults() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestRedirectScanner_SeverityCounts(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Configure mock to return multiple redirect responses with different severities
	highHeaders := make(http.Header)
	highHeaders.Set("Location", "//evil.com")
	mock.responses["https://example.com/redir?url=%2F%2Fevil.com"] = &http.Response{
		StatusCode: http.StatusFound,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     highHeaders,
	}

	mediumHeaders := make(http.Header)
	mediumHeaders.Set("Location", "https://evil.com.example.com")
	mock.responses["https://example.com/redir?url=https%3A%2F%2Fevil.com.example.com"] = &http.Response{
		StatusCode: http.StatusFound,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     mediumHeaders,
	}

	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock), WithRedirectCanaryDomain("evil.com"))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/redir?url=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Verify summary counts are calculated correctly
	totalFindings := result.Summary.HighSeverityCount + result.Summary.MediumSeverityCount + result.Summary.LowSeverityCount
	if totalFindings != len(result.Findings) {
		t.Errorf("Sum of severity counts (%d) doesn't match total findings (%d)", totalFindings, len(result.Findings))
	}

	if result.Summary.VulnerabilitiesFound != len(result.Findings) {
		t.Errorf("VulnerabilitiesFound (%d) doesn't match findings length (%d)", result.Summary.VulnerabilitiesFound, len(result.Findings))
	}
}

func TestRedirectScanner_WithRateLimitConfig(t *testing.T) {
	config := ratelimit.Config{
		RequestsPerSecond: 10,
	}

	scanner := NewRedirectScanner(WithRedirectRateLimitConfig(config))

	if scanner == nil {
		t.Fatal("NewRedirectScanner returned nil")
	}

	if scanner.rateLimiter == nil {
		t.Error("Expected rate limiter to be set")
	}
}

func TestRedirectScanner_PayloadVariants(t *testing.T) {
	scanner := NewRedirectScanner()

	tests := []struct {
		name        string
		payload     string
		payloadType string
		expectedMin int
	}{
		{
			name:        "protocol-relative variants",
			payload:     "//evil.com",
			payloadType: "protocol-relative",
			expectedMin: 2,
		},
		{
			name:        "at-symbol variants",
			payload:     "https://trusted@attacker.com",
			payloadType: "at-symbol",
			expectedMin: 2,
		},
		{
			name:        "encoded variants",
			payload:     "%2F%2Fevil.com",
			payloadType: "encoded",
			expectedMin: 2,
		},
		{
			name:        "subdomain variants",
			payload:     "https://example.com.evil.com",
			payloadType: "subdomain",
			expectedMin: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := scanner.generateRedirectPayloadVariants(tt.payload, tt.payloadType)

			if len(variants) < tt.expectedMin {
				t.Errorf("Expected at least %d variants, got %d", tt.expectedMin, len(variants))
			}

			// First variant should always be the original payload
			if variants[0] != tt.payload {
				t.Errorf("Expected first variant to be original payload %s, got %s", tt.payload, variants[0])
			}
		})
	}
}

func TestRedirectScanner_ExtractTargetFromPayload(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected string
	}{
		{
			name:     "evil.com in payload",
			payload:  "//evil.com",
			expected: "evil.com",
		},
		{
			name:     "attacker.com in payload",
			payload:  "https://attacker.com",
			expected: "attacker.com",
		},
		{
			name:     "javascript protocol",
			payload:  "javascript:alert(1)",
			expected: "javascript",
		},
		{
			name:     "unknown target",
			payload:  "http://unknown-domain.com",
			expected: "unknown-domain.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTargetFromPayload(tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestRedirectScanner_NoFalsePositive_DOMXSSPage verifies that a page which reads URL
// parameters via document.location.href (DOM XSS style) does NOT produce a false
// positive open redirect finding for the javascript: payload type.
// The word "javascript" appears on virtually every web page and must not be used as a
// body-match target on its own.
func TestRedirectScanner_NoFalsePositive_DOMXSSPage(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Simulate a DOM XSS page that reads the URL parameter via document.location.href
	// and writes it back to the DOM — but does NOT perform an open redirect.
	// The body intentionally contains "javascript" (from the <script> tag and code) and
	// "location.href" (from the parameter-reading logic), which are the two conditions
	// that previously triggered the false positive.
	domXSSPage := `<html>
<head><title>DOM XSS test</title></head>
<body>
<select name="default">
<script type="text/javascript">
if (document.location.href.indexOf("default=") >= 0) {
    var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
    document.write("<option value='" + lang + "'>" + decodeURIComponent(lang) + "</option>");
    document.write("<option value='' disabled='disabled'>----</option>");
}
document.write("<option value='English'>English</option>");
</script>
</select>
</body>
</html>`

	// The scanner will test ?default=javascript:alert(document.domain)
	// The static HTML response does NOT contain the payload in a redirect context.
	mock.responses["https://example.com/xss_d?default=javascript%3Aalert%28document.domain%29"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(domXSSPage)),
		Header:     make(http.Header),
	}

	scanner := NewRedirectScanner(WithRedirectHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/xss_d?default=English")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// No open redirect findings should be reported — any finding here is a false positive.
	for _, f := range result.Findings {
		if f.Type == "javascript" {
			t.Errorf("False positive: javascript: payload incorrectly flagged as open redirect "+
				"on DOM XSS page (param=%s evidence=%s)", f.Parameter, f.Evidence)
		}
	}
}

// TestRedirectScanner_CanaryDomainSubstitution verifies that WithRedirectCanaryDomain
// correctly replaces "evil.com" in all payload strings and Target fields, and that
// the updated payloads are sent to the server and detected when the server reflects
// the canary domain back in a Location header.
func TestRedirectScanner_CanaryDomainSubstitution(t *testing.T) {
	const canary = "canary.redirect-test.invalid"

	mock := newMockRedirectHTTPClient()

	// Register a response for the protocol-relative payload with the custom canary.
	// The payload "//canary.redirect-test.invalid" URL-encodes to "%2F%2Fcanary.redirect-test.invalid".
	headers := make(http.Header)
	headers.Set("Location", "//"+canary)
	mock.responses["https://app.example.com/go?url=%2F%2Fcanary.redirect-test.invalid"] = &http.Response{
		StatusCode: http.StatusFound,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     headers,
	}

	s := NewRedirectScanner(
		WithRedirectHTTPClient(mock),
		WithRedirectCanaryDomain(canary),
	)

	// Verify the canary domain was stored correctly.
	if s.canaryDomain != canary {
		t.Errorf("Expected canaryDomain %q, got %q", canary, s.canaryDomain)
	}

	// Verify buildActivePayloads substitutes the canary in every non-javascript payload.
	active := s.buildActivePayloads()
	for _, p := range active {
		if p.Target == "javascript" {
			// javascript payload must remain unchanged
			if strings.Contains(p.Payload, canary) {
				t.Errorf("javascript payload should not contain canary domain: %s", p.Payload)
			}
			continue
		}
		if p.Target != canary {
			t.Errorf("Expected payload Target %q, got %q (payload: %s)", canary, p.Target, p.Payload)
		}
		// The hard-coded "evil.com" must not appear in any substituted payload.
		if strings.Contains(p.Payload, "evil.com") {
			t.Errorf("Payload still contains 'evil.com' after canary substitution: %s", p.Payload)
		}
	}

	// Run a scan and confirm the vulnerability is detected using the canary.
	ctx := context.Background()
	result := s.Scan(ctx, "https://app.example.com/go?url=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected at least one finding when canary domain is reflected in Location header")
	}

	// The finding payload should reference the custom canary, not "evil.com".
	for _, f := range result.Findings {
		if strings.Contains(f.Payload, "evil.com") {
			t.Errorf("Finding payload still references 'evil.com': %s", f.Payload)
		}
	}

	// Verify that the original "evil.com" payloads were NOT sent to the server.
	for _, req := range mock.requests {
		if strings.Contains(req.URL.String(), "evil.com") {
			t.Errorf("Scanner sent a request containing 'evil.com' instead of the canary domain: %s", req.URL.String())
		}
	}
}

// TestRedirectScanner_DefaultCanaryDomain verifies that the default canary domain
// is "example.com" (RFC 2606-reserved) when no canary is explicitly configured.
func TestRedirectScanner_DefaultCanaryDomain(t *testing.T) {
	s := NewRedirectScanner()
	if s.canaryDomain != defaultCanaryDomain {
		t.Errorf("Expected default canary domain %q, got %q", defaultCanaryDomain, s.canaryDomain)
	}

	// All non-javascript payloads must target the default canary.
	active := s.buildActivePayloads()
	for _, p := range active {
		if p.Target == "javascript" {
			continue
		}
		if p.Target != defaultCanaryDomain {
			t.Errorf("Expected default canary target %q, got %q (payload: %s)", defaultCanaryDomain, p.Target, p.Payload)
		}
	}
}

// TestRedirectScanner_NoSubstringFalsePositive verifies that the exact hostname
// matching in isRedirectToPayload does not flag a redirect to "notevil.com" when
// the canary is "evil.com".
func TestRedirectScanner_NoSubstringFalsePositive(t *testing.T) {
	mock := newMockRedirectHTTPClient()

	// Return a redirect to "notevil.com" — contains "evil.com" as substring,
	// but it is NOT the canary domain itself.
	headers := make(http.Header)
	headers.Set("Location", "https://notevil.com/path")
	mock.responses["https://app.example.com/redir?url=https%3A%2F%2Fevil.com"] = &http.Response{
		StatusCode: http.StatusFound,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     headers,
	}

	s := NewRedirectScanner(
		WithRedirectHTTPClient(mock),
		WithRedirectCanaryDomain("evil.com"),
	)

	ctx := context.Background()
	result := s.Scan(ctx, "https://app.example.com/redir?url=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// "notevil.com" is NOT equal to "evil.com" — must not be flagged as a vulnerability.
	for _, f := range result.Findings {
		if strings.Contains(f.Evidence, "notevil.com") {
			t.Errorf("False positive: redirect to 'notevil.com' was incorrectly flagged (evidence: %s)", f.Evidence)
		}
	}
}

func TestNewNoRedirectHTTPClient(t *testing.T) {
	client := NewNoRedirectHTTPClient(30 * time.Second)

	if client == nil {
		t.Fatal("NewNoRedirectHTTPClient returned nil")
	}

	// Verify that the client has the correct timeout
	httpClient, ok := client.(*http.Client)
	if !ok {
		t.Fatal("Expected *http.Client type")
	}

	if httpClient.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", httpClient.Timeout)
	}

	// Verify that the client does not follow redirects
	if httpClient.CheckRedirect == nil {
		t.Error("Expected CheckRedirect function to be set")
	}
}
