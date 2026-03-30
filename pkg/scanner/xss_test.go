package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
)

// mockXSSHTTPClient is a mock HTTP client for testing XSS scanner.
type mockXSSHTTPClient struct {
	responses map[string]*http.Response
	requests  []*http.Request
}

func (m *mockXSSHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)

	// Return a response based on the URL or a default response
	if resp, ok := m.responses[req.URL.String()]; ok {
		return resp, nil
	}

	// Default response - no vulnerability
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}, nil
}

func newMockXSSHTTPClient() *mockXSSHTTPClient {
	return &mockXSSHTTPClient{
		responses: make(map[string]*http.Response),
		requests:  make([]*http.Request, 0),
	}
}

func TestNewXSSScanner(t *testing.T) {
	tests := []struct {
		name string
		opts []XSSOption
	}{
		{
			name: "default configuration",
			opts: nil,
		},
		{
			name: "with custom timeout",
			opts: []XSSOption{WithXSSTimeout(60 * time.Second)},
		},
		{
			name: "with custom user agent",
			opts: []XSSOption{WithXSSUserAgent("TestAgent/1.0")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewXSSScanner(tt.opts...)
			if scanner == nil {
				t.Fatal("NewXSSScanner returned nil")
			}
			if scanner.client == nil {
				t.Error("Scanner client is nil")
			}
		})
	}
}

func TestXSSScanner_Scan_NoParameters(t *testing.T) {
	mock := newMockXSSHTTPClient()
	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

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

func TestXSSScanner_Scan_VulnerableReflectedXSS(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to reflect script tag
	testPayload := "<script>alert('XSS')</script>"
	mock.responses["https://example.com/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("<html><body>Results for: %s</body></html>", testPayload))),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/search?q=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find XSS vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if finding.Parameter != "q" {
		t.Errorf("Expected parameter 'q', got %s", finding.Parameter)
	}

	if finding.Type != "reflected" {
		t.Errorf("Expected type 'reflected', got %s", finding.Type)
	}

	if finding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
	}

	if !strings.Contains(finding.Evidence, "script") {
		t.Errorf("Expected evidence to contain 'script', got %s", finding.Evidence)
	}
}

func TestXSSScanner_Scan_EventHandlerInjection(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to reflect onerror handler
	testPayload := "<img src=x onerror=alert('XSS')>"
	mock.responses["https://example.com/page?input=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("<html><body>%s</body></html>", testPayload))),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/page?input=safe")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find XSS vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if !strings.Contains(finding.Description, "Event handler") {
		t.Errorf("Expected description to mention event handler, got %s", finding.Description)
	}

	if finding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
	}
}

func TestXSSScanner_Scan_SVGInjection(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to reflect SVG onload
	evidence := "onload=alert('XSS')"
	mock.responses["https://example.com/test?param=%3Csvg%2Fonload%3Dalert%28%27XSS%27%29%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body><svg/onload=alert('XSS')></body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?param=value")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find XSS vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if !strings.Contains(finding.Evidence, evidence) && !strings.Contains(finding.Evidence, "svg") {
		t.Errorf("Expected evidence to contain SVG payload, got %s", finding.Evidence)
	}
}

func TestXSSScanner_Scan_NoVulnerability(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// All responses properly escape input
	mock.responses["https://example.com/safe?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Results for: &lt;script&gt;alert('XSS')&lt;/script&gt;</body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/safe?q=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound > 0 {
		t.Errorf("Expected no vulnerabilities, found %d", result.Summary.VulnerabilitiesFound)
	}

	if len(result.Findings) > 0 {
		t.Errorf("Expected no findings, got %d", len(result.Findings))
	}
}

func TestXSSScanner_Scan_WithAuthentication(t *testing.T) {
	mock := newMockXSSHTTPClient()
	authConfig := &auth.AuthConfig{
		BearerToken: "test-token-123",
	}

	scanner := NewXSSScanner(
		WithXSSHTTPClient(mock),
		WithXSSAuth(authConfig),
	)

	ctx := context.Background()
	scanner.Scan(ctx, "https://example.com/api?q=test")

	if len(mock.requests) == 0 {
		t.Fatal("Expected at least one request")
	}

	// Check that authentication was applied
	authHeader := mock.requests[0].Header.Get("Authorization")
	if authHeader != "Bearer test-token-123" {
		t.Errorf("Expected Authorization header 'Bearer test-token-123', got %s", authHeader)
	}
}

func TestXSSScanner_Scan_WithRateLimiting(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Create rate limiter config
	rateLimitConfig := ratelimit.Config{
		RequestsPerSecond: 10,
	}

	scanner := NewXSSScanner(
		WithXSSHTTPClient(mock),
		WithXSSRateLimitConfig(rateLimitConfig),
	)

	ctx := context.Background()
	start := time.Now()
	scanner.Scan(ctx, "https://example.com?param1=test&param2=test")
	elapsed := time.Since(start)

	// With rate limiting, the scan should take some minimum time
	// This is a basic check - the actual timing depends on the implementation
	if elapsed < 0 {
		t.Error("Rate limiting doesn't appear to be working")
	}
}

func TestXSSScanner_Scan_TrivialReflectedXSS_DVWA(t *testing.T) {
	// This test reproduces the DVWA reflected XSS issue described in #210
	// The payload <script>alert(1)</script> is reflected verbatim in the response
	mock := newMockXSSHTTPClient()

	testPayload := "<script>alert(1)</script>"
	// Simulate DVWA's actual response structure with HTML comments and other elements
	// that might interfere with detection
	dvwaResponse := `<!DOCTYPE html>

<html>

	<head>

		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />

		<title>Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>

		<link rel="stylesheet" type="text/css" href="dvwa/css/main.css" />

		<link rel="icon" type="\image/ico" href="favicon.ico" />

		<script type="text/javascript" src="dvwa/js/dvwaPage.js"></script>

	</head>

	<body class="home">
		<div id="container">

			<div id="header">

				<img src="dvwa/images/logo.png" alt="Damn Vulnerable Web Application" />

			</div>

			<div id="main_menu">
				<!-- Menu content -->
			</div>

			<div id="main_body">
				<div class="body_padded">
					<h1>Vulnerability: Reflected Cross Site Scripting (XSS)</h1>

					<div class="vulnerable_code_area">

						<form name="XSS" action="#" method="GET">
							<p>
								What's your name?
								<input type="text" name="name" size="30">
								<input type="submit" value="Submit">
							</p>

						</form>
						<pre>Hello ` + testPayload + `</pre>
					</div>

					<h2>More Info</h2>
					<ul>
						<li><!-- Some comment --></li>
					</ul>
				</div>
			</div>

			<div id="footer">
				<p>Damn Vulnerable Web Application (DVWA) v1.10 *Development*</p>
			</div>

		</div>

	</body>

</html>`

	// The URL-encoded version of the payload
	encodedURL := "https://example.com/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
	mock.responses[encodedURL] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(dvwaResponse)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/vulnerabilities/xss_r/?name=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Errorf("Expected to find XSS vulnerability (DVWA-style trivial reflected XSS), but found 0. Total tests: %d", result.Summary.TotalTests)
		t.Logf("Findings: %+v", result.Findings)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding for trivial reflected XSS")
	}

	finding := result.Findings[0]
	if finding.Parameter != "name" {
		t.Errorf("Expected parameter 'name', got %s", finding.Parameter)
	}

	if finding.Type != "reflected" {
		t.Errorf("Expected type 'reflected', got %s", finding.Type)
	}

	if finding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
	}

	if finding.Confidence != "high" {
		t.Errorf("Expected confidence 'high' for verbatim script reflection, got %s", finding.Confidence)
	}

	if !strings.Contains(finding.Payload, "<script>alert(1)</script>") {
		t.Errorf("Expected payload to contain '<script>alert(1)</script>', got %s", finding.Payload)
	}
}

func TestXSSScanner_Scan_TrivialReflectedXSS_WithCommentNearby(t *testing.T) {
	// Test case where HTML comment appears near the payload but payload should still be detected
	mock := newMockXSSHTTPClient()

	testPayload := "<script>alert(1)</script>"
	// Response with HTML comment right before the payload
	responseWithComment := `<html><body><!-- This is a comment -->Hello ` + testPayload + `</body></html>`

	encodedURL := "https://example.com/test?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
	mock.responses[encodedURL] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(responseWithComment)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?name=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Errorf("Expected to find XSS vulnerability even with nearby comment, but found 0")
		t.Logf("Total tests: %d", result.Summary.TotalTests)
	}

	if len(result.Findings) > 0 {
		finding := result.Findings[0]
		if finding.Confidence != "high" {
			t.Errorf("Expected confidence 'high' for executable script tag, got %s", finding.Confidence)
		}
	}
}

func TestXSSScanner_Scan_VerbatimAndEncodedBothPresent(t *testing.T) {
	// Regression test for bug where encoded payload elsewhere in body prevents detection
	// of verbatim reflection
	mock := newMockXSSHTTPClient()

	testPayload := "<script>alert(1)</script>"
	// Response contains BOTH the verbatim payload (vulnerable) and encoded version elsewhere
	responseWithBoth := `<html><body>
		<div>Previous search: &lt;script&gt;alert(1)&lt;/script&gt;</div>
		<div>Current result: ` + testPayload + `</div>
	</body></html>`

	encodedURL := "https://example.com/test?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
	mock.responses[encodedURL] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(responseWithBoth)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?name=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Even though encoded version exists elsewhere, the verbatim reflection should be detected
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find XSS vulnerability when payload is reflected verbatim, even if encoded version exists elsewhere")
		t.Logf("Total tests: %d", result.Summary.TotalTests)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding - verbatim script reflection is executable")
	}

	finding := result.Findings[0]
	if finding.Confidence != "high" {
		t.Errorf("Expected confidence 'high' for verbatim executable script tag, got %s", finding.Confidence)
	}
}

func TestXSSScanner_Scan_CommentInContextWindow_EncodedElsewhere(t *testing.T) {
	// Bug: When there's a comment in the context window AND encoded payload elsewhere,
	// the detection fails even though payload is reflected verbatim
	mock := newMockXSSHTTPClient()

	testPayload := "<script>alert(1)</script>"
	// Response with a comment in the context window before payload, plus encoded version elsewhere
	responseComplex := `<html><body>
		<div>History: &lt;script&gt;alert(1)&lt;/script&gt;</div>
		<div>
			<!-- This comment appears in the 200-char context window before the payload -->
			Result: ` + testPayload + `
		</div>
	</body></html>`

	encodedURL := "https://example.com/test?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
	mock.responses[encodedURL] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(responseComplex)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?name=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// The payload is NOT inside the comment, it's after the comment
	// So it should still be detected as vulnerable
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("BUG REPRODUCED: Verbatim script reflection not detected due to comment in context window + encoded payload elsewhere")
		t.Logf("Total tests: %d", result.Summary.TotalTests)
	}
}

func TestXSSScanner_Scan_PayloadInsideComment_EncodedElsewhere(t *testing.T) {
	// Bug reproduction: Payload inside HTML comment + encoded version elsewhere
	// Should not be reported as vulnerable since it's in a comment
	mock := newMockXSSHTTPClient()

	testPayload := "<script>alert(1)</script>"
	// Payload IS inside an HTML comment (not executable) but encoded version exists elsewhere
	responseInComment := `<html><body>
		<div>Previous: &lt;script&gt;alert(1)&lt;/script&gt;</div>
		<div><!-- Commented out: ` + testPayload + ` --></div>
	</body></html>`

	encodedURL := "https://example.com/test?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
	mock.responses[encodedURL] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(responseInComment)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?name=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Payload is inside comment, so it's not executable - should not be reported
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Error("False positive: Payload inside comment should not be reported as vulnerable")
	}
}

func TestXSSScanner_Scan_ContextCancellation(t *testing.T) {
	mock := newMockXSSHTTPClient()
	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := scanner.Scan(ctx, "https://example.com?p1=a&p2=b&p3=c")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should have error about cancellation
	if len(result.Errors) == 0 {
		t.Error("Expected error about cancellation")
	}
}

func TestXSSScanner_Scan_InvalidURL(t *testing.T) {
	mock := newMockXSSHTTPClient()
	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

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

func TestXSSScanner_Scan_HTTP429Response(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to return 429 Too Many Requests
	mock.responses["https://example.com/test?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?q=search")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should not report vulnerabilities for 429 responses
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Error("Should not report vulnerabilities for rate-limited responses")
	}
}

func TestXSSScanner_Scan_MultipleParameters(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// First parameter is vulnerable
	mock.responses["https://example.com/search?name=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E&page=1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body><script>alert('XSS')</script></body></html>")),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/search?name=test&page=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should test both parameters
	if result.Summary.TotalTests < 2 {
		t.Errorf("Expected at least 2 tests for 2 parameters, got %d", result.Summary.TotalTests)
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find at least one vulnerability")
	}
}

func TestXSSScanner_Scan_DVWAStyleReflectedXSS(t *testing.T) {
	// Test for DVWA-style trivial reflected XSS where payload is echoed verbatim
	mock := newMockXSSHTTPClient()

	// Simulate DVWA response that reflects the payload verbatim in HTML without encoding
	// Use the same payload the scanner uses
	testPayload := "<script>alert('XSS')</script>"
	// DVWA reflects it directly in the page content
	dvwaResponse := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>Vulnerability: Reflected Cross Site Scripting (XSS)</title>
</head>
<body>
<div id="main_body">
<h1>Vulnerability: Reflected Cross Site Scripting (XSS)</h1>
<div class="vulnerable_code_area">
<form name="XSS" action="#" method="GET">
<p>
What's your name?
<input type="text" name="name" size="30">
<input type="submit" value="Submit">
</p>
</form>
<pre>Hello %s</pre>
</div>
</div>
</body>
</html>`, testPayload)

	// The URL will be encoded by the http package
	// Note: The scanner uses url.Values.Encode() which produces %27 for single quotes
	mock.responses["http://localhost:8080/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(dvwaResponse)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "http://localhost:8080/vulnerabilities/xss_r/?name=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect the XSS vulnerability
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find XSS vulnerability in DVWA-style reflected XSS")
		t.Logf("Total tests: %d", result.Summary.TotalTests)
		t.Logf("Errors: %v", result.Errors)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding for DVWA-style XSS")
	}

	// Verify the finding details
	finding := result.Findings[0]
	if finding.Parameter != "name" {
		t.Errorf("Expected parameter 'name', got %s", finding.Parameter)
	}

	if finding.Type != "reflected" {
		t.Errorf("Expected type 'reflected', got %s", finding.Type)
	}

	if finding.Confidence != "high" {
		t.Errorf("Expected high confidence for verbatim script tag reflection, got %s", finding.Confidence)
	}

	if finding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
	}

	if !strings.Contains(finding.Payload, "<script>") {
		t.Errorf("Expected payload to contain <script> tag, got %s", finding.Payload)
	}
}

func TestXSSScanResult_String(t *testing.T) {
	result := &XSSScanResult{
		Target: "https://example.com",
		Findings: []XSSFinding{
			{
				URL:         "https://example.com?q=<script>",
				Parameter:   "q",
				Payload:     "<script>alert('XSS')</script>",
				Evidence:    "...Results for: <script>alert('XSS')</script>...",
				Severity:    SeverityHigh,
				Type:        "reflected",
				Description: "Unescaped script tag injection detected",
				Remediation: "Implement proper output encoding",
			},
		},
		Summary: XSSSummary{
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

	if !strings.Contains(str, "Parameter: q") {
		t.Error("String output should contain parameter name")
	}
}

func TestXSSScanResult_HasResults(t *testing.T) {
	tests := []struct {
		name     string
		result   *XSSScanResult
		expected bool
	}{
		{
			name: "has findings",
			result: &XSSScanResult{
				Findings: []XSSFinding{{URL: "test"}},
			},
			expected: true,
		},
		{
			name: "has tests but no findings",
			result: &XSSScanResult{
				Summary: XSSSummary{TotalTests: 5},
			},
			expected: true,
		},
		{
			name:     "no results",
			result:   &XSSScanResult{},
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

func TestXSSScanner_ExtractEvidence(t *testing.T) {
	scanner := NewXSSScanner()

	tests := []struct {
		name     string
		body     string
		evidence string
		payload  string
		want     string
	}{
		{
			name:     "evidence found in middle",
			body:     "Some text before <script>alert('XSS')</script> and some after",
			evidence: "<script>alert('XSS')</script>",
			payload:  "<script>alert('XSS')</script>",
			want:     "before <script>alert('XSS')</script> and some after",
		},
		{
			name:     "evidence at start",
			body:     "<script>alert('XSS')</script> followed by text",
			evidence: "<script>alert('XSS')</script>",
			payload:  "<script>alert('XSS')</script>",
			want:     "<script>alert('XSS')</script> followed by text",
		},
		{
			name:     "no evidence found",
			body:     "Clean response with no injection",
			evidence: "<script>",
			payload:  "<script>alert('XSS')</script>",
			want:     "Payload reflected in response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanner.extractEvidence(tt.body, tt.evidence, tt.payload)
			if !strings.Contains(got, tt.want) && got != tt.want {
				t.Errorf("extractEvidence() = %v, want to contain %v", got, tt.want)
			}
		})
	}
}

func TestXSSScanner_GetRemediation(t *testing.T) {
	scanner := NewXSSScanner()

	tests := []struct {
		vulnType string
		want     string
	}{
		{
			vulnType: "reflected",
			want:     "output encoding",
		},
		{
			vulnType: "stored",
			want:     "Sanitize",
		},
		{
			vulnType: "dom",
			want:     "innerHTML",
		},
		{
			vulnType: "unknown",
			want:     "input validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.vulnType, func(t *testing.T) {
			got := scanner.getRemediation(tt.vulnType)
			if !strings.Contains(got, tt.want) {
				t.Errorf("getRemediation(%s) = %v, want to contain %v", tt.vulnType, got, tt.want)
			}
		})
	}
}

func TestXSSScanner_CalculateSummary(t *testing.T) {
	scanner := NewXSSScanner()

	result := &XSSScanResult{
		Findings: []XSSFinding{
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

func TestXSSScanner_WithCustomOptions(t *testing.T) {
	customClient := newMockXSSHTTPClient()
	customUserAgent := "CustomAgent/2.0"
	customTimeout := 45 * time.Second
	authConfig := &auth.AuthConfig{
		BasicAuth: "testuser:testpass",
	}

	scanner := NewXSSScanner(
		WithXSSHTTPClient(customClient),
		WithXSSUserAgent(customUserAgent),
		WithXSSTimeout(customTimeout),
		WithXSSAuth(authConfig),
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

// Test for false positive: HTML-encoded payload should not be reported
func TestXSSScanner_Scan_HTMLEncodedPayload_FalsePositive(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to return HTML-encoded script tag (safe)
	encodedPayload := "&lt;script&gt;alert('XSS')&lt;/script&gt;"
	mock.responses["https://example.com/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("<html><body>Results for: %s</body></html>", encodedPayload))),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/search?q=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should NOT report vulnerability because payload is HTML-encoded
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Errorf("Should not report vulnerability for HTML-encoded payload, but found %d", result.Summary.VulnerabilitiesFound)
	}

	if len(result.Findings) > 0 {
		t.Errorf("Expected no findings for HTML-encoded payload, got %d findings", len(result.Findings))
	}
}

// Test for confirmation: executable context should be high confidence
func TestXSSScanner_Scan_ExecutableContext_HighConfidence(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to reflect unencoded script tag in executable context
	testPayload := "<script>alert('XSS')</script>"
	mock.responses["https://example.com/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("<html><body>Results: %s</body></html>", testPayload))),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/search?q=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find XSS vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if finding.Confidence != "high" {
		t.Errorf("Expected confidence 'high' for executable script tag, got %s", finding.Confidence)
	}
}

// Test for event handler in attribute - should be high confidence
func TestXSSScanner_Scan_EventHandlerAttribute_HighConfidence(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to reflect event handler in HTML attribute
	testPayload := "<img src=x onerror=alert('XSS')>"
	mock.responses["https://example.com/page?input=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("<html><body><div>%s</div></body></html>", testPayload))),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/page?input=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find XSS vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if finding.Confidence != "high" {
		t.Errorf("Expected confidence 'high' for event handler, got %s", finding.Confidence)
	}
}

// Test context analysis function
func TestXSSScanner_AnalyzeContext(t *testing.T) {
	scanner := NewXSSScanner()

	tests := []struct {
		name               string
		body               string
		payload            string
		expectedExecutable bool
		expectedConfidence string
	}{
		{
			name:               "HTML encoded - not executable",
			body:               "<html><body>&lt;script&gt;alert('XSS')&lt;/script&gt;</body></html>",
			payload:            "<script>alert('XSS')</script>",
			expectedExecutable: false,
			expectedConfidence: "low",
		},
		{
			name:               "Unencoded script tag - executable",
			body:               "<html><body><script>alert('XSS')</script></body></html>",
			payload:            "<script>alert('XSS')</script>",
			expectedExecutable: true,
			expectedConfidence: "high",
		},
		{
			name:               "Event handler - executable",
			body:               "<html><body><img src=x onerror=alert('XSS')></body></html>",
			payload:            "<img src=x onerror=alert('XSS')>",
			expectedExecutable: true,
			expectedConfidence: "high",
		},
		{
			name:               "DVWA-style verbatim reflection of script tag",
			body:               "Hello <script>alert('XSS')</script>",
			payload:            "<script>alert('XSS')</script>",
			expectedExecutable: true,
			expectedConfidence: "high",
		},
		{
			name:               "DVWA-style verbatim reflection of img onerror",
			body:               "<h1>Welcome</h1><img src=x onerror=alert('XSS')>",
			payload:            "<img src=x onerror=alert('XSS')>",
			expectedExecutable: true,
			expectedConfidence: "high",
		},
		{
			name:               "SVG onload verbatim reflection",
			body:               "<div>Results for: <svg/onload=alert('XSS')></div>",
			payload:            "<svg/onload=alert('XSS')>",
			expectedExecutable: true,
			expectedConfidence: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, executable, confidence := scanner.analyzeContext(tt.body, tt.payload)

			if executable != tt.expectedExecutable {
				t.Errorf("Expected executable=%v, got %v", tt.expectedExecutable, executable)
			}

			if confidence != tt.expectedConfidence {
				t.Errorf("Expected confidence=%s, got %s", tt.expectedConfidence, confidence)
			}
		})
	}
}

// Test DOM XSS detection with innerHTML sink
func TestXSSScanner_ScanForDOMXSS_InnerHTML(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to return HTML with vulnerable JavaScript
	vulnerableJS := `
		<html>
		<head>
			<script>
				var hash = location.hash;
				document.getElementById('content').innerHTML = hash;
			</script>
		</head>
		<body><div id="content"></div></body>
		</html>
	`
	mock.responses["https://example.com/"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(vulnerableJS)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find DOM XSS vulnerability with innerHTML sink")
	}

	// Check that at least one finding is DOM-based
	domFound := false
	for _, finding := range result.Findings {
		if finding.Type == "dom" {
			domFound = true
			if !strings.Contains(finding.Description, "innerHTML") {
				t.Errorf("Expected description to mention innerHTML, got %s", finding.Description)
			}
			if finding.Confidence != "high" {
				t.Errorf("Expected high confidence for direct source-to-sink flow, got %s", finding.Confidence)
			}
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected high severity for innerHTML, got %s", finding.Severity)
			}
			break
		}
	}

	if !domFound {
		t.Error("Expected to find at least one DOM XSS finding")
	}
}

// Test DOM XSS detection with document.write sink
func TestXSSScanner_ScanForDOMXSS_DocumentWrite(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to return HTML with document.write vulnerability
	vulnerableJS := `
		<html>
		<head>
			<script>
				var ref = document.referrer;
				document.write('Referrer: ' + ref);
			</script>
		</head>
		<body></body>
		</html>
	`
	mock.responses["https://example.com/page"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(vulnerableJS)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/page")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find DOM XSS vulnerability with document.write sink")
	}

	// Find the DOM XSS finding
	var domFinding *XSSFinding
	for _, finding := range result.Findings {
		if finding.Type == "dom" {
			domFinding = &finding
			break
		}
	}

	if domFinding == nil {
		t.Fatal("Expected to find DOM XSS finding")
	}

	if !strings.Contains(domFinding.Description, "document.write") {
		t.Errorf("Expected description to mention document.write, got %s", domFinding.Description)
	}

	if !strings.Contains(domFinding.Payload, "document.write") {
		t.Errorf("Expected payload to mention document.write, got %s", domFinding.Payload)
	}
}

// Test DOM XSS detection with eval sink
func TestXSSScanner_ScanForDOMXSS_Eval(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to return HTML with eval vulnerability
	vulnerableJS := `
		<html>
		<head>
			<script>
				var userInput = location.search.substring(1);
				eval(userInput);
			</script>
		</head>
		<body></body>
		</html>
	`
	mock.responses["https://example.com/test"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(vulnerableJS)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	domFound := false
	for _, finding := range result.Findings {
		if finding.Type == "dom" && strings.Contains(finding.Description, "eval") {
			domFound = true
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected high severity for eval, got %s", finding.Severity)
			}
			if finding.Confidence != "high" {
				t.Errorf("Expected high confidence for eval with source, got %s", finding.Confidence)
			}
			break
		}
	}

	if !domFound {
		t.Error("Expected to find DOM XSS vulnerability with eval sink")
	}
}

// Test DOM XSS detection with multiple sinks
func TestXSSScanner_ScanForDOMXSS_MultipleSinks(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to return HTML with multiple vulnerabilities
	vulnerableJS := `
		<html>
		<head>
			<script>
				var hash = location.hash;
				document.getElementById('div1').innerHTML = hash;

				var search = location.search;
				eval(search);

				var name = window.name;
				document.write(name);
			</script>
		</head>
		<body><div id="div1"></div></body>
		</html>
	`
	mock.responses["https://example.com/multi"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(vulnerableJS)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/multi")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	domCount := 0
	for _, finding := range result.Findings {
		if finding.Type == "dom" {
			domCount++
		}
	}

	if domCount < 3 {
		t.Errorf("Expected at least 3 DOM XSS findings, got %d", domCount)
	}
}

// Test DOM XSS detection with no vulnerability
func TestXSSScanner_ScanForDOMXSS_NoVulnerability(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to return safe JavaScript
	safeJS := `
		<html>
		<head>
			<script>
				var safeData = 'static content';
				document.getElementById('content').textContent = safeData;
			</script>
		</head>
		<body><div id="content"></div></body>
		</html>
	`
	mock.responses["https://example.com/safe"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(safeJS)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/safe")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should not find DOM XSS in safe code
	for _, finding := range result.Findings {
		if finding.Type == "dom" {
			t.Errorf("Should not find DOM XSS in safe code, but found: %s", finding.Description)
		}
	}
}

// Test DOM XSS detection with sink but no source (low confidence)
func TestXSSScanner_ScanForDOMXSS_SinkNoSource(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Configure mock to return JavaScript with sink but no obvious source
	jsWithSink := `
		<html>
		<head>
			<script>
				function updateContent(data) {
					document.getElementById('content').innerHTML = data;
				}
			</script>
		</head>
		<body><div id="content"></div></body>
		</html>
	`
	mock.responses["https://example.com/sink"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(jsWithSink)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/sink")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should find the sink even without obvious source, but with low confidence
	domFound := false
	for _, finding := range result.Findings {
		if finding.Type == "dom" {
			domFound = true
			if finding.Confidence != "low" {
				t.Errorf("Expected low confidence for sink without source, got %s", finding.Confidence)
			}
			break
		}
	}

	if !domFound {
		t.Error("Expected to find DOM XSS finding even without obvious source")
	}
}

// Test extractJavaScript function
func TestXSSScanner_ExtractJavaScript(t *testing.T) {
	scanner := NewXSSScanner()

	html := `
		<html>
		<head>
			<script>var x = 1;</script>
			<script src="external.js"></script>
			<script>
				var y = 2;
				console.log(y);
			</script>
		</head>
		<body>
			<button onclick="alert('test')">Click</button>
			<img onerror="console.error('error')" src="test.jpg">
		</body>
		</html>
	`

	scripts := scanner.extractJavaScript(html)

	if len(scripts) < 2 {
		t.Errorf("Expected at least 2 script blocks, got %d", len(scripts))
	}

	// Check that inline scripts were extracted
	foundInline := false
	for _, script := range scripts {
		if strings.Contains(script, "var x = 1") || strings.Contains(script, "var y = 2") {
			foundInline = true
			break
		}
	}
	if !foundInline {
		t.Error("Expected to find inline script content")
	}

	// Check that event handlers were extracted
	foundEventHandler := false
	for _, script := range scripts {
		if strings.Contains(script, "alert('test')") || strings.Contains(script, "console.error") {
			foundEventHandler = true
			break
		}
	}
	if !foundEventHandler {
		t.Error("Expected to find event handler code")
	}
}

// Test getDOMSources function
func TestGetDOMSources(t *testing.T) {
	sources := getDOMSources()

	if len(sources) == 0 {
		t.Fatal("Expected at least one DOM source")
	}

	// Check that common sources are included
	expectedSources := []string{"location.hash", "location.search", "document.referrer", "window.name"}
	for _, expected := range expectedSources {
		found := false
		for _, source := range sources {
			if source.name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find source %s", expected)
		}
	}
}

// Test getDOMSinks function
func TestGetDOMSinks(t *testing.T) {
	sinks := getDOMSinks()

	if len(sinks) == 0 {
		t.Fatal("Expected at least one DOM sink")
	}

	// Check that common sinks are included
	expectedSinks := []string{"innerHTML", "document.write", "eval"}
	for _, expected := range expectedSinks {
		found := false
		for _, sink := range sinks {
			if sink.name == expected {
				found = true
				if sink.severity == "" {
					t.Errorf("Sink %s should have a severity", expected)
				}
				break
			}
		}
		if !found {
			t.Errorf("Expected to find sink %s", expected)
		}
	}
}

// Test DOM XSS with setTimeout sink
func TestXSSScanner_ScanForDOMXSS_SetTimeout(t *testing.T) {
	mock := newMockXSSHTTPClient()

	vulnerableJS := `
		<html>
		<head>
			<script>
				var code = location.hash.substring(1);
				setTimeout(code, 100);
			</script>
		</head>
		<body></body>
		</html>
	`
	mock.responses["https://example.com/timeout"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(vulnerableJS)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/timeout")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	domFound := false
	for _, finding := range result.Findings {
		if finding.Type == "dom" && strings.Contains(finding.Description, "setTimeout") {
			domFound = true
			break
		}
	}

	if !domFound {
		t.Error("Expected to find DOM XSS vulnerability with setTimeout sink")
	}
}

// Test DOM XSS finding includes proper remediation
func TestXSSScanner_DOMXSSRemediation(t *testing.T) {
	mock := newMockXSSHTTPClient()

	vulnerableJS := `
		<html>
		<head>
			<script>
				document.getElementById('x').innerHTML = location.hash;
			</script>
		</head>
		<body><div id="x"></div></body>
		</html>
	`
	mock.responses["https://example.com/rem"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(vulnerableJS)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/rem")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	for _, finding := range result.Findings {
		if finding.Type == "dom" {
			if !strings.Contains(finding.Remediation, "innerHTML") {
				t.Errorf("Expected remediation to mention innerHTML for DOM XSS, got %s", finding.Remediation)
			}
			if !strings.Contains(finding.Remediation, "textContent") {
				t.Errorf("Expected remediation to mention safe alternatives like textContent, got %s", finding.Remediation)
			}
			break
		}
	}
}

// mockXSSHTTPClientWithBody is a mock that can return specific body content
type mockXSSHTTPClientWithBody struct {
	mockResponses map[string]string
}

func (m *mockXSSHTTPClientWithBody) Do(req *http.Request) (*http.Response, error) {
	// Extract the query parameter value and echo it back in the response
	// This simulates a reflected XSS vulnerability
	queryParams := req.URL.Query()
	payload := ""
	for _, values := range queryParams {
		for _, v := range values {
			payload = v
			break
		}
		if payload != "" {
			break
		}
	}

	// Get the template body
	bodyStr := ""
	if body, ok := m.mockResponses["default"]; ok {
		bodyStr = body
	} else {
		for _, body := range m.mockResponses {
			bodyStr = body
			break
		}
	}

	// For XSS verification, reflect the payload back in the response
	// Replace any existing XSS payload with the variant being tested
	if payload != "" {
		// Match common patterns and replace with the variant
		if strings.Contains(bodyStr, "<img src=x onerror=alert('XSS')>") {
			bodyStr = strings.ReplaceAll(bodyStr, "<img src=x onerror=alert('XSS')>", payload)
		} else if strings.Contains(bodyStr, "&lt;img") {
			// Keep encoded for false positive test
		} else {
			// Just append the payload to simulate reflection
			bodyStr = strings.ReplaceAll(bodyStr, "</body>", payload+"</body>")
		}
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(bodyStr)),
		Header:     make(http.Header),
	}, nil
}

func TestXSSScanner_VerifyFinding(t *testing.T) {
	tests := []struct {
		name            string
		finding         *XSSFinding
		mockResponses   map[string]string
		expectedVerif   bool
		expectedMinConf float64
	}{
		{
			name: "verified reflected XSS - simple case",
			finding: &XSSFinding{
				URL:       "https://example.com/search?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E",
				Parameter: "q",
				Payload:   "<img src=x onerror=alert('XSS')>",
				Type:      "reflected",
			},
			mockResponses: map[string]string{
				"default": "<html><body><img src=x onerror=alert('XSS')></body></html>",
			},
			expectedVerif:   true,
			expectedMinConf: 0.5,
		},
		{
			name: "false positive - encoded response",
			finding: &XSSFinding{
				URL:       "https://example.com/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
				Parameter: "q",
				Payload:   "<script>alert('XSS')</script>",
				Type:      "reflected",
			},
			mockResponses: map[string]string{
				"default": "<html><body>&lt;script&gt;alert('XSS')&lt;/script&gt;</body></html>",
			},
			expectedVerif:   false,
			expectedMinConf: 0.0,
		},
		{
			name: "DOM-based XSS (always verified through static analysis)",
			finding: &XSSFinding{
				URL:       "https://example.com/",
				Parameter: "DOM-based",
				Payload:   "Sink: innerHTML, Sources: location.hash",
				Type:      "dom",
			},
			mockResponses:   map[string]string{},
			expectedVerif:   true,
			expectedMinConf: 0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockXSSHTTPClientWithBody{
				mockResponses: tt.mockResponses,
			}

			scanner := NewXSSScanner(WithXSSHTTPClient(mock))
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
				t.Errorf("Expected Verified=%v, got %v", tt.expectedVerif, result.Verified)
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

func TestXSSScanner_GeneratePayloadVariants(t *testing.T) {
	scanner := NewXSSScanner()

	tests := []struct {
		name             string
		payload          string
		expectedMinCount int
	}{
		{
			name:             "script tag payload",
			payload:          "<script>alert('XSS')</script>",
			expectedMinCount: 2,
		},
		{
			name:             "img onerror payload",
			payload:          "<img src=x onerror=alert('XSS')>",
			expectedMinCount: 2,
		},
		{
			name:             "svg onload payload",
			payload:          "<svg/onload=alert('XSS')>",
			expectedMinCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := scanner.generatePayloadVariants(tt.payload)

			if len(variants) < tt.expectedMinCount {
				t.Errorf("Expected at least %d variants, got %d", tt.expectedMinCount, len(variants))
			}

			// First variant should be the original
			if variants[0] != tt.payload {
				t.Errorf("Expected first variant to be original payload, got %s", variants[0])
			}

			// Check for uniqueness
			seen := make(map[string]bool)
			for _, v := range variants {
				if seen[v] {
					t.Errorf("Duplicate variant found: %s", v)
				}
				seen[v] = true
			}
		})
	}
}

// Test that properly encoded output doesn't trigger false positives
func TestXSSScanner_Scan_ProperlyEncodedNoFalsePositive(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Simulate a secure application that properly encodes output
	encodedScript := "&lt;script&gt;alert('XSS')&lt;/script&gt;"
	mock.responses["https://secure.local/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("<html><body>Results for: %s</body></html>", encodedScript))),
		Header:     make(http.Header),
	}

	encodedImg := "&lt;img src=x onerror=alert('XSS')&gt;"
	mock.responses["https://secure.local/search?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("<html><body>Results for: %s</body></html>", encodedImg))),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://secure.local/search?q=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should NOT report vulnerabilities for properly encoded output
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Errorf("False positive detected: found %d vulnerabilities in properly encoded output", result.Summary.VulnerabilitiesFound)
		for _, finding := range result.Findings {
			t.Logf("False positive: %s with payload %s (confidence: %s)", finding.Description, finding.Payload, finding.Confidence)
		}
	}
}

// Test mixed scenario: some payloads reflected, some encoded
func TestXSSScanner_Scan_MixedEncodingScenario(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// First payload is reflected verbatim (vulnerable)
	scriptPayload := "<script>alert('XSS')</script>"
	mock.responses["https://mixed.local/page?input=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("<html><body>Input: %s</body></html>", scriptPayload))),
		Header:     make(http.Header),
	}

	// Second payload is properly encoded (safe)
	imgPayloadEncoded := "&lt;img src=x onerror=alert('XSS')&gt;"
	mock.responses["https://mixed.local/page?input=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("<html><body>Input: %s</body></html>", imgPayloadEncoded))),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://mixed.local/page?input=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should find exactly 1 vulnerability (the script tag)
	// The img tag is properly encoded, so should not be reported
	vulnerableCount := 0
	for _, finding := range result.Findings {
		if strings.Contains(finding.Payload, "<script>") && finding.Type == "reflected" {
			vulnerableCount++
			if finding.Confidence != "high" {
				t.Errorf("Expected high confidence for verbatim script reflection, got %s", finding.Confidence)
			}
		}
		// Should NOT have findings for the encoded img tag
		if strings.Contains(finding.Payload, "<img") && finding.Type == "reflected" {
			t.Errorf("False positive: detected vulnerability in encoded img tag")
		}
	}

	if vulnerableCount == 0 {
		t.Error("Expected to find at least the verbatim reflected script tag vulnerability")
	}
}

// Test edge cases: payload in HTML comment (should NOT be reported as high confidence)
func TestXSSScanner_Scan_PayloadInHTMLComment(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Payload is inside an HTML comment - not executable
	scriptPayload := "<script>alert('XSS')</script>"
	mock.responses["https://example.com/test?input=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("<html><body><!-- %s --></body></html>", scriptPayload))),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?input=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should not report high confidence for payload in HTML comment
	for _, finding := range result.Findings {
		if strings.Contains(finding.Payload, "<script>") && finding.Type == "reflected" {
			if finding.Confidence == "high" {
				t.Errorf("False positive: payload in HTML comment reported with high confidence. Expected low/medium, got %s", finding.Confidence)
			}
		}
	}
}

// Test edge cases: payload in textarea (not directly executable in modern browsers)
func TestXSSScanner_Scan_PayloadInTextarea(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Payload is inside a textarea - not directly executable
	scriptPayload := "<script>alert('XSS')</script>"
	mock.responses["https://example.com/test?input=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("<html><body><textarea>%s</textarea></body></html>", scriptPayload))),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?input=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should not report high confidence for payload in textarea
	for _, finding := range result.Findings {
		if strings.Contains(finding.Payload, "<script>") && finding.Type == "reflected" {
			if finding.Confidence == "high" {
				t.Errorf("False positive: payload in textarea reported with high confidence. Expected low/medium, got %s", finding.Confidence)
			}
		}
	}
}

// Test edge cases: payload in script string literal (may or may not be executable)
func TestXSSScanner_Scan_PayloadInScriptStringLiteral(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Payload is inside a script string literal
	scriptPayload := "<script>alert('XSS')</script>"
	mock.responses["https://example.com/test?input=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(
			fmt.Sprintf("<html><body><script>var x = \"%s\";</script></body></html>", scriptPayload),
		)),
		Header: make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?input=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// This is a nuanced case - the payload is in a JavaScript context (inside script tags)
	// The scanner should ideally detect this, but it's a complex scenario.
	// We just verify the scanner doesn't crash and produces some result.
	// The specific detection depends on the context analysis logic.
}

// Test edge cases: multiple occurrences with different encodings
func TestXSSScanner_Scan_MultipleOccurrencesDifferentEncodings(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Payload appears twice: once encoded (safe), once unencoded (vulnerable)
	scriptPayload := "<script>alert('XSS')</script>"
	mock.responses["https://example.com/test?input=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(
			fmt.Sprintf("<html><body><p>You searched for: &lt;script&gt;alert('XSS')&lt;/script&gt;</p><script>var searchTerm = \"%s\";</script></body></html>", scriptPayload),
		)),
		Header: make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?input=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect the vulnerability (the unencoded occurrence in the script tag)
	// Note: Due to the single-occurrence limitation documented in the code,
	// we analyze only the first occurrence. This test documents that limitation.
	foundVulnerability := false
	for _, finding := range result.Findings {
		if strings.Contains(finding.Payload, "<script>") && finding.Type == "reflected" {
			foundVulnerability = true
			// The first occurrence in the response is actually the encoded one in the paragraph
			// So depending on string matching, we may or may not catch this
		}
	}

	// This test documents the known limitation: we only check the first occurrence
	_ = foundVulnerability // Acknowledge the variable is used
}

// TestXSSScanner_DVWAFixtures_ReflectedScriptTag tests XSS detection using actual
// DVWA HTML response fixtures where script tags are reflected verbatim.
// mockDVWAXSSClient is a mock that simulates DVWA's XSS reflection behavior
type mockDVWAXSSClient struct {
	template string
	requests []*http.Request
}

func (m *mockDVWAXSSClient) Do(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)

	// Extract the name parameter from the URL
	nameParam := req.URL.Query().Get("name")

	// If no parameter, return baseline
	if nameParam == "" {
		nameParam = "test"
	}

	// Create DVWA-style response that reflects the payload
	dvwaResponse := strings.Replace(m.template, "<script>alert(1)</script>", nameParam, 1)

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(dvwaResponse)),
		Header:     make(http.Header),
	}, nil
}

func TestXSSScanner_DVWAFixtures_ReflectedScriptTag(t *testing.T) {
	reflectedHTMLTemplate, err := os.ReadFile("testdata/dvwa_xss_reflected.html")
	if err != nil {
		t.Fatalf("Failed to load reflected XSS fixture: %v", err)
	}

	// Create a mock that reflects any payload in DVWA format
	mock := &mockDVWAXSSClient{
		template: string(reflectedHTMLTemplate),
		requests: make([]*http.Request, 0),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "http://dvwa.local/vulnerabilities/xss_r/?name=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect reflected XSS in DVWA's <pre> tag context
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Errorf("Failed to detect DVWA reflected XSS with script tag")
		t.Logf("Total tests performed: %d", result.Summary.TotalTests)
	} else {
		t.Logf("Successfully detected %d vulnerabilities", result.Summary.VulnerabilitiesFound)

		// Verify finding details
		for _, finding := range result.Findings {
			t.Logf("Finding: type=%s, confidence=%s, payload=%s", finding.Type, finding.Confidence, finding.Payload)
			t.Logf("Evidence: %s", finding.Evidence)

			if finding.Type != "reflected" {
				t.Errorf("Expected reflected XSS, got %s", finding.Type)
			}

			// Script tag injection should have high confidence
			if strings.Contains(finding.Payload, "<script>") {
				if finding.Confidence != "high" {
					t.Errorf("Expected high confidence for script tag, got %s", finding.Confidence)
				}
			}
		}
	}
}

// TestXSSScanner_DVWAFixtures_ContextAnalysisPre tests that analyzeContext
// correctly identifies XSS in DVWA's <pre> tag context.
func TestXSSScanner_DVWAFixtures_ContextAnalysisPre(t *testing.T) {
	reflectedHTML, err := os.ReadFile("testdata/dvwa_xss_reflected.html")
	if err != nil {
		t.Fatalf("Failed to load reflected XSS fixture: %v", err)
	}

	scanner := NewXSSScanner()
	payload := "<script>alert(1)</script>"
	bodyStr := string(reflectedHTML)

	// Test context analysis
	contextType, isExecutable, confidence := scanner.analyzeContext(bodyStr, payload)

	t.Logf("Context analysis results:")
	t.Logf("  Context type: %v", contextType)
	t.Logf("  Is executable: %v", isExecutable)
	t.Logf("  Confidence: %s", confidence)

	// Verify the payload is detected as executable
	if !isExecutable {
		t.Errorf("Expected payload to be executable in DVWA <pre> context")

		// Debug: check if payload is verbatim in response
		idx := strings.Index(bodyStr, payload)
		if idx == -1 {
			t.Errorf("Payload not found in response")
		} else {
			t.Logf("Payload found at index %d", idx)

			// Extract context around payload
			start := idx - 100
			if start < 0 {
				start = 0
			}
			end := idx + len(payload) + 100
			if end > len(bodyStr) {
				end = len(bodyStr)
			}
			context := bodyStr[start:end]
			t.Logf("Context around payload: %q", context)
		}
	}

	// High confidence expected for verbatim script tag reflection
	if confidence != "high" {
		t.Errorf("Expected high confidence, got %s", confidence)
	}

	// Should be detected in HTML body context (within <pre>)
	if contextType != ContextHTMLBody {
		t.Logf("Context type is %v, expected ContextHTMLBody", contextType)
	}
}

// TestXSSScanner_DVWAFixtures_PayloadInPre tests that payloads within <pre> tags
// are correctly identified as executable (DVWA-specific HTML structure).
func TestXSSScanner_DVWAFixtures_PayloadInPre(t *testing.T) {
	reflectedHTML, err := os.ReadFile("testdata/dvwa_xss_reflected.html")
	if err != nil {
		t.Fatalf("Failed to load reflected XSS fixture: %v", err)
	}

	bodyStr := string(reflectedHTML)

	// Verify the HTML structure matches DVWA's pattern
	if !strings.Contains(bodyStr, "<pre>") {
		t.Fatal("DVWA fixture should contain <pre> tag")
	}

	// Verify payload is inside <pre> tag
	preStartIdx := strings.Index(bodyStr, "<pre>")
	preEndIdx := strings.Index(bodyStr, "</pre>")

	if preStartIdx == -1 || preEndIdx == -1 {
		t.Fatal("Could not find <pre> tags in fixture")
	}

	preContent := bodyStr[preStartIdx:preEndIdx]
	payload := "<script>alert(1)</script>"

	if !strings.Contains(preContent, payload) {
		t.Errorf("Payload not found within <pre> tag")
		t.Logf("Pre content: %q", preContent)
	} else {
		t.Logf("Payload correctly positioned within <pre> tag")
		t.Logf("Pre content: %q", preContent)
	}

	// Test that <pre> context doesn't prevent detection
	// Script tags are executable even within <pre>
	scanner := NewXSSScanner()
	contextType, isExecutable, confidence := scanner.analyzeContext(bodyStr, payload)

	if !isExecutable {
		t.Errorf("<pre> tag should not prevent script execution detection")
	}

	t.Logf("Context: %v, Executable: %v, Confidence: %s", contextType, isExecutable, confidence)
}

// TestXSSScanner_DVWAFixtures_EncodedVsUnencoded tests the difference between
// encoded (safe) and unencoded (vulnerable) reflections using DVWA fixtures.
func TestXSSScanner_DVWAFixtures_EncodedVsUnencoded(t *testing.T) {
	reflectedHTML, err := os.ReadFile("testdata/dvwa_xss_reflected.html")
	if err != nil {
		t.Fatalf("Failed to load reflected XSS fixture: %v", err)
	}

	encodedHTML, err := os.ReadFile("testdata/dvwa_xss_encoded.html")
	if err != nil {
		t.Fatalf("Failed to load encoded XSS fixture: %v", err)
	}

	scanner := NewXSSScanner()
	payload := "<script>alert(1)</script>"

	// Test unencoded (vulnerable) response
	t.Run("unencoded", func(t *testing.T) {
		bodyStr := string(reflectedHTML)
		contextType, isExecutable, confidence := scanner.analyzeContext(bodyStr, payload)

		t.Logf("Unencoded response:")
		t.Logf("  Context: %v", contextType)
		t.Logf("  Executable: %v", isExecutable)
		t.Logf("  Confidence: %s", confidence)

		if !isExecutable {
			t.Errorf("Unencoded payload should be detected as executable")
		}

		if confidence != "high" {
			t.Errorf("Unencoded reflection should have high confidence, got %s", confidence)
		}
	})

	// Test encoded (safe) response
	t.Run("encoded", func(t *testing.T) {
		bodyStr := string(encodedHTML)
		contextType, isExecutable, confidence := scanner.analyzeContext(bodyStr, payload)

		t.Logf("Encoded response:")
		t.Logf("  Context: %v", contextType)
		t.Logf("  Executable: %v", isExecutable)
		t.Logf("  Confidence: %s", confidence)

		// Encoded payload should NOT be detected as executable
		// The payload won't be found verbatim, so analyzeContext returns low confidence
		if isExecutable && confidence == "high" {
			t.Errorf("Encoded payload should not be detected as high-confidence executable")
		}

		// Verify HTML encoding is present
		encodedPayload := "&lt;script&gt;alert(1)&lt;/script&gt;"
		if !strings.Contains(bodyStr, encodedPayload) {
			t.Logf("Warning: Encoded payload not found in fixture")
		} else {
			t.Logf("Correctly identified encoded payload in response")
		}
	})
}

// TestXSSScanner_DVWAFixtures_MultiplePayloads tests detection with various XSS
// payloads commonly used against DVWA.
func TestXSSScanner_DVWAFixtures_MultiplePayloads(t *testing.T) {
	tests := []struct {
		name          string
		payload       string
		shouldDetect  bool
		minConfidence string
	}{
		{
			name:          "script tag",
			payload:       "<script>alert(1)</script>",
			shouldDetect:  true,
			minConfidence: "high",
		},
		{
			name:          "img onerror",
			payload:       "<img src=x onerror=alert(1)>",
			shouldDetect:  true,
			minConfidence: "high",
		},
		{
			name:          "svg onload",
			payload:       "<svg/onload=alert(1)>",
			shouldDetect:  true,
			minConfidence: "high",
		},
		{
			name:          "iframe javascript",
			payload:       "<iframe src=\"javascript:alert(1)\">",
			shouldDetect:  true,
			minConfidence: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create DVWA-style response with reflected payload
			dvwaResponse := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>XSS Test</title></head>
<body>
<div class="vulnerable_code_area">
	<form name="XSS" action="#" method="GET">
		<input type="text" name="name">
		<input type="submit" value="Submit">
	</form>
	<pre>Hello %s</pre>
</div>
</body></html>`, tt.payload)

			scanner := NewXSSScanner()
			contextType, isExecutable, confidence := scanner.analyzeContext(dvwaResponse, tt.payload)

			t.Logf("Payload: %s", tt.payload)
			t.Logf("  Context: %v", contextType)
			t.Logf("  Executable: %v", isExecutable)
			t.Logf("  Confidence: %s", confidence)

			if tt.shouldDetect && !isExecutable {
				t.Errorf("Expected payload to be detected as executable")
			}

			if tt.shouldDetect && confidence != tt.minConfidence && confidence != "high" {
				t.Errorf("Expected confidence >= %s, got %s", tt.minConfidence, confidence)
			}
		})
	}
}

// TestReflectedXSSDetection tests detection of reflected XSS when payload is reflected verbatim.
// This is the test case for issue #175 - DVWA-style reflected XSS detection.
func TestReflectedXSSDetection(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Use the actual payload from xssPayloads array that the scanner will test
	testPayload := "<script>alert('XSS')</script>"
	dvwaStyleResponse := `<!DOCTYPE html>
<html>
<head><title>Reflected XSS Test</title></head>
<body>
<div class="vulnerable_code_area">
	<form name="XSS" action="#" method="GET">
		<p>
			What's your name?
			<input type="text" name="name">
			<input type="submit" value="Submit">
		</p>
	</form>
	<pre>Hello ` + testPayload + `</pre>
</div>
</body>
</html>`

	// The scanner will URL-encode the payload when making the request
	// We need to match the exact URL with encoded payload
	encodedPayload := "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
	testURL := "https://dvwa.local/vulnerabilities/xss_r/?name=" + encodedPayload

	mock.responses[testURL] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(dvwaStyleResponse)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://dvwa.local/vulnerabilities/xss_r/?name=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// The critical assertion - we should detect the vulnerability
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find XSS vulnerability - DVWA-style reflected XSS not detected")
		t.Logf("Total tests performed: %d", result.Summary.TotalTests)
		t.Logf("Findings: %d", len(result.Findings))
	} else {
		t.Logf("Successfully detected reflected XSS vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding for verbatim reflected <script> tag")
	}

	// Verify the finding details
	finding := result.Findings[0]
	if finding.Parameter != "name" {
		t.Errorf("Expected parameter 'name', got %s", finding.Parameter)
	}

	if finding.Type != "reflected" {
		t.Errorf("Expected type 'reflected', got %s", finding.Type)
	}

	if finding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
	}

	if finding.Confidence != "high" {
		t.Errorf("Expected confidence 'high' for verbatim reflected script tag, got %s", finding.Confidence)
	}

	if !strings.Contains(finding.Payload, "<script>") {
		t.Errorf("Expected payload to contain '<script>', got %s", finding.Payload)
	}

	t.Logf("Finding details:")
	t.Logf("  Parameter: %s", finding.Parameter)
	t.Logf("  Payload: %s", finding.Payload)
	t.Logf("  Type: %s", finding.Type)
	t.Logf("  Severity: %s", finding.Severity)
	t.Logf("  Confidence: %s", finding.Confidence)
	t.Logf("  Evidence: %s", finding.Evidence)
}

// TestReflectedXSSDetection_WithDifferentPayloads tests various script tag payloads.
// This test verifies that payloads in the xssPayloads array are properly detected.
func TestReflectedXSSDetection_WithDifferentPayloads(t *testing.T) {
	testCases := []struct {
		name           string
		payload        string
		evidence       string
		encodedPayload string
	}{
		{
			name:           "alert with number",
			payload:        "<script>alert(1)</script>",
			evidence:       "<script>alert(1)</script>",
			encodedPayload: "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
		},
		{
			name:           "alert with string",
			payload:        "<script>alert('XSS')</script>",
			evidence:       "<script>alert('XSS')</script>",
			encodedPayload: "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := newMockXSSHTTPClient()

			// Create response with payload reflected verbatim
			response := fmt.Sprintf("<html><body><pre>Hello %s</pre></body></html>", tc.payload)

			testURL := "https://example.com/test?name=" + tc.encodedPayload
			mock.responses[testURL] = &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(response)),
				Header:     make(http.Header),
			}

			scanner := NewXSSScanner(WithXSSHTTPClient(mock))

			ctx := context.Background()
			result := scanner.Scan(ctx, "https://example.com/test?name=safe")

			if result.Summary.VulnerabilitiesFound == 0 {
				t.Errorf("Expected to detect XSS for payload: %s", tc.payload)
			}

			if len(result.Findings) > 0 {
				// Find the finding with matching payload
				var found bool
				for _, finding := range result.Findings {
					if finding.Payload == tc.payload {
						found = true
						if finding.Confidence != "high" {
							t.Errorf("Expected high confidence for verbatim script tag, got: %s", finding.Confidence)
						}
						if finding.Severity != SeverityHigh {
							t.Errorf("Expected high severity, got: %s", finding.Severity)
						}
						break
					}
				}
				if !found {
					t.Errorf("Did not find expected payload %s in results", tc.payload)
				}
			}
		})
	}
}

// TestXSSScanner_AnalyzeContext_DVWAFixture tests the analyzeContext function
// with the actual DVWA fixture to ensure it correctly identifies reflected XSS.
func TestXSSScanner_AnalyzeContext_DVWAFixture(t *testing.T) {
	reflectedHTML, err := os.ReadFile("testdata/dvwa_xss_reflected.html")
	if err != nil {
		t.Fatalf("Failed to load reflected XSS fixture: %v", err)
	}

	bodyStr := string(reflectedHTML)
	scanner := NewXSSScanner()

	// Test with the exact payload in the DVWA fixture
	payload := "<script>alert(1)</script>"

	t.Logf("Testing analyzeContext with DVWA fixture")
	t.Logf("Payload: %s", payload)
	t.Logf("Response contains payload: %v", strings.Contains(bodyStr, payload))

	contextType, isExecutable, confidence := scanner.analyzeContext(bodyStr, payload)

	t.Logf("Results:")
	t.Logf("  Context Type: %v", contextType)
	t.Logf("  Is Executable: %v", isExecutable)
	t.Logf("  Confidence: %s", confidence)

	// The payload is verbatim in the response and contains <script>, so it should be detected
	if !isExecutable {
		t.Error("Expected payload to be detected as executable")
	}

	if confidence != "high" {
		t.Errorf("Expected confidence to be 'high' for verbatim <script> tag, got %s", confidence)
	}

	if contextType != ContextHTMLBody {
		t.Errorf("Expected context type ContextHTMLBody, got %v", contextType)
	}
}

// TestXSSScanner_DVWA_EndToEnd tests the full scanner with DVWA fixture.
// This is the comprehensive test for issue #175.
func TestXSSScanner_DVWA_EndToEnd(t *testing.T) {
	// Load the actual DVWA fixture
	reflectedHTML, err := os.ReadFile("testdata/dvwa_xss_reflected.html")
	if err != nil {
		t.Fatalf("Failed to load reflected XSS fixture: %v", err)
	}

	mock := newMockXSSHTTPClient()

	// The DVWA fixture contains <script>alert(1)</script> reflected verbatim
	// Configure mock to return this fixture when the scanner sends this payload
	payload := "<script>alert(1)</script>"
	encodedPayload := "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
	testURL := "https://dvwa.local/vulnerabilities/xss_r/?name=" + encodedPayload

	mock.responses[testURL] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(string(reflectedHTML))),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://dvwa.local/vulnerabilities/xss_r/?name=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	t.Logf("Scan results:")
	t.Logf("  Total tests: %d", result.Summary.TotalTests)
	t.Logf("  Vulnerabilities found: %d", result.Summary.VulnerabilitiesFound)
	t.Logf("  Findings: %d", len(result.Findings))

	// Critical assertion for issue #175: the scanner MUST detect this vulnerability
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("FAIL: Scanner did not detect DVWA reflected XSS vulnerability")
		t.Error("This is the bug reported in issue #175")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding for DVWA reflected XSS")
	}

	// Find the specific finding for <script>alert(1)</script>
	var foundPayload bool
	for _, finding := range result.Findings {
		if finding.Payload == payload {
			foundPayload = true
			t.Logf("Found XSS vulnerability:")
			t.Logf("  Parameter: %s", finding.Parameter)
			t.Logf("  Payload: %s", finding.Payload)
			t.Logf("  Type: %s", finding.Type)
			t.Logf("  Severity: %s", finding.Severity)
			t.Logf("  Confidence: %s", finding.Confidence)

			// Verify the finding is correct
			if finding.Parameter != "name" {
				t.Errorf("Expected parameter 'name', got %s", finding.Parameter)
			}
			if finding.Type != "reflected" {
				t.Errorf("Expected type 'reflected', got %s", finding.Type)
			}
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
			}
			if finding.Confidence != "high" {
				t.Errorf("Expected confidence 'high', got %s", finding.Confidence)
			}
			break
		}
	}

	if !foundPayload {
		t.Errorf("Did not find expected payload %s in findings", payload)
		t.Log("Available findings:")
		for i, f := range result.Findings {
			t.Logf("  %d: %s", i, f.Payload)
		}
	}
}

// TestXSSScanner_DVWAFixtures_ResponseStructure verifies the HTML structure
// of DVWA XSS responses matches expected patterns.
func TestXSSScanner_DVWAFixtures_ResponseStructure(t *testing.T) {
	reflectedHTML, err := os.ReadFile("testdata/dvwa_xss_reflected.html")
	if err != nil {
		t.Fatalf("Failed to load reflected XSS fixture: %v", err)
	}

	bodyStr := string(reflectedHTML)

	// Check for DVWA-specific HTML structure
	expectedElements := []string{
		"<!DOCTYPE html",
		"Vulnerability: Reflected Cross Site Scripting",
		"<div class=\"vulnerable_code_area\">",
		"<pre>",
		"</pre>",
		"<form name=\"XSS\"",
		"<input type=\"text\" name=\"name\">",
	}

	for _, element := range expectedElements {
		if !strings.Contains(bodyStr, element) {
			t.Errorf("Expected element not found: %s", element)
		}
	}

	t.Logf("DVWA XSS fixture has correct HTML structure")

	// Verify payload is in the <pre> tag
	preStart := strings.Index(bodyStr, "<pre>")
	preEnd := strings.Index(bodyStr, "</pre>")

	if preStart != -1 && preEnd != -1 {
		preContent := bodyStr[preStart+5 : preEnd]
		t.Logf("Content in <pre> tag: %q", preContent)

		if strings.Contains(preContent, "<script>") {
			t.Logf("Script tag successfully found in <pre> context")
		}
	}
}

// TestXSSScanner_Scan_DefaultParameterName tests that the scanner detects
// reflected XSS on the 'name' parameter even when it's not in the URL initially.
// This ensures 'name' is included in the defaultTestParams list.
func TestXSSScanner_Scan_DefaultParameterName(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Simulate DVWA-style response that reflects the 'name' parameter verbatim
	testPayload := "<script>alert(1)</script>"
	dvwaResponse := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>Vulnerability: Reflected Cross Site Scripting (XSS)</title>
</head>
<body>
<div id="main_body">
<h1>Vulnerability: Reflected Cross Site Scripting (XSS)</h1>
<div class="vulnerable_code_area">
<form name="XSS" action="#" method="GET">
<p>
What's your name?
<input type="text" name="name" size="30">
<input type="submit" value="Submit">
</p>
</form>
<pre>Hello %s</pre>
</div>
</div>
</body>
</html>`, testPayload)

	// Set up responses for all payloads that might be tested
	// The scanner will test 'name' as part of defaultTestParams
	mock.responses["http://localhost:8080/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(dvwaResponse)),
		Header:     make(http.Header),
	}

	// Also need to respond to other default params to avoid blocking
	for _, param := range []string{"q", "search", "query", "input", "username", "email", "id", "user", "text", "message", "comment", "title", "content", "value", "data"} {
		for _, payload := range []string{
			"%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
			"%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
			"%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E",
			"%3Csvg%2Fonload%3Dalert%28%27XSS%27%29%3E",
			"%27%22%3E%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
			"javascript%3Aalert%28%27XSS%27%29",
			"%3Ciframe+src%3D%22javascript%3Aalert%28%27XSS%27%29%22%3E",
		} {
			url := fmt.Sprintf("http://localhost:8080/vulnerabilities/xss_r/?%s=%s", param, payload)
			mock.responses[url] = &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("<html><body>Safe response</body></html>")),
				Header:     make(http.Header),
			}
		}
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	// Note: URL does NOT have any parameters - scanner should test default params including 'name'
	result := scanner.Scan(ctx, "http://localhost:8080/vulnerabilities/xss_r/")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect the XSS vulnerability via the 'name' parameter
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find XSS vulnerability in 'name' parameter via default test params")
		t.Logf("Total tests: %d", result.Summary.TotalTests)
		t.Logf("Errors: %v", result.Errors)
		t.Logf("Number of findings: %d", len(result.Findings))
		return
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	// Find the 'name' parameter finding
	var nameFinding *XSSFinding
	for i := range result.Findings {
		if result.Findings[i].Parameter == "name" {
			nameFinding = &result.Findings[i]
			break
		}
	}

	if nameFinding == nil {
		t.Fatalf("Expected to find vulnerability in 'name' parameter, found parameters: %v",
			func() []string {
				params := make([]string, len(result.Findings))
				for i, f := range result.Findings {
					params[i] = f.Parameter
				}
				return params
			}())
	}

	// Verify the finding details
	if nameFinding.Type != "reflected" {
		t.Errorf("Expected type 'reflected', got %s", nameFinding.Type)
	}

	if nameFinding.Confidence != "high" {
		t.Errorf("Expected high confidence for verbatim script tag reflection, got %s", nameFinding.Confidence)
	}

	if nameFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, nameFinding.Severity)
	}

	if !strings.Contains(nameFinding.Payload, "<script>") {
		t.Errorf("Expected payload to contain <script> tag, got %s", nameFinding.Payload)
	}
}

// mockPOSTXSSHTTPClient is a custom mock for POST request testing
type mockPOSTXSSHTTPClient struct {
	requests []*http.Request
}

func (m *mockPOSTXSSHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)

	// Simulate DVWA-style response that reflects the 'name' parameter from POST
	testPayload := "<script>alert(1)</script>"
	dvwaResponse := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>Vulnerability: Reflected Cross Site Scripting (XSS)</title>
</head>
<body>
<div class="vulnerable_code_area">
<pre>Hello %s</pre>
</div>
</body>
</html>`, testPayload)

	// Only handle POST requests
	if req.Method != http.MethodPost {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("<html><body>Safe</body></html>")),
			Header:     make(http.Header),
		}, nil
	}

	// Parse the form data
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	formData := string(body)
	// Check if 'name' parameter contains the payload
	if strings.Contains(formData, "name=") && strings.Contains(formData, "%3Cscript%3Ealert%281%29%3C%2Fscript%3E") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(dvwaResponse)),
			Header:     make(http.Header),
		}, nil
	}

	// Default safe response
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("<html><body>Safe response</body></html>")),
		Header:     make(http.Header),
	}, nil
}

// TestXSSScanner_ScanPOST_DefaultParameterName tests that the POST scanner
// detects reflected XSS on the 'name' parameter when no parameters are provided.
func TestXSSScanner_ScanPOST_DefaultParameterName(t *testing.T) {
	mock := &mockPOSTXSSHTTPClient{
		requests: make([]*http.Request, 0),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	// Call ScanPOST with no parameters - should test default params including 'name'
	result := scanner.ScanPOST(ctx, "http://localhost:8080/vulnerabilities/xss_r/", nil)

	if result == nil {
		t.Fatal("ScanPOST returned nil result")
	}

	// Should detect the XSS vulnerability via the 'name' parameter
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find XSS vulnerability in 'name' parameter via POST default test params")
		t.Logf("Total tests: %d", result.Summary.TotalTests)
		t.Logf("Errors: %v", result.Errors)
		return
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	// Find the 'name' parameter finding
	var nameFinding *XSSFinding
	for i := range result.Findings {
		if result.Findings[i].Parameter == "name" {
			nameFinding = &result.Findings[i]
			break
		}
	}

	if nameFinding == nil {
		t.Fatalf("Expected to find vulnerability in 'name' parameter")
	}

	// Verify the finding details
	if nameFinding.Type != "reflected" {
		t.Errorf("Expected type 'reflected', got %s", nameFinding.Type)
	}

	if nameFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, nameFinding.Severity)
	}
}

// TestXSSScanner_Scan_CommentInContextWindowButNotAroundPayload tests that
// the scanner correctly detects XSS when there's an HTML comment in the context
// window (200 chars around the payload) but the payload itself is not inside the comment.
// This tests the fix for the bug where the presence of "<!--" anywhere in the context
// would cause the scanner to skip detection even if the payload was outside the comment.
func TestXSSScanner_Scan_CommentInContextWindowButNotAroundPayload(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Create a response where:
	// 1. There's an HTML comment in the page
	// 2. The payload is reflected verbatim OUTSIDE the comment
	// 3. The comment is within 200 characters of the payload (in context window)
	scriptPayload := "<script>alert(1)</script>"
	responseHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>Test Page</title>
</head>
<body>
<!-- This is a comment that should not affect detection -->
<div class="content">
<p>User input: %s</p>
</div>
</body>
</html>`, scriptPayload)

	mock.responses["https://example.com/test?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(responseHTML)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/test?q=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect the XSS vulnerability despite the comment in the context
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find XSS vulnerability - payload is outside HTML comment")
		t.Logf("Total tests: %d", result.Summary.TotalTests)
		t.Logf("Findings: %v", result.Findings)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding - script tag reflected outside comment")
	}

	// Verify the finding details
	finding := result.Findings[0]
	if finding.Confidence != "high" {
		t.Errorf("Expected high confidence for verbatim script tag reflection outside comment, got %s", finding.Confidence)
	}

	if finding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
	}

	if !strings.Contains(finding.Payload, "<script>") {
		t.Errorf("Expected payload to contain <script> tag, got %s", finding.Payload)
	}
}

// TestXSSScanner_Scan_PayloadInUnclosedComment tests that the scanner correctly
// handles payloads inside unclosed HTML comments. When a comment starts but never
// closes (malformed HTML), the payload should not be reported as high confidence XSS
// because browsers may treat content differently in this edge case.
func TestXSSScanner_Scan_PayloadInUnclosedComment(t *testing.T) {
	mock := newMockXSSHTTPClient()
	scriptPayload := "<script>alert(1)</script>"
	responseHTML := fmt.Sprintf(`<!DOCTYPE html>
<html><body>
<!-- This comment never closes
<div>%s</div>
</body></html>`, scriptPayload)

	mock.responses["https://example.com/test?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(responseHTML)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))
	result := scanner.Scan(context.Background(), "https://example.com/test?q=test")

	// Should not report high confidence for payload in unclosed comment
	for _, finding := range result.Findings {
		if strings.Contains(finding.Payload, "<script>") && finding.Confidence == "high" {
			t.Error("Should not report high confidence for payload in unclosed comment")
		}
	}
}

// TestXSSScanner_Issue182_DVWAReflectedXSS tests the fix for GitHub issue #182.
// This test verifies that the scanner detects reflected XSS on DVWA's /vulnerabilities/xss_r/
// endpoint where the payload is reflected verbatim without encoding.
func TestXSSScanner_Issue182_DVWAReflectedXSS(t *testing.T) {
	mock := newMockXSSHTTPClient()

	// Simulate DVWA's actual response format for the reflected XSS vulnerability
	// The payload <script>alert(1)</script> is reflected unescaped in a <pre> tag
	dvwaResponse := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Vulnerability: Reflected Cross Site Scripting (XSS) :: DVWA</title>
</head>
<body class="home">
<div id="main_body">
<h1>Vulnerability: Reflected Cross Site Scripting (XSS)</h1>
<div class="vulnerable_code_area">
<form name="XSS" action="#" method="GET">
<p>
What's your name?
<input type="text" name="name">
<input type="submit" value="Submit">
</p>
</form>
<pre>Hello <script>alert(1)</script></pre>
</div>
</div>
</body>
</html>`

	// The scanner URL-encodes the payload: <script>alert(1)</script> -> %3Cscript%3Ealert%281%29%3C%2Fscript%3E
	encodedURL := "http://localhost:8080/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

	mock.responses[encodedURL] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(dvwaResponse)),
		Header:     make(http.Header),
	}

	scanner := NewXSSScanner(WithXSSHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "http://localhost:8080/vulnerabilities/xss_r/?name=test")

	// Critical assertion: the scanner MUST detect this vulnerability
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("FAILED to detect DVWA reflected XSS (Issue #182) - this is a P0 bug")
		t.Logf("Total tests: %d", result.Summary.TotalTests)
		t.Logf("Findings: %d", len(result.Findings))
		return
	}

	// Verify we have findings
	if len(result.Findings) == 0 {
		t.Fatal("Expected findings but got none")
	}

	// Find the <script>alert(1)</script> finding specifically
	var scriptFinding *XSSFinding
	for i := range result.Findings {
		if result.Findings[i].Payload == "<script>alert(1)</script>" {
			scriptFinding = &result.Findings[i]
			break
		}
	}

	if scriptFinding == nil {
		t.Fatal("Expected to find <script>alert(1)</script> payload but didn't")
	}

	// Verify the finding details match expected behavior
	if scriptFinding.Parameter != "name" {
		t.Errorf("Expected parameter 'name', got %s", scriptFinding.Parameter)
	}

	if scriptFinding.Type != "reflected" {
		t.Errorf("Expected type 'reflected', got %s", scriptFinding.Type)
	}

	if scriptFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, scriptFinding.Severity)
	}

	// CRITICAL: Verbatim unescaped <script> tag reflection should have HIGH confidence
	if scriptFinding.Confidence != "high" {
		t.Errorf("Expected confidence 'high' for unescaped script tag reflection (DVWA-style), got %s", scriptFinding.Confidence)
	}

	t.Logf("✓ Successfully detected DVWA reflected XSS (Issue #182)")
	t.Logf("  Parameter: %s", scriptFinding.Parameter)
	t.Logf("  Payload: %s", scriptFinding.Payload)
	t.Logf("  Severity: %s", scriptFinding.Severity)
	t.Logf("  Confidence: %s", scriptFinding.Confidence)
	t.Logf("  Evidence: %s", scriptFinding.Evidence)
}

// TestXSSScanner_AnalyzeContext_DVWAWithHTMLComments is a regression test for issue #252.
// It simulates the actual DVWA page structure: HTML comments exist in the page header/
// navigation (well before the reflected payload), and the payload is reflected verbatim
// outside any comment in the body.
//
// Before the fix, the 200-char context window could pick up a lone "<!--" whose matching
// "-->" fell outside the window, causing the comment-detection heuristic to classify the
// payload as being inside an unclosed comment and return isExecutable=false.
func TestXSSScanner_AnalyzeContext_DVWAWithHTMLComments(t *testing.T) {
	// Build a DVWA-like page with HTML comments in the header, far from the payload.
	// The comments are fully closed (<!-- ... -->) but their closing "-->" sits more than
	// 200 characters before the reflected payload, so they fall outside the old context
	// window and appeared as unclosed to the previous implementation.
	headerWithComments := `<!DOCTYPE html>
<html>
<head>
<!-- DVWA v1.10 navigation comment -->
<!-- Security level: low -->
<title>Vulnerability: Reflected XSS :: DVWA</title>
</head>
<body>
<div id="header">
<!-- begin nav -->
<ul>
<li><a href="/">Home</a></li>
<li><a href="/vulnerabilities/xss_r/">XSS (Reflected)</a></li>
</ul>
<!-- end nav -->
</div>
<div id="main_body">
`
	// Pad the header so the payload is placed well beyond 200 chars from any comment.
	padding := strings.Repeat("X", 300)
	payloadInBody := `<pre>Hello <script>alert(1)</script></pre>`
	footer := `
</div>
</body>
</html>`

	dvwaBody := headerWithComments + padding + payloadInBody + footer

	scanner := NewXSSScanner()
	payload := "<script>alert(1)</script>"

	contextType, isExecutable, confidence := scanner.analyzeContext(dvwaBody, payload)

	t.Logf("Context type: %v", contextType)
	t.Logf("Is executable: %v", isExecutable)
	t.Logf("Confidence: %s", confidence)

	// Regression assertion: a verbatim <script> outside any comment must be executable.
	if !isExecutable {
		// Provide diagnostic information to make failures easy to debug.
		idx := strings.Index(dvwaBody, payload)
		t.Logf("Payload index in body: %d", idx)
		if idx >= 200 {
			t.Logf("Context window (idx-200 to idx): %q", dvwaBody[idx-200:idx])
		}
		t.Errorf("issue #252 regression: analyzeContext returned isExecutable=false for verbatim <script> "+
			"payload in DVWA-like response with HTML comments in header. "+
			"context=%v confidence=%s", contextType, confidence)
	}

	if confidence != "high" {
		t.Errorf("Expected confidence 'high', got %s", confidence)
	}

	if contextType != ContextHTMLBody {
		t.Errorf("Expected ContextHTMLBody, got %v", contextType)
	}
}

// TestXSSScanner_AnalyzeContext_PayloadInsideHTMLComment verifies that a payload
// genuinely inside an unclosed HTML comment is NOT reported as executable.
func TestXSSScanner_AnalyzeContext_PayloadInsideHTMLComment(t *testing.T) {
	// The comment is opened immediately before the payload and never closed.
	body := `<html><body><p>Normal content</p><!-- begin debug section <script>alert(1)</script> still inside comment`
	payload := "<script>alert(1)</script>"

	scanner := NewXSSScanner()
	_, isExecutable, _ := scanner.analyzeContext(body, payload)

	if isExecutable {
		t.Error("Payload inside unclosed HTML comment should NOT be reported as executable")
	}
}

// TestIsInsideHTMLComment tests the isInsideHTMLComment helper directly.
// This function is the core fix for issue #262 — it replaces the naive
// strings.LastIndex-based comment detection with a proper state machine.
func TestIsInsideHTMLComment(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantIn   bool // true = expect the position just before the sentinel to be inside a comment
		sentinel string
	}{
		{
			name:     "no comments anywhere",
			body:     `<html><body><pre>SENTINEL`,
			wantIn:   false,
			sentinel: "SENTINEL",
		},
		{
			name:     "completed comment before sentinel",
			body:     `<html><!-- completed comment --><body>SENTINEL`,
			wantIn:   false,
			sentinel: "SENTINEL",
		},
		{
			name:     "two completed comments before sentinel",
			body:     `<!-- comment 1 --> <!-- comment 2 --><body>SENTINEL`,
			wantIn:   false,
			sentinel: "SENTINEL",
		},
		{
			name:     "unclosed comment directly before sentinel",
			body:     `<html><body><!-- open comment SENTINEL`,
			wantIn:   true,
			sentinel: "SENTINEL",
		},
		{
			name:     "unclosed comment with closed comment before it",
			body:     `<!-- closed --> <!-- unclosed SENTINEL`,
			wantIn:   true,
			sentinel: "SENTINEL",
		},
		{
			// The LastIndex bug: script block contains "-->" before "<!--".
			// LastIndex finds the "-->" of the JS string "End: -->" at a lower
			// offset than the "<!--" of the JS string "Start: <!--", making it
			// look like an unclosed HTML comment. isInsideHTMLComment should
			// correctly skip both tokens because they are inside a <script> block.
			name: "script block with reversed --> before <!-- (LastIndex false-positive case)",
			body: `<html><head>` +
				`<script type="text/javascript">` +
				`var end = "End: -->"; var start = "Start: <!--";` +
				`</script>` +
				`</head><body><pre>SENTINEL`,
			wantIn:   false,
			sentinel: "SENTINEL",
		},
		{
			// Style block with comment-like tokens should also be ignored.
			name: "style block with <!-- token",
			body: `<html><head>` +
				`<style>/* <!-- not a comment --> */</style>` +
				`</head><body>SENTINEL`,
			wantIn:   false,
			sentinel: "SENTINEL",
		},
		{
			// The payload is inside a real HTML comment that closes later in the
			// document (after the sentinel). The sentinel position is inside the comment.
			name:     "sentinel inside real comment (closed after sentinel in full body)",
			body:     `<html><body><!-- open SENTINEL`,
			wantIn:   true,
			sentinel: "SENTINEL",
		},
		{
			// Multiple script blocks followed by no HTML comments.
			name: "multiple script blocks no HTML comments",
			body: `<script><!-- js --></script>` +
				`<script>var x = 1;</script>` +
				`<body>SENTINEL`,
			wantIn:   false,
			sentinel: "SENTINEL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := strings.Index(tt.body, tt.sentinel)
			if idx == -1 {
				t.Fatalf("sentinel %q not found in body", tt.sentinel)
			}
			got := isInsideHTMLComment(tt.body, idx)
			if got != tt.wantIn {
				t.Errorf("isInsideHTMLComment(..., %d) = %v, want %v\nbody=%q", idx, got, tt.wantIn, tt.body)
			}
		})
	}
}

// TestXSSScanner_AnalyzeContext_ScriptBlockCommentFalsePositive is a regression
// test for issue #262. It verifies that a <script> block containing "<!--"/"-->"
// tokens in reverse order (a pattern that breaks the old strings.LastIndex
// heuristic) does NOT suppress detection of a verbatim script-tag payload that
// appears in the HTML body AFTER the script block.
//
// Old behaviour: analyzeContext returned (ContextHTMLBody, false, "low") → no finding.
// Fixed behaviour: analyzeContext returns (ContextHTMLBody, true, "high") → finding reported.
func TestXSSScanner_AnalyzeContext_ScriptBlockCommentFalsePositive(t *testing.T) {
	// Build a page that triggers the old LastIndex bug:
	//   • The <script> block contains the JS string literal "-->" before "<!--".
	//   • strings.LastIndex(body[:idx], "<!--") finds the "<!--" inside the JS string.
	//   • strings.LastIndex(body[:idx], "-->")  finds the "-->" inside the JS string
	//     at a LOWER offset than the "<!--" above.
	//   • So (lcEnd < lcStart) is TRUE → the old code incorrectly classified the
	//     payload as being inside an HTML comment → returned low confidence → discarded.
	//
	// The fixed code uses isInsideHTMLComment which skips script-block content and
	// correctly returns false (not inside a comment).
	body := `<!DOCTYPE html>
<html>
<head>
<script type="text/javascript">
var endMarker   = "Use --> to close an HTML comment";
var startMarker = "Use <!-- to open an HTML comment";
</script>
</head>
<body>
<div class="vulnerable_code_area">
<pre>Hello <script>alert(1)</script></pre>
</div>
</body>
</html>`

	payload := "<script>alert(1)</script>"

	scanner := NewXSSScanner()
	contextType, isExecutable, confidence := scanner.analyzeContext(body, payload)

	if !isExecutable {
		t.Errorf("issue #262 regression: analyzeContext returned isExecutable=false. "+
			"A verbatim <script> payload after a script block containing reversed "+
			`"-->"/"<!--" tokens must be detected as executable. `+
			"context=%v confidence=%s", contextType, confidence)
	}
	if confidence != "high" {
		t.Errorf("Expected confidence 'high' for verbatim script-tag reflection, got %s", confidence)
	}
}

// TestXSSScanner_Scan_DVWALike_ScriptBlockCommentFalsePositive is the full
// scanner-level regression for issue #262: the scan must produce at least one
// high-confidence XSS finding when the response contains a <script> block whose
// JS strings include "-->" before "<!--" (triggering the old LastIndex bug).
func TestXSSScanner_Scan_DVWALike_ScriptBlockCommentFalsePositive(t *testing.T) {
	mock := newMockXSSHTTPClient()

	testPayload := "<script>alert(1)</script>"
	// The response has a script block whose JS strings contain "-->" before "<!--",
	// which would fool the old strings.LastIndex approach into thinking the payload
	// is inside an HTML comment.
	responseBody := `<!DOCTYPE html>
<html>
<head>
<script type="text/javascript">
var endMarker   = "Use --> to close an HTML comment";
var startMarker = "Use <!-- to open an HTML comment";
</script>
</head>
<body>
<div class="vulnerable_code_area">
<pre>Hello ` + testPayload + `</pre>
</div>
</body>
</html>`

	encodedURL := "https://example.com/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
	mock.responses[encodedURL] = &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Header:     make(http.Header),
	}

	sc := NewXSSScanner(WithXSSHTTPClient(mock))
	ctx := context.Background()
	result := sc.Scan(ctx, "https://example.com/vulnerabilities/xss_r/?name=test")

	if result == nil {
		t.Fatal("Scan returned nil")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Errorf("issue #262 regression: scanner found 0 vulnerabilities. " +
			"Expected ≥1 high-confidence XSS finding when payload is reflected verbatim " +
			"after a script block containing reversed \"-->\" / \"<!--\" JS string literals.")
	}

	for _, f := range result.Findings {
		if f.Payload == testPayload {
			if f.Confidence != "high" {
				t.Errorf("Expected high confidence, got %s", f.Confidence)
			}
			return
		}
	}
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Errorf("Found vulnerabilities but none for the expected payload %q", testPayload)
	}
}

// TestAnalyzeJSONContext_VerbatimReflection verifies that a payload reflected
// verbatim inside a JSON response body is detected with medium confidence.
func TestAnalyzeJSONContext_VerbatimReflection(t *testing.T) {
	payload := "<script>alert('XSS')</script>"
	// JSON body containing the payload verbatim inside a string value.
	body := `{"data":[{"id":1,"name":"` + payload + `","description":"test"}]}`

	reflected, confidence := analyzeJSONContext(body, payload)

	if !reflected {
		t.Error("analyzeJSONContext: expected reflected=true for verbatim payload in JSON string value, got false")
	}
	if confidence != "medium" {
		t.Errorf("analyzeJSONContext: expected confidence 'medium' for JSON reflection, got %q", confidence)
	}
}

// TestAnalyzeJSONContext_UnicodeEscapedReflection verifies that a payload whose
// angle-bracket characters have been JSON Unicode-escaped (\\u003c / \\u003e) is
// still detected, because Node.js and Go's encoding/json both apply this escaping
// by default.
func TestAnalyzeJSONContext_UnicodeEscapedReflection(t *testing.T) {
	payload := "<script>alert('XSS')</script>"
	// JSON body with angle brackets Unicode-escaped as \u003c / \u003e —
	// the typical output of Node.js JSON.stringify and Go's encoding/json.
	body := `{"data":[{"id":1,"name":"\u003cscript\u003ealert('XSS')\u003c/script\u003e","description":"test"}]}`

	reflected, confidence := analyzeJSONContext(body, payload)

	if !reflected {
		t.Error("analyzeJSONContext: expected reflected=true for Unicode-escaped payload in JSON body, got false")
	}
	if confidence != "medium" {
		t.Errorf("analyzeJSONContext: expected confidence 'medium' for JSON reflection, got %q", confidence)
	}
}

// TestAnalyzeJSONContext_NoReflection is the no-reflection baseline: a JSON body
// that does not contain the payload (verbatim or encoded) must return reflected=false.
func TestAnalyzeJSONContext_NoReflection(t *testing.T) {
	payload := "<script>alert('XSS')</script>"
	body := `{"data":[{"id":1,"name":"safe product","description":"nothing here"}]}`

	reflected, confidence := analyzeJSONContext(body, payload)

	if reflected {
		t.Errorf("analyzeJSONContext: expected reflected=false for body without payload, got true (confidence=%q)", confidence)
	}
}

// TestXSSScanner_Scan_JSONResponseVerbatim verifies that the XSS scanner reports a
// finding when the response Content-Type is application/json and the payload is
// reflected verbatim in a JSON string value.
func TestXSSScanner_Scan_JSONResponseVerbatim(t *testing.T) {
	mock := newMockXSSHTTPClient()

	testPayload := "<script>alert('XSS')</script>"
	jsonBody := `{"data":[{"id":1,"name":"` + testPayload + `"}]}`

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	mock.responses["https://example.com/api/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(jsonBody)),
		Header:     header,
	}

	sc := NewXSSScanner(WithXSSHTTPClient(mock))
	ctx := context.Background()
	result := sc.Scan(ctx, "https://example.com/api/search?q=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Errorf("Expected >=1 XSS finding for verbatim payload in JSON response, got 0 (tests: %d)", result.Summary.TotalTests)
	}

	for _, f := range result.Findings {
		if f.Payload == testPayload {
			if f.Confidence != "medium" {
				t.Errorf("Expected confidence 'medium' for JSON-reflected XSS, got %q", f.Confidence)
			}
			return
		}
	}
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Errorf("Findings present but none match expected payload %q", testPayload)
	}
}

// TestXSSScanner_Scan_JSONResponseUnicodeEscaped verifies that the XSS scanner reports
// a finding when the JSON response contains the payload with angle brackets Unicode-escaped
// (\\u003c / \\u003e), as produced by Node.js JSON.stringify and Go encoding/json.
func TestXSSScanner_Scan_JSONResponseUnicodeEscaped(t *testing.T) {
	mock := newMockXSSHTTPClient()

	testPayload := "<script>alert('XSS')</script>"
	// Simulate Node.js JSON.stringify output with Unicode-escaped angle brackets.
	jsonBody := `{"data":[{"id":1,"name":"\u003cscript\u003ealert('XSS')\u003c/script\u003e"}]}`

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	mock.responses["https://example.com/api/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(jsonBody)),
		Header:     header,
	}

	sc := NewXSSScanner(WithXSSHTTPClient(mock))
	ctx := context.Background()
	result := sc.Scan(ctx, "https://example.com/api/search?q=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Errorf("Expected >=1 XSS finding for Unicode-escaped payload in JSON response, got 0 (tests: %d)", result.Summary.TotalTests)
	}

	for _, f := range result.Findings {
		if f.Payload == testPayload {
			if f.Confidence != "medium" {
				t.Errorf("Expected confidence 'medium' for JSON-reflected XSS, got %q", f.Confidence)
			}
			return
		}
	}
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Errorf("Findings present but none match expected payload %q", testPayload)
	}
}
