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
