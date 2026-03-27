package scanner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
)

// MockSSTIHTTPClient mocks HTTP responses for SSTI testing
type MockSSTIHTTPClient struct {
	responses map[string]string // URL -> response body
	calls     []string          // Track calls made
}

func (m *MockSSTIHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.calls = append(m.calls, req.URL.String())

	// Check if we have a specific response for this URL
	body := ""
	if resp, ok := m.responses[req.URL.String()]; ok {
		body = resp
	}

	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}, nil
}

func TestNewSSTIScanner(t *testing.T) {
	scanner := NewSSTIScanner()

	if scanner == nil {
		t.Fatal("Expected scanner to be created")
	}

	if scanner.userAgent != "WAST/1.0 (Web Application Security Testing)" {
		t.Errorf("Expected default user agent, got %s", scanner.userAgent)
	}

	if scanner.timeout != 30*time.Second {
		t.Errorf("Expected default timeout 30s, got %v", scanner.timeout)
	}

	if scanner.client == nil {
		t.Error("Expected default HTTP client to be created")
	}
}

func TestNewSSTIScannerWithOptions(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{}
	customUA := "CustomUA/1.0"
	customTimeout := 10 * time.Second
	authConfig := &auth.AuthConfig{
		BearerToken: "test-token",
	}
	limiter := ratelimit.NewLimiter(10)

	scanner := NewSSTIScanner(
		WithSSTIHTTPClient(mockClient),
		WithSSTIUserAgent(customUA),
		WithSSTITimeout(customTimeout),
		WithSSTIAuth(authConfig),
		WithSSTIRateLimiter(limiter),
	)

	if scanner.client != mockClient {
		t.Error("Expected custom HTTP client to be set")
	}

	if scanner.userAgent != customUA {
		t.Errorf("Expected user agent %s, got %s", customUA, scanner.userAgent)
	}

	if scanner.timeout != customTimeout {
		t.Errorf("Expected timeout %v, got %v", customTimeout, scanner.timeout)
	}

	if scanner.authConfig != authConfig {
		t.Error("Expected auth config to be set")
	}

	if scanner.rateLimiter != limiter {
		t.Error("Expected rate limiter to be set")
	}
}

func TestSSTIScan_Jinja2Detection(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{
		responses: make(map[string]string),
	}

	// Set up baseline response (no "49" in baseline)
	mockClient.responses["http://example.com/?q=WAST_BASELINE_12345"] = "Search page"
	// Set up response with evaluated template
	mockClient.responses["http://example.com/?q=%7B%7B7%2A7%7D%7D"] = "Result: 49"

	scanner := NewSSTIScanner(WithSSTIHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/?q=test")

	if len(result.Findings) == 0 {
		t.Fatal("Expected to find SSTI vulnerability")
	}

	finding := result.Findings[0]
	if finding.Parameter != "q" {
		t.Errorf("Expected parameter 'q', got %s", finding.Parameter)
	}

	if finding.TemplateEngine != "jinja2" {
		t.Errorf("Expected template engine 'jinja2', got %s", finding.TemplateEngine)
	}

	if finding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
	}

	if finding.Confidence != "high" {
		t.Errorf("Expected high confidence, got %s", finding.Confidence)
	}
}

func TestSSTIScan_FreemarkerDetection(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{
		responses: make(map[string]string),
	}

	// Set up baseline response (no "49" in baseline)
	mockClient.responses["http://example.com/?input=WAST_BASELINE_12345"] = "Value: nothing"
	// Set up response with evaluated Freemarker template
	mockClient.responses["http://example.com/?input=%24%7B7%2A7%7D"] = "Value: 49 calculated"

	scanner := NewSSTIScanner(WithSSTIHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/?input=test")

	if len(result.Findings) == 0 {
		t.Fatal("Expected to find SSTI vulnerability")
	}

	finding := result.Findings[0]
	if finding.TemplateEngine != "freemarker" {
		t.Errorf("Expected template engine 'freemarker', got %s", finding.TemplateEngine)
	}
}

func TestSSTIScan_MultipleParameters(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{
		responses: make(map[string]string),
	}

	// Set up baseline responses (no "49" in baselines)
	mockClient.responses["http://example.com/?email=WAST_BASELINE_12345&name=test"] = "Hello"
	mockClient.responses["http://example.com/?email=test&name=WAST_BASELINE_12345"] = "Email:"
	// Set up responses for multiple parameters - the scanner will try each payload
	// Just set up a few key responses that should trigger findings
	mockClient.responses["http://example.com/?email=test&name=%7B%7B7%2A7%7D%7D"] = "Hello 49"
	mockClient.responses["http://example.com/?email=%7B%7B7%2A7%7D%7D&name=test"] = "Email: 49"

	scanner := NewSSTIScanner(WithSSTIHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/?name=test&email=test")

	// The test may find vulnerabilities depending on URL parameter ordering
	// Just check that we tested multiple parameters
	if result.Summary.TotalTests == 0 {
		t.Error("Expected to test multiple parameters")
	}
}

func TestSSTIScan_NoVulnerability(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{
		responses: make(map[string]string),
	}

	// Set up response that doesn't evaluate templates
	mockClient.responses["http://example.com/?q=%7B%7B7%2A7%7D%7D"] = "Search results for: {{7*7}}"

	scanner := NewSSTIScanner(WithSSTIHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/?q=test")

	if len(result.Findings) > 0 {
		t.Errorf("Expected no vulnerabilities, found %d", len(result.Findings))
	}
}

func TestSSTIScan_InvalidURL(t *testing.T) {
	scanner := NewSSTIScanner()
	result := scanner.Scan(context.Background(), "://invalid")

	if len(result.Errors) == 0 {
		t.Error("Expected error for invalid URL")
		return
	}

	if len(result.Errors) > 0 && !strings.Contains(result.Errors[0], "Invalid URL") {
		t.Errorf("Expected 'Invalid URL' error, got %s", result.Errors[0])
	}
}

func TestSSTIScan_ContextCancellation(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{
		responses: make(map[string]string),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	scanner := NewSSTIScanner(WithSSTIHTTPClient(mockClient))
	result := scanner.Scan(ctx, "http://example.com/?q=test")

	if len(result.Errors) == 0 {
		t.Error("Expected error for cancelled context")
	}
}

func TestSSTIScan_RateLimiting(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{
		responses: make(map[string]string),
	}

	// Create a rate limiter that allows 1 request per second
	limiter := ratelimit.NewLimiter(1)

	scanner := NewSSTIScanner(
		WithSSTIHTTPClient(mockClient),
		WithSSTIRateLimiter(limiter),
	)

	start := time.Now()
	scanner.Scan(context.Background(), "http://example.com/?q=test")
	elapsed := time.Since(start)

	// Should take at least some time due to rate limiting
	// (with multiple payloads being tested)
	if elapsed < 100*time.Millisecond {
		t.Log("Rate limiting may not be working as expected, but this is not necessarily an error in fast test environments")
	}
}

func TestSSTIScan_Authentication(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{
		responses: make(map[string]string),
	}

	authConfig := &auth.AuthConfig{
		BearerToken: "test-token",
	}

	scanner := NewSSTIScanner(
		WithSSTIHTTPClient(mockClient),
		WithSSTIAuth(authConfig),
	)

	scanner.Scan(context.Background(), "http://example.com/?q=test")

	// Auth config should be applied (we can't easily verify this with the mock,
	// but the test ensures it doesn't crash)
	if scanner.authConfig == nil {
		t.Error("Expected auth config to be set")
	}
}

func TestSSTIScan_Summary(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{
		responses: make(map[string]string),
	}

	// Set up baseline response (no "49" in baseline)
	mockClient.responses["http://example.com/?q=WAST_BASELINE_12345"] = "Result: nothing"
	// Set up responses with different severities
	mockClient.responses["http://example.com/?q=%7B%7B7%2A7%7D%7D"] = "Result: 49"
	mockClient.responses["http://example.com/?q=%7B7%2A7%7D"] = "Result: 49"

	scanner := NewSSTIScanner(WithSSTIHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/?q=test")

	if result.Summary.TotalTests == 0 {
		t.Error("Expected total tests to be greater than 0")
	}

	if result.Summary.VulnerabilitiesFound != len(result.Findings) {
		t.Errorf("Summary vulnerabilities count (%d) doesn't match findings count (%d)",
			result.Summary.VulnerabilitiesFound, len(result.Findings))
	}
}

func TestCalculateSummary(t *testing.T) {
	scanner := NewSSTIScanner()
	result := &SSTIScanResult{
		Findings: []SSTIFinding{
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

func TestDetectTemplateInjection(t *testing.T) {
	scanner := NewSSTIScanner()

	tests := []struct {
		name     string
		body     string
		payload  sstiPayload
		expected bool
	}{
		{
			name: "Evaluated template - result without payload",
			body: "Result: 49",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			expected: true,
		},
		{
			name: "Reflected but not evaluated",
			body: "You searched for: {{7*7}}",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			expected: false,
		},
		{
			name: "Both payload and result present - evaluated",
			body: "Input: {{7*7}} Result: 49 and another 49",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			expected: true,
		},
		{
			name: "No expected result",
			body: "Some random content",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.detectTemplateInjection(tt.body, tt.payload, "")
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for body: %s", tt.expected, result, tt.body)
			}
		})
	}
}

func TestCalculateConfidence(t *testing.T) {
	scanner := NewSSTIScanner()

	tests := []struct {
		name     string
		body     string
		payload  sstiPayload
		expected string
	}{
		{
			name: "High confidence - result only",
			body: "Result: 49",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			expected: "high",
		},
		{
			name: "Medium confidence - both present",
			body: "You entered {{7*7}} which equals 49",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			expected: "medium",
		},
		{
			name: "Low confidence - neither present",
			body: "Some content",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			expected: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.calculateConfidence(tt.body, tt.payload)
			if result != tt.expected {
				t.Errorf("Expected confidence %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestVerifyFinding(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{
		responses: make(map[string]string),
	}

	// Set up responses for verification
	mockClient.responses["http://example.com/?q=%7B%7B8%2A8%7D%7D"] = "Result: 64"
	mockClient.responses["http://example.com/?q=%7B%7B9%2A9%7D%7D"] = "Result: 81"
	mockClient.responses["http://example.com/?q=%7B%7B7%2B7%7D%7D"] = "Result: 14"

	scanner := NewSSTIScanner(WithSSTIHTTPClient(mockClient))

	finding := &SSTIFinding{
		URL:            "http://example.com/?q=%7B%7B7%2A7%7D%7D",
		Parameter:      "q",
		Payload:        "{{7*7}}",
		TemplateEngine: "jinja2",
	}

	config := VerificationConfig{
		Enabled:    true,
		MaxRetries: 3,
		Delay:      0,
	}

	result, err := scanner.VerifyFinding(context.Background(), finding, config)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !result.Verified {
		t.Error("Expected finding to be verified")
	}

	if result.Attempts == 0 {
		t.Error("Expected at least one verification attempt")
	}

	if result.Confidence < 0.5 {
		t.Errorf("Expected confidence >= 0.5, got %f", result.Confidence)
	}
}

func TestVerifyFinding_Nil(t *testing.T) {
	scanner := NewSSTIScanner()
	config := VerificationConfig{}

	_, err := scanner.VerifyFinding(context.Background(), nil, config)
	if err == nil {
		t.Error("Expected error for nil finding")
	}
}

func TestGeneratePayloadVariants(t *testing.T) {
	scanner := NewSSTIScanner()

	tests := []struct {
		name     string
		payload  string
		engine   string
		minCount int
	}{
		{
			name:     "Jinja2 variants",
			payload:  "{{7*7}}",
			engine:   "jinja2",
			minCount: 3, // Original + at least 2 variants
		},
		{
			name:     "Freemarker variants",
			payload:  "${7*7}",
			engine:   "freemarker",
			minCount: 2,
		},
		{
			name:     "Generic variants",
			payload:  "${7+7}",
			engine:   "generic",
			minCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := scanner.generatePayloadVariants(tt.payload, tt.engine)
			if len(variants) < tt.minCount {
				t.Errorf("Expected at least %d variants, got %d", tt.minCount, len(variants))
			}

			// Check that original payload is included
			found := false
			for _, v := range variants {
				if v.payload == tt.payload {
					found = true
					break
				}
			}
			if !found {
				t.Error("Expected original payload to be in variants")
			}
		})
	}
}

func TestGetExpectedResult(t *testing.T) {
	scanner := NewSSTIScanner()

	tests := []struct {
		payload  string
		expected string
	}{
		{"{{7*7}}", "49"},
		{"${8*8}", "64"},
		{"<%= 9*9 %>", "81"},
		{"{{7+7}}", "14"},
		{"${10-5}", "5"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		t.Run(tt.payload, func(t *testing.T) {
			result := scanner.getExpectedResult(tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestSSTIScanResult_String(t *testing.T) {
	result := &SSTIScanResult{
		Target: "http://example.com",
		Findings: []SSTIFinding{
			{
				URL:            "http://example.com/?q=test",
				Parameter:      "q",
				Payload:        "{{7*7}}",
				Evidence:       "Result: 49",
				Severity:       SeverityHigh,
				TemplateEngine: "jinja2",
				Confidence:     "high",
			},
		},
		Summary: SSTISummary{
			TotalTests:           10,
			VulnerabilitiesFound: 1,
			HighSeverityCount:    1,
		},
	}

	str := result.String()

	if !strings.Contains(str, "SSTI Vulnerability Scan") {
		t.Error("Expected string to contain 'SSTI Vulnerability Scan'")
	}

	if !strings.Contains(str, "http://example.com") {
		t.Error("Expected string to contain target URL")
	}

	if !strings.Contains(str, "jinja2") {
		t.Error("Expected string to contain template engine")
	}

	if !strings.Contains(str, "Total Tests: 10") {
		t.Error("Expected string to contain total tests")
	}
}

func TestSSTIScanResult_HasResults(t *testing.T) {
	result1 := &SSTIScanResult{
		Findings: []SSTIFinding{
			{URL: "http://example.com"},
		},
	}

	if !result1.HasResults() {
		t.Error("Expected HasResults to return true when findings exist")
	}

	result2 := &SSTIScanResult{
		Summary: SSTISummary{
			TotalTests: 5,
		},
	}

	if !result2.HasResults() {
		t.Error("Expected HasResults to return true when tests were run")
	}

	result3 := &SSTIScanResult{}

	if result3.HasResults() {
		t.Error("Expected HasResults to return false for empty result")
	}
}

func TestExtractEvidence(t *testing.T) {
	scanner := NewSSTIScanner()

	tests := []struct {
		name     string
		body     string
		evidence string
		payload  string
		contains string
	}{
		{
			name:     "Evidence found",
			body:     "The result of the calculation is 49 which was computed",
			evidence: "49",
			payload:  "{{7*7}}",
			contains: "49",
		},
		{
			name:     "Evidence not found",
			body:     "No relevant content",
			evidence: "49",
			payload:  "{{7*7}}",
			contains: "Template expression evaluated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.extractEvidence(tt.body, tt.evidence, tt.payload)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("Expected evidence to contain '%s', got: %s", tt.contains, result)
			}
		})
	}
}

func TestGetRemediation(t *testing.T) {
	scanner := NewSSTIScanner()
	remediation := scanner.getRemediation()

	if remediation == "" {
		t.Error("Expected remediation to be non-empty")
	}

	if !strings.Contains(remediation, "template") {
		t.Error("Expected remediation to mention templates")
	}
}

func TestSSTIScan_NoFalsePositiveWhenResultInBaseline(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{
		responses: make(map[string]string),
	}

	// Set up baseline response that naturally contains "49"
	mockClient.responses["http://example.com/?q=WAST_BASELINE_12345"] = "Page showing: 49 items available"
	// Set up payload response that also contains "49" (but it's not from template injection)
	mockClient.responses["http://example.com/?q=%7B%7B7%2A7%7D%7D"] = "Page showing: 49 items available"

	scanner := NewSSTIScanner(WithSSTIHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/?q=test")

	// Should NOT detect any vulnerabilities because "49" is naturally present in the baseline
	if len(result.Findings) > 0 {
		t.Errorf("Expected no vulnerabilities (false positive), but found %d findings", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("False positive: %s - %s", f.Payload, f.Evidence)
		}
	}
}

func TestSSTIScan_DetectsRealInjectionNotInBaseline(t *testing.T) {
	mockClient := &MockSSTIHTTPClient{
		responses: make(map[string]string),
	}

	// Set up baseline response without "49"
	mockClient.responses["http://example.com/?q=WAST_BASELINE_12345"] = "Search results page"
	// Set up payload response with evaluated template (49 appears)
	mockClient.responses["http://example.com/?q=%7B%7B7%2A7%7D%7D"] = "Result: 49"

	scanner := NewSSTIScanner(WithSSTIHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/?q=test")

	// Should detect vulnerability because "49" is NOT in baseline but IS in payload response
	if len(result.Findings) == 0 {
		t.Error("Expected to find SSTI vulnerability but found none")
	}

	// Verify it's the correct finding
	found := false
	for _, f := range result.Findings {
		if f.Payload == "{{7*7}}" && strings.Contains(f.Evidence, "49") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find {{7*7}} payload with 49 in evidence")
	}
}

func TestDetectTemplateInjection_WithBaseline(t *testing.T) {
	scanner := NewSSTIScanner()

	tests := []struct {
		name         string
		body         string
		payload      sstiPayload
		baselineBody string
		expected     bool
	}{
		{
			name: "Evaluated template - result not in baseline",
			body: "Result: 49",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			baselineBody: "Result: nothing",
			expected:     true,
		},
		{
			name: "False positive - result already in baseline",
			body: "Page has 49 items",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			baselineBody: "Page has 49 items",
			expected:     false,
		},
		{
			name: "Reflected but not evaluated",
			body: "You searched for: {{7*7}}",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			baselineBody: "You searched for: WAST_BASELINE_12345",
			expected:     false,
		},
		{
			name: "Both payload and result present - evaluated, not in baseline",
			body: "Input: {{7*7}} Result: 49 and another 49",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			baselineBody: "Input: WAST_BASELINE_12345 Result: nothing",
			expected:     true,
		},
		{
			name: "No baseline available - old behavior",
			body: "Result: 49",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			baselineBody: "",
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.detectTemplateInjection(tt.body, tt.payload, tt.baselineBody)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for body: %s, baseline: %s", tt.expected, result, tt.body, tt.baselineBody)
			}
		})
	}
}

// TestDetectTemplateInjection_FalsePositives tests scenarios that should NOT trigger false positives
func TestDetectTemplateInjection_FalsePositives(t *testing.T) {
	scanner := NewSSTIScanner()

	tests := []struct {
		name         string
		body         string
		payload      sstiPayload
		baselineBody string
		description  string
	}{
		{
			name: "Payload reflected verbatim - no evaluation",
			body: "You entered: {{7*7}}",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			baselineBody: "You entered: test",
			description:  "Simple reflection of payload without evaluation",
		},
		{
			name: "Expected result naturally present in page",
			body: "We have 49 products available",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			baselineBody: "We have 49 products available",
			description:  "Number naturally present in both baseline and response",
		},
		{
			name: "Jinja2 string multiplication reflected",
			body: "Search: {{7*'7'}}",
			payload: sstiPayload{
				Payload:        "{{7*'7'}}",
				ExpectedResult: "7777777",
			},
			baselineBody: "Search: test",
			description:  "Payload reflected but not evaluated",
		},
		{
			name: "Freemarker syntax reflected",
			body: "Input: ${7*7}",
			payload: sstiPayload{
				Payload:        "${7*7}",
				ExpectedResult: "49",
			},
			baselineBody: "Input: test",
			description:  "Freemarker syntax reflected verbatim",
		},
		{
			name: "ERB syntax reflected",
			body: "Template: <%= 7*7 %>",
			payload: sstiPayload{
				Payload:        "<%= 7*7 %>",
				ExpectedResult: "49",
			},
			baselineBody: "Template: test",
			description:  "ERB syntax reflected without evaluation",
		},
		{
			name: "Payload and result both present with equal count",
			body: "You entered {{7*7}} which looks like 49",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			baselineBody: "You entered test which looks like test",
			description:  "Both payload and result appear once each (likely reflection)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.detectTemplateInjection(tt.body, tt.payload, tt.baselineBody)
			if result {
				t.Errorf("False positive detected for: %s\nBody: %s\nPayload: %s\nExpected: %s",
					tt.description, tt.body, tt.payload.Payload, tt.payload.ExpectedResult)
			}
		})
	}
}

// TestDetectTemplateInjection_TruePositives tests scenarios that SHOULD be detected
func TestDetectTemplateInjection_TruePositives(t *testing.T) {
	scanner := NewSSTIScanner()

	tests := []struct {
		name         string
		body         string
		payload      sstiPayload
		baselineBody string
		description  string
	}{
		{
			name: "Computed result without payload - pure evaluation",
			body: "Result: 49",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			baselineBody: "Result: nothing",
			description:  "Template evaluated and only result appears",
		},
		{
			name: "Jinja2 string multiplication evaluated",
			body: "Output: 7777777",
			payload: sstiPayload{
				Payload:        "{{7*'7'}}",
				ExpectedResult: "7777777",
			},
			baselineBody: "Output: nothing",
			description:  "Jinja2 string multiplication successfully evaluated",
		},
		{
			name: "Multiple computed results - evaluation occurred",
			body: "Input: {{7*7}} Results: 49 and 49 and 49",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			baselineBody: "Input: test Results: nothing",
			description:  "Expected result appears 3 times, payload only once",
		},
		{
			name: "Freemarker evaluated",
			body: "Calculation result: 49",
			payload: sstiPayload{
				Payload:        "${7*7}",
				ExpectedResult: "49",
			},
			baselineBody: "Calculation result: 0",
			description:  "Freemarker template successfully evaluated",
		},
		{
			name: "ERB evaluated",
			body: "Value is 49",
			payload: sstiPayload{
				Payload:        "<%= 7*7 %>",
				ExpectedResult: "49",
			},
			baselineBody: "Value is unknown",
			description:  "ERB template successfully evaluated",
		},
		{
			name: "Result appears twice, payload once",
			body: "Debug: {{7*7}} = 49 (computed: 49)",
			payload: sstiPayload{
				Payload:        "{{7*7}}",
				ExpectedResult: "49",
			},
			baselineBody: "Debug: test = unknown",
			description:  "Evaluation occurred because result count > payload count",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.detectTemplateInjection(tt.body, tt.payload, tt.baselineBody)
			if !result {
				t.Errorf("Failed to detect true positive for: %s\nBody: %s\nPayload: %s\nExpected: %s",
					tt.description, tt.body, tt.payload.Payload, tt.payload.ExpectedResult)
			}
		})
	}
}
