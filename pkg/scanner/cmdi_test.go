package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// mockCMDiHTTPClient is a mock HTTP client for testing command injection detection.
type mockCMDiHTTPClient struct {
	responses map[string]*mockCMDiResponse
}

type mockCMDiResponse struct {
	statusCode int
	body       string
	delay      time.Duration
}

func (m *mockCMDiHTTPClient) Do(req *http.Request) (*http.Response, error) {
	url := req.URL.String()

	// Simulate delay if configured
	if resp, ok := m.responses[url]; ok {
		if resp.delay > 0 {
			time.Sleep(resp.delay)
		}

		return &http.Response{
			StatusCode: resp.statusCode,
			Body:       io.NopCloser(strings.NewReader(resp.body)),
		}, nil
	}

	// Default response
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("OK")),
	}, nil
}

func TestNewCMDiScanner(t *testing.T) {
	scanner := NewCMDiScanner()

	if scanner == nil {
		t.Fatal("Expected scanner to be created")
	}

	if scanner.userAgent == "" {
		t.Error("Expected default user agent to be set")
	}

	if scanner.timeout == 0 {
		t.Error("Expected default timeout to be set")
	}

	if scanner.timeBasedDelay != 5*time.Second {
		t.Errorf("Expected default time-based delay to be 5s, got %v", scanner.timeBasedDelay)
	}
}

func TestCMDiScanner_ErrorBasedDetection_Unix(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?cmd=test": {
				statusCode: 200,
				body:       "Normal response",
			},
			"http://example.com/test?cmd=%3Bid": {
				statusCode: 500,
				body:       "sh: 1: badcommand: not found\nError executing command",
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?cmd=test")

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	// Should detect at least one vulnerability
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find at least one command injection vulnerability")
	}

	// Check that we found a Unix-based vulnerability
	foundUnix := false
	for _, finding := range result.Findings {
		if finding.OSType == "unix" && finding.Type == "error-based" {
			foundUnix = true
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
			}
			if finding.Confidence != "high" {
				t.Errorf("Expected confidence high, got %s", finding.Confidence)
			}
		}
	}

	if !foundUnix {
		t.Error("Expected to find Unix command injection vulnerability")
	}
}

func TestCMDiScanner_ErrorBasedDetection_Windows(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?cmd=test": {
				statusCode: 200,
				body:       "Normal response",
			},
			"http://example.com/test?cmd=%26+dir": {
				statusCode: 500,
				body:       "'badcommand' is not recognized as an internal or external command",
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?cmd=test")

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find at least one command injection vulnerability")
	}

	// Check that we found a Windows-based vulnerability
	foundWindows := false
	for _, finding := range result.Findings {
		if finding.OSType == "windows" && finding.Type == "error-based" {
			foundWindows = true
			if finding.Evidence == "" {
				t.Error("Expected evidence to be captured")
			}
		}
	}

	if !foundWindows {
		t.Error("Expected to find Windows command injection vulnerability")
	}
}

func TestCMDiScanner_TimeBasedDetection_Unix(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?cmd=test": {
				statusCode: 200,
				body:       "Normal response",
				delay:      100 * time.Millisecond, // Baseline delay
			},
			"http://example.com/test?cmd=%3Bsleep+5": {
				statusCode: 200,
				body:       "Delayed response",
				delay:      5100 * time.Millisecond, // Baseline + 5 seconds
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?cmd=test")

	// Should detect time-based command injection
	foundTimeBased := false
	for _, finding := range result.Findings {
		if finding.Type == "time-based" && finding.OSType == "unix" {
			foundTimeBased = true
			if !strings.Contains(finding.Evidence, "Request took") {
				t.Error("Expected timing evidence to be captured")
			}
			if finding.Confidence != "high" {
				t.Errorf("Expected high confidence for time-based detection, got %s", finding.Confidence)
			}
		}
	}

	if !foundTimeBased {
		t.Error("Expected to find time-based command injection vulnerability")
	}
}

func TestCMDiScanner_TimeBasedDetection_Windows(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?cmd=test": {
				statusCode: 200,
				body:       "Normal response",
				delay:      50 * time.Millisecond,
			},
			"http://example.com/test?cmd=%26timeout+5": {
				statusCode: 200,
				body:       "Delayed response",
				delay:      5050 * time.Millisecond, // Baseline + 5 seconds
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?cmd=test")

	foundTimeBased := false
	for _, finding := range result.Findings {
		if finding.Type == "time-based" && finding.OSType == "windows" {
			foundTimeBased = true
			if finding.Payload != "&timeout 5" {
				t.Errorf("Expected Windows timeout payload, got %s", finding.Payload)
			}
		}
	}

	if !foundTimeBased {
		t.Error("Expected to find Windows time-based command injection")
	}
}

func TestCMDiScanner_URLEncodedPayloads(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?cmd=test": {
				statusCode: 200,
				body:       "Normal response",
			},
			"http://example.com/test?cmd=%3Bsleep+5": {
				statusCode: 200,
				body:       "Delayed response",
				delay:      5000 * time.Millisecond,
			},
			"http://example.com/test?cmd=%7Csleep+5": {
				statusCode: 200,
				body:       "Delayed response",
				delay:      5000 * time.Millisecond,
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?cmd=test")

	// Should detect URL-encoded payloads
	foundEncoded := false
	for _, finding := range result.Findings {
		if strings.Contains(finding.Payload, "%") {
			foundEncoded = true
			if finding.Type != "time-based" {
				t.Errorf("Expected time-based type for URL-encoded payload, got %s", finding.Type)
			}
		}
	}

	if !foundEncoded {
		t.Error("Expected to find URL-encoded command injection")
	}
}

func TestCMDiScanner_NoVulnerabilities(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?cmd=test")

	if result.Summary.VulnerabilitiesFound != 0 {
		t.Errorf("Expected no vulnerabilities, found %d", result.Summary.VulnerabilitiesFound)
	}

	if result.Summary.HighSeverityCount != 0 {
		t.Error("Expected no high severity findings")
	}
}

func TestCMDiScanner_VulnerableParameters(t *testing.T) {
	// Test without any query parameters - should test common vulnerable param names
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test")

	// Should test common vulnerable parameters
	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run for common vulnerable parameters")
	}
}

func TestCMDiScanner_MultipleInjectionTypes(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?cmd=test": {
				statusCode: 200,
				body:       "Normal response",
				delay:      100 * time.Millisecond,
			},
			"http://example.com/test?cmd=%3Bid": {
				statusCode: 500,
				body:       "/bin/sh: 1: badcmd: not found",
			},
			"http://example.com/test?cmd=%3Bsleep+5": {
				statusCode: 200,
				body:       "Delayed",
				delay:      5100 * time.Millisecond,
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?cmd=test")

	// Should detect both error-based and time-based
	hasErrorBased := false
	hasTimeBased := false

	for _, finding := range result.Findings {
		if finding.Type == "error-based" {
			hasErrorBased = true
		}
		if finding.Type == "time-based" {
			hasTimeBased = true
		}
	}

	if !hasErrorBased {
		t.Error("Expected to find error-based command injection")
	}

	if !hasTimeBased {
		t.Error("Expected to find time-based command injection")
	}
}

func TestCMDiScanner_CalculateSummary(t *testing.T) {
	result := &CMDiScanResult{
		Findings: []CMDiFinding{
			{Severity: SeverityHigh},
			{Severity: SeverityHigh},
			{Severity: SeverityMedium},
			{Severity: SeverityLow},
		},
	}

	scanner := NewCMDiScanner()
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

func TestCMDiScanner_String(t *testing.T) {
	result := &CMDiScanResult{
		Target: "http://example.com",
		Findings: []CMDiFinding{
			{
				Parameter:   "cmd",
				Payload:     ";id",
				Severity:    SeverityHigh,
				Type:        "error-based",
				OSType:      "unix",
				Description: "Command injection detected",
				Evidence:    "/bin/sh: not found",
				Confidence:  "high",
				Remediation: "Use parameterized APIs",
			},
		},
		Summary: CMDiSummary{
			TotalTests:           10,
			VulnerabilitiesFound: 1,
			HighSeverityCount:    1,
		},
	}

	output := result.String()

	if !strings.Contains(output, "Command Injection Vulnerability Scan") {
		t.Error("Expected output to contain title")
	}

	if !strings.Contains(output, "http://example.com") {
		t.Error("Expected output to contain target URL")
	}

	if !strings.Contains(output, "cmd") {
		t.Error("Expected output to contain parameter name")
	}

	if !strings.Contains(output, ";id") {
		t.Error("Expected output to contain payload")
	}
}

func TestCMDiScanner_HasResults(t *testing.T) {
	// Result with findings
	result1 := &CMDiScanResult{
		Findings: []CMDiFinding{
			{Parameter: "cmd", Payload: ";id"},
		},
	}

	if !result1.HasResults() {
		t.Error("Expected HasResults to return true when findings exist")
	}

	// Result with tests but no findings
	result2 := &CMDiScanResult{
		Summary: CMDiSummary{TotalTests: 10},
	}

	if !result2.HasResults() {
		t.Error("Expected HasResults to return true when tests were run")
	}

	// Empty result
	result3 := &CMDiScanResult{}

	if result3.HasResults() {
		t.Error("Expected HasResults to return false for empty result")
	}
}

func TestCMDiScanner_VerifyFinding(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?cmd=test": {
				statusCode: 200,
				body:       "Normal response",
				delay:      100 * time.Millisecond,
			},
			"http://example.com/test?cmd=%3Bid": {
				statusCode: 500,
				body:       "/bin/sh: 1: badcmd: not found",
			},
			"http://example.com/test?cmd=%26%26id": {
				statusCode: 500,
				body:       "/bin/sh: 1: badcmd: not found",
			},
			"http://example.com/test?cmd=%7Cwhoami": {
				statusCode: 500,
				body:       "/bin/sh: 1: badcmd: not found",
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))

	finding := &CMDiFinding{
		URL:       "http://example.com/test?cmd=%3Bid",
		Parameter: "cmd",
		Payload:   ";id",
		Type:      "error-based",
		OSType:    "unix",
	}

	config := VerificationConfig{
		Enabled:    true,
		MaxRetries: 3,
		Delay:      10 * time.Millisecond,
	}

	result, err := scanner.VerifyFinding(context.Background(), finding, config)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !result.Verified {
		t.Error("Expected finding to be verified")
	}

	if result.Confidence < 0.5 {
		t.Errorf("Expected confidence >= 0.5, got %f", result.Confidence)
	}

	if result.Attempts == 0 {
		t.Error("Expected verification attempts to be recorded")
	}
}

func TestCMDiScanner_VerifyFinding_TimeBased(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?cmd=test": {
				statusCode: 200,
				body:       "Normal",
				delay:      50 * time.Millisecond,
			},
			"http://example.com/test?cmd=%3Bsleep+5": {
				statusCode: 200,
				body:       "Delayed",
				delay:      5050 * time.Millisecond,
			},
			"http://example.com/test?cmd=%3BSLEEP+5": {
				statusCode: 200,
				body:       "Delayed",
				delay:      5050 * time.Millisecond,
			},
			"http://example.com/test?cmd=%26%26sleep+5": {
				statusCode: 200,
				body:       "Delayed",
				delay:      5050 * time.Millisecond,
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))

	finding := &CMDiFinding{
		URL:       "http://example.com/test?cmd=%3Bsleep+5",
		Parameter: "cmd",
		Payload:   ";sleep 5",
		Type:      "time-based",
		OSType:    "unix",
	}

	config := VerificationConfig{
		Enabled:    true,
		MaxRetries: 3,
		Delay:      10 * time.Millisecond,
	}

	result, err := scanner.VerifyFinding(context.Background(), finding, config)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !result.Verified {
		t.Error("Expected time-based finding to be verified")
	}

	if result.Confidence < 0.5 {
		t.Errorf("Expected confidence >= 0.5, got %f", result.Confidence)
	}
}

func TestCMDiScanner_GeneratePayloadVariants(t *testing.T) {
	scanner := NewCMDiScanner()

	// Test semicolon separator
	variants := scanner.generateCMDiPayloadVariants(";sleep 5", "time-based")

	if len(variants) == 0 {
		t.Error("Expected variants to be generated")
	}

	// Should include original
	foundOriginal := false
	for _, v := range variants {
		if v == ";sleep 5" {
			foundOriginal = true
			break
		}
	}
	if !foundOriginal {
		t.Error("Expected original payload in variants")
	}

	// Should include separator variants
	foundAnd := false
	for _, v := range variants {
		if v == "&&sleep 5" {
			foundAnd = true
			break
		}
	}
	if !foundAnd {
		t.Error("Expected separator variant with &&")
	}

	// Test URL encoding
	variants2 := scanner.generateCMDiPayloadVariants(";id", "error-based")
	foundEncoded := false
	for _, v := range variants2 {
		if strings.Contains(v, "%") {
			foundEncoded = true
			break
		}
	}
	if !foundEncoded {
		t.Error("Expected URL-encoded variant")
	}
}

func TestCMDiScanner_InvalidURL(t *testing.T) {
	scanner := NewCMDiScanner()
	result := scanner.Scan(context.Background(), "://invalid-url")

	if len(result.Errors) == 0 {
		t.Error("Expected error for invalid URL")
	}

	if result.Summary.VulnerabilitiesFound != 0 {
		t.Error("Expected no vulnerabilities for invalid URL")
	}
}

func TestCMDiScanner_ContextCancellation(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := scanner.Scan(ctx, "http://example.com/test?cmd=test")

	// Should handle cancellation gracefully
	if len(result.Errors) == 0 {
		t.Error("Expected error for cancelled context")
	}
}

func TestCMDiScanner_RateLimiting(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?cmd=test": {
				statusCode: http.StatusTooManyRequests,
				body:       "Rate limited",
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?cmd=test")

	// Should handle rate limiting gracefully (no findings from rate-limited responses)
	if result.Summary.VulnerabilitiesFound != 0 {
		t.Error("Expected no vulnerabilities when rate limited")
	}
}

func TestCMDiScanner_Options(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{}

	scanner := NewCMDiScanner(
		WithCMDiHTTPClient(mockClient),
		WithCMDiUserAgent("TestAgent"),
		WithCMDiTimeout(60*time.Second),
		WithCMDiTimeBasedDelay(10*time.Second),
	)

	if scanner.client != mockClient {
		t.Error("Expected custom HTTP client to be set")
	}

	if scanner.userAgent != "TestAgent" {
		t.Errorf("Expected user agent TestAgent, got %s", scanner.userAgent)
	}

	if scanner.timeout != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", scanner.timeout)
	}

	if scanner.timeBasedDelay != 10*time.Second {
		t.Errorf("Expected time-based delay 10s, got %v", scanner.timeBasedDelay)
	}
}
