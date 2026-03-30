package scanner

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
			"http://example.com/test?cmd=%3B+sleep+5": {
				statusCode: 200,
				body:       "Delayed response",
				delay:      5000 * time.Millisecond,
			},
			"http://example.com/test?cmd=%7C+sleep+5": {
				statusCode: 200,
				body:       "Delayed response",
				delay:      5000 * time.Millisecond,
			},
			"http://example.com/test?cmd=%26%26+sleep+5": {
				statusCode: 200,
				body:       "Delayed response",
				delay:      5000 * time.Millisecond,
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?cmd=test")

	// Should detect payloads that get URL-encoded (contain special chars that will be encoded)
	foundSpacedPayload := false
	for _, finding := range result.Findings {
		// Check for payloads with spaces that would be URL-encoded
		if strings.Contains(finding.Payload, "; sleep") ||
			strings.Contains(finding.Payload, "| sleep") ||
			strings.Contains(finding.Payload, "&& sleep") {
			foundSpacedPayload = true
			if finding.Type != "time-based" {
				t.Errorf("Expected time-based type for spaced payload, got %s", finding.Type)
			}
		}
	}

	if !foundSpacedPayload {
		t.Error("Expected to find command injection with spaced payloads that get URL-encoded")
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
			"http://example.com/test?cmd=%7Csleep+5": {
				statusCode: 200,
				body:       "Delayed",
				delay:      5050 * time.Millisecond,
			},
			"http://example.com/test?cmd=%3Bsleep+6": {
				statusCode: 200,
				body:       "Delayed",
				delay:      6050 * time.Millisecond,
			},
			"http://example.com/test?cmd=%3Bsleep+4": {
				statusCode: 200,
				body:       "Delayed",
				delay:      4050 * time.Millisecond,
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))

	finding := &CMDiFinding{
		URL:       "http://example.com/test?cmd=test",
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

func TestCMDiScanner_OutputBasedDetection_Unix(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?ip=test": {
				statusCode: 200,
				body:       "Normal response without command output",
			},
			"http://example.com/test?ip=127.0.0.1%3B+id": {
				statusCode: 200,
				body:       "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
			},
			"http://example.com/test?ip=127.0.0.1+%26%26+whoami": {
				statusCode: 200,
				body:       "www-data",
			},
			"http://example.com/test?ip=test%3B+whoami": {
				statusCode: 200,
				body:       "uid=1000(testuser) gid=1000(testuser)",
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?ip=test")

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	// Should detect output-based command injection
	foundOutputBased := false
	for _, finding := range result.Findings {
		if finding.Type == "output-based" && finding.OSType == "unix" {
			foundOutputBased = true
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
			}
			if finding.Confidence != "high" {
				t.Errorf("Expected confidence high, got %s", finding.Confidence)
			}
			if finding.Evidence == "" {
				t.Error("Expected evidence to be captured")
			}
			// Check that the payload contains command injection patterns
			if !strings.Contains(finding.Payload, "id") && !strings.Contains(finding.Payload, "whoami") {
				t.Errorf("Expected payload to contain command, got %s", finding.Payload)
			}
		}
	}

	if !foundOutputBased {
		t.Error("Expected to find output-based Unix command injection vulnerability")
	}
}

func TestCMDiScanner_OutputBasedDetection_Windows(t *testing.T) {
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?cmd=test": {
				statusCode: 200,
				body:       "Normal response",
			},
			"http://example.com/test?cmd=127.0.0.1+%26+whoami": {
				statusCode: 200,
				body:       "NT AUTHORITY\\SYSTEM",
			},
			"http://example.com/test?cmd=test+%26+whoami": {
				statusCode: 200,
				body:       "BUILTIN\\Administrators",
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?cmd=test")

	// Should detect output-based Windows command injection
	foundOutputBased := false
	for _, finding := range result.Findings {
		if finding.Type == "output-based" && finding.OSType == "windows" {
			foundOutputBased = true
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
			}
			if finding.Evidence == "" {
				t.Error("Expected evidence to be captured")
			}
			// Evidence should contain Windows-specific patterns
			if !strings.Contains(finding.Evidence, "NT AUTHORITY") && !strings.Contains(finding.Evidence, "BUILTIN") {
				t.Errorf("Expected Windows-specific evidence, got %s", finding.Evidence)
			}
		}
	}

	if !foundOutputBased {
		t.Error("Expected to find output-based Windows command injection vulnerability")
	}
}

func TestCMDiScanner_OutputBasedDetectionPOST(t *testing.T) {
	// Create a custom mock client for POST testing
	mockClient := &mockCMDiHTTPClientPOST{}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	params := map[string]string{
		"ip": "127.0.0.1",
	}
	result := scanner.ScanPOST(context.Background(), "http://example.com/exec", params)

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	// Should detect output-based command injection in POST
	foundOutputBased := false
	for _, finding := range result.Findings {
		if finding.Type == "output-based" {
			foundOutputBased = true
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
			}
			if finding.Confidence != "high" {
				t.Errorf("Expected confidence high, got %s", finding.Confidence)
			}
			if finding.Evidence == "" {
				t.Error("Expected evidence to be captured")
			}
			// Verify the evidence contains command output patterns
			if !strings.Contains(finding.Evidence, "uid=") && !strings.Contains(finding.Evidence, "gid=") {
				t.Errorf("Expected evidence to contain command output, got %s", finding.Evidence)
			}
		}
	}

	if !foundOutputBased {
		t.Error("Expected to find output-based command injection vulnerability in POST")
	}
}

// mockCMDiHTTPClientPOST is a custom mock for POST testing with output-based detection
type mockCMDiHTTPClientPOST struct{}

func (m *mockCMDiHTTPClientPOST) Do(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost {
		// Read the form data
		body, _ := io.ReadAll(req.Body)
		formData := string(body)

		// Check if the payload contains command injection
		if strings.Contains(formData, "127.0.0.1%3B+id") || strings.Contains(formData, "127.0.0.1;+id") ||
			strings.Contains(formData, "127.0.0.1%3B%20id") {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("uid=33(www-data) gid=33(www-data) groups=33(www-data)")),
			}, nil
		}
		if strings.Contains(formData, "test+%26%26+whoami") || strings.Contains(formData, "test+&&+whoami") ||
			strings.Contains(formData, "test%26%26whoami") {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("uid=1000(testuser) gid=1000(testuser)")),
			}, nil
		}

		// Default response for baseline
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("Normal response")),
		}, nil
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("OK")),
	}, nil
}

func TestCMDiScanner_OutputBasedDetection_NoDifferential(t *testing.T) {
	// Test that output patterns in baseline don't trigger false positives
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{
			"http://example.com/test?user=test": {
				statusCode: 200,
				body:       "User info: uid=1000(testuser) gid=1000(testuser) - this is legitimate content",
			},
			"http://example.com/test?user=127.0.0.1%3B+id": {
				statusCode: 200,
				body:       "User info: uid=1000(testuser) gid=1000(testuser) - this is legitimate content",
			},
		},
	}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?user=test")

	// Should NOT detect false positives when output pattern exists in baseline
	for _, finding := range result.Findings {
		if finding.Type == "output-based" {
			t.Errorf("Found false positive output-based detection: %v", finding)
		}
	}
}

// TestCMDiScanner_DVWALikeExecPOST tests detection of command injection on DVWA-like exec endpoint
// that accepts a POST parameter 'ip' and passes it to shell_exec() for ping command.
// This simulates DVWA's /vulnerabilities/exec/ endpoint behavior.
func TestCMDiScanner_DVWALikeExecPOST(t *testing.T) {
	// Create a custom mock client that simulates DVWA exec endpoint behavior
	mockClient := &mockDVWAExecHTTPClient{}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	params := map[string]string{
		"ip": "127.0.0.1",
	}
	result := scanner.ScanPOST(context.Background(), "http://localhost:8080/vulnerabilities/exec/", params)

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	// Should detect output-based command injection when whoami/id appended to valid IP
	foundOutputBased := false
	for _, finding := range result.Findings {
		if finding.Type == "output-based" && finding.Parameter == "ip" {
			foundOutputBased = true
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
			}
			if finding.Confidence != "high" {
				t.Errorf("Expected confidence high, got %s", finding.Confidence)
			}
			if finding.Evidence == "" {
				t.Error("Expected evidence to be captured")
			}
			t.Logf("Detected DVWA-like vulnerability: payload=%s, evidence=%s", finding.Payload, finding.Evidence)
		}
	}

	if !foundOutputBased {
		t.Error("Expected to find output-based command injection on DVWA-like exec endpoint")
	}
}

// mockDVWAExecHTTPClient simulates DVWA's /vulnerabilities/exec/ endpoint behavior:
// - Valid IP (127.0.0.1) returns ping output
// - Injected command (127.0.0.1; whoami) returns ping output + username
// - Injected command (127.0.0.1; id) returns ping output + uid/gid info
type mockDVWAExecHTTPClient struct{}

// TestCMDiScanner_DVWALikeExecPOST_WithHTMLPageStructure tests that the scanner
// correctly handles DVWA pages where the username might appear in the page header/footer
// (e.g., "Logged in as www-data") and doesn't cause false negatives due to differential analysis.
func TestCMDiScanner_DVWALikeExecPOST_WithHTMLPageStructure(t *testing.T) {
	// Create a custom mock client that simulates DVWA with HTML page structure
	mockClient := &mockDVWAExecHTMLHTTPClient{}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	params := map[string]string{
		"ip":     "127.0.0.1",
		"Submit": "Submit",
	}
	result := scanner.ScanPOST(context.Background(), "http://localhost:8080/vulnerabilities/exec/", params)

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	// Should still detect output-based command injection even with HTML page structure
	foundOutputBased := false
	for _, finding := range result.Findings {
		if finding.Type == "output-based" && finding.Parameter == "ip" {
			foundOutputBased = true
			t.Logf("Detected vulnerability despite HTML structure: payload=%s, evidence=%s", finding.Payload, finding.Evidence)
		}
	}

	if !foundOutputBased {
		t.Error("Expected to find output-based command injection on DVWA-like exec endpoint with HTML page structure")
	}
}

// mockDVWAExecHTMLHTTPClient simulates DVWA's exec endpoint with realistic HTML page structure
// that includes the username in the page header/footer (a potential source of false negatives).
type mockDVWAExecHTMLHTTPClient struct{}

func (m *mockDVWAExecHTMLHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost {
		// Read the form data
		body, _ := io.ReadAll(req.Body)
		formData := string(body)

		// HTML page structure that's common to all responses (header with username, footer, etc.)
		htmlHeader := `<!DOCTYPE html>
<html>
<head><title>DVWA - Command Injection</title></head>
<body>
<div class="header">Logged in as: www-data | Security Level: low</div>
<div class="main">
<h1>Command Injection</h1>
<form method="POST">
Enter an IP address: <input name="ip" />
<input type="submit" name="Submit" value="Submit" />
</form>
<pre>`

		htmlFooter := `</pre>
</div>
<div class="footer">© DVWA Project | User: www-data</div>
</body>
</html>`

		// Baseline: valid IP returns only ping output (no command output patterns)
		if (strings.Contains(formData, "ip=127.0.0.1") || strings.Contains(formData, "ip=127.0.0.1")) &&
			!strings.Contains(formData, "%3B") && !strings.Contains(formData, ";") &&
			!strings.Contains(formData, "%26") && !strings.Contains(formData, "&") &&
			!strings.Contains(formData, "%7C") && !strings.Contains(formData, "|") {
			pingOutput := `PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.028 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.028/0.028/0.028/0.000 ms`
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(htmlHeader + pingOutput + htmlFooter)),
			}, nil
		}

		// Command injection: 127.0.0.1; whoami
		if strings.Contains(formData, "whoami") && strings.Contains(formData, "127.0.0.1") {
			cmdOutput := `PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.028 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.028/0.028/0.028/0.000 ms
www-data`
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(htmlHeader + cmdOutput + htmlFooter)),
			}, nil
		}

		// Command injection: 127.0.0.1; id
		if strings.Contains(formData, "id") && strings.Contains(formData, "127.0.0.1") {
			cmdOutput := `PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.028 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.028/0.028/0.028/0.000 ms
uid=33(www-data) gid=33(www-data) groups=33(www-data)`
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(htmlHeader + cmdOutput + htmlFooter)),
			}, nil
		}

		// Default baseline response
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(htmlHeader + "No output" + htmlFooter)),
		}, nil
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("OK")),
	}, nil
}

func (m *mockDVWAExecHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost {
		// Read the form data
		body, _ := io.ReadAll(req.Body)
		formData := string(body)

		// Baseline: valid IP returns only ping output
		if (strings.Contains(formData, "ip=127.0.0.1") || strings.Contains(formData, "ip=127.0.0.1")) &&
			!strings.Contains(formData, "%3B") && !strings.Contains(formData, ";") &&
			!strings.Contains(formData, "%26") && !strings.Contains(formData, "&") &&
			!strings.Contains(formData, "%7C") && !strings.Contains(formData, "|") {
			return &http.Response{
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(`PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.028 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.051 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.043 ms

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2037ms
rtt min/avg/max/mdev = 0.028/0.040/0.051/0.009 ms`)),
			}, nil
		}

		// Command injection: 127.0.0.1; whoami or similar patterns
		if (strings.Contains(formData, "whoami") || strings.Contains(formData, "WHOAMI")) &&
			(strings.Contains(formData, "127.0.0.1") || strings.Contains(formData, "test")) {
			return &http.Response{
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(`PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.028 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.028/0.028/0.028/0.000 ms
www-data`)),
			}, nil
		}

		// Command injection: 127.0.0.1; id
		if strings.Contains(formData, "id") && strings.Contains(formData, "127.0.0.1") {
			return &http.Response{
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(`PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.028 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.028/0.028/0.028/0.000 ms
uid=33(www-data) gid=33(www-data) groups=33(www-data)`)),
			}, nil
		}

		// Default baseline response
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("Normal response")),
		}, nil
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("OK")),
	}, nil
}

// TestIsSubmitButton verifies that the isSubmitButton helper correctly identifies
// common submit button parameter names.
func TestIsSubmitButton(t *testing.T) {
	tests := []struct {
		name     string
		param    string
		expected bool
	}{
		// Exact-match patterns (case-insensitive)
		{"exact Submit", "Submit", true},
		{"lowercase submit", "submit", true},
		{"go", "go", true},
		{"search", "search", true},
		{"action", "action", true},
		{"send", "send", true},
		// Prefix/suffix expansion patterns (btn, button)
		{"btn", "btn", true},
		{"btn_submit", "btn_submit", true},
		{"btn_primary should be submit", "btn_primary", true},
		{"button", "button", true},
		{"my_button should be submit", "my_button", true},
		// Ambiguous patterns: exact-match only, prefix/suffix must NOT match
		{"search_query should NOT be submit", "search_query", false},
		{"action_type should NOT be submit", "action_type", false},
		{"go_to should NOT be submit", "go_to", false},
		{"data_submit should NOT be submit", "data_submit", false},
		// Non-submit data field params
		{"ip param", "ip", false},
		{"cmd param", "cmd", false},
		{"username", "username", false},
		{"email", "email", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSubmitButton(tt.param)
			if got != tt.expected {
				t.Errorf("isSubmitButton(%q) = %v, want %v", tt.param, got, tt.expected)
			}
		})
	}
}

// TestCMDiScanner_ScanPOST_SkipsSubmitParams verifies that ScanPOST does not inject into
// submit-button parameters, only into actual data parameters.
func TestCMDiScanner_ScanPOST_SkipsSubmitParams(t *testing.T) {
	// Track which parameters payloads are tested against
	testedParams := make(map[string]bool)

	mockClient := &mockSubmitParamTrackingClient{testedParams: testedParams}
	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))

	params := map[string]string{
		"ip":     "127.0.0.1",
		"Submit": "Submit",
	}
	result := scanner.ScanPOST(context.Background(), "http://example.com/exec", params)

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	// Submit should NOT be tested
	if testedParams["Submit"] {
		t.Error("Expected Submit parameter to be skipped, but it was tested")
	}

	// ip SHOULD be tested
	if !testedParams["ip"] {
		t.Error("Expected ip parameter to be tested")
	}
}

// mockSubmitParamTrackingClient records which parameters receive injected payloads.
type mockSubmitParamTrackingClient struct {
	mu           sync.Mutex
	testedParams map[string]bool
}

func (m *mockSubmitParamTrackingClient) Do(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost {
		body, _ := io.ReadAll(req.Body)
		formData, _ := url.ParseQuery(string(body))
		// A parameter is "tested" when its value differs from the original values
		// (i.e. a payload has been injected). We detect this by checking for typical
		// payload indicators in each field.
		for k, vals := range formData {
			v := ""
			if len(vals) > 0 {
				v = vals[0]
			}
			// If the value contains shell metacharacters it's a payload, not an original value
			if strings.ContainsAny(v, ";|&`$()") {
				m.mu.Lock()
				m.testedParams[k] = true
				m.mu.Unlock()
			}
		}
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("Normal response")),
	}, nil
}

// TestCMDiScanner_BaselineUsesDefaultForEmptyParam verifies that when a parameter
// has an empty string value, the baseline request substitutes a benign placeholder
// so that differential analysis works correctly.
func TestCMDiScanner_BaselineUsesDefaultForEmptyParam(t *testing.T) {
	// Record what value the baseline request sends for the "ip" parameter
	var baselineIPValue string
	mockClient := &mockBaselineValueCapturingClient{capturedValues: &baselineIPValue}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))

	// ip has an empty string value — simulates a form with no default
	params := map[string]string{
		"ip": "",
	}
	scanner.ScanPOST(context.Background(), "http://example.com/exec", params)

	// The baseline should NOT have sent an empty ip value
	if baselineIPValue == "" {
		t.Error("Expected baseline to use a non-empty default value for empty parameter, got empty string")
	}
}

// mockBaselineValueCapturingClient captures the value of the "ip" parameter on the
// first (baseline) POST request.
type mockBaselineValueCapturingClient struct {
	capturedValues *string
	callCount      int
}

func (m *mockBaselineValueCapturingClient) Do(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost && m.callCount == 0 {
		body, _ := io.ReadAll(req.Body)
		formData, _ := url.ParseQuery(string(body))
		if vals, ok := formData["ip"]; ok && len(vals) > 0 {
			*m.capturedValues = vals[0]
		}
		m.callCount++
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("Normal response")),
	}, nil
}

// TestBuildPrependedPayloads verifies that buildPrependedPayloads produces the correct
// set of payload variants for both empty and non-empty original values.
func TestBuildPrependedPayloads(t *testing.T) {
	t.Run("non-empty original value", func(t *testing.T) {
		variants := buildPrependedPayloads("127.0.0.1", ";sleep 5")
		// Should include the direct payload and the prepended version
		if len(variants) < 2 {
			t.Fatalf("Expected at least 2 variants for non-empty original value, got %d", len(variants))
		}
		found := map[string]bool{}
		for _, v := range variants {
			found[v] = true
		}
		if !found[";sleep 5"] {
			t.Error("Expected direct payload ;sleep 5 in variants")
		}
		if !found["127.0.0.1;sleep 5"] {
			t.Error("Expected prepended payload 127.0.0.1;sleep 5 in variants")
		}
	})

	t.Run("empty original value", func(t *testing.T) {
		variants := buildPrependedPayloads("", ";sleep 5")
		// Should include the direct payload plus benign-prefix variants
		if len(variants) < 3 {
			t.Fatalf("Expected at least 3 variants for empty original value, got %d", len(variants))
		}
		found := map[string]bool{}
		for _, v := range variants {
			found[v] = true
		}
		if !found[";sleep 5"] {
			t.Error("Expected direct payload ;sleep 5 in variants")
		}
		if !found["127.0.0.1;sleep 5"] {
			t.Error("Expected 127.0.0.1 prefixed payload in variants")
		}
		if !found["test;sleep 5"] {
			t.Error("Expected test prefixed payload in variants")
		}
	})

	t.Run("payload equal to original value", func(t *testing.T) {
		// When originalValue + payload == payload (e.g. empty string), no duplicate
		variants := buildPrependedPayloads("", "")
		for _, v := range variants {
			_ = v // just ensure no panic
		}
	})
}

// TestCMDiScanner_DVWALikeExecPOST_EmptyIPParam simulates the DVWA discovery scenario
// where the form scraper extracts ip="" (empty default value). The scanner must detect
// command injection by prepending a valid IP before the shell separator payload.
// This is the key regression test for the P0 CMDi detection bug on live DVWA.
func TestCMDiScanner_DVWALikeExecPOST_EmptyIPParam(t *testing.T) {
	mockClient := &mockDVWAExecEmptyIPClient{}

	scanner := NewCMDiScanner(WithCMDiHTTPClient(mockClient))
	// ip="" simulates the discovery pipeline extracting an empty default value
	params := map[string]string{
		"ip":     "",
		"Submit": "Submit",
	}
	result := scanner.ScanPOST(context.Background(), "http://localhost:8080/vulnerabilities/exec/", params)

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	// Should detect output-based command injection via prepended payload (127.0.0.1; id)
	foundOutputBased := false
	for _, finding := range result.Findings {
		if finding.Type == "output-based" && finding.Parameter == "ip" {
			foundOutputBased = true
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
			}
			if finding.Confidence != "high" {
				t.Errorf("Expected confidence high, got %s", finding.Confidence)
			}
			if finding.Evidence == "" {
				t.Error("Expected evidence to be captured")
			}
			t.Logf("Detected CMDi via prepended payload: payload=%s evidence=%s", finding.Payload, finding.Evidence)
		}
	}

	if !foundOutputBased {
		t.Error("Expected to find output-based CMDi via prepended payload when original ip param is empty (DVWA scenario)")
	}

	// Submit should not be tested
	for _, finding := range result.Findings {
		if strings.EqualFold(finding.Parameter, "submit") {
			t.Errorf("Expected Submit parameter to be skipped, but found finding on it: %+v", finding)
		}
	}
}

// mockDVWAExecEmptyIPClient simulates DVWA's /vulnerabilities/exec/ endpoint when
// the ip parameter starts as empty. The server only responds to requests where ip
// contains a valid IP address prefix — injections without a prefix (e.g., ip=;id)
// return no meaningful output, while prepended payloads (ip=127.0.0.1;id) work.
type mockDVWAExecEmptyIPClient struct{}

func (m *mockDVWAExecEmptyIPClient) Do(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("OK")),
		}, nil
	}

	body, _ := io.ReadAll(req.Body)
	formData, _ := url.ParseQuery(string(body))

	ipVals := formData["ip"]
	ipValue := ""
	if len(ipVals) > 0 {
		ipValue = ipVals[0]
	}

	// App only processes the form when ip starts with a valid-looking IP prefix.
	// Payloads without a prefix (e.g., ";sleep 5", ";id") produce no useful output.
	hasValidPrefix := strings.HasPrefix(ipValue, "127.0.0.1") || strings.HasPrefix(ipValue, "test")

	if !hasValidPrefix {
		// DVWA ignores the form — no shell command runs
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("<html>No output — invalid IP</html>")),
		}, nil
	}

	// With a valid prefix, the app runs the shell command. If the value contains
	// a shell separator, command injection succeeds.
	isInjected := strings.ContainsAny(ipValue, ";|&")

	if isInjected && (strings.Contains(ipValue, "id") || strings.Contains(ipValue, "whoami")) {
		return &http.Response{
			StatusCode: 200,
			Body: io.NopCloser(strings.NewReader(`PING 127.0.0.1 56 bytes of data.
64 bytes icmp_seq=1
uid=33(www-data) gid=33(www-data) groups=33(www-data)`)),
		}, nil
	}

	// Note: time-based detection (sleep payloads) is tested separately in
	// TestCMDiScanner_TimeBasedDetection_Unix. This mock focuses on output-based
	// detection to keep the test fast.

	// Normal ping output (baseline or non-injected)
	return &http.Response{
		StatusCode: 200,
		Body: io.NopCloser(strings.NewReader(`PING 127.0.0.1 56 bytes of data.
64 bytes icmp_seq=1
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received`)),
	}, nil
}

// TestStripCMDiPayloadFromBody verifies that the reflection-stripping helper
// removes injected payload text (and HTML/URL-encoded variants) from the
// response body so that reflected input does not trigger output-based patterns.
func TestStripCMDiPayloadFromBody(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		payload string
		want    string
	}{
		{
			name:    "empty payload returns body unchanged",
			body:    "root:x:0:0:root:/root:/bin/bash",
			payload: "",
			want:    "root:x:0:0:root:/root:/bin/bash",
		},
		{
			name:    "reflected /etc/passwd payload is stripped",
			body:    `<pre>localhost; cat /etc/passwd</pre>`,
			payload: "localhost; cat /etc/passwd",
			want:    `<pre></pre>`,
		},
		{
			name:    "genuine command output survives stripping",
			body:    "localhost; cat /etc/passwd\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
			payload: "localhost; cat /etc/passwd",
			want:    "\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
		},
		{
			name:    "HTML-escaped payload is stripped",
			body:    `<input value="localhost; cat /etc/passwd">`,
			payload: "localhost; cat /etc/passwd",
			want:    `<input value="">`,
		},
		{
			name:    "HTML entity &amp; variant is stripped",
			body:    `<div>test &amp;&amp; id</div>`,
			payload: "test && id",
			want:    `<div></div>`,
		},
		{
			name:    "URL-encoded payload is stripped",
			body:    `localhost%3B+cat+%2Fetc%2Fpasswd appeared in page`,
			payload: "localhost; cat /etc/passwd",
			want:    ` appeared in page`,
		},
		{
			name:    "case-insensitive stripping",
			body:    `LOCALHOST; CAT /ETC/PASSWD root:x:0`,
			payload: "localhost; cat /etc/passwd",
			want:    ` root:x:0`,
		},
		{
			name:    "multiple reflected occurrences are all stripped",
			body:    `echo: localhost; cat /etc/passwd result: localhost; cat /etc/passwd done`,
			payload: "localhost; cat /etc/passwd",
			want:    `echo:  result:  done`,
		},
		{
			name:    "no match leaves body unchanged",
			body:    "some normal page content",
			payload: "localhost; cat /etc/passwd",
			want:    "some normal page content",
		},
		{
			name:    "uid pattern in reflected payload is stripped",
			body:    `<pre>127.0.0.1; id</pre><br>uid=33(www-data)`,
			payload: "127.0.0.1; id",
			want:    `<pre></pre><br>uid=33(www-data)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripCMDiPayloadFromBody(tt.body, tt.payload)
			if got != tt.want {
				t.Errorf("stripCMDiPayloadFromBody() =\n  %q\nwant:\n  %q", got, tt.want)
			}
		})
	}
}

// TestOutputBased_ReflectionStripping verifies that the output-based CMDi
// detector does NOT flag a parameter that merely reflects the injected payload
// (simulating an XSS-vulnerable parameter like DVWA's 'name' on /xss_r/).
func TestOutputBased_ReflectionStripping(t *testing.T) {
	// Mock: the "name" parameter reflects whatever is sent, no command execution.
	mockClient := &mockCMDiHTTPClient{
		responses: map[string]*mockCMDiResponse{},
	}

	scanner := NewCMDiScanner(
		WithCMDiHTTPClient(mockClient),
		WithCMDiTimeout(5*time.Second),
	)

	// Baseline response for the reflecting parameter
	baselineBody := `<html><body>Hello test</body></html>`

	// For every output-based payload, the reflecting page echoes it back.
	// We register catch-all responses via the mock's default behaviour, but
	// need specific URLs. Instead, we'll use ScanPOST with a custom mock.
	reflectingMock := &reflectingMockClient{baselineBody: baselineBody}
	scanner.client = reflectingMock

	ctx := context.Background()
	result := scanner.ScanPOST(ctx, "http://example.com/xss_r/", map[string]string{
		"name": "test",
	})

	// There should be zero output-based findings on the 'name' parameter,
	// because all cmd output patterns come from the reflected payload.
	for _, f := range result.Findings {
		if f.Type == "output-based" && f.Parameter == "name" {
			t.Errorf("False positive: output-based CMDi on reflecting param 'name': payload=%s evidence=%s", f.Payload, f.Evidence)
		}
	}
}

// reflectingMockClient simulates a page that reflects the parameter value.
type reflectingMockClient struct {
	baselineBody string
	mu           sync.Mutex
}

func (m *reflectingMockClient) Do(req *http.Request) (*http.Response, error) {
	// Parse the parameter value from query string (GET) or body (POST).
	var nameValue string
	if req.Method == http.MethodPost && req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		vals, _ := url.ParseQuery(string(bodyBytes))
		nameValue = vals.Get("name")
	} else {
		nameValue = req.URL.Query().Get("name")
	}

	// If the value looks like the baseline (or is empty), return baseline body.
	if nameValue == "" || nameValue == "test" || nameValue == "randomstring_12345" {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(m.baselineBody)),
		}, nil
	}

	// Otherwise reflect the value back — simulating an XSS-vulnerable page.
	body := `<html><body>Hello ` + nameValue + `</body></html>`
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}
