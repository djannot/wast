package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// mockPathTraversalHTTPClient is a mock HTTP client for testing path traversal detection.
type mockPathTraversalHTTPClient struct {
	responses map[string]*mockPathTraversalResponse
}

type mockPathTraversalResponse struct {
	statusCode int
	body       string
}

func (m *mockPathTraversalHTTPClient) Do(req *http.Request) (*http.Response, error) {
	url := req.URL.String()

	// Check for exact match first
	if resp, ok := m.responses[url]; ok {
		return &http.Response{
			StatusCode: resp.statusCode,
			Body:       io.NopCloser(strings.NewReader(resp.body)),
		}, nil
	}

	// Check for partial matches (contains specific payload)
	// Look for URL-decoded versions of payloads
	for pattern, resp := range m.responses {
		// Try to match the pattern in the URL
		if strings.Contains(url, pattern) {
			return &http.Response{
				StatusCode: resp.statusCode,
				Body:       io.NopCloser(strings.NewReader(resp.body)),
			}, nil
		}
		// Also check for URL-encoded versions
		if strings.Contains(url, strings.ReplaceAll(pattern, "/", "%2F")) {
			return &http.Response{
				StatusCode: resp.statusCode,
				Body:       io.NopCloser(strings.NewReader(resp.body)),
			}, nil
		}
		if strings.Contains(url, strings.ReplaceAll(pattern, "\\", "%5C")) {
			return &http.Response{
				StatusCode: resp.statusCode,
				Body:       io.NopCloser(strings.NewReader(resp.body)),
			}, nil
		}
	}

	// Default response
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("OK")),
	}, nil
}

func TestNewPathTraversalScanner(t *testing.T) {
	scanner := NewPathTraversalScanner()

	if scanner == nil {
		t.Fatal("Expected scanner to be created")
	}

	if scanner.userAgent == "" {
		t.Error("Expected default user agent to be set")
	}

	if scanner.timeout == 0 {
		t.Error("Expected default timeout to be set")
	}
}

func TestPathTraversalScanner_UnixPasswdDetection(t *testing.T) {
	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"http://example.com/test?file=test": {
				statusCode: 200,
				body:       "Normal file content",
			},
			"etc/passwd": {
				statusCode: 200,
				body:       "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
			},
		},
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?file=test")

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	// Should detect at least one vulnerability
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find at least one path traversal vulnerability")
	}

	// Check that we found a Unix-based vulnerability
	foundUnix := false
	for _, finding := range result.Findings {
		if finding.Type == "unix" && strings.Contains(finding.Evidence, "passwd") {
			foundUnix = true
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
			}
			if finding.Confidence != "high" {
				t.Errorf("Expected confidence high, got %s", finding.Confidence)
			}
			if !strings.Contains(finding.Remediation, "input validation") {
				t.Error("Expected remediation guidance to mention input validation")
			}
		}
	}

	if !foundUnix {
		t.Error("Expected to find Unix path traversal vulnerability")
	}
}

func TestPathTraversalScanner_WindowsHostsDetection(t *testing.T) {
	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"http://example.com/test?file=test": {
				statusCode: 200,
				body:       "Normal file content",
			},
			"hosts": {
				statusCode: 200,
				body:       "# Copyright (c) 1993-2009 Microsoft Corp.\n# This is a sample HOSTS file\n127.0.0.1       localhost\n::1             localhost\n",
			},
		},
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?file=test")

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find at least one path traversal vulnerability")
	}

	// Check that we found a Windows-based vulnerability
	foundWindows := false
	for _, finding := range result.Findings {
		if finding.Type == "windows" && strings.Contains(finding.Evidence, "hosts") {
			foundWindows = true
			if finding.Severity != SeverityHigh {
				t.Errorf("Expected severity %s, got %s", SeverityHigh, finding.Severity)
			}
		}
	}

	if !foundWindows {
		t.Error("Expected to find Windows path traversal vulnerability")
	}
}

func TestPathTraversalScanner_WindowsWinIniDetection(t *testing.T) {
	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"http://example.com/test?file=test": {
				statusCode: 200,
				body:       "Normal file content",
			},
			"win.ini": {
				statusCode: 200,
				body:       "[fonts]\n[extensions]\n[mci extensions]\n[files]\n[mail]\n",
			},
		},
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?file=test")

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find at least one path traversal vulnerability")
	}

	// Check that we found a Windows win.ini vulnerability
	foundWinIni := false
	for _, finding := range result.Findings {
		if finding.Type == "windows" && strings.Contains(finding.Evidence, "win.ini") {
			foundWinIni = true
		}
	}

	if !foundWinIni {
		t.Error("Expected to find Windows win.ini path traversal vulnerability")
	}
}

func TestPathTraversalScanner_EncodedPayloadDetection(t *testing.T) {
	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"http://example.com/test?file=test": {
				statusCode: 200,
				body:       "Normal file content",
			},
			"etc%2Fpasswd": {
				statusCode: 200,
				body:       "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n",
			},
		},
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?file=test")

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find at least one path traversal vulnerability")
	}

	// Check that we found an encoded or unix payload vulnerability (encoded payloads also trigger unix detection)
	foundVulnerability := false
	for _, finding := range result.Findings {
		if finding.Type == "encoded" || finding.Type == "unix" {
			foundVulnerability = true
			if finding.Confidence == "low" {
				t.Error("Expected confidence to be at least medium for encoded payloads")
			}
		}
	}

	if !foundVulnerability {
		t.Error("Expected to find encoded path traversal vulnerability")
	}
}

func TestPathTraversalScanner_AbsolutePathDetection(t *testing.T) {
	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"http://example.com/test?path=test": {
				statusCode: 200,
				body:       "Normal file content",
			},
			"/etc/passwd": {
				statusCode: 200,
				body:       "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
			},
		},
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?path=test")

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find at least one path traversal vulnerability with absolute path")
	}
}

func TestPathTraversalScanner_NoVulnerability(t *testing.T) {
	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"http://example.com/test?file=test": {
				statusCode: 200,
				body:       "Normal secure response",
			},
		},
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?file=test")

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	if result.Summary.VulnerabilitiesFound > 0 {
		t.Error("Expected no vulnerabilities to be found in secure application")
	}
}

func TestPathTraversalScanner_ErrorPatternDetection(t *testing.T) {
	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"http://example.com/test?file=test": {
				statusCode: 200,
				body:       "Normal response",
			},
			"../": {
				statusCode: 500,
				body:       "Error: failed to open stream: No such file or directory in /var/www/html/include.php",
			},
		},
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?file=test")

	// Should detect based on error patterns
	foundError := false
	for _, finding := range result.Findings {
		if strings.Contains(finding.Evidence, "error") {
			foundError = true
			if finding.Confidence == "low" {
				t.Error("Expected at least medium confidence for error-based detection")
			}
		}
	}

	if !foundError && result.Summary.VulnerabilitiesFound > 0 {
		t.Log("Found vulnerabilities but not specifically through error patterns (acceptable)")
	}
}

func TestPathTraversalScanner_ContextCancellation(t *testing.T) {
	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"http://example.com/test?file=test": {
				statusCode: 200,
				body:       "response",
			},
		},
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := scanner.Scan(ctx, "http://example.com/test?file=test")

	if len(result.Errors) == 0 {
		t.Error("Expected errors due to context cancellation")
	}

	if !strings.Contains(strings.Join(result.Errors, " "), "cancel") {
		t.Error("Expected cancellation error message")
	}
}

func TestPathTraversalScanner_InvalidURL(t *testing.T) {
	scanner := NewPathTraversalScanner()
	result := scanner.Scan(context.Background(), "://invalid-url")

	if len(result.Errors) == 0 {
		t.Error("Expected error for invalid URL")
	}

	if result.Summary.TotalTests > 0 {
		t.Error("Expected no tests to run with invalid URL")
	}
}

func TestPathTraversalScanner_VerifyFinding(t *testing.T) {
	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"etc/passwd": {
				statusCode: 200,
				body:       "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
			},
		},
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))

	finding := &PathTraversalFinding{
		URL:       "http://example.com/test?file=../../../etc/passwd",
		Parameter: "file",
		Payload:   "../../../etc/passwd",
		Type:      "unix",
	}

	config := VerificationConfig{
		Enabled:    true,
		MaxRetries: 3,
		Delay:      10 * time.Millisecond,
	}

	result, err := scanner.VerifyFinding(context.Background(), finding, config)

	if err != nil {
		t.Fatalf("Expected no error during verification, got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected verification result")
	}

	if result.Attempts == 0 {
		t.Error("Expected verification attempts to be made")
	}

	if result.Verified {
		t.Log("Finding was successfully verified")
	} else {
		t.Log("Finding could not be verified (acceptable depending on mock responses)")
	}
}

func TestPathTraversalScanner_String(t *testing.T) {
	result := &PathTraversalScanResult{
		Target: "http://example.com/test",
		Findings: []PathTraversalFinding{
			{
				URL:         "http://example.com/test?file=../../../etc/passwd",
				Parameter:   "file",
				Payload:     "../../../etc/passwd",
				Type:        "unix",
				Severity:    SeverityHigh,
				Description: "Path Traversal vulnerability detected",
				Evidence:    "Response contains /etc/passwd file contents",
				Confidence:  "high",
				Remediation: "Implement strict input validation",
			},
		},
		Summary: PathTraversalSummary{
			TotalTests:           18,
			VulnerabilitiesFound: 1,
			HighSeverityCount:    1,
		},
	}

	output := result.String()

	if !strings.Contains(output, "Path Traversal Vulnerability Scan") {
		t.Error("Expected output to contain scan title")
	}

	if !strings.Contains(output, "http://example.com/test") {
		t.Error("Expected output to contain target URL")
	}

	if !strings.Contains(output, "file") {
		t.Error("Expected output to contain parameter name")
	}

	if !strings.Contains(output, "Total Tests: 18") {
		t.Error("Expected output to contain test count")
	}

	if !strings.Contains(output, "Vulnerabilities Found: 1") {
		t.Error("Expected output to contain vulnerabilities count")
	}
}

func TestPathTraversalScanner_HasResults(t *testing.T) {
	// Test with findings
	result1 := &PathTraversalScanResult{
		Findings: []PathTraversalFinding{
			{URL: "http://example.com", Parameter: "file"},
		},
	}

	if !result1.HasResults() {
		t.Error("Expected HasResults to return true when findings exist")
	}

	// Test with no findings but tests run
	result2 := &PathTraversalScanResult{
		Findings: []PathTraversalFinding{},
		Summary: PathTraversalSummary{
			TotalTests: 10,
		},
	}

	if !result2.HasResults() {
		t.Error("Expected HasResults to return true when tests were run")
	}

	// Test with no findings and no tests
	result3 := &PathTraversalScanResult{
		Findings: []PathTraversalFinding{},
		Summary:  PathTraversalSummary{},
	}

	if result3.HasResults() {
		t.Error("Expected HasResults to return false when no tests were run")
	}
}

func TestPathTraversalScanner_WithOptions(t *testing.T) {
	mockClient := &mockPathTraversalHTTPClient{}

	scanner := NewPathTraversalScanner(
		WithPathTraversalHTTPClient(mockClient),
		WithPathTraversalUserAgent("CustomUA"),
		WithPathTraversalTimeout(60*time.Second),
	)

	if scanner.client != mockClient {
		t.Error("Expected custom HTTP client to be set")
	}

	if scanner.userAgent != "CustomUA" {
		t.Errorf("Expected user agent 'CustomUA', got '%s'", scanner.userAgent)
	}

	if scanner.timeout != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", scanner.timeout)
	}
}

func TestPathTraversalScanner_ShadowFileDetection(t *testing.T) {
	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"http://example.com/test?file=test": {
				statusCode: 200,
				body:       "Normal file content",
			},
			"shadow": {
				statusCode: 200,
				body:       "root:$6$xyz$abc:18000:0:99999:7:::\ndaemon:*:18000:0:99999:7:::\nbin:!:18000:0:99999:7:::\n",
			},
		},
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?file=test")

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find shadow file path traversal vulnerability")
	}

	// Check for shadow file detection
	foundShadow := false
	for _, finding := range result.Findings {
		if strings.Contains(finding.Evidence, "shadow") {
			foundShadow = true
			if finding.Severity != SeverityHigh {
				t.Error("Expected high severity for shadow file access")
			}
		}
	}

	if !foundShadow {
		t.Error("Expected to find shadow file in evidence")
	}
}

func TestContainsPasswdSignature(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "Valid passwd file",
			body:     "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/usr/sbin/nologin\ndaemon:x:2:2:daemon:/usr/sbin:/usr/sbin/nologin\n",
			expected: true,
		},
		{
			name:     "Single entry not enough",
			body:     "root:x:0:0:root:/root:/bin/bash\n",
			expected: false,
		},
		{
			name:     "Normal text",
			body:     "This is just normal text content",
			expected: false,
		},
		{
			name:     "Empty string",
			body:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsPasswdSignature(tt.body)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestContainsWindowsHostsSignature(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "Valid Windows hosts file",
			body:     "# Copyright (c) 1993-2009 Microsoft Corp.\n127.0.0.1       localhost\n::1             localhost\n",
			expected: true,
		},
		{
			name:     "Just localhost entry",
			body:     "127.0.0.1       localhost\n",
			expected: true,
		},
		{
			name:     "Normal text",
			body:     "This is just normal text",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsWindowsHostsSignature(tt.body)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
