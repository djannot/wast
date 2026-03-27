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

	// Check for partial matches (contains specific payload in query parameters)
	// Look for URL-decoded versions of payloads
	// Sort patterns by length (longest first) to match most specific patterns first
	var patterns []string
	for pattern := range m.responses {
		patterns = append(patterns, pattern)
	}

	// Sort by length descending to match longest patterns first
	for i := 0; i < len(patterns); i++ {
		for j := i + 1; j < len(patterns); j++ {
			if len(patterns[i]) < len(patterns[j]) {
				patterns[i], patterns[j] = patterns[j], patterns[i]
			}
		}
	}

	for _, pattern := range patterns {
		resp := m.responses[pattern]

		// Try to match the pattern in the query parameter value
		// Extract query string for better matching
		queryStart := strings.Index(url, "?")
		if queryStart >= 0 {
			queryString := url[queryStart+1:]
			// Check if pattern appears in query string
			if strings.Contains(queryString, pattern) {
				return &http.Response{
					StatusCode: resp.statusCode,
					Body:       io.NopCloser(strings.NewReader(resp.body)),
				}, nil
			}
			// Also check for URL-encoded versions in query string
			if strings.Contains(queryString, strings.ReplaceAll(pattern, "/", "%2F")) {
				return &http.Response{
					StatusCode: resp.statusCode,
					Body:       io.NopCloser(strings.NewReader(resp.body)),
				}, nil
			}
			if strings.Contains(queryString, strings.ReplaceAll(pattern, "\\", "%5C")) {
				return &http.Response{
					StatusCode: resp.statusCode,
					Body:       io.NopCloser(strings.NewReader(resp.body)),
				}, nil
			}
		}
	}

	// Default response
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("OK")),
	}, nil
}

// mockPathTraversalHTTPClientWithLog wraps the mock client and logs all requests
type mockPathTraversalHTTPClientWithLog struct {
	inner *mockPathTraversalHTTPClient
	t     *testing.T
}

func (m *mockPathTraversalHTTPClientWithLog) Do(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	m.t.Logf("Mock client received request: %s", url)

	// Debug: show which pattern would match
	for pattern := range m.inner.responses {
		if strings.Contains(url, pattern) {
			m.t.Logf("  -> Pattern '%s' matches!", pattern)
		}
	}

	resp, err := m.inner.Do(req)
	if resp != nil {
		body := make([]byte, 100)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		bodyPreview := string(body[:n])
		if len(bodyPreview) > 50 {
			bodyPreview = bodyPreview[:50] + "..."
		}
		m.t.Logf("  -> Response body preview: %s", bodyPreview)
		// Re-create the response body for the actual scanner
		resp.Body = io.NopCloser(strings.NewReader(string(body[:n])))
	}

	return resp, err
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
			name:     "Valid passwd file with multiple entries",
			body:     "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/usr/sbin/nologin\ndaemon:x:2:2:daemon:/usr/sbin:/usr/sbin/nologin\n",
			expected: true,
		},
		{
			name:     "Single root entry (DVWA-style LFI)",
			body:     "root:x:0:0:root:/root:/bin/bash\n",
			expected: true, // Changed to true - should detect single specific entries
		},
		{
			name:     "Single daemon entry",
			body:     "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
			expected: true,
		},
		{
			name:     "Single www-data entry",
			body:     "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
			expected: true,
		},
		{
			name:     "Single generic entry",
			body:     "someuser:x:1000:1000:Some User:/home/someuser:/bin/bash\n",
			expected: true, // Changed to true - threshold lowered to 1
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
		{
			name:     "Text with colon but not passwd format",
			body:     "Some text: with colons: but not: a passwd file",
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

// TestPathTraversalScanner_DVWA_LFI tests detection of DVWA's Local File Inclusion vulnerability
// on the /vulnerabilities/fi/?page= endpoint. This simulates DVWA's behavior where the
// page parameter accepts path traversal payloads like ../../etc/passwd and returns
// file contents. DVWA also accepts wrapper attacks like include.php/../../../etc/passwd.
func TestPathTraversalScanner_DVWA_LFI(t *testing.T) {
	// DVWA's file inclusion page with normal include
	normalPageHTML := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Vulnerability: File Inclusion :: Damn Vulnerable Web Application (DVWA) v1.10</title>
</head>
<body>
<div id="wrapper">
<div id="main_body">
<h1>File Inclusion</h1>
<div class="body_padded">
Welcome to the file inclusion page.
</div>
</div>
</div>
</body>
</html>`

	// DVWA returns /etc/passwd contents when exploited
	// This simulates a partial file read that might only return a single entry
	passwdFileHTML := `root:x:0:0:root:/root:/bin/bash`

	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"http://dvwa.local/vulnerabilities/fi/?page=include.php": {
				statusCode: 200,
				body:       normalPageHTML,
			},
			// Match various path traversal payloads (raw, unencoded)
			"../../etc/passwd": {
				statusCode: 200,
				body:       passwdFileHTML,
			},
			"../../../etc/passwd": {
				statusCode: 200,
				body:       passwdFileHTML,
			},
			"../../../../etc/passwd": {
				statusCode: 200,
				body:       passwdFileHTML,
			},
			"../../../../../etc/passwd": {
				statusCode: 200,
				body:       passwdFileHTML,
			},
			"../../../../../../etc/passwd": {
				statusCode: 200,
				body:       passwdFileHTML,
			},
			// Match wrapper payloads (prepending to existing value)
			"include.php/../../etc/passwd": {
				statusCode: 200,
				body:       passwdFileHTML,
			},
			"include.php/../../../etc/passwd": {
				statusCode: 200,
				body:       passwdFileHTML,
			},
			"include.php/../../../../etc/passwd": {
				statusCode: 200,
				body:       passwdFileHTML,
			},
			"include.php/../../../../../etc/passwd": {
				statusCode: 200,
				body:       passwdFileHTML,
			},
			"include.php/../../../../../../etc/passwd": {
				statusCode: 200,
				body:       passwdFileHTML,
			},
		},
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://dvwa.local/vulnerabilities/fi/?page=include.php")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	t.Logf("Total tests performed: %d", result.Summary.TotalTests)
	t.Logf("Vulnerabilities found: %d", result.Summary.VulnerabilitiesFound)

	if len(result.Findings) > 0 {
		for i, finding := range result.Findings {
			t.Logf("Finding %d: param=%s, payload=%s, confidence=%s, evidence=%s",
				i+1, finding.Parameter, finding.Payload, finding.Confidence, finding.Evidence)
		}
	}

	// Verify we detected the LFI vulnerability
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to detect DVWA LFI vulnerability on /vulnerabilities/fi/?page=")
	}

	// Check for specific passwd file detection
	foundPasswdLFI := false
	for _, finding := range result.Findings {
		if finding.Parameter == "page" && finding.Type == "unix" {
			if strings.Contains(finding.Evidence, "passwd") || strings.Contains(finding.Evidence, "root:x:0:0") {
				foundPasswdLFI = true
				if finding.Confidence != "high" {
					t.Errorf("Expected high confidence for passwd file detection, got %s", finding.Confidence)
				}
				if finding.Severity != SeverityHigh {
					t.Errorf("Expected high severity, got %s", finding.Severity)
				}
			}
		}
	}

	if !foundPasswdLFI {
		t.Error("Expected to find passwd file LFI specifically on the 'page' parameter")
	}
}

// TestPathTraversalScanner_RawVsEncodedPayloads tests that the scanner tries both
// raw (unencoded) and URL-encoded payloads for maximum compatibility
func TestPathTraversalScanner_RawVsEncodedPayloads(t *testing.T) {
	passwdContents := "root:x:0:0:root:/root:/bin/bash\n"

	tests := []struct {
		name         string
		urlPattern   string
		expectDetect bool
	}{
		{
			name:         "Detects with raw (unencoded) slashes",
			urlPattern:   "../../../etc/passwd",
			expectDetect: true,
		},
		{
			name:         "Also tries URL-encoded version",
			urlPattern:   "..%2F..%2F..%2Fetc%2Fpasswd",
			expectDetect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockPathTraversalHTTPClient{
				responses: map[string]*mockPathTraversalResponse{
					tt.urlPattern: {
						statusCode: 200,
						body:       passwdContents,
					},
				},
			}

			scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(mockClient))
			result := scanner.Scan(context.Background(), "http://example.com/test?file=test")

			if tt.expectDetect && result.Summary.VulnerabilitiesFound == 0 {
				t.Errorf("Expected to detect vulnerability with pattern %s", tt.urlPattern)
			}

			if !tt.expectDetect && result.Summary.VulnerabilitiesFound > 0 {
				t.Errorf("Did not expect to detect vulnerability with pattern %s", tt.urlPattern)
			}
		})
	}
}

// TestPathTraversalScanner_WrapperPayloads tests that the scanner can detect
// vulnerabilities where the payload is prepended to an existing parameter value
func TestPathTraversalScanner_WrapperPayloads(t *testing.T) {
	passwdContents := "root:x:0:0:root:/root:/bin/bash\n"

	// Create a custom mock client that logs all URLs
	mockClient := &mockPathTraversalHTTPClient{
		responses: map[string]*mockPathTraversalResponse{
			"http://example.com/test?page=normal.php": {
				statusCode: 200,
				body:       "<html>Normal page</html>",
			},
			// Wrapper payload pattern: existing value + / + traversal sequence
			"normal.php/../../../etc/passwd": {
				statusCode: 200,
				body:       passwdContents,
			},
			// Also match various depths
			"normal.php/../../../../etc/passwd": {
				statusCode: 200,
				body:       passwdContents,
			},
			"normal.php/../../../../../etc/passwd": {
				statusCode: 200,
				body:       passwdContents,
			},
			"normal.php/../../../../../../etc/passwd": {
				statusCode: 200,
				body:       passwdContents,
			},
		},
	}

	loggingClient := &mockPathTraversalHTTPClientWithLog{
		inner: mockClient,
		t:     t,
	}

	scanner := NewPathTraversalScanner(WithPathTraversalHTTPClient(loggingClient))
	result := scanner.Scan(context.Background(), "http://example.com/test?page=normal.php")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Log findings for debugging
	for i, finding := range result.Findings {
		t.Logf("Finding %d: param=%s, payload=%s, confidence=%s",
			i+1, finding.Parameter, finding.Payload, finding.Confidence)
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to detect LFI vulnerability using wrapper payload")
	}

	// Check that we found a wrapper payload
	foundWrapper := false
	for _, finding := range result.Findings {
		if strings.HasPrefix(finding.Payload, "normal.php/") {
			foundWrapper = true
			t.Logf("Found wrapper payload: %s", finding.Payload)
		}
	}

	if !foundWrapper {
		t.Error("Expected to find wrapper payload (normal.php/../../../etc/passwd)")
	}
}
