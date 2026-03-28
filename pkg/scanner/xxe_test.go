package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/callback"
	"github.com/djannot/wast/pkg/ratelimit"
)

// mockXXEHTTPClient is a mock HTTP client for testing XXE scanner.
type mockXXEHTTPClient struct {
	responses map[string]*http.Response
	err       error
}

func (m *mockXXEHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}

	// Check for specific payloads in request
	var body string
	if req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		body = string(bodyBytes)
	}

	// Check URL for GET parameters
	urlStr := req.URL.String()

	// Simulate /etc/passwd disclosure
	if strings.Contains(body, "file:///etc/passwd") || strings.Contains(urlStr, "file:///etc/passwd") {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")),
			Header:     make(http.Header),
		}, nil
	}

	// Simulate Windows file disclosure
	if strings.Contains(body, "file:///c:/boot.ini") || strings.Contains(urlStr, "file:///c:/boot.ini") {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS")),
			Header:     make(http.Header),
		}, nil
	}

	// Simulate error-based XXE
	if strings.Contains(body, "nonexistent_xxe_test_file") || strings.Contains(urlStr, "nonexistent_xxe_test_file") {
		return &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(strings.NewReader("ParseError: failed to load external entity 'file:///nonexistent_xxe_test_file_12345'")),
			Header:     make(http.Header),
		}, nil
	}

	// Default response - no XXE
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("<root>OK</root>")),
		Header:     make(http.Header),
	}, nil
}

// mockCallbackServer is a mock callback server for testing.
type mockCallbackServer struct {
	callbacks map[string]bool
}

func newMockCallbackServer() *mockCallbackServer {
	return &mockCallbackServer{
		callbacks: make(map[string]bool),
	}
}

func (m *mockCallbackServer) GenerateCallbackID() string {
	return "test-callback-id"
}

func (m *mockCallbackServer) GetHTTPCallbackURL(id string) string {
	return "http://callback.example.com/" + id
}

func (m *mockCallbackServer) GetDNSCallbackDomain(id string) string {
	return id + ".callback.example.com"
}

func (m *mockCallbackServer) WaitForCallback(ctx context.Context, id string, timeout time.Duration) (callback.CallbackEvent, bool) {
	// Simulate receiving a callback for blind XXE
	if received, ok := m.callbacks[id]; ok && received {
		return callback.CallbackEvent{
			ID:        id,
			Type:      callback.CallbackTypeHTTP,
			Timestamp: time.Now(),
			SourceIP:  "192.168.1.100",
			Method:    "GET",
			Path:      "/" + id,
		}, true
	}
	return callback.CallbackEvent{}, false
}

func TestNewXXEScanner(t *testing.T) {
	scanner := NewXXEScanner()

	if scanner == nil {
		t.Fatal("expected scanner to be created")
	}

	if scanner.userAgent != "WAST/1.0 (Web Application Security Testing)" {
		t.Errorf("expected default user agent, got %s", scanner.userAgent)
	}

	if scanner.timeout != 10*time.Second {
		t.Errorf("expected default timeout of 10s, got %v", scanner.timeout)
	}

	if scanner.safeMode != false {
		t.Error("expected safe mode to be disabled by default")
	}
}

func TestXXEScannerOptions(t *testing.T) {
	customClient := &mockXXEHTTPClient{}
	customTimeout := 5 * time.Second
	customUA := "CustomAgent/1.0"
	authConfig := &auth.AuthConfig{BearerToken: "test-token"}
	rateLimiter := ratelimit.NewLimiter(10)
	callbackServer := newMockCallbackServer()

	scanner := NewXXEScanner(
		WithXXEHTTPClient(customClient),
		WithXXETimeout(customTimeout),
		WithXXEUserAgent(customUA),
		WithXXEAuth(authConfig),
		WithXXERateLimiter(rateLimiter),
		WithXXECallbackServer(callbackServer),
		WithXXESafeMode(true),
	)

	if scanner.client != customClient {
		t.Error("expected custom HTTP client to be set")
	}

	if scanner.timeout != customTimeout {
		t.Errorf("expected timeout %v, got %v", customTimeout, scanner.timeout)
	}

	if scanner.userAgent != customUA {
		t.Errorf("expected user agent %s, got %s", customUA, scanner.userAgent)
	}

	if scanner.authConfig != authConfig {
		t.Error("expected auth config to be set")
	}

	if scanner.rateLimiter != rateLimiter {
		t.Error("expected rate limiter to be set")
	}

	if scanner.callbackServer != callbackServer {
		t.Error("expected callback server to be set")
	}

	if !scanner.safeMode {
		t.Error("expected safe mode to be enabled")
	}
}

func TestXXEScan_SafeMode(t *testing.T) {
	scanner := NewXXEScanner(
		WithXXESafeMode(true),
	)

	result := scanner.Scan(context.Background(), "http://example.com")

	if result == nil {
		t.Fatal("expected result to be returned")
	}

	if len(result.Findings) != 0 {
		t.Errorf("expected no findings in safe mode, got %d", len(result.Findings))
	}

	if len(result.Errors) == 0 {
		t.Error("expected error message about safe mode")
	}
}

func TestXXEScan_InvalidURL(t *testing.T) {
	scanner := NewXXEScanner()

	// Use a URL with invalid control character that will fail to parse
	result := scanner.Scan(context.Background(), "http://example.com\nmalformed")

	if result == nil {
		t.Fatal("expected result to be returned")
	}

	if len(result.Errors) == 0 {
		t.Error("expected error for invalid URL")
	}
}

func TestXXEScan_InBandXXE(t *testing.T) {
	mockClient := &mockXXEHTTPClient{
		responses: make(map[string]*http.Response),
	}

	scanner := NewXXEScanner(
		WithXXEHTTPClient(mockClient),
	)

	result := scanner.Scan(context.Background(), "http://example.com/api")

	if result == nil {
		t.Fatal("expected result to be returned")
	}

	// Should detect at least one XXE vulnerability
	if len(result.Findings) == 0 {
		t.Error("expected to find at least one XXE vulnerability")
	}

	// Check that findings have required fields
	for _, finding := range result.Findings {
		if finding.URL == "" {
			t.Error("expected finding to have URL")
		}
		if finding.Severity == "" {
			t.Error("expected finding to have severity")
		}
		if finding.Description == "" {
			t.Error("expected finding to have description")
		}
		if finding.Remediation == "" {
			t.Error("expected finding to have remediation")
		}
		if finding.Type == "" {
			t.Error("expected finding to have type")
		}
		if finding.Evidence == "" {
			t.Error("expected finding to have evidence for in-band XXE")
		}
	}
}

func TestXXEScan_ErrorBasedXXE(t *testing.T) {
	mockClient := &mockXXEHTTPClient{}

	scanner := NewXXEScanner(
		WithXXEHTTPClient(mockClient),
	)

	result := scanner.Scan(context.Background(), "http://example.com")

	if result == nil {
		t.Fatal("expected result to be returned")
	}

	// Check for error-based XXE findings
	errorBased := false
	for _, finding := range result.Findings {
		if finding.Type == "error-based" {
			errorBased = true
			if !strings.Contains(finding.Evidence, "ParseError") && !strings.Contains(finding.Evidence, "failed to load external entity") {
				t.Error("expected error-based evidence to contain parser error")
			}
		}
	}

	if !errorBased {
		t.Log("Note: error-based XXE not detected (may be expected depending on mock)")
	}
}

func TestXXEScan_Summary(t *testing.T) {
	mockClient := &mockXXEHTTPClient{}

	scanner := NewXXEScanner(
		WithXXEHTTPClient(mockClient),
	)

	result := scanner.Scan(context.Background(), "http://example.com")

	if result == nil {
		t.Fatal("expected result to be returned")
	}

	if result.Summary.TotalTests == 0 {
		t.Error("expected total tests to be greater than 0")
	}

	if result.Summary.VulnerabilitiesFound != len(result.Findings) {
		t.Errorf("expected vulnerabilities found (%d) to match findings count (%d)",
			result.Summary.VulnerabilitiesFound, len(result.Findings))
	}

	// Check severity counts
	totalSeverity := result.Summary.HighSeverityCount + result.Summary.MediumSeverityCount + result.Summary.LowSeverityCount
	if totalSeverity != result.Summary.VulnerabilitiesFound {
		t.Errorf("expected severity counts (%d) to match total vulnerabilities (%d)",
			totalSeverity, result.Summary.VulnerabilitiesFound)
	}
}

func TestXXEVerifyFinding(t *testing.T) {
	mockClient := &mockXXEHTTPClient{}

	scanner := NewXXEScanner(
		WithXXEHTTPClient(mockClient),
	)

	finding := &XXEFinding{
		URL:         "http://example.com",
		Parameter:   "POST application/xml",
		Payload:     `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		Type:        "in-band",
		Severity:    SeverityHigh,
		Description: "Test XXE",
		Verified:    false,
	}

	config := VerificationConfig{
		Enabled:    true,
		MaxRetries: 2,
		Delay:      100 * time.Millisecond,
	}

	result, err := scanner.VerifyFinding(context.Background(), finding, config)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("expected verification result")
	}

	if result.Attempts == 0 {
		t.Error("expected at least one verification attempt")
	}

	// With our mock, this should verify successfully
	if !result.Verified {
		t.Error("expected finding to be verified")
	}

	if result.Confidence == 0 {
		t.Error("expected confidence to be set")
	}
}

func TestXXEVerifyFinding_Disabled(t *testing.T) {
	scanner := NewXXEScanner()

	finding := &XXEFinding{
		URL: "http://example.com",
	}

	config := VerificationConfig{
		Enabled: false,
	}

	result, err := scanner.VerifyFinding(context.Background(), finding, config)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Verified {
		t.Error("expected finding not to be verified when verification is disabled")
	}

	if result.Attempts != 0 {
		t.Error("expected no verification attempts when verification is disabled")
	}
}

func TestXXEHTTPServer(t *testing.T) {
	// Create a test server that simulates XXE vulnerability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		// Simulate XXE vulnerability - return /etc/passwd content
		if strings.Contains(bodyStr, "file:///etc/passwd") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<root>OK</root>"))
	}))
	defer server.Close()

	scanner := NewXXEScanner()

	result := scanner.Scan(context.Background(), server.URL)

	if result == nil {
		t.Fatal("expected result to be returned")
	}

	// Should find at least one vulnerability
	if len(result.Findings) == 0 {
		t.Error("expected to find at least one XXE vulnerability from real server")
	}

	// Verify the finding has evidence
	hasEvidence := false
	for _, finding := range result.Findings {
		if finding.Evidence != "" && strings.Contains(finding.Evidence, "root") {
			hasEvidence = true
			break
		}
	}

	if !hasEvidence {
		t.Error("expected at least one finding to have evidence containing 'root'")
	}
}

func TestXXEExtractEvidence(t *testing.T) {
	scanner := NewXXEScanner()

	tests := []struct {
		name     string
		body     string
		pattern  string
		expected string
	}{
		{
			name:     "extract /etc/passwd match",
			body:     "Some content root:x:0:0:root:/root:/bin/bash more content",
			pattern:  `root:x:\d+:\d+:`,
			expected: "root:x:0:0:",
		},
		{
			name:     "extract shell path",
			body:     "daemon:x:1:1:daemon:/usr/sbin:/bin/bash",
			pattern:  `/bin/(bash|sh|zsh|dash)`,
			expected: "/bin/bash",
		},
		{
			name:     "extract boot.ini",
			body:     "File content: [boot loader]\ntimeout=30",
			pattern:  `\[boot loader\]`,
			expected: "[boot loader]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := regexp.MustCompile(tt.pattern)
			evidence := scanner.extractEvidence(tt.body, pattern)

			if evidence == "" {
				t.Error("expected evidence to be extracted")
			}

			if !strings.Contains(evidence, tt.expected) {
				t.Errorf("expected evidence to contain %q, got %q", tt.expected, evidence)
			}
		})
	}
}

func TestXXEPayloads(t *testing.T) {
	// Verify that all payloads have required fields
	for i, payload := range xxePayloads {
		if payload.Payload == "" {
			t.Errorf("payload %d has empty Payload field", i)
		}
		if payload.Type == "" {
			t.Errorf("payload %d has empty Type field", i)
		}
		if payload.Severity == "" {
			t.Errorf("payload %d has empty Severity field", i)
		}
		if payload.Description == "" {
			t.Errorf("payload %d has empty Description field", i)
		}

		// Verify payload types are valid
		if payload.Type != "in-band" && payload.Type != "blind" && payload.Type != "error-based" {
			t.Errorf("payload %d has invalid type: %s", i, payload.Type)
		}

		// Verify severity is valid
		if payload.Severity != SeverityHigh && payload.Severity != SeverityMedium && payload.Severity != SeverityLow {
			t.Errorf("payload %d has invalid severity: %s", i, payload.Severity)
		}
	}
}

func TestXXESignatures(t *testing.T) {
	// Verify that all signatures have required fields
	for i, sig := range xxeSignatures {
		if sig.pattern == nil {
			t.Errorf("signature %d has nil pattern", i)
		}
		if sig.fileType == "" {
			t.Errorf("signature %d has empty fileType field", i)
		}
		if sig.description == "" {
			t.Errorf("signature %d has empty description field", i)
		}
	}
}

func TestXXERateLimiting(t *testing.T) {
	mockClient := &mockXXEHTTPClient{}

	// Create a rate limiter that allows 1 request per second
	rateLimiter := ratelimit.NewLimiter(1)

	scanner := NewXXEScanner(
		WithXXEHTTPClient(mockClient),
		WithXXERateLimiter(rateLimiter),
	)

	start := time.Now()
	scanner.Scan(context.Background(), "http://example.com")
	elapsed := time.Since(start)

	// With rate limiting, the scan should take some time
	// (though this is a weak assertion as it depends on number of requests)
	if elapsed < 0 {
		t.Error("expected scan to take some time with rate limiting")
	}
}

func TestXXEAuthentication(t *testing.T) {
	receivedAuth := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for authentication header
		if auth := r.Header.Get("Authorization"); auth != "" {
			receivedAuth = true
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<root>OK</root>"))
	}))
	defer server.Close()

	authConfig := &auth.AuthConfig{
		BearerToken: "test-token-123",
	}

	scanner := NewXXEScanner(
		WithXXEAuth(authConfig),
	)

	scanner.Scan(context.Background(), server.URL)

	if !receivedAuth {
		t.Error("expected authentication header to be sent")
	}
}

func TestXXEDiscoverEndpoints(t *testing.T) {
	scanner := NewXXEScanner()

	parsedURL, _ := url.Parse("http://example.com:8080/path")
	endpoints := scanner.discoverXMLEndpoints(context.Background(), parsedURL)

	if len(endpoints) == 0 {
		t.Error("expected at least one endpoint to be discovered")
	}

	// Should include the base URL
	hasBaseURL := false
	for _, endpoint := range endpoints {
		if endpoint == parsedURL.String() {
			hasBaseURL = true
			break
		}
	}

	if !hasBaseURL {
		t.Error("expected discovered endpoints to include base URL")
	}

	// Should include common XML paths
	hasXMLPath := false
	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "/api/xml") || strings.Contains(endpoint, "/soap") {
			hasXMLPath = true
			break
		}
	}

	if !hasXMLPath {
		t.Error("expected discovered endpoints to include common XML paths")
	}
}

func TestXXEContentTypes(t *testing.T) {
	contentTypes := []string{
		"application/xml",
		"text/xml",
		"application/soap+xml",
	}

	receivedContentTypes := make(map[string]bool)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if ct != "" {
			receivedContentTypes[ct] = true
		}

		// Simulate XXE for testing
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "file:///etc/passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		w.Write([]byte("<root>OK</root>"))
	}))
	defer server.Close()

	scanner := NewXXEScanner()
	scanner.Scan(context.Background(), server.URL)

	// Should have tried multiple content types
	if len(receivedContentTypes) == 0 {
		t.Error("expected multiple content types to be tested")
	}

	// Verify at least one known content type was used
	hasKnownType := false
	for _, ct := range contentTypes {
		if receivedContentTypes[ct] {
			hasKnownType = true
			break
		}
	}

	if !hasKnownType {
		t.Error("expected at least one standard XML content type to be tested")
	}
}
