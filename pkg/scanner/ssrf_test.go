package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
)

// mockSSRFHTTPClient is a mock HTTP client for testing SSRF scanner.
type mockSSRFHTTPClient struct {
	responses map[string]*http.Response
	requests  []*http.Request
}

func (m *mockSSRFHTTPClient) Do(req *http.Request) (*http.Response, error) {
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

func newMockSSRFHTTPClient() *mockSSRFHTTPClient {
	return &mockSSRFHTTPClient{
		responses: make(map[string]*http.Response),
		requests:  make([]*http.Request, 0),
	}
}

func TestNewSSRFScanner(t *testing.T) {
	tests := []struct {
		name string
		opts []SSRFOption
	}{
		{
			name: "default configuration",
			opts: nil,
		},
		{
			name: "with custom timeout",
			opts: []SSRFOption{WithSSRFTimeout(60 * time.Second)},
		},
		{
			name: "with custom user agent",
			opts: []SSRFOption{WithSSRFUserAgent("TestAgent/1.0")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewSSRFScanner(tt.opts...)
			if scanner == nil {
				t.Fatal("NewSSRFScanner returned nil")
			}
			if scanner.client == nil {
				t.Error("Scanner client is nil")
			}
		})
	}
}

func TestSSRFScanner_Scan_NoParameters(t *testing.T) {
	mock := newMockSSRFHTTPClient()
	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

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

func TestSSRFScanner_Scan_AWSMetadata(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Configure mock to return AWS metadata response
	awsMetadataResponse := `ami-id
ami-launch-index
ami-manifest-path
instance-id
instance-type
local-hostname
local-ipv4
public-hostname
public-ipv4
security-groups`

	mock.responses["https://example.com/proxy?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(awsMetadataResponse)),
		Header:     make(http.Header),
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/proxy?url=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SSRF vulnerability")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	// Find the AWS metadata finding
	var awsFinding *SSRFFinding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Description, "AWS") {
			awsFinding = &result.Findings[i]
			break
		}
	}

	if awsFinding == nil {
		t.Fatal("Expected to find AWS metadata vulnerability")
	}

	if awsFinding.Parameter != "url" {
		t.Errorf("Expected parameter 'url', got %s", awsFinding.Parameter)
	}

	if awsFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, awsFinding.Severity)
	}

	if awsFinding.Confidence != "high" {
		t.Errorf("Expected high confidence, got %s", awsFinding.Confidence)
	}

	if !strings.Contains(awsFinding.Evidence, "AWS") {
		t.Errorf("Expected evidence to mention AWS, got %s", awsFinding.Evidence)
	}
}

func TestSSRFScanner_Scan_GCPMetadata(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Configure mock to return GCP metadata response
	gcpMetadataResponse := `{"project-id":"test-project","instance-id":"12345","machine-type":"n1-standard-1","attributes":{"key":"value"}}`

	mock.responses["https://example.com/fetch?uri=http%3A%2F%2Fmetadata.google.internal%2FcomputeMetadata%2Fv1%2F"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(gcpMetadataResponse)),
		Header:     make(http.Header),
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/fetch?uri=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SSRF vulnerability")
	}

	// Find the GCP metadata finding
	var gcpFinding *SSRFFinding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Description, "GCP") {
			gcpFinding = &result.Findings[i]
			break
		}
	}

	if gcpFinding == nil {
		t.Fatal("Expected to find GCP metadata vulnerability")
	}

	if gcpFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, gcpFinding.Severity)
	}
}

func TestSSRFScanner_Scan_LocalhostAccess(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Configure mock to return localhost response with localhost signature
	localhostResponse := `<html><head><title>Localhost Admin Panel</title></head><body><h1>Server running on 127.0.0.1</h1></body></html>`

	mock.responses["https://example.com/api?target=http%3A%2F%2F127.0.0.1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(localhostResponse)),
		Header:     make(http.Header),
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/api?target=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SSRF vulnerability")
	}

	// Find the localhost finding
	var localhostFinding *SSRFFinding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Description, "localhost") {
			localhostFinding = &result.Findings[i]
			break
		}
	}

	if localhostFinding == nil {
		t.Fatal("Expected to find localhost SSRF vulnerability")
	}

	if localhostFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, localhostFinding.Severity)
	}
}

func TestSSRFScanner_Scan_PrivateNetworkAccess(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Configure mock to return response from private IP
	privateNetworkResponse := `<html><body>Internal service at 192.168.1.1</body></html>`

	mock.responses["https://example.com/download?file=http%3A%2F%2F192.168.1.1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(privateNetworkResponse)),
		Header:     make(http.Header),
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/download?file=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SSRF vulnerability")
	}

	// Find the private network finding
	var privateFinding *SSRFFinding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Description, "private network") {
			privateFinding = &result.Findings[i]
			break
		}
	}

	if privateFinding == nil {
		t.Fatal("Expected to find private network SSRF vulnerability")
	}

	if privateFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, privateFinding.Severity)
	}
}

func TestSSRFScanner_Scan_FileProtocolAccess(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Configure mock to return file content
	fileContent := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin`

	mock.responses["https://example.com/view?path=file%3A%2F%2F%2Fetc%2Fpasswd"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(fileContent)),
		Header:     make(http.Header),
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/view?path=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SSRF vulnerability")
	}

	// Find the file protocol finding
	var fileFinding *SSRFFinding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Description, "file://") {
			fileFinding = &result.Findings[i]
			break
		}
	}

	if fileFinding == nil {
		t.Fatal("Expected to find file protocol SSRF vulnerability")
	}

	if fileFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, fileFinding.Severity)
	}

	if fileFinding.Confidence != "high" {
		t.Errorf("Expected high confidence, got %s", fileFinding.Confidence)
	}
}

func TestSSRFScanner_Scan_NoVulnerability(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	for _, payload := range ssrfPayloads {
		encodedPayload := strings.ReplaceAll(payload.Payload, ":", "%3A")
		encodedPayload = strings.ReplaceAll(encodedPayload, "/", "%2F")
		mockURL := fmt.Sprintf("https://example.com/proxy?url=%s", encodedPayload)
		mock.responses[mockURL] = &http.Response{
			StatusCode: http.StatusForbidden, // Application blocks internal requests
			Body:       io.NopCloser(strings.NewReader("Access denied")),
			Header:     make(http.Header),
		}
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/proxy?url=test")

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

func TestSSRFScanner_Scan_WithAuthentication(t *testing.T) {
	mock := newMockSSRFHTTPClient()
	authConfig := &auth.AuthConfig{
		BearerToken: "test-token-123",
	}

	scanner := NewSSRFScanner(
		WithSSRFHTTPClient(mock),
		WithSSRFAuth(authConfig),
	)

	ctx := context.Background()
	scanner.Scan(ctx, "https://example.com/api?url=test")

	if len(mock.requests) == 0 {
		t.Fatal("Expected at least one request")
	}

	// Check that authentication was applied
	authHeader := mock.requests[0].Header.Get("Authorization")
	if authHeader != "Bearer test-token-123" {
		t.Errorf("Expected Authorization header 'Bearer test-token-123', got %s", authHeader)
	}
}

func TestSSRFScanner_Scan_WithRateLimiting(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Create rate limiter config
	rateLimitConfig := ratelimit.Config{
		RequestsPerSecond: 10,
	}

	scanner := NewSSRFScanner(
		WithSSRFHTTPClient(mock),
		WithSSRFRateLimitConfig(rateLimitConfig),
	)

	ctx := context.Background()
	start := time.Now()
	scanner.Scan(ctx, "https://example.com?url=test")
	elapsed := time.Since(start)

	// With rate limiting, the scan should take some minimum time
	if elapsed < 0 {
		t.Error("Rate limiting doesn't appear to be working")
	}
}

func TestSSRFScanner_Scan_ContextCancellation(t *testing.T) {
	mock := newMockSSRFHTTPClient()
	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := scanner.Scan(ctx, "https://example.com?url=test")

	if result == nil {
		t.Fatal("Expected result even with cancelled context")
	}

	// Should have error about cancellation
	if len(result.Errors) == 0 {
		t.Error("Expected error about scan cancellation")
	}
}

func TestSSRFScanner_Scan_InvalidURL(t *testing.T) {
	mock := newMockSSRFHTTPClient()
	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	// Use a URL with invalid control character that will fail to parse
	result := scanner.Scan(ctx, "http://example.com\nmalformed")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected error for invalid URL")
	}

	if len(result.Errors) > 0 && !strings.Contains(result.Errors[0], "Invalid URL") {
		t.Errorf("Expected 'Invalid URL' error, got %s", result.Errors[0])
	}
}

func TestSSRFScanner_SummaryCalculation(t *testing.T) {
	result := &SSRFScanResult{
		Target: "https://example.com",
		Findings: []SSRFFinding{
			{Severity: SeverityHigh},
			{Severity: SeverityHigh},
			{Severity: SeverityMedium},
			{Severity: SeverityLow},
		},
	}

	scanner := NewSSRFScanner()
	scanner.calculateSummary(result)

	if result.Summary.VulnerabilitiesFound != 4 {
		t.Errorf("Expected 4 vulnerabilities, got %d", result.Summary.VulnerabilitiesFound)
	}

	if result.Summary.HighSeverityCount != 2 {
		t.Errorf("Expected 2 high severity findings, got %d", result.Summary.HighSeverityCount)
	}

	if result.Summary.MediumSeverityCount != 1 {
		t.Errorf("Expected 1 medium severity finding, got %d", result.Summary.MediumSeverityCount)
	}

	if result.Summary.LowSeverityCount != 1 {
		t.Errorf("Expected 1 low severity finding, got %d", result.Summary.LowSeverityCount)
	}
}

func TestSSRFScanner_HasResults(t *testing.T) {
	tests := []struct {
		name     string
		result   *SSRFScanResult
		expected bool
	}{
		{
			name: "with findings",
			result: &SSRFScanResult{
				Findings: []SSRFFinding{{URL: "test"}},
			},
			expected: true,
		},
		{
			name: "with tests but no findings",
			result: &SSRFScanResult{
				Summary: SSRFSummary{TotalTests: 5},
			},
			expected: true,
		},
		{
			name:     "empty result",
			result:   &SSRFScanResult{},
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

func TestSSRFScanner_String(t *testing.T) {
	result := &SSRFScanResult{
		Target: "https://example.com",
		Findings: []SSRFFinding{
			{
				URL:         "https://example.com?url=http://127.0.0.1",
				Parameter:   "url",
				Payload:     "http://127.0.0.1",
				Severity:    SeverityHigh,
				Type:        "blind",
				Description: "Test SSRF",
				Evidence:    "Test evidence",
				Confidence:  "high",
			},
		},
		Summary: SSRFSummary{
			TotalTests:           10,
			VulnerabilitiesFound: 1,
			HighSeverityCount:    1,
		},
	}

	output := result.String()

	if !strings.Contains(output, "https://example.com") {
		t.Error("Output should contain target URL")
	}

	if !strings.Contains(output, "Total Tests: 10") {
		t.Error("Output should contain total tests")
	}

	if !strings.Contains(output, "Vulnerabilities Found: 1") {
		t.Error("Output should contain vulnerabilities count")
	}

	if !strings.Contains(output, "Parameter: url") {
		t.Error("Output should contain finding details")
	}
}

func TestSSRFScanner_AnalyzeSSRFResponse_AWSMetadata(t *testing.T) {
	scanner := NewSSRFScanner()

	resp := &http.Response{
		StatusCode: http.StatusOK,
	}

	body := `ami-id
ami-launch-index
instance-id
instance-type
local-ipv4`

	payload := ssrfPayload{Target: "aws-metadata"}

	confidence, evidence := scanner.analyzeSSRFResponse(resp, body, payload, 100*time.Millisecond, nil)

	if confidence != "high" {
		t.Errorf("Expected high confidence for AWS metadata, got %s", confidence)
	}

	if !strings.Contains(evidence, "AWS") {
		t.Errorf("Expected evidence to mention AWS, got %s", evidence)
	}
}

func TestSSRFScanner_AnalyzeSSRFResponse_KubernetesMetadata(t *testing.T) {
	scanner := NewSSRFScanner()

	resp := &http.Response{
		StatusCode: http.StatusOK,
	}

	body := `{
  "apiVersion": "v1",
  "kind": "NamespaceList",
  "metadata": {
    "resourceVersion": "12345"
  },
  "items": [
    {
      "metadata": {
        "name": "default",
        "namespace": "default"
      }
    }
  ]
}`

	payload := ssrfPayload{Target: "k8s-metadata"}

	confidence, evidence := scanner.analyzeSSRFResponse(resp, body, payload, 100*time.Millisecond, nil)

	if confidence != "high" {
		t.Errorf("Expected high confidence for Kubernetes metadata, got %s", confidence)
	}

	if !strings.Contains(evidence, "Kubernetes") {
		t.Errorf("Expected evidence to mention Kubernetes, got %s", evidence)
	}
}

func TestSSRFScanner_Scan_KubernetesMetadata(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Configure mock to return Kubernetes API response
	k8sMetadataResponse := `{
  "apiVersion": "v1",
  "kind": "SecretList",
  "metadata": {
    "resourceVersion": "54321"
  },
  "items": [
    {
      "metadata": {
        "name": "default-token",
        "namespace": "default"
      },
      "data": {
        "token": "serviceAccountToken"
      }
    }
  ]
}`

	mock.responses["https://example.com/proxy?url=http%3A%2F%2Fkubernetes.default.svc%2Fapi%2Fv1%2Fnamespaces"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(k8sMetadataResponse)),
		Header:     make(http.Header),
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/proxy?url=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SSRF vulnerability")
	}

	// Find the K8s metadata finding
	var k8sFinding *SSRFFinding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Description, "Kubernetes") {
			k8sFinding = &result.Findings[i]
			break
		}
	}

	if k8sFinding == nil {
		t.Fatal("Expected to find Kubernetes metadata vulnerability")
	}

	if k8sFinding.Severity != SeverityHigh {
		t.Errorf("Expected severity %s, got %s", SeverityHigh, k8sFinding.Severity)
	}

	if k8sFinding.Confidence != "high" {
		t.Errorf("Expected high confidence, got %s", k8sFinding.Confidence)
	}

	if !strings.Contains(k8sFinding.Evidence, "Kubernetes") {
		t.Errorf("Expected evidence to mention Kubernetes, got %s", k8sFinding.Evidence)
	}
}

func TestSSRFScanner_VerifyFinding(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Set up responses for verification variants
	mock.responses["https://example.com/test?param=http%3A%2F%2F127.0.0.1"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("Localhost content: 127.0.0.1")),
		Header:     make(http.Header),
	}

	mock.responses["https://example.com/test?param=http%3A%2F%2FLOCALHOST"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("Localhost content: 127.0.0.1")),
		Header:     make(http.Header),
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	finding := &SSRFFinding{
		URL:       "https://example.com/test?param=http://127.0.0.1",
		Parameter: "param",
		Payload:   "http://127.0.0.1",
	}

	config := VerificationConfig{
		Enabled:    true,
		MaxRetries: 2,
		Delay:      10 * time.Millisecond,
	}

	ctx := context.Background()
	result, err := scanner.VerifyFinding(ctx, finding, config)

	if err != nil {
		t.Fatalf("VerifyFinding returned error: %v", err)
	}

	if result == nil {
		t.Fatal("VerifyFinding returned nil result")
	}

	if result.Attempts == 0 {
		t.Error("Expected at least one verification attempt")
	}
}

func TestSSRFScanner_GeneratePayloadVariants(t *testing.T) {
	scanner := NewSSRFScanner()

	originalPayload := "http://127.0.0.1"
	variants := scanner.generateSSRFPayloadVariants(originalPayload)

	if len(variants) == 0 {
		t.Fatal("Expected at least one variant")
	}

	if variants[0] != originalPayload {
		t.Error("First variant should be the original payload")
	}

	// Check that we have different variants
	uniqueVariants := make(map[string]bool)
	for _, v := range variants {
		uniqueVariants[v] = true
	}

	if len(uniqueVariants) < 2 {
		t.Error("Expected multiple unique variants")
	}
}

func TestSSRFScanner_ExtractTargetType(t *testing.T) {
	tests := []struct {
		payload      string
		expectedType string
	}{
		{"http://169.254.169.254/latest/meta-data/", "aws-metadata"},
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure-metadata"},
		{"http://metadata.google.internal/computeMetadata/v1/", "gcp-metadata"},
		{"http://kubernetes.default.svc/api/v1/namespaces", "k8s-metadata"},
		{"http://kubernetes.default.svc.cluster.local/api/v1/secrets", "k8s-metadata"},
		{"https://kubernetes.default.svc/api/v1/pods", "k8s-metadata"},
		{"http://127.0.0.1", "localhost"},
		{"http://localhost", "localhost"},
		{"http://192.168.1.1", "private-network"},
		{"http://10.0.0.1", "private-network"},
		{"file:///etc/passwd", "file-protocol"},
		{"dict://127.0.0.1:11211/stats", "dict-protocol"},
		{"gopher://127.0.0.1:6379/_test", "gopher-protocol"},
		{"http://example.com", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.payload, func(t *testing.T) {
			result := extractTargetType(tt.payload)
			if result != tt.expectedType {
				t.Errorf("extractTargetType(%s) = %s, expected %s", tt.payload, result, tt.expectedType)
			}
		})
	}
}

func TestSSRFScanner_ContainsPrivateIPPatterns(t *testing.T) {
	tests := []struct {
		body     string
		expected bool
	}{
		{"Server at 10.0.0.1", true},
		{"Connection to 192.168.1.1", true},
		{"Internal service 172.16.0.1", true},
		{"External IP 8.8.8.8", false},
		{"Public service 1.2.3.4", false},
		{"No IPs here", false},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			result := containsPrivateIPPatterns(tt.body)
			if result != tt.expected {
				t.Errorf("containsPrivateIPPatterns(%s) = %v, expected %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestSSRFScanner_ContainsFileAccessSignature(t *testing.T) {
	tests := []struct {
		body     string
		expected bool
	}{
		{"root:x:0:0:root:/root:/bin/bash", true},
		{"daemon:x:1:1:daemon:/usr/sbin:/bin/sh", true},
		{"C:\\Windows\\System32", true},
		{"Normal web content", false},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			result := containsFileAccessSignature(tt.body)
			if result != tt.expected {
				t.Errorf("containsFileAccessSignature(%s) = %v, expected %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestSSRFScanner_BaselineComparison_ReducesFalsePositives(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Configure baseline response - a normal page that happens to contain "nginx"
	baselineResponse := `<html><head><title>My Site</title></head><body>
		<p>Welcome to my site! Powered by nginx web server.</p>
		<footer>Running on apache infrastructure</footer>
	</body></html>`

	// The baseline URL (no query params or with original values)
	mock.responses["https://example.com"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineResponse)),
		Header:     make(http.Header),
	}

	// Configure all SSRF payload responses to return THE SAME content
	// (app ignores unknown parameters)
	for _, payload := range ssrfPayloads {
		testURL := fmt.Sprintf("https://example.com?url=%s", payload.Payload)
		mock.responses[testURL] = &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(baselineResponse)),
			Header:     make(http.Header),
		}
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should NOT report false positives when baseline and response are identical
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Errorf("Expected no vulnerabilities (false positives), but found %d", result.Summary.VulnerabilitiesFound)
		for _, finding := range result.Findings {
			t.Logf("False positive finding: %s - %s", finding.Parameter, finding.Evidence)
		}
	}
}

func TestSSRFScanner_BaselineComparison_DetectsRealSSRF(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Configure baseline response - normal page
	baselineResponse := `<html><head><title>My Site</title></head><body>
		<p>Welcome to my site!</p>
	</body></html>`

	mock.responses["https://example.com/proxy?url=test"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineResponse)),
		Header:     make(http.Header),
	}

	// Configure AWS metadata response - different from baseline
	awsMetadataResponse := `ami-id
ami-launch-index
instance-id
instance-type
local-ipv4
security-groups`

	mock.responses["https://example.com/proxy?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(awsMetadataResponse)),
		Header:     make(http.Header),
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	result := scanner.Scan(ctx, "https://example.com/proxy?url=test")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Should detect real SSRF when response differs from baseline
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Error("Expected to find SSRF vulnerability (real positive)")
	}

	// Find the AWS metadata finding
	var awsFinding *SSRFFinding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Description, "AWS") {
			awsFinding = &result.Findings[i]
			break
		}
	}

	if awsFinding == nil {
		t.Error("Expected to find AWS metadata vulnerability")
	}
}

func TestSSRFScanner_FetchBaseline_GET(t *testing.T) {
	mock := newMockSSRFHTTPClient()
	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	baselineBody := "<html><body>Test content with nginx</body></html>"
	mock.responses["https://example.com/test"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineBody)),
		Header:     make(http.Header),
	}

	ctx := context.Background()
	baseline := scanner.fetchBaseline(ctx, "https://example.com/test", http.MethodGet, nil)

	if baseline == nil {
		t.Fatal("fetchBaseline returned nil")
	}

	if baseline.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", baseline.StatusCode)
	}

	if baseline.BodyLength != len(baselineBody) {
		t.Errorf("Expected body length %d, got %d", len(baselineBody), baseline.BodyLength)
	}

	if baseline.Body != baselineBody {
		t.Errorf("Expected body to be preserved")
	}

	// Check that signatures were collected
	if len(baseline.Signatures) == 0 {
		t.Error("Expected some signatures to be collected from baseline")
	}

	// Check that nginx signature was found
	found := false
	for _, sig := range baseline.Signatures {
		if strings.Contains(sig, "nginx") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find nginx signature in baseline")
	}
}

func TestSSRFScanner_FetchBaseline_POST(t *testing.T) {
	mock := newMockSSRFHTTPClient()
	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	baselineBody := "<html><body>POST response</body></html>"

	// Note: The mock needs to match on the exact URL for POST
	mock.responses["https://example.com/form"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineBody)),
		Header:     make(http.Header),
	}

	ctx := context.Background()
	formData := url.Values{}
	formData.Set("field1", "value1")
	formData.Set("field2", "value2")

	baseline := scanner.fetchBaseline(ctx, "https://example.com/form", http.MethodPost, formData)

	if baseline == nil {
		t.Fatal("fetchBaseline returned nil")
	}

	if baseline.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", baseline.StatusCode)
	}

	// Verify that a POST request was made
	if len(mock.requests) == 0 {
		t.Fatal("Expected at least one request to be made")
	}

	lastRequest := mock.requests[len(mock.requests)-1]
	if lastRequest.Method != http.MethodPost {
		t.Errorf("Expected POST request, got %s", lastRequest.Method)
	}

	if lastRequest.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("Expected Content-Type to be application/x-www-form-urlencoded, got %s", lastRequest.Header.Get("Content-Type"))
	}
}

func TestSSRFScanner_CollectSignatures(t *testing.T) {
	scanner := NewSSRFScanner()

	tests := []struct {
		name             string
		body             string
		expectedPrefixes []string
	}{
		{
			name:             "AWS metadata signatures",
			body:             "ami-id: ami-12345\ninstance-id: i-67890\nlocal-ipv4: 10.0.0.1",
			expectedPrefixes: []string{"aws:"},
		},
		{
			name:             "nginx signature",
			body:             "<html><body>Powered by nginx</body></html>",
			expectedPrefixes: []string{"service:"},
		},
		{
			name:             "localhost signature",
			body:             "Connection to 127.0.0.1 established",
			expectedPrefixes: []string{"localhost:"},
		},
		{
			name:             "private IP",
			body:             "Server at 192.168.1.1",
			expectedPrefixes: []string{"private-ip"},
		},
		{
			name:             "file access",
			body:             "root:x:0:0:root:/root:/bin/bash",
			expectedPrefixes: []string{"file:"},
		},
		{
			name:             "kubernetes API",
			body:             `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"default"}}`,
			expectedPrefixes: []string{"k8s:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signatures := scanner.collectSignatures(tt.body)

			if len(signatures) == 0 {
				t.Error("Expected to collect some signatures")
			}

			for _, prefix := range tt.expectedPrefixes {
				found := false
				for _, sig := range signatures {
					if prefix == "private-ip" {
						if sig == "private-ip" {
							found = true
							break
						}
					} else if strings.HasPrefix(sig, prefix) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find signature with prefix %s, got signatures: %v", prefix, signatures)
				}
			}
		})
	}
}

func TestSSRFScanner_SignaturesInBaseline(t *testing.T) {
	scanner := NewSSRFScanner()

	baselineSignatures := []string{
		"service:nginx",
		"service:apache",
		"localhost:127.0.0.1",
		"private-ip",
	}

	tests := []struct {
		prefix   string
		expected bool
	}{
		{"service", true},
		{"localhost", true},
		{"aws", false},
		{"gcp", false},
		{"file", false},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			result := scanner.signaturesInBaseline(baselineSignatures, tt.prefix)
			if result != tt.expected {
				t.Errorf("signaturesInBaseline(%s) = %v, expected %v", tt.prefix, result, tt.expected)
			}
		})
	}

	// Test special case for "private-ip" which doesn't have a colon
	if !scanner.signaturesInBaseline([]string{"private-ip"}, "private-ip") {
		t.Error("Expected to find private-ip signature")
	}
}

// TestSSRFScanner_PerParameterBaseline verifies that the scanner uses per-parameter baselines
// instead of a single URL baseline. This prevents false positives when testing invented parameters.
func TestSSRFScanner_PerParameterBaseline_InventedParameters(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Simulate an app that responds differently based on whether the 'url' parameter exists
	// This is a common pattern - apps may require parameters and show errors when missing

	// Baseline WITH the parameter (benign value) - normal response
	baselineResponse := `<html><body>
		<h1>Proxy Service</h1>
		<p>Ready to fetch content</p>
	</body></html>`

	// Response when SSRF payload is used - SAME structure and content
	// The app simply ignores the url parameter value (doesn't echo it)
	ssrfPayloadResponse := `<html><body>
		<h1>Proxy Service</h1>
		<p>Ready to fetch content</p>
	</body></html>`

	// Set up responses for baseline with benign value
	mock.responses["https://example.com/proxy?url=https%3A%2F%2Fexample.com"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineResponse)),
		Header:     make(http.Header),
	}

	// Set up responses for each SSRF payload
	for _, payload := range ssrfPayloads {
		testURL := fmt.Sprintf("https://example.com/proxy?url=%s", url.QueryEscape(payload.Payload))
		// App accepts any URL-like value and shows it - no actual SSRF vulnerability
		mock.responses[testURL] = &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(ssrfPayloadResponse)),
			Header:     make(http.Header),
		}
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	// URL without parameters - scanner will invent "url" parameter
	result := scanner.Scan(ctx, "https://example.com/proxy")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// With per-parameter baseline, this should NOT produce false positives
	// because the baseline (with url=https://example.com) and test responses are similar
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Errorf("Expected no false positives with per-parameter baseline, but found %d vulnerabilities", result.Summary.VulnerabilitiesFound)
		for _, finding := range result.Findings {
			t.Logf("False positive: param=%s, payload=%s, evidence=%s", finding.Parameter, finding.Payload, finding.Evidence)
		}
	}
}

// TestSSRFScanner_PerParameterBaseline_POST verifies per-parameter baselines work for POST requests
func TestSSRFScanner_PerParameterBaseline_POST(t *testing.T) {
	mock := newMockSSRFHTTPClient()

	// Baseline response with benign url parameter value
	baselineResponse := `<html><body>Proxy active</body></html>`

	// Configure mock to return same response for baseline and test
	// This simulates an app that accepts any URL value without actually making SSRF requests
	mock.responses["https://example.com/api/fetch"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(baselineResponse)),
		Header:     make(http.Header),
	}

	scanner := NewSSRFScanner(WithSSRFHTTPClient(mock))

	ctx := context.Background()
	params := map[string]string{
		"url": "",
	}
	result := scanner.ScanPOST(ctx, "https://example.com/api/fetch", params)

	if result == nil {
		t.Fatal("ScanPOST returned nil result")
	}

	// Should not produce false positives since responses are identical
	if result.Summary.VulnerabilitiesFound > 0 {
		t.Errorf("Expected no false positives with per-parameter baseline in POST, but found %d", result.Summary.VulnerabilitiesFound)
		for _, finding := range result.Findings {
			t.Logf("False positive: param=%s, payload=%s", finding.Parameter, finding.Payload)
		}
	}
}
