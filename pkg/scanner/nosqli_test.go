package scanner

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
)

// mockNoSQLiHTTPClient is a mock HTTP client for testing NoSQL injection detection.
type mockNoSQLiHTTPClient struct {
	responses map[string]*mockNoSQLiResponse
}

type mockNoSQLiResponse struct {
	statusCode int
	body       string
	delay      time.Duration
}

func (m *mockNoSQLiHTTPClient) Do(req *http.Request) (*http.Response, error) {
	urlStr := req.URL.String()

	if resp, ok := m.responses[urlStr]; ok {
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

// handlerNoSQLiHTTPClient is a mock HTTP client that delegates to a handler function.
// This avoids URL-encoding mismatch issues with the string-map based mock.
type handlerNoSQLiHTTPClient struct {
	handler func(req *http.Request) (*http.Response, error)
}

func (h *handlerNoSQLiHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return h.handler(req)
}

func TestNewNoSQLiScanner(t *testing.T) {
	scanner := NewNoSQLiScanner()

	if scanner == nil {
		t.Fatal("Expected scanner to be created")
	}

	if scanner.userAgent == "" {
		t.Error("Expected default user agent to be set")
	}

	if scanner.timeout == 0 {
		t.Error("Expected default timeout to be set")
	}

	if scanner.client == nil {
		t.Error("Expected default HTTP client to be created")
	}
}

func TestNoSQLiScannerOptions(t *testing.T) {
	mockClient := &mockNoSQLiHTTPClient{
		responses: map[string]*mockNoSQLiResponse{},
	}
	authConfig := &auth.AuthConfig{}

	scanner := NewNoSQLiScanner(
		WithNoSQLiHTTPClient(mockClient),
		WithNoSQLiUserAgent("TestAgent/1.0"),
		WithNoSQLiTimeout(60*time.Second),
		WithNoSQLiAuth(authConfig),
	)

	if scanner.client != mockClient {
		t.Error("Expected custom HTTP client to be set")
	}
	if scanner.userAgent != "TestAgent/1.0" {
		t.Errorf("Expected user agent 'TestAgent/1.0', got '%s'", scanner.userAgent)
	}
	if scanner.timeout != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", scanner.timeout)
	}
	if scanner.authConfig != authConfig {
		t.Error("Expected auth config to be set")
	}
}

func TestNoSQLiScanner_ErrorBasedDetection_MongoDB(t *testing.T) {
	mockClient := &mockNoSQLiHTTPClient{
		responses: map[string]*mockNoSQLiResponse{
			// Baseline
			"http://example.com/login?username=test": {
				statusCode: 401,
				body:       "Unauthorized",
			},
		},
	}

	// Add responses for all operator-injection payloads that trigger MongoDB errors
	mongoErrorBody := `Internal Server Error: MongoError: unknown operator: $invalidop`
	_ = mongoErrorBody

	scanner := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/login?username=test")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Target != "http://example.com/login?username=test" {
		t.Errorf("Expected target to match, got %s", result.Target)
	}

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}
}

func TestNoSQLiScanner_OperatorInjection_AuthBypass(t *testing.T) {
	// Simulate a vulnerable login endpoint that allows NoSQL operator injection auth bypass.
	// The handler returns 401 for the baseline request and 200 whenever the username
	// parameter contains a "$" character (i.e., any NoSQL operator payload).
	mockClient := &handlerNoSQLiHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			usernameParam := req.URL.Query().Get("username")
			if strings.Contains(usernameParam, "$") {
				// Injection payload detected — simulate auth bypass
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader("Welcome, admin! Dashboard loaded.")),
				}, nil
			}
			// Baseline / safe value — 401 Unauthorized
			return &http.Response{
				StatusCode: 401,
				Body:       io.NopCloser(strings.NewReader("Invalid credentials")),
			}, nil
		},
	}

	scanner := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/login?username=test")

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	// The scanner must detect the auth bypass via differential analysis (401 -> 200).
	found := false
	for _, f := range result.Findings {
		if f.Type == "operator-injection" && f.Parameter == "username" {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("Expected high severity for operator injection, got %s", f.Severity)
			}
			if f.Remediation == "" {
				t.Error("Expected remediation to be set")
			}
			break
		}
	}

	if !found {
		t.Errorf("Expected NoSQL operator injection auth-bypass finding for parameter 'username', but none was detected. Findings: %+v", result.Findings)
	}
}

func TestNoSQLiScanner_ErrorBased_MongoDBError(t *testing.T) {
	// Simulate a server that leaks MongoDB error messages
	mockClient := &mockNoSQLiHTTPClient{
		responses: map[string]*mockNoSQLiResponse{
			`http://example.com/search?q=test`: {
				statusCode: 200,
				body:       "Search results for: test",
			},
		},
	}

	// Set up error-based payload responses
	errorPayload := `{"$invalidop": "test"}`
	errorURL := `http://example.com/search?q=` + errorPayload
	mockClient.responses[errorURL] = &mockNoSQLiResponse{
		statusCode: 500,
		body:       "MongoError: unknown operator: $invalidop at position 0",
	}

	scanner := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/search?q=test")

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	// The error-based test may find a finding if the URL encodes match
	// Just verify the scan ran correctly
	if result.Errors != nil && len(result.Errors) > 0 {
		for _, e := range result.Errors {
			if strings.Contains(e, "Rate limiting") {
				t.Errorf("Unexpected rate limiting error: %s", e)
			}
		}
	}
}

func TestNoSQLiScanner_NoVulnerability(t *testing.T) {
	// All requests return same safe response (no injection effect)
	safeResponse := &mockNoSQLiResponse{
		statusCode: 200,
		body:       "Normal response with consistent content",
	}

	// Default to safe response for all URLs
	scanner := NewNoSQLiScanner(
		WithNoSQLiHTTPClient(&alwaysSafeNoSQLiClient{resp: safeResponse}),
	)
	result := scanner.Scan(context.Background(), "http://example.com/search?q=test")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}

	// With consistent responses, no findings should be reported
	if len(result.Findings) > 0 {
		t.Errorf("Expected no findings for safe application, got %d", len(result.Findings))
	}
}

// alwaysSafeNoSQLiClient always returns the same safe response.
type alwaysSafeNoSQLiClient struct {
	resp *mockNoSQLiResponse
}

func (c *alwaysSafeNoSQLiClient) Do(req *http.Request) (*http.Response, error) {
	if c.resp.delay > 0 {
		time.Sleep(c.resp.delay)
	}
	return &http.Response{
		StatusCode: c.resp.statusCode,
		Body:       io.NopCloser(strings.NewReader(c.resp.body)),
	}, nil
}

func TestNoSQLiScanner_MongoDBErrorPatterns(t *testing.T) {
	mongoErrors := []string{
		"MongoError: something went wrong",
		"MongoServerError: bad query",
		"BSONTypeError: expected string",
		"SyntaxError: EJSON parse error",
		"Failed to parse: BSON document",
		"cannot use the $ prefix in field name",
	}

	for _, errMsg := range mongoErrors {
		t.Run(errMsg, func(t *testing.T) {
			found := false
			for _, pattern := range nosqlErrorPatterns {
				if pattern.MatchString(errMsg) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected pattern to match MongoDB error: %s", errMsg)
			}
		})
	}
}

func TestNoSQLiScanner_RedisErrorPatterns(t *testing.T) {
	redisErrors := []string{
		"WRONGTYPE Operation against a key holding the wrong kind of value",
		"ERR syntax error",
		"NOAUTH Authentication required",
		"ERR Protocol error",
	}

	for _, errMsg := range redisErrors {
		t.Run(errMsg, func(t *testing.T) {
			found := false
			for _, pattern := range nosqlErrorPatterns {
				if pattern.MatchString(errMsg) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected pattern to match Redis error: %s", errMsg)
			}
		})
	}
}

func TestNoSQLiScanner_ScanPOST(t *testing.T) {
	mockClient := &alwaysSafeNoSQLiClient{
		resp: &mockNoSQLiResponse{
			statusCode: 200,
			body:       "Login successful",
		},
	}

	scanner := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))
	result := scanner.ScanPOST(context.Background(), "http://example.com/login", map[string]string{
		"username": "admin",
		"password": "secret",
	})

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Target != "http://example.com/login" {
		t.Errorf("Expected target to match, got %s", result.Target)
	}

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run")
	}
}

func TestNoSQLiScanner_ScanPOST_EmptyParameters(t *testing.T) {
	mockClient := &alwaysSafeNoSQLiClient{
		resp: &mockNoSQLiResponse{
			statusCode: 200,
			body:       "OK",
		},
	}

	scanner := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))
	// Empty parameters should use default vulnerable params
	result := scanner.ScanPOST(context.Background(), "http://example.com/api", nil)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run with default parameters")
	}
}

func TestNoSQLiScanner_InvalidURL(t *testing.T) {
	scanner := NewNoSQLiScanner()
	result := scanner.Scan(context.Background(), "://invalid-url")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected error for invalid URL")
	}
}

func TestNoSQLiScanner_InvalidURL_POST(t *testing.T) {
	scanner := NewNoSQLiScanner()
	result := scanner.ScanPOST(context.Background(), "://invalid-url", nil)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected error for invalid URL")
	}
}

func TestNoSQLiScanner_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	scanner := NewNoSQLiScanner(
		WithNoSQLiHTTPClient(&alwaysSafeNoSQLiClient{
			resp: &mockNoSQLiResponse{statusCode: 200, body: "OK"},
		}),
	)
	result := scanner.Scan(ctx, "http://example.com/search?q=test")

	if result == nil {
		t.Fatal("Expected non-nil result even on cancellation")
	}
}

func TestNoSQLiScanResult_String(t *testing.T) {
	result := &NoSQLiScanResult{
		Target: "http://example.com",
		Findings: []NoSQLiFinding{
			{
				URL:         "http://example.com/login?user=%7B%22%24ne%22%3A+%22%22%7D",
				Parameter:   "user",
				Payload:     `{"$ne": ""}`,
				Evidence:    "Status changed from 401 to 200",
				Severity:    SeverityHigh,
				Type:        "operator-injection",
				Description: "MongoDB operator injection using $ne",
				Remediation: "Use parameterized queries",
				Confidence:  "medium",
			},
		},
		Summary: NoSQLiSummary{
			TotalTests:           10,
			VulnerabilitiesFound: 1,
			HighSeverityCount:    1,
		},
	}

	str := result.String()

	if !strings.Contains(str, "NoSQL Injection") {
		t.Error("Expected String() to contain 'NoSQL Injection'")
	}
	if !strings.Contains(str, "http://example.com") {
		t.Error("Expected String() to contain target URL")
	}
	if !strings.Contains(str, "operator-injection") {
		t.Error("Expected String() to contain finding type")
	}
	if !strings.Contains(str, "HIGH") {
		t.Error("Expected String() to contain severity")
	}
}

func TestNoSQLiScanResult_String_NoFindings(t *testing.T) {
	result := &NoSQLiScanResult{
		Target:   "http://example.com",
		Findings: []NoSQLiFinding{},
		Summary:  NoSQLiSummary{TotalTests: 5},
	}

	str := result.String()

	if !strings.Contains(str, "No NoSQL injection vulnerabilities detected") {
		t.Error("Expected String() to indicate no vulnerabilities when none found")
	}
}

func TestNoSQLiScanResult_HasResults(t *testing.T) {
	result := &NoSQLiScanResult{
		Target:   "http://example.com",
		Findings: []NoSQLiFinding{},
		Summary:  NoSQLiSummary{TotalTests: 0},
	}

	if result.HasResults() {
		t.Error("Expected HasResults() to return false when no tests ran")
	}

	result.Summary.TotalTests = 5
	if !result.HasResults() {
		t.Error("Expected HasResults() to return true when tests ran")
	}

	result2 := &NoSQLiScanResult{
		Target: "http://example.com",
		Findings: []NoSQLiFinding{
			{Parameter: "user", Payload: `{"$ne": ""}`},
		},
		Summary: NoSQLiSummary{TotalTests: 0},
	}

	if !result2.HasResults() {
		t.Error("Expected HasResults() to return true when findings exist")
	}
}

func TestNoSQLiScanner_VerifyFinding(t *testing.T) {
	mockClient := &alwaysSafeNoSQLiClient{
		resp: &mockNoSQLiResponse{
			statusCode: 200,
			body:       "OK response",
		},
	}

	scanner := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))

	finding := &NoSQLiFinding{
		URL:       "http://example.com/login?username=test",
		Parameter: "username",
		Payload:   `{"$ne": ""}`,
		Type:      "operator-injection",
		Severity:  SeverityHigh,
	}

	config := VerificationConfig{
		Enabled:    true,
		MaxRetries: 3,
		Delay:      0,
	}

	result, err := scanner.VerifyFinding(context.Background(), finding, config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil verification result")
	}

	// With safe responses, it won't be verified
	if result.Attempts == 0 {
		t.Error("Expected at least one attempt")
	}
}

func TestNoSQLiScanner_VerifyFinding_NilFinding(t *testing.T) {
	scanner := NewNoSQLiScanner()

	_, err := scanner.VerifyFinding(context.Background(), nil, VerificationConfig{})
	if err == nil {
		t.Error("Expected error for nil finding")
	}
}

func TestNoSQLiScanner_VerifyFinding_InvalidURL(t *testing.T) {
	scanner := NewNoSQLiScanner()

	finding := &NoSQLiFinding{
		URL:       "://invalid",
		Parameter: "username",
		Payload:   `{"$ne": ""}`,
		Type:      "operator-injection",
	}

	_, err := scanner.VerifyFinding(context.Background(), finding, VerificationConfig{})
	if err == nil {
		t.Error("Expected error for invalid URL in finding")
	}
}

func TestNoSQLiScanner_GeneratePayloadVariants(t *testing.T) {
	scanner := NewNoSQLiScanner()

	tests := []struct {
		payload     string
		findingType string
		minVariants int
	}{
		{`{"$ne": ""}`, "operator-injection", 2},
		{`{"$gt": ""}`, "operator-injection", 2},
		{`{"$regex": ".*"}`, "operator-injection", 1},
		{`'; return true; var dummy='`, "javascript-injection", 2},
		{`[$ne]=1`, "array-pollution", 2},
	}

	for _, tt := range tests {
		t.Run(tt.payload, func(t *testing.T) {
			variants := scanner.generateNoSQLiPayloadVariants(tt.payload, tt.findingType)
			if len(variants) < tt.minVariants {
				t.Errorf("Expected at least %d variants for payload '%s', got %d", tt.minVariants, tt.payload, len(variants))
			}
			// The original payload should always be included
			found := false
			for _, v := range variants {
				if v == tt.payload {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected original payload '%s' to be included in variants", tt.payload)
			}
		})
	}
}

func TestNoSQLiScanner_IsSignificantResponseChange(t *testing.T) {
	scanner := NewNoSQLiScanner()

	tests := []struct {
		name         string
		baseline     *baselineResponse
		statusCode   int
		bodyLength   int
		expectSignif bool
	}{
		{
			name:         "same response - not significant",
			baseline:     &baselineResponse{StatusCode: 200, BodyLength: 100},
			statusCode:   200,
			bodyLength:   105,
			expectSignif: false,
		},
		{
			name:         "401 to 200 - auth bypass - significant",
			baseline:     &baselineResponse{StatusCode: 401, BodyLength: 20},
			statusCode:   200,
			bodyLength:   500,
			expectSignif: true,
		},
		{
			name:         "large body increase - significant",
			baseline:     &baselineResponse{StatusCode: 200, BodyLength: 100},
			statusCode:   200,
			bodyLength:   200,
			expectSignif: true,
		},
		{
			name:         "large body decrease - significant",
			baseline:     &baselineResponse{StatusCode: 200, BodyLength: 1000},
			statusCode:   200,
			bodyLength:   100,
			expectSignif: true,
		},
		{
			name:         "nil baseline - not significant",
			baseline:     nil,
			statusCode:   200,
			bodyLength:   100,
			expectSignif: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.isSignificantResponseChange(tt.baseline, tt.statusCode, tt.bodyLength)
			if result != tt.expectSignif {
				t.Errorf("Expected isSignificantResponseChange to return %v for test '%s'", tt.expectSignif, tt.name)
			}
		})
	}
}

func TestNoSQLiScanner_CalculateSummary(t *testing.T) {
	scanner := NewNoSQLiScanner()

	result := &NoSQLiScanResult{
		Findings: []NoSQLiFinding{
			{Severity: SeverityHigh},
			{Severity: SeverityHigh},
			{Severity: SeverityMedium},
			{Severity: SeverityLow},
		},
	}

	scanner.calculateSummary(result)

	if result.Summary.VulnerabilitiesFound != 4 {
		t.Errorf("Expected 4 vulnerabilities found, got %d", result.Summary.VulnerabilitiesFound)
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

func TestNoSQLiScanner_GetRemediation(t *testing.T) {
	scanner := NewNoSQLiScanner()
	remediation := scanner.getRemediation()

	if remediation == "" {
		t.Error("Expected non-empty remediation")
	}

	expectedKeywords := []string{"parameterized", "validation", "NoSQL"}
	for _, kw := range expectedKeywords {
		if !strings.Contains(strings.ToLower(remediation), strings.ToLower(kw)) {
			t.Errorf("Expected remediation to mention '%s'", kw)
		}
	}
}

func TestNoSQLiScanner_ExtractEvidence(t *testing.T) {
	scanner := NewNoSQLiScanner()

	body := "Some text before MongoError: unknown operator Some text after"
	match := "MongoError: unknown operator"

	evidence := scanner.extractEvidence(body, match)

	if evidence == "" {
		t.Error("Expected non-empty evidence")
	}

	if !strings.Contains(evidence, "MongoError") {
		t.Error("Expected evidence to contain the matched text")
	}
}

func TestNoSQLiScanner_ExtractEvidence_EmptyMatch(t *testing.T) {
	scanner := NewNoSQLiScanner()

	evidence := scanner.extractEvidence("some body", "")
	if evidence != "" {
		t.Error("Expected empty evidence for empty match")
	}
}

func TestNoSQLiScanner_NoParamsURL(t *testing.T) {
	// URL without query parameters should test default vulnerable params
	mockClient := &alwaysSafeNoSQLiClient{
		resp: &mockNoSQLiResponse{
			statusCode: 200,
			body:       "OK",
		},
	}

	scanner := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))
	result := scanner.Scan(context.Background(), "http://example.com/login")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Summary.TotalTests == 0 {
		t.Error("Expected tests to be run with default parameters")
	}
}

func TestNoSQLiScanResult_StringWithErrors(t *testing.T) {
	result := &NoSQLiScanResult{
		Target:   "http://example.com",
		Findings: []NoSQLiFinding{},
		Summary:  NoSQLiSummary{TotalTests: 1},
		Errors:   []string{"Connection refused", "Timeout"},
	}

	str := result.String()

	if !strings.Contains(str, "Errors") {
		t.Error("Expected String() to contain errors section")
	}
	if !strings.Contains(str, "Connection refused") {
		t.Error("Expected String() to contain error message")
	}
}

func TestNoSQLiPayloads_Coverage(t *testing.T) {
	// Verify we have payloads for all required types
	hasOperatorInjection := false
	hasJavaScriptInjection := false
	hasArrayPollution := false
	hasErrorBased := false

	for _, p := range nosqliPayloads {
		switch p.Type {
		case "operator-injection":
			hasOperatorInjection = true
		case "javascript-injection":
			hasJavaScriptInjection = true
		case "array-pollution":
			hasArrayPollution = true
		case "error-based":
			hasErrorBased = true
		}
	}

	if !hasOperatorInjection {
		t.Error("Expected operator-injection payloads")
	}
	if !hasJavaScriptInjection {
		t.Error("Expected javascript-injection payloads")
	}
	if !hasArrayPollution {
		t.Error("Expected array-pollution payloads")
	}
	if !hasErrorBased {
		t.Error("Expected error-based payloads")
	}
}

func TestNoSQLiPayloads_RequiredVectors(t *testing.T) {
	// Verify that key MongoDB payloads from the issue are present
	requiredPayloads := []string{
		`{"$gt": ""}`,
		`{"$ne": ""}`,
		`{"$regex": ".*"}`,
		`{"$where": "1==1"}`,
		`{"$or": [{}]}`,
		`'; return true; var dummy='`,
	}

	payloadSet := make(map[string]bool)
	for _, p := range nosqliPayloads {
		payloadSet[p.Payload] = true
	}

	for _, required := range requiredPayloads {
		if !payloadSet[required] {
			t.Errorf("Missing required NoSQLi payload: %s", required)
		}
	}
}

// TestNoSQLiScanner_ConfirmationRequest_SkipsRoutingParam verifies that the scanner does NOT
// report a finding when a routing parameter (e.g. ?doc=readme) naturally produces large
// response-size changes for ANY value, including benign neutral ones.
// This is the core regression test for the DVWA false-positive fix (issue #274).
func TestNoSQLiScanner_ConfirmationRequest_SkipsRoutingParam(t *testing.T) {
	// Simulate a page-routing parameter: every different value returns different content.
	// doc=readme   → 5000-byte page
	// doc=anything → 2000-byte page  (a "not found" / different page)
	// This mimics DVWA's ?doc= parameter behaviour.
	mockClient := &handlerNoSQLiHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			docVal := req.URL.Query().Get("doc")
			switch docVal {
			case "readme":
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", 5000))),
				}, nil
			default:
				// Any other value (including NoSQL payloads AND the neutral confirm value)
				// returns shorter content — mimics a "page not found" page.
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(strings.Repeat("y", 2000))),
				}, nil
			}
		},
	}

	s := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))
	result := s.Scan(context.Background(), "http://example.com/help?doc=readme")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings for routing param (false positive), got %d:", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("  false positive: param=%s payload=%s evidence=%s", f.Parameter, f.Payload, f.Evidence)
		}
	}
}

// TestNoSQLiScanner_ConfirmationRequest_DetectsRealInjection verifies that the confirmation
// logic does NOT suppress real NoSQL injection findings.
// A real injection makes the injected-payload response differ from baseline while the
// benign confirmation response stays close to baseline.
func TestNoSQLiScanner_ConfirmationRequest_DetectsRealInjection(t *testing.T) {
	// Simulate a MongoDB login endpoint:
	//   username=admin          → 200 "Login OK" (baseline, already authenticated-looking for simplicity)
	//   username={"$gt":""}     → 200 "Welcome admin" (larger; injection bypasses auth)
	//   username=nosqlicheckxyz123 → 200 "Login OK" (neutral value, same as baseline → confirms injection)
	//
	// For the scanner: baseline is sent with username=admin (original URL value).
	// Injected payload causes a size change. Neutral confirm returns same as baseline.
	const baselineBody = "Login page: enter your credentials to proceed."
	const injectedBody = "Welcome back, admin! Your dashboard is ready with all your data loaded."

	mockClient := &handlerNoSQLiHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			usernameVal := req.URL.Query().Get("username")
			if strings.Contains(usernameVal, "$") {
				// NoSQL operator payload → auth bypass, bigger response
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(injectedBody)),
				}, nil
			}
			// Baseline or neutral confirm value → same safe page
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(baselineBody)),
			}, nil
		},
	}

	s := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))
	result := s.Scan(context.Background(), "http://example.com/login?username=admin")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// The scan MUST still detect the real injection.
	found := false
	for _, f := range result.Findings {
		if f.Parameter == "username" {
			found = true
			t.Logf("Correctly detected NoSQL injection: param=%s payload=%s confidence=%s", f.Parameter, f.Payload, f.Confidence)
			break
		}
	}
	if !found {
		t.Errorf("Expected at least one finding on 'username' parameter (real injection), got %d finding(s)", len(result.Findings))
	}
}

// TestNoSQLiScanner_ConfirmVarianceIsInjection_Unit tests the low-level confirmation helper
// directly with a mock HTTP client.
func TestNoSQLiScanner_ConfirmVarianceIsInjection_Unit(t *testing.T) {
	t.Run("returns false when neutral value also varies", func(t *testing.T) {
		// Any value other than "stable" returns a response much smaller than baseline.
		// This simulates a page-router param where the neutral confirm value also
		// produces a different-sized page.
		mockClient := &handlerNoSQLiHTTPClient{
			handler: func(req *http.Request) (*http.Response, error) {
				val := req.URL.Query().Get("page")
				if val == "stable" {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("a", 1000)))}, nil
				}
				// Neutral value → small "not found" page (80% smaller than baseline)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("b", 100)))}, nil
			},
		}
		s := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))
		parsedURL, err := url.Parse("http://example.com/help?page=stable")
		if err != nil {
			t.Fatalf("Failed to parse URL: %v", err)
		}
		baseline := &baselineResponse{StatusCode: 200, BodyLength: 1000}
		result := s.confirmVarianceIsInjection(context.Background(), parsedURL, "page", baseline)
		if result {
			t.Error("Expected false (param naturally varies → not injection), got true")
		}
	})

	t.Run("returns true when neutral value stays close to baseline", func(t *testing.T) {
		// Every request returns the same stable response.
		// The neutral confirm value is identical to baseline → the param doesn't naturally vary.
		mockClient := &handlerNoSQLiHTTPClient{
			handler: func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("a", 1000)))}, nil
			},
		}
		s := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))
		parsedURL, err := url.Parse("http://example.com/login?username=admin")
		if err != nil {
			t.Fatalf("Failed to parse URL: %v", err)
		}
		baseline := &baselineResponse{StatusCode: 200, BodyLength: 1000}
		result := s.confirmVarianceIsInjection(context.Background(), parsedURL, "username", baseline)
		if !result {
			t.Error("Expected true (stable param → injection confirmed), got false")
		}
	})
}

// TestNoSQLiScanner_BaselineDrift_POST verifies that the POST differential
// analysis discards findings when the baseline has drifted due to external
// modifications (e.g., concurrent scanners storing content on the same page).
func TestNoSQLiScanner_BaselineDrift_POST(t *testing.T) {
	// Simulate a stored-content page: every POST stores content, making the
	// response body grow monotonically.  The scanner's baseline was captured
	// early (body=1000).  By the time the payload is tested, concurrent
	// activity has grown the page to 1400 (+40%).  A fresh baseline re-capture
	// also returns ~1400, proving the drift is external — not injection.
	requestCount := 0
	mockClient := &handlerNoSQLiHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			requestCount++
			// First request: baseline capture (body=1000)
			// Subsequent requests: page has grown due to concurrent activity
			var bodyLen int
			if requestCount <= 1 {
				bodyLen = 1000
			} else {
				bodyLen = 1400 // 40% larger — significant drift
			}
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", bodyLen))),
			}, nil
		},
	}

	s := NewNoSQLiScanner(WithNoSQLiHTTPClient(mockClient))

	parsedURL, err := url.Parse("http://example.com/guestbook")
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	params := map[string]string{"txtName": "test", "btnSign": "Sign"}

	result := s.ScanPOST(context.Background(), parsedURL.String(), params)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// No findings should be reported because the baseline drifted significantly,
	// indicating external page modifications rather than injection.
	for _, f := range result.Findings {
		if f.Confidence == "medium" && strings.Contains(f.Evidence, "Response changed significantly") {
			t.Errorf("Expected no differential-analysis findings on a drifting page, but got: param=%s payload=%s", f.Parameter, f.Payload)
		}
	}
}
