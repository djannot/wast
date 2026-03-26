package websocket

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestNewSecurityScanner(t *testing.T) {
	tests := []struct {
		name       string
		opts       []ScannerOption
		wantActive bool
	}{
		{
			name:       "default scanner",
			opts:       nil,
			wantActive: false,
		},
		{
			name: "with active mode",
			opts: []ScannerOption{
				WithActiveMode(true),
			},
			wantActive: true,
		},
		{
			name: "with custom options",
			opts: []ScannerOption{
				WithScannerUserAgent("TestAgent/1.0"),
				WithScannerTimeout(10 * time.Second),
				WithActiveMode(false),
			},
			wantActive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewSecurityScanner(tt.opts...)
			if scanner == nil {
				t.Fatal("NewSecurityScanner returned nil")
			}
			if scanner.client == nil {
				t.Error("scanner.client is nil")
			}
			if scanner.userAgent == "" {
				t.Error("scanner.userAgent is empty")
			}
			if scanner.activeMode != tt.wantActive {
				t.Errorf("activeMode = %v, want %v", scanner.activeMode, tt.wantActive)
			}
		})
	}
}

func TestScanInsecureProtocol(t *testing.T) {
	scanner := NewSecurityScanner()

	detectionResult := &DetectionResult{
		Target: "https://example.com",
		Endpoints: []WebSocketEndpoint{
			{
				URL:             "ws://example.com/socket",
				DetectionMethod: "javascript",
				SourcePage:      "https://example.com",
				IsSecure:        false,
			},
		},
	}

	ctx := context.Background()
	result := scanner.Scan(ctx, detectionResult)

	if result == nil {
		t.Fatal("Scan returned nil")
	}

	if result.Target != detectionResult.Target {
		t.Errorf("target = %q, want %q", result.Target, detectionResult.Target)
	}

	if result.Summary.TotalEndpoints != 1 {
		t.Errorf("TotalEndpoints = %d, want 1", result.Summary.TotalEndpoints)
	}

	// Should have at least one finding for insecure protocol
	if len(result.Findings) == 0 {
		t.Fatal("no findings detected for insecure protocol")
	}

	// Check for insecure protocol finding
	foundInsecure := false
	for _, finding := range result.Findings {
		if finding.FindingType == "insecure_protocol" {
			foundInsecure = true
			if finding.Severity != SeverityMedium {
				t.Errorf("insecure protocol severity = %q, want %q", finding.Severity, SeverityMedium)
			}
			if finding.RuleID != "WAST-WS-001" {
				t.Errorf("insecure protocol rule ID = %q, want %q", finding.RuleID, "WAST-WS-001")
			}
			if finding.CWE != "CWE-319" {
				t.Errorf("insecure protocol CWE = %q, want %q", finding.CWE, "CWE-319")
			}
			if finding.URL != "ws://example.com/socket" {
				t.Errorf("finding URL = %q, want %q", finding.URL, "ws://example.com/socket")
			}
		}
	}

	if !foundInsecure {
		t.Error("insecure_protocol finding not found")
	}

	// Check summary counts
	if result.Summary.MediumSeverityCount == 0 {
		t.Error("MediumSeverityCount should be > 0 for insecure protocol")
	}

	if result.Summary.VulnerableEndpoints != 1 {
		t.Errorf("VulnerableEndpoints = %d, want 1", result.Summary.VulnerableEndpoints)
	}
}

func TestScanSecureProtocol(t *testing.T) {
	scanner := NewSecurityScanner()

	detectionResult := &DetectionResult{
		Target: "https://example.com",
		Endpoints: []WebSocketEndpoint{
			{
				URL:             "wss://example.com/socket",
				DetectionMethod: "javascript",
				SourcePage:      "https://example.com",
				IsSecure:        true,
			},
		},
	}

	ctx := context.Background()
	result := scanner.Scan(ctx, detectionResult)

	if result == nil {
		t.Fatal("Scan returned nil")
	}

	// Should not have insecure protocol finding
	for _, finding := range result.Findings {
		if finding.FindingType == "insecure_protocol" {
			t.Error("found insecure_protocol finding for wss:// endpoint")
		}
	}
}

func TestScanPassiveMode(t *testing.T) {
	scanner := NewSecurityScanner(WithActiveMode(false))

	detectionResult := &DetectionResult{
		Target: "https://example.com",
		Endpoints: []WebSocketEndpoint{
			{
				URL:             "wss://example.com/socket",
				DetectionMethod: "javascript",
				SourcePage:      "https://example.com",
				IsSecure:        true,
			},
		},
	}

	ctx := context.Background()
	result := scanner.Scan(ctx, detectionResult)

	if result == nil {
		t.Fatal("Scan returned nil")
	}

	// In passive mode, should have info finding about potential missing origin validation
	foundPassiveCheck := false
	for _, finding := range result.Findings {
		if finding.FindingType == "potential_missing_origin_validation" {
			foundPassiveCheck = true
			if finding.Severity != SeverityInfo {
				t.Errorf("passive check severity = %q, want %q", finding.Severity, SeverityInfo)
			}
			if finding.RuleID != "WAST-WS-002" {
				t.Errorf("passive check rule ID = %q, want %q", finding.RuleID, "WAST-WS-002")
			}
			if finding.Confidence != "low" {
				t.Errorf("passive check confidence = %q, want %q", finding.Confidence, "low")
			}
		}
	}

	if !foundPassiveCheck {
		t.Error("passive origin validation check not found")
	}
}

func TestScanMultipleEndpoints(t *testing.T) {
	scanner := NewSecurityScanner()

	detectionResult := &DetectionResult{
		Target: "https://example.com",
		Endpoints: []WebSocketEndpoint{
			{
				URL:             "ws://example.com/chat",
				DetectionMethod: "javascript",
				SourcePage:      "https://example.com/chat.html",
				IsSecure:        false,
			},
			{
				URL:             "wss://example.com/notifications",
				DetectionMethod: "javascript",
				SourcePage:      "https://example.com/app.html",
				IsSecure:        true,
			},
			{
				URL:             "ws://example.com/logs",
				DetectionMethod: "javascript",
				SourcePage:      "https://example.com/admin.html",
				IsSecure:        false,
			},
		},
	}

	ctx := context.Background()
	result := scanner.Scan(ctx, detectionResult)

	if result == nil {
		t.Fatal("Scan returned nil")
	}

	if result.Summary.TotalEndpoints != 3 {
		t.Errorf("TotalEndpoints = %d, want 3", result.Summary.TotalEndpoints)
	}

	// Should have findings for insecure endpoints
	insecureCount := 0
	for _, finding := range result.Findings {
		if finding.FindingType == "insecure_protocol" {
			insecureCount++
		}
	}

	if insecureCount != 2 {
		t.Errorf("found %d insecure protocol findings, want 2", insecureCount)
	}

	// Check that vulnerable endpoints count is correct
	if result.Summary.VulnerableEndpoints < 2 {
		t.Errorf("VulnerableEndpoints = %d, want at least 2", result.Summary.VulnerableEndpoints)
	}
}

func TestScanEmptyDetectionResult(t *testing.T) {
	scanner := NewSecurityScanner()

	detectionResult := &DetectionResult{
		Target:    "https://example.com",
		Endpoints: []WebSocketEndpoint{},
	}

	ctx := context.Background()
	result := scanner.Scan(ctx, detectionResult)

	if result == nil {
		t.Fatal("Scan returned nil")
	}

	if result.Summary.TotalEndpoints != 0 {
		t.Errorf("TotalEndpoints = %d, want 0", result.Summary.TotalEndpoints)
	}

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for empty detection result, got %d", len(result.Findings))
	}

	if result.Summary.VulnerableEndpoints != 0 {
		t.Errorf("VulnerableEndpoints = %d, want 0", result.Summary.VulnerableEndpoints)
	}
}

func TestScanResultString(t *testing.T) {
	result := &ScanResult{
		Target: "https://example.com",
		Summary: ScanSummary{
			TotalEndpoints:      2,
			VulnerableEndpoints: 1,
			HighSeverityCount:   0,
			MediumSeverityCount: 1,
			LowSeverityCount:    0,
			InfoCount:           1,
		},
		Findings: []WebSocketFinding{
			{
				URL:         "ws://example.com/socket",
				FindingType: "insecure_protocol",
				Severity:    SeverityMedium,
				Description: "Insecure WebSocket connection",
				RuleID:      "WAST-WS-001",
				CWE:         "CWE-319",
			},
		},
	}

	str := result.String()

	if str == "" {
		t.Error("String() returned empty string")
	}

	// Check that important information is included
	if !strings.Contains(str, "WebSocket Security Scan") {
		t.Error("String() missing header")
	}

	if !strings.Contains(str, result.Target) {
		t.Error("String() missing target")
	}

	if !strings.Contains(str, "Total Endpoints") {
		t.Error("String() missing statistics")
	}

	if !strings.Contains(str, "WAST-WS-001") {
		t.Error("String() missing rule ID")
	}

	if !strings.Contains(str, "CWE-319") {
		t.Error("String() missing CWE")
	}

	if !strings.Contains(str, "insecure_protocol") {
		t.Error("String() missing finding type")
	}
}

func TestWebSocketFindingFields(t *testing.T) {
	finding := WebSocketFinding{
		URL:                 "ws://example.com/socket",
		FindingType:         "insecure_protocol",
		Severity:            SeverityMedium,
		Description:         "Test description",
		Remediation:         "Test remediation",
		Evidence:            "Test evidence",
		Confidence:          "high",
		RuleID:              "WAST-WS-001",
		CWE:                 "CWE-319",
		OriginHeader:        "http://evil.com",
		OriginValidated:     false,
		AcceptHeaderPresent: true,
	}

	if finding.URL != "ws://example.com/socket" {
		t.Errorf("URL = %q, want %q", finding.URL, "ws://example.com/socket")
	}

	if finding.Severity != SeverityMedium {
		t.Errorf("Severity = %q, want %q", finding.Severity, SeverityMedium)
	}

	if finding.RuleID != "WAST-WS-001" {
		t.Errorf("RuleID = %q, want %q", finding.RuleID, "WAST-WS-001")
	}

	if finding.CWE != "CWE-319" {
		t.Errorf("CWE = %q, want %q", finding.CWE, "CWE-319")
	}
}

func TestScanSummaryAccumulation(t *testing.T) {
	scanner := NewSecurityScanner()

	detectionResult := &DetectionResult{
		Target: "https://example.com",
		Endpoints: []WebSocketEndpoint{
			{
				URL:             "ws://example.com/socket1",
				DetectionMethod: "javascript",
				SourcePage:      "https://example.com",
				IsSecure:        false,
			},
			{
				URL:             "ws://example.com/socket2",
				DetectionMethod: "javascript",
				SourcePage:      "https://example.com",
				IsSecure:        false,
			},
		},
	}

	ctx := context.Background()
	result := scanner.Scan(ctx, detectionResult)

	// Verify that all severity counts are accumulated correctly
	totalSeverity := result.Summary.HighSeverityCount +
		result.Summary.MediumSeverityCount +
		result.Summary.LowSeverityCount +
		result.Summary.InfoCount

	if totalSeverity != len(result.Findings) {
		t.Errorf("sum of severity counts (%d) != total findings (%d)",
			totalSeverity, len(result.Findings))
	}
}

func TestScanContext(t *testing.T) {
	scanner := NewSecurityScanner()

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	detectionResult := &DetectionResult{
		Target: "https://example.com",
		Endpoints: []WebSocketEndpoint{
			{
				URL:             "wss://example.com/socket",
				DetectionMethod: "javascript",
				SourcePage:      "https://example.com",
				IsSecure:        true,
			},
		},
	}

	// Should still return a result even with cancelled context (passive mode)
	result := scanner.Scan(ctx, detectionResult)
	if result == nil {
		t.Fatal("Scan returned nil with cancelled context")
	}
}

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     string
	}{
		{"info", SeverityInfo, "info"},
		{"low", SeverityLow, "low"},
		{"medium", SeverityMedium, "medium"},
		{"high", SeverityHigh, "high"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.severity != tt.want {
				t.Errorf("severity constant = %q, want %q", tt.severity, tt.want)
			}
		})
	}
}

func TestScanResultWithErrors(t *testing.T) {
	result := &ScanResult{
		Target: "https://example.com",
		Summary: ScanSummary{
			TotalEndpoints: 1,
		},
		Findings: []WebSocketFinding{},
		Errors: []string{
			"Error 1: Connection timeout",
			"Error 2: Invalid URL",
		},
	}

	str := result.String()

	if !strings.Contains(str, "Error 1") {
		t.Error("String() missing first error")
	}

	if !strings.Contains(str, "Error 2") {
		t.Error("String() missing second error")
	}

	if !strings.Contains(str, "Errors encountered") {
		t.Error("String() missing errors section header")
	}
}

func TestFindingConfidenceLevels(t *testing.T) {
	tests := []struct {
		name       string
		confidence string
	}{
		{"high confidence", "high"},
		{"medium confidence", "medium"},
		{"low confidence", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := WebSocketFinding{
				Confidence: tt.confidence,
			}

			if finding.Confidence != tt.confidence {
				t.Errorf("Confidence = %q, want %q", finding.Confidence, tt.confidence)
			}
		})
	}
}

func TestScannerOptions(t *testing.T) {
	scanner := NewSecurityScanner(
		WithScannerHTTPClient(nil),
		WithScannerUserAgent("TestAgent"),
		WithScannerTimeout(5*time.Second),
		WithScannerAuth(nil),
		WithScannerRateLimiter(nil),
		WithScannerTracer(nil),
		WithActiveMode(true),
	)

	if scanner.userAgent != "TestAgent" {
		t.Errorf("userAgent = %q, want %q", scanner.userAgent, "TestAgent")
	}

	if scanner.timeout != 5*time.Second {
		t.Errorf("timeout = %v, want %v", scanner.timeout, 5*time.Second)
	}

	if !scanner.activeMode {
		t.Error("activeMode = false, want true")
	}
}

func TestScanSummaryStructure(t *testing.T) {
	summary := ScanSummary{
		TotalEndpoints:      5,
		VulnerableEndpoints: 3,
		HighSeverityCount:   1,
		MediumSeverityCount: 2,
		LowSeverityCount:    1,
		InfoCount:           1,
	}

	if summary.TotalEndpoints != 5 {
		t.Errorf("TotalEndpoints = %d, want 5", summary.TotalEndpoints)
	}

	if summary.VulnerableEndpoints != 3 {
		t.Errorf("VulnerableEndpoints = %d, want 3", summary.VulnerableEndpoints)
	}

	total := summary.HighSeverityCount + summary.MediumSeverityCount +
		summary.LowSeverityCount + summary.InfoCount

	if total != 5 {
		t.Errorf("sum of severity counts = %d, want 5", total)
	}
}

func TestWebSocketFindingCWE(t *testing.T) {
	tests := []struct {
		name        string
		findingType string
		wantCWE     string
		wantRuleID  string
	}{
		{
			name:        "insecure protocol",
			findingType: "insecure_protocol",
			wantCWE:     "CWE-319",
			wantRuleID:  "WAST-WS-001",
		},
		{
			name:        "missing origin validation",
			findingType: "missing_origin_validation",
			wantCWE:     "CWE-346",
			wantRuleID:  "WAST-WS-002",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewSecurityScanner()
			detectionResult := &DetectionResult{
				Target: "https://example.com",
				Endpoints: []WebSocketEndpoint{
					{
						URL:             "ws://example.com/socket",
						DetectionMethod: "javascript",
						SourcePage:      "https://example.com",
						IsSecure:        false,
					},
				},
			}

			result := scanner.Scan(context.Background(), detectionResult)

			for _, finding := range result.Findings {
				if finding.FindingType == tt.findingType {
					if finding.CWE != tt.wantCWE && tt.wantCWE != "" {
						t.Errorf("CWE = %q, want %q", finding.CWE, tt.wantCWE)
					}
					if finding.RuleID != tt.wantRuleID {
						t.Errorf("RuleID = %q, want %q", finding.RuleID, tt.wantRuleID)
					}
					return
				}
			}

			if tt.wantRuleID == "WAST-WS-001" {
				// For insecure protocol, we should definitely find it
				t.Errorf("finding with type %q not found", tt.findingType)
			}
		})
	}
}

// mockHTTPClientWithFunc extends the existing mockHTTPClient with custom response function
type mockHTTPClientWithFunc struct {
	doFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClientWithFunc) Do(req *http.Request) (*http.Response, error) {
	if m.doFunc != nil {
		return m.doFunc(req)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}, nil
}

// Test performActiveTests with mock WebSocket server
func TestPerformActiveTests(t *testing.T) {
	// Create a mock WebSocket server that accepts all connections
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		// Echo server
		io.Copy(ws, ws)
	}))
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/socket"

	tests := []struct {
		name          string
		endpoint      WebSocketEndpoint
		wantFindings  int
		checkFinding  func(*testing.T, []WebSocketFinding)
	}{
		{
			name: "insecure endpoint with active tests",
			endpoint: WebSocketEndpoint{
				URL:             wsURL,
				DetectionMethod: "javascript",
				SourcePage:      "http://example.com",
				IsSecure:        false,
			},
			wantFindings: 1, // Should detect missing origin validation
			checkFinding: func(t *testing.T, findings []WebSocketFinding) {
				found := false
				for _, f := range findings {
					if f.FindingType == "missing_origin_validation" {
						found = true
						if f.Severity != SeverityHigh {
							t.Errorf("Expected high severity, got %s", f.Severity)
						}
						if f.RuleID != "WAST-WS-002" {
							t.Errorf("Expected WAST-WS-002, got %s", f.RuleID)
						}
					}
				}
				if !found {
					t.Error("missing_origin_validation finding not found")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewSecurityScanner(
				WithActiveMode(true),
				WithScannerTimeout(5*time.Second),
			)

			ctx := context.Background()
			findings := scanner.performActiveTests(ctx, tt.endpoint)

			if len(findings) < tt.wantFindings {
				t.Errorf("performActiveTests() returned %d findings, want at least %d", len(findings), tt.wantFindings)
			}

			if tt.checkFinding != nil {
				tt.checkFinding(t, findings)
			}
		})
	}
}

// Test testOriginValidation
func TestTestOriginValidation(t *testing.T) {
	tests := []struct {
		name             string
		acceptEvil       bool
		acceptLegitimate bool
		wantFindingType  string
		wantSeverity     string
	}{
		{
			name:             "accepts malicious origin - vulnerable",
			acceptEvil:       true,
			acceptLegitimate: true,
			wantFindingType:  "missing_origin_validation",
			wantSeverity:     SeverityHigh,
		},
		{
			name:             "rejects malicious, accepts legitimate - secure",
			acceptEvil:       false,
			acceptLegitimate: true,
			wantFindingType:  "origin_validation_present",
			wantSeverity:     SeverityInfo,
		},
		{
			name:             "rejects both - endpoint down",
			acceptEvil:       false,
			acceptLegitimate: false,
			wantFindingType:  "",
			wantSeverity:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock WebSocket server with origin validation
			handler := func(ws *websocket.Conn) {
				defer ws.Close()
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				origin := r.Header.Get("Origin")

				// Determine if we should accept based on test case
				shouldAccept := false
				if origin == "http://evil.com" && tt.acceptEvil {
					shouldAccept = true
				} else if origin != "http://evil.com" && tt.acceptLegitimate {
					shouldAccept = true
				}

				if shouldAccept {
					// Perform WebSocket upgrade
					websocket.Handler(handler).ServeHTTP(w, r)
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
			}))
			defer server.Close()

			wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/socket"

			scanner := NewSecurityScanner(
				WithScannerTimeout(2 * time.Second),
			)

			endpoint := WebSocketEndpoint{
				URL:      wsURL,
				IsSecure: false,
			}

			ctx := context.Background()
			finding := scanner.testOriginValidation(ctx, endpoint)

			if tt.wantFindingType == "" {
				if finding != nil {
					t.Errorf("Expected nil finding, got %v", finding.FindingType)
				}
				return
			}

			if finding == nil {
				t.Fatal("Expected finding, got nil")
			}

			if finding.FindingType != tt.wantFindingType {
				t.Errorf("FindingType = %q, want %q", finding.FindingType, tt.wantFindingType)
			}

			if finding.Severity != tt.wantSeverity {
				t.Errorf("Severity = %q, want %q", finding.Severity, tt.wantSeverity)
			}

			// Check specific fields based on finding type
			if tt.wantFindingType == "missing_origin_validation" {
				if finding.OriginValidated {
					t.Error("Expected OriginValidated to be false")
				}
				if finding.OriginHeader != "http://evil.com" {
					t.Errorf("OriginHeader = %q, want %q", finding.OriginHeader, "http://evil.com")
				}
				if finding.CWE != "CWE-346" {
					t.Errorf("CWE = %q, want %q", finding.CWE, "CWE-346")
				}
			} else if tt.wantFindingType == "origin_validation_present" {
				if !finding.OriginValidated {
					t.Error("Expected OriginValidated to be true")
				}
			}
		})
	}
}

// Test testOriginValidation with secure WebSocket (wss://)
func TestTestOriginValidationSecure(t *testing.T) {
	// Create a TLS-enabled mock server
	handler := func(ws *websocket.Conn) {
		defer ws.Close()
	}

	server := httptest.NewTLSServer(websocket.Handler(handler))
	defer server.Close()

	// Convert HTTPS URL to WSS URL
	wssURL := "wss" + strings.TrimPrefix(server.URL, "https") + "/socket"

	scanner := NewSecurityScanner(
		WithScannerTimeout(2 * time.Second),
	)

	endpoint := WebSocketEndpoint{
		URL:      wssURL,
		IsSecure: true,
	}

	ctx := context.Background()
	finding := scanner.testOriginValidation(ctx, endpoint)

	// Should detect missing origin validation (server accepts evil origin)
	if finding == nil {
		t.Fatal("Expected finding, got nil")
	}

	if finding.FindingType != "missing_origin_validation" {
		t.Errorf("FindingType = %q, want %q", finding.FindingType, "missing_origin_validation")
	}
}

// Test testWebSocketAccept
func TestTestWebSocketAccept(t *testing.T) {
	tests := []struct {
		name                string
		statusCode          int
		includeAcceptHeader bool
		wantFinding         bool
		wantFindingType     string
	}{
		{
			name:                "proper handshake with accept header",
			statusCode:          http.StatusSwitchingProtocols,
			includeAcceptHeader: true,
			wantFinding:         false,
		},
		{
			name:                "missing accept header",
			statusCode:          http.StatusSwitchingProtocols,
			includeAcceptHeader: false,
			wantFinding:         true,
			wantFindingType:     "missing_accept_header",
		},
		{
			name:                "non-upgrade response",
			statusCode:          http.StatusOK,
			includeAcceptHeader: false,
			wantFinding:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockHTTPClientWithFunc{
				doFunc: func(req *http.Request) (*http.Response, error) {
					resp := &http.Response{
						StatusCode: tt.statusCode,
						Body:       http.NoBody,
						Header:     make(http.Header),
					}

					if tt.includeAcceptHeader {
						resp.Header.Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
					}

					// Verify WebSocket headers were sent
					if req.Header.Get("Upgrade") != "websocket" {
						t.Error("Missing Upgrade: websocket header")
					}
					if req.Header.Get("Sec-WebSocket-Key") != "dGhlIHNhbXBsZSBub25jZQ==" {
						t.Error("Missing or incorrect Sec-WebSocket-Key header")
					}

					return resp, nil
				},
			}

			scanner := NewSecurityScanner(
				WithScannerHTTPClient(mock),
			)

			endpoint := WebSocketEndpoint{
				URL:      "ws://example.com/socket",
				IsSecure: false,
			}

			ctx := context.Background()
			finding := scanner.testWebSocketAccept(ctx, endpoint)

			if tt.wantFinding {
				if finding == nil {
					t.Fatal("Expected finding, got nil")
				}

				if finding.FindingType != tt.wantFindingType {
					t.Errorf("FindingType = %q, want %q", finding.FindingType, tt.wantFindingType)
				}

				if finding.Severity != SeverityLow {
					t.Errorf("Severity = %q, want %q", finding.Severity, SeverityLow)
				}

				if finding.RuleID != "WAST-WS-004" {
					t.Errorf("RuleID = %q, want %q", finding.RuleID, "WAST-WS-004")
				}

				if finding.AcceptHeaderPresent {
					t.Error("AcceptHeaderPresent should be false")
				}
			} else {
				if finding != nil {
					t.Errorf("Expected nil finding, got %v", finding.FindingType)
				}
			}
		})
	}
}

// Test testWebSocketAccept with secure endpoint (wss://)
func TestTestWebSocketAcceptSecure(t *testing.T) {
	called := false
	mock := &mockHTTPClientWithFunc{
		doFunc: func(req *http.Request) (*http.Response, error) {
			called = true
			// Verify HTTPS was used
			if req.URL.Scheme != "https" {
				t.Errorf("Expected https scheme, got %s", req.URL.Scheme)
			}

			header := make(http.Header)
			header.Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

			return &http.Response{
				StatusCode: http.StatusSwitchingProtocols,
				Body:       http.NoBody,
				Header:     header,
			}, nil
		},
	}

	scanner := NewSecurityScanner(
		WithScannerHTTPClient(mock),
	)

	endpoint := WebSocketEndpoint{
		URL:      "wss://example.com/socket",
		IsSecure: true,
	}

	ctx := context.Background()
	finding := scanner.testWebSocketAccept(ctx, endpoint)

	if !called {
		t.Fatal("Mock HTTP client was not called")
	}

	if finding != nil {
		t.Errorf("Expected nil finding for proper handshake, got %v", finding.FindingType)
	}
}

// Test dialWebSocket
func TestDialWebSocket(t *testing.T) {
	t.Run("successful connection", func(t *testing.T) {
		server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()
			// Simple echo
			io.Copy(ws, ws)
		}))
		defer server.Close()

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/socket"

		scanner := NewSecurityScanner()

		config := &websocket.Config{
			Location: mustParseURL(wsURL),
			Origin:   mustParseURL("http://localhost"),
			Version:  13,
		}

		ctx := context.Background()
		conn, err := scanner.dialWebSocket(ctx, config)

		if err != nil {
			t.Fatalf("dialWebSocket failed: %v", err)
		}

		if conn == nil {
			t.Fatal("Expected connection, got nil")
		}

		conn.Close()
	})

	t.Run("context timeout", func(t *testing.T) {
		scanner := NewSecurityScanner()

		// Create a config that will hang (non-existent server)
		config := &websocket.Config{
			Location: mustParseURL("ws://192.0.2.1:9999/socket"), // TEST-NET-1, should timeout
			Origin:   mustParseURL("http://localhost"),
			Version:  13,
		}

		// Use very short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		conn, err := scanner.dialWebSocket(ctx, config)

		if err == nil {
			if conn != nil {
				conn.Close()
			}
			t.Fatal("Expected error due to timeout, got nil")
		}

		if err != context.DeadlineExceeded {
			t.Errorf("Expected context.DeadlineExceeded, got %v", err)
		}

		if conn != nil {
			t.Error("Expected nil connection on error")
		}
	})

	t.Run("connection error", func(t *testing.T) {
		scanner := NewSecurityScanner()

		// Invalid URL that should fail immediately
		config := &websocket.Config{
			Location: mustParseURL("ws://localhost:0/socket"),
			Origin:   mustParseURL("http://localhost"),
			Version:  13,
		}

		ctx := context.Background()
		conn, err := scanner.dialWebSocket(ctx, config)

		if err == nil {
			if conn != nil {
				conn.Close()
			}
			t.Fatal("Expected error for invalid connection, got nil")
		}

		if conn != nil {
			t.Error("Expected nil connection on error")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		scanner := NewSecurityScanner()

		config := &websocket.Config{
			Location: mustParseURL("ws://192.0.2.1:9999/socket"),
			Origin:   mustParseURL("http://localhost"),
			Version:  13,
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		conn, err := scanner.dialWebSocket(ctx, config)

		if err == nil {
			if conn != nil {
				conn.Close()
			}
			t.Fatal("Expected error due to cancellation, got nil")
		}

		if err != context.Canceled {
			t.Errorf("Expected context.Canceled, got %v", err)
		}
	})

	t.Run("secure websocket with TLS config", func(t *testing.T) {
		server := httptest.NewTLSServer(websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()
		}))
		defer server.Close()

		wssURL := "wss" + strings.TrimPrefix(server.URL, "https") + "/socket"

		scanner := NewSecurityScanner()

		config := &websocket.Config{
			Location: mustParseURL(wssURL),
			Origin:   mustParseURL("https://localhost"),
			Version:  13,
			TlsConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}

		ctx := context.Background()
		conn, err := scanner.dialWebSocket(ctx, config)

		if err != nil {
			t.Fatalf("dialWebSocket failed for secure connection: %v", err)
		}

		if conn == nil {
			t.Fatal("Expected connection, got nil")
		}

		conn.Close()
	})
}

// Test performActiveTests integration with rate limiting
func TestPerformActiveTestsWithRateLimiting(t *testing.T) {
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/socket"

	// Create a simple rate limiter that tracks wait calls
	waitCalled := false
	mockLimiter := &mockRateLimiter{
		waitFunc: func(ctx context.Context) error {
			waitCalled = true
			return nil
		},
	}

	scanner := NewSecurityScanner(
		WithActiveMode(true),
		WithScannerRateLimiter(mockLimiter),
	)

	endpoint := WebSocketEndpoint{
		URL:      wsURL,
		IsSecure: false,
	}

	ctx := context.Background()
	findings := scanner.performActiveTests(ctx, endpoint)

	if !waitCalled {
		t.Error("Rate limiter wait was not called")
	}

	if len(findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

// Test error handling in testWebSocketAccept
func TestTestWebSocketAcceptErrors(t *testing.T) {
	t.Run("HTTP client error", func(t *testing.T) {
		mock := &mockHTTPClientWithFunc{
			doFunc: func(req *http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("connection error")
			},
		}

		scanner := NewSecurityScanner(
			WithScannerHTTPClient(mock),
		)

		endpoint := WebSocketEndpoint{
			URL:      "ws://example.com/socket",
			IsSecure: false,
		}

		ctx := context.Background()
		finding := scanner.testWebSocketAccept(ctx, endpoint)

		if finding != nil {
			t.Errorf("Expected nil finding on error, got %v", finding.FindingType)
		}
	})

	t.Run("invalid URL", func(t *testing.T) {
		scanner := NewSecurityScanner()

		endpoint := WebSocketEndpoint{
			URL:      "://invalid-url",
			IsSecure: false,
		}

		ctx := context.Background()
		finding := scanner.testWebSocketAccept(ctx, endpoint)

		if finding != nil {
			t.Errorf("Expected nil finding for invalid URL, got %v", finding.FindingType)
		}
	})
}

// Test error handling in testOriginValidation
func TestTestOriginValidationErrors(t *testing.T) {
	t.Run("invalid URL", func(t *testing.T) {
		scanner := NewSecurityScanner()

		endpoint := WebSocketEndpoint{
			URL:      "://invalid-url",
			IsSecure: false,
		}

		ctx := context.Background()
		finding := scanner.testOriginValidation(ctx, endpoint)

		if finding != nil {
			t.Errorf("Expected nil finding for invalid URL, got %v", finding.FindingType)
		}
	})
}

// Test full scan with active mode enabled
func TestScanActiveMode(t *testing.T) {
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/socket"

	scanner := NewSecurityScanner(
		WithActiveMode(true),
		WithScannerTimeout(2 * time.Second),
	)

	detectionResult := &DetectionResult{
		Target: "http://example.com",
		Endpoints: []WebSocketEndpoint{
			{
				URL:             wsURL,
				DetectionMethod: "javascript",
				SourcePage:      "http://example.com",
				IsSecure:        false,
			},
		},
	}

	ctx := context.Background()
	result := scanner.Scan(ctx, detectionResult)

	if result == nil {
		t.Fatal("Scan returned nil")
	}

	// Should have findings from both passive (insecure protocol) and active tests
	if len(result.Findings) == 0 {
		t.Error("Expected findings from active scan")
	}

	// Check for active test findings
	foundActive := false
	for _, finding := range result.Findings {
		if finding.FindingType == "missing_origin_validation" {
			foundActive = true
			break
		}
	}

	if !foundActive {
		t.Error("Expected active test findings in active mode")
	}
}

// Helper functions and mocks

// mockRateLimiter is a mock rate limiter for testing
type mockRateLimiter struct {
	waitFunc  func(ctx context.Context) error
	allowFunc func() bool
}

func (m *mockRateLimiter) Wait(ctx context.Context) error {
	if m.waitFunc != nil {
		return m.waitFunc(ctx)
	}
	return nil
}

func (m *mockRateLimiter) Allow() bool {
	if m.allowFunc != nil {
		return m.allowFunc()
	}
	return true
}

// mustParseURL parses a URL and panics on error (for tests only)
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(fmt.Sprintf("failed to parse URL %q: %v", rawURL, err))
	}
	return u
}
