package websocket

import (
	"context"
	"strings"
	"testing"
	"time"
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
