package scanner

import (
	"context"
	"testing"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
)

func TestExecuteScan_SafeMode(t *testing.T) {
	// Test safe mode (passive checks only)
	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         30,
		SafeMode:        true,
		VerifyFindings:  false,
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
		Tracer:          nil,
	}

	ctx := context.Background()
	result, stats := ExecuteScan(ctx, cfg)

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if result.Target != cfg.Target {
		t.Errorf("Expected target %s, got %s", cfg.Target, result.Target)
	}

	if !result.PassiveOnly {
		t.Error("Expected PassiveOnly to be true in safe mode")
	}

	if result.Headers == nil {
		t.Error("Expected Headers result, got nil")
	}

	// In safe mode, active scanners should not run
	if result.XSS != nil || result.SQLi != nil || result.CSRF != nil || result.SSRF != nil {
		t.Error("Active scanners should not run in safe mode")
	}

	if stats == nil {
		t.Error("Expected stats, got nil")
	}
}

func TestExecuteScan_ActiveMode(t *testing.T) {
	// Test active mode (with vulnerability testing)
	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         30,
		SafeMode:        false,
		VerifyFindings:  false,
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
		Tracer:          nil,
	}

	ctx := context.Background()
	result, stats := ExecuteScan(ctx, cfg)

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if result.PassiveOnly {
		t.Error("Expected PassiveOnly to be false in active mode")
	}

	if result.Headers == nil {
		t.Error("Expected Headers result, got nil")
	}

	// In active mode, all scanners should run
	if result.XSS == nil {
		t.Error("Expected XSS result in active mode")
	}
	if result.SQLi == nil {
		t.Error("Expected SQLi result in active mode")
	}
	if result.CSRF == nil {
		t.Error("Expected CSRF result in active mode")
	}
	if result.SSRF == nil {
		t.Error("Expected SSRF result in active mode")
	}

	if stats == nil {
		t.Error("Expected stats, got nil")
	}
}

func TestExecuteScan_WithAuthentication(t *testing.T) {
	// Test with authentication configured
	authCfg := &auth.AuthConfig{
		BearerToken: "test-token",
	}

	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         30,
		SafeMode:        true,
		VerifyFindings:  false,
		AuthConfig:      authCfg,
		RateLimitConfig: ratelimit.Config{},
		Tracer:          nil,
	}

	ctx := context.Background()
	result, _ := ExecuteScan(ctx, cfg)

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Verify that scan completed (authentication should be passed to scanners)
	if result.Headers == nil {
		t.Error("Expected Headers result with authentication")
	}
}

func TestExecuteScan_WithRateLimit(t *testing.T) {
	// Test with rate limiting configured
	rateLimitCfg := ratelimit.Config{
		RequestsPerSecond: 10,
		DelayMs:           0,
	}

	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         30,
		SafeMode:        true,
		VerifyFindings:  false,
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: rateLimitCfg,
		Tracer:          nil,
	}

	ctx := context.Background()
	result, _ := ExecuteScan(ctx, cfg)

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Verify that scan completed with rate limiting
	if result.Headers == nil {
		t.Error("Expected Headers result with rate limiting")
	}
}

func TestCalculateFilteredCount(t *testing.T) {
	tests := []struct {
		name     string
		stats    *ScanStats
		result   *UnifiedScanResult
		expected int
	}{
		{
			name:     "nil stats",
			stats:    nil,
			result:   &UnifiedScanResult{},
			expected: 0,
		},
		{
			name:     "nil result",
			stats:    &ScanStats{},
			result:   nil,
			expected: 0,
		},
		{
			name: "no filtering",
			stats: &ScanStats{
				TotalXSSFindings:  0,
				TotalSQLiFindings: 0,
				TotalCSRFFindings: 0,
				TotalSSRFFindings: 0,
			},
			result: &UnifiedScanResult{
				XSS:  &XSSScanResult{Findings: []XSSFinding{}},
				SQLi: &SQLiScanResult{Findings: []SQLiFinding{}},
				CSRF: &CSRFScanResult{Findings: []CSRFFinding{}},
				SSRF: &SSRFScanResult{Findings: []SSRFFinding{}},
			},
			expected: 0,
		},
		{
			name: "some findings filtered",
			stats: &ScanStats{
				TotalXSSFindings:  5,
				TotalSQLiFindings: 3,
				TotalCSRFFindings: 2,
				TotalSSRFFindings: 1,
			},
			result: &UnifiedScanResult{
				XSS:  &XSSScanResult{Findings: []XSSFinding{{}, {}}}, // 2 verified out of 5
				SQLi: &SQLiScanResult{Findings: []SQLiFinding{{}}},   // 1 verified out of 3
				CSRF: &CSRFScanResult{Findings: []CSRFFinding{}},     // 0 verified out of 2
				SSRF: &SSRFScanResult{Findings: []SSRFFinding{{}}},   // 1 verified out of 1
			},
			expected: 6, // (5-2) + (3-1) + (2-0) + (1-1) = 3 + 2 + 2 + 0 = 7... wait let me recalculate
			// XSS: 5 total - 2 verified = 3 filtered
			// SQLi: 3 total - 1 verified = 2 filtered
			// CSRF: 2 total - 0 verified = 2 filtered
			// SSRF: 1 total - 1 verified = 0 filtered
			// Total filtered: 3 + 2 + 2 + 0 = 7
		},
	}

	// Fix the expected value in the test case above
	tests[3].expected = 7

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateFilteredCount(tt.stats, tt.result)
			if got != tt.expected {
				t.Errorf("CalculateFilteredCount() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFormatFilteredMessage(t *testing.T) {
	tests := []struct {
		name          string
		filteredCount int
		expected      string
	}{
		{
			name:          "no filtered findings",
			filteredCount: 0,
			expected:      "",
		},
		{
			name:          "some filtered findings",
			filteredCount: 5,
			expected:      "ℹ️  Verification: 5 findings excluded due to failed verification",
		},
		{
			name:          "many filtered findings",
			filteredCount: 100,
			expected:      "ℹ️  Verification: 100 findings excluded due to failed verification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatFilteredMessage(tt.filteredCount)
			if got != tt.expected {
				t.Errorf("FormatFilteredMessage() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestScanConfig(t *testing.T) {
	// Test that ScanConfig properly encapsulates all scan parameters
	cfg := ScanConfig{
		Target:         "https://example.com",
		Timeout:        60,
		SafeMode:       false,
		VerifyFindings: true,
		AuthConfig: &auth.AuthConfig{
			BasicAuth: "user:pass",
		},
		RateLimitConfig: ratelimit.Config{
			RequestsPerSecond: 5,
			DelayMs:           0,
		},
		Tracer: nil,
	}

	if cfg.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", cfg.Target)
	}
	if cfg.Timeout != 60 {
		t.Errorf("Expected timeout 60, got %d", cfg.Timeout)
	}
	if cfg.SafeMode {
		t.Error("Expected SafeMode to be false")
	}
	if !cfg.VerifyFindings {
		t.Error("Expected VerifyFindings to be true")
	}
	if cfg.AuthConfig == nil {
		t.Error("Expected AuthConfig to be set")
	}
	if cfg.RateLimitConfig.RequestsPerSecond != 5 {
		t.Errorf("Expected rate limit 5, got %f", cfg.RateLimitConfig.RequestsPerSecond)
	}
}

func TestIntermediateScanResult(t *testing.T) {
	// Test that IntermediateScanResult properly holds scan results
	result := IntermediateScanResult{
		Target:      "https://example.com",
		PassiveOnly: false,
		Headers:     &HeaderScanResult{},
		XSS:         &XSSScanResult{},
		SQLi:        &SQLiScanResult{},
		CSRF:        &CSRFScanResult{},
		SSRF:        &SSRFScanResult{},
		Errors:      []string{"error1", "error2"},
	}

	if result.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", result.Target)
	}
	if result.PassiveOnly {
		t.Error("Expected PassiveOnly to be false")
	}
	if len(result.Errors) != 2 {
		t.Errorf("Expected 2 errors, got %d", len(result.Errors))
	}
}
