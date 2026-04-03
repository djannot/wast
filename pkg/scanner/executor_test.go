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

// TestApplyConfidenceFromResult exercises every branch of the helper, including
// the previously-uncovered edge case where Verified is true but Confidence ≤ 0.5.
func TestApplyConfidenceFromResult(t *testing.T) {
	tests := []struct {
		name     string
		vr       VerificationResult
		wantConf string
	}{
		{
			name:     "high confidence",
			vr:       VerificationResult{Verified: true, Confidence: 0.9},
			wantConf: "high",
		},
		{
			name:     "high confidence boundary (exactly 0.8 is not high)",
			vr:       VerificationResult{Verified: true, Confidence: 0.8},
			wantConf: "medium",
		},
		{
			name:     "medium confidence",
			vr:       VerificationResult{Verified: true, Confidence: 0.7},
			wantConf: "medium",
		},
		{
			name:     "medium confidence boundary (exactly 0.5 is not medium)",
			vr:       VerificationResult{Verified: true, Confidence: 0.5},
			wantConf: "low",
		},
		{
			name:     "verified but low confidence",
			vr:       VerificationResult{Verified: true, Confidence: 0.3},
			wantConf: "low",
		},
		{
			name:     "not verified",
			vr:       VerificationResult{Verified: false, Confidence: 0.9},
			wantConf: "low",
		},
		{
			name:     "not verified zero confidence",
			vr:       VerificationResult{Verified: false, Confidence: 0.0},
			wantConf: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := "unchanged"
			applyConfidenceFromResult(&got, &tt.vr)
			if got != tt.wantConf {
				t.Errorf("applyConfidenceFromResult() confidence = %q, want %q", got, tt.wantConf)
			}
		})
	}
}

// TestVerifiedCountFromUnified checks that the helper counts all scanner result
// types, including SSTI which was previously omitted.
func TestVerifiedCountFromUnified(t *testing.T) {
	tests := []struct {
		name   string
		result *UnifiedScanResult
		want   int
	}{
		{
			name:   "nil result fields",
			result: &UnifiedScanResult{},
			want:   0,
		},
		{
			name: "counts all scanner types including SSTI",
			result: &UnifiedScanResult{
				XSS:           &XSSScanResult{Findings: []XSSFinding{{}, {}}},                 // 2
				SQLi:          &SQLiScanResult{Findings: []SQLiFinding{{}}},                   // 1
				NoSQLi:        &NoSQLiScanResult{Findings: []NoSQLiFinding{{}, {}, {}}},       // 3
				CSRF:          &CSRFScanResult{Findings: []CSRFFinding{}},                     // 0
				SSRF:          &SSRFScanResult{Findings: []SSRFFinding{{}}},                   // 1
				Redirect:      &RedirectScanResult{Findings: []RedirectFinding{{}}},           // 1
				CMDi:          &CMDiScanResult{Findings: []CMDiFinding{{}}},                   // 1
				PathTraversal: &PathTraversalScanResult{Findings: []PathTraversalFinding{{}}}, // 1
				SSTI:          &SSTIScanResult{Findings: []SSTIFinding{{}, {}}},               // 2
				XXE:           &XXEScanResult{Findings: []XXEFinding{{}}},                     // 1
			},
			want: 13,
		},
		{
			name: "only SSTI findings",
			result: &UnifiedScanResult{
				SSTI: &SSTIScanResult{Findings: []SSTIFinding{{}, {}, {}}},
			},
			want: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifiedCountFromUnified(tt.result)
			if got != tt.want {
				t.Errorf("verifiedCountFromUnified() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestCalculateFilteredCount_WithSSTI verifies that SSTI findings are correctly
// included in the filtered count calculation.
// ─── Scanner filtering tests ────────────────────────────────────────────────

func TestValidateScanners_Valid(t *testing.T) {
	err := ValidateScanners([]string{"xss", "sqli", "CSRF", "Headers"})
	if err != nil {
		t.Errorf("expected nil error for valid scanners, got: %v", err)
	}
}

func TestValidateScanners_Invalid(t *testing.T) {
	err := ValidateScanners([]string{"xss", "foobar", "baz"})
	if err == nil {
		t.Fatal("expected error for invalid scanners, got nil")
	}
	if !contains(err.Error(), "foobar") || !contains(err.Error(), "baz") {
		t.Errorf("error should mention invalid names, got: %v", err)
	}
}

func TestValidateScanners_Empty(t *testing.T) {
	err := ValidateScanners(nil)
	if err != nil {
		t.Errorf("expected nil error for empty scanners, got: %v", err)
	}
}

func TestIsScannerEnabled(t *testing.T) {
	tests := []struct {
		name     string
		scanner  string
		list     []string
		expected bool
	}{
		{"empty list enables all", "XSS", nil, true},
		{"matching case-insensitive", "xss", []string{"XSS", "sqli"}, true},
		{"not in list", "csrf", []string{"xss", "sqli"}, false},
		{"exact match", "SQLi", []string{"sqli"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isScannerEnabled(tt.scanner, tt.list)
			if got != tt.expected {
				t.Errorf("isScannerEnabled(%q, %v) = %v, want %v", tt.scanner, tt.list, got, tt.expected)
			}
		})
	}
}

func TestExecuteScan_WithScannersFilter(t *testing.T) {
	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         30,
		SafeMode:        false,
		VerifyFindings:  false,
		Scanners:        []string{"xss", "sqli"},
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
	}

	ctx := context.Background()
	result, _ := ExecuteScan(ctx, cfg)

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	// XSS and SQLi should be present
	if result.XSS == nil {
		t.Error("Expected XSS result when xss scanner is selected")
	}
	if result.SQLi == nil {
		t.Error("Expected SQLi result when sqli scanner is selected")
	}

	// Other active scanners should NOT be present
	if result.CSRF != nil {
		t.Error("Expected CSRF to be nil when not in scanners list")
	}
	if result.SSRF != nil {
		t.Error("Expected SSRF to be nil when not in scanners list")
	}
	if result.NoSQLi != nil {
		t.Error("Expected NoSQLi to be nil when not in scanners list")
	}
	if result.Redirect != nil {
		t.Error("Expected Redirect to be nil when not in scanners list")
	}
	if result.CMDi != nil {
		t.Error("Expected CMDi to be nil when not in scanners list")
	}
	if result.PathTraversal != nil {
		t.Error("Expected PathTraversal to be nil when not in scanners list")
	}
	if result.SSTI != nil {
		t.Error("Expected SSTI to be nil when not in scanners list")
	}
	if result.XXE != nil {
		t.Error("Expected XXE to be nil when not in scanners list")
	}

	// Headers should also be nil (not in the list)
	if result.Headers != nil {
		t.Error("Expected Headers to be nil when not in scanners list")
	}
}

func TestExecuteScan_ScannersFilterIncludesHeaders(t *testing.T) {
	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         30,
		SafeMode:        true,
		Scanners:        []string{"headers"},
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
	}

	ctx := context.Background()
	result, _ := ExecuteScan(ctx, cfg)

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if result.Headers == nil {
		t.Error("Expected Headers result when headers scanner is selected")
	}
}

// TestExecuteScan_WithScannersFilterAndVerify ensures that combining --scanners
// with --verify does not panic when non-selected scanners are absent from
// entryByName. Stats fields for non-selected scanners must remain zero.
func TestExecuteScan_WithScannersFilterAndVerify(t *testing.T) {
	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         30,
		SafeMode:        false,
		VerifyFindings:  true,
		Scanners:        []string{"xss", "sqli"},
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
	}

	ctx := context.Background()
	// Must not panic.
	result, _ := ExecuteScan(ctx, cfg)

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Selected scanners should be present.
	if result.XSS == nil {
		t.Error("Expected XSS result when xss scanner is selected")
	}
	if result.SQLi == nil {
		t.Error("Expected SQLi result when sqli scanner is selected")
	}

	// Non-selected scanners should not be present.
	if result.CSRF != nil {
		t.Error("Expected CSRF to be nil when not in scanners list")
	}
	if result.NoSQLi != nil {
		t.Error("Expected NoSQLi to be nil when not in scanners list")
	}
}

// TestExecuteScan_HeadersWithVerify ensures that a passive-only subset
// (headers) combined with --verify does not panic.
func TestExecuteScan_HeadersWithVerify(t *testing.T) {
	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         30,
		SafeMode:        true,
		VerifyFindings:  true,
		Scanners:        []string{"headers"},
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
	}

	ctx := context.Background()
	// Must not panic.
	result, _ := ExecuteScan(ctx, cfg)

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if result.Headers == nil {
		t.Error("Expected Headers result when headers scanner is selected")
	}
}

func TestExecuteScan_EmptyScannersRunsAll(t *testing.T) {
	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         30,
		SafeMode:        false,
		Scanners:        nil, // empty = run all
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
	}

	ctx := context.Background()
	result, _ := ExecuteScan(ctx, cfg)

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	// All active scanners should run
	if result.XSS == nil {
		t.Error("Expected XSS result when no scanner filter")
	}
	if result.SQLi == nil {
		t.Error("Expected SQLi result when no scanner filter")
	}
	if result.CSRF == nil {
		t.Error("Expected CSRF result when no scanner filter")
	}
	if result.Headers == nil {
		t.Error("Expected Headers result when no scanner filter")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestCalculateFilteredCount_WithSSTI(t *testing.T) {
	stats := &ScanStats{
		TotalSSTIFindings: 4,
	}
	result := &UnifiedScanResult{
		SSTI: &SSTIScanResult{Findings: []SSTIFinding{{}}}, // 1 verified out of 4
	}
	got := CalculateFilteredCount(stats, result)
	if got != 3 {
		t.Errorf("CalculateFilteredCount() with SSTI = %d, want 3", got)
	}
}
