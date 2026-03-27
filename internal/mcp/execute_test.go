package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/crawler"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/scanner"
)

// TestExecuteRecon tests the executeRecon function
func TestExecuteRecon(t *testing.T) {
	tests := []struct {
		name              string
		target            string
		timeout           time.Duration
		includeSubdomains bool
		wantTarget        string
	}{
		{
			name:              "basic recon without subdomains",
			target:            "example.com",
			timeout:           5 * time.Second,
			includeSubdomains: false,
			wantTarget:        "example.com",
		},
		{
			name:              "basic recon with subdomains",
			target:            "example.com",
			timeout:           5 * time.Second,
			includeSubdomains: true,
			wantTarget:        "example.com",
		},
		{
			name:              "recon with short timeout",
			target:            "test.com",
			timeout:           1 * time.Second,
			includeSubdomains: false,
			wantTarget:        "test.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result := executeRecon(ctx, tt.target, tt.timeout, tt.includeSubdomains, nil, nil)

			// Verify result is not nil
			if result == nil {
				t.Fatal("executeRecon returned nil")
			}

			// Verify result structure
			reconResult, ok := result.(ReconResult)
			if !ok {
				t.Fatalf("Expected ReconResult type, got %T", result)
			}

			if reconResult.Target != tt.wantTarget {
				t.Errorf("Expected target %s, got %s", tt.wantTarget, reconResult.Target)
			}

			// DNS result should be populated
			if reconResult.DNS == nil {
				t.Error("DNS result should not be nil")
			}

			// TLS result should be populated
			if reconResult.TLS == nil {
				t.Error("TLS result should not be nil")
			}

			// If includeSubdomains is true, subdomains should be checked
			if tt.includeSubdomains && reconResult.DNS != nil {
				// Subdomains array should exist (may be empty if none found)
				if reconResult.DNS.Subdomains == nil {
					t.Error("Subdomains should be initialized when includeSubdomains is true")
				}
			}
		})
	}
}

// TestExecuteReconContextCancellation tests context cancellation in executeRecon
func TestExecuteReconContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Use a timeout longer than context to ensure context cancellation is tested
	result := executeRecon(ctx, "example.com", 30*time.Second, true, nil, nil)

	// Result should still be returned even if context is canceled
	if result == nil {
		t.Fatal("executeRecon should return a result even with canceled context")
	}

	reconResult, ok := result.(ReconResult)
	if !ok {
		t.Fatalf("Expected ReconResult type, got %T", result)
	}

	// Basic structure should be populated
	if reconResult.Target != "example.com" {
		t.Errorf("Expected target example.com, got %s", reconResult.Target)
	}
}

// TestExecuteScan tests the executeScan function
func TestExecuteScan(t *testing.T) {
	tests := []struct {
		name           string
		target         string
		timeout        int
		safeMode       bool
		verifyFindings bool
		wantPassive    bool
	}{
		{
			name:           "safe mode scan without verification",
			target:         "https://example.com",
			timeout:        30,
			safeMode:       true,
			verifyFindings: false,
			wantPassive:    true,
		},
		{
			name:           "safe mode scan with verification",
			target:         "https://example.com",
			timeout:        30,
			safeMode:       true,
			verifyFindings: true,
			wantPassive:    true,
		},
		{
			name:           "active scan without verification",
			target:         "https://example.com",
			timeout:        30,
			safeMode:       false,
			verifyFindings: false,
			wantPassive:    false,
		},
		{
			name:           "active scan with verification",
			target:         "https://example.com",
			timeout:        30,
			safeMode:       false,
			verifyFindings: true,
			wantPassive:    false,
		},
		{
			name:           "short timeout scan",
			target:         "https://test.com",
			timeout:        5,
			safeMode:       true,
			verifyFindings: false,
			wantPassive:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Create default auth and rate limit configs
			authConfig := &auth.AuthConfig{}
			rateLimitConfig := ratelimit.Config{}

			result := executeScan(ctx, tt.target, tt.timeout, tt.safeMode, tt.verifyFindings, false, 2, 5, 5, authConfig, rateLimitConfig, nil, nil)

			// Verify result is not nil
			if result == nil {
				t.Fatal("executeScan returned nil")
			}

			// Verify result structure
			scanResult, ok := result.(*scanner.UnifiedScanResult)
			if !ok {
				t.Fatalf("Expected *scanner.UnifiedScanResult type, got %T", result)
			}

			if scanResult.Target != tt.target {
				t.Errorf("Expected target %s, got %s", tt.target, scanResult.Target)
			}

			if scanResult.PassiveOnly != tt.wantPassive {
				t.Errorf("Expected PassiveOnly %v, got %v", tt.wantPassive, scanResult.PassiveOnly)
			}

			// Headers should always be scanned
			if scanResult.Headers == nil {
				t.Error("Headers scan result should not be nil")
			}

			// Active scans should be present only in non-safe mode
			if !tt.safeMode {
				if scanResult.XSS == nil {
					t.Error("XSS scan result should not be nil in active mode")
				}
				if scanResult.SQLi == nil {
					t.Error("SQLi scan result should not be nil in active mode")
				}
				if scanResult.CSRF == nil {
					t.Error("CSRF scan result should not be nil in active mode")
				}
			} else {
				// In safe mode, active scans should be nil
				if scanResult.XSS != nil {
					t.Error("XSS scan result should be nil in safe mode")
				}
				if scanResult.SQLi != nil {
					t.Error("SQLi scan result should be nil in safe mode")
				}
				if scanResult.CSRF != nil {
					t.Error("CSRF scan result should be nil in safe mode")
				}
			}

			// Errors array should be initialized
			if scanResult.Errors == nil {
				t.Error("Errors array should be initialized")
			}
		})
	}
}

// TestExecuteScanWithAuth tests executeScan with authentication
func TestExecuteScanWithAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{
		BearerToken: "test-token",
		BasicAuth:   "user:pass",
		Cookies:     []string{"session=abc123"},
	}
	rateLimitConfig := ratelimit.Config{}

	result := executeScan(ctx, "https://example.com", 30, true, false, false, 2, 5, 5, authConfig, rateLimitConfig, nil, nil)

	if result == nil {
		t.Fatal("executeScan with auth returned nil")
	}

	scanResult, ok := result.(*scanner.UnifiedScanResult)
	if !ok {
		t.Fatalf("Expected *scanner.UnifiedScanResult type, got %T", result)
	}

	if scanResult.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", scanResult.Target)
	}
}

// TestExecuteScanWithRateLimit tests executeScan with rate limiting
func TestExecuteScanWithRateLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{}
	rateLimitConfig := ratelimit.Config{
		RequestsPerSecond: 5.0,
	}

	result := executeScan(ctx, "https://example.com", 30, true, false, false, 2, 5, 5, authConfig, rateLimitConfig, nil, nil)

	if result == nil {
		t.Fatal("executeScan with rate limit returned nil")
	}

	scanResult, ok := result.(*scanner.UnifiedScanResult)
	if !ok {
		t.Fatalf("Expected *scanner.UnifiedScanResult type, got %T", result)
	}

	if scanResult.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", scanResult.Target)
	}
}

// TestExecuteCrawl tests the executeCrawl function
func TestExecuteCrawl(t *testing.T) {
	tests := []struct {
		name          string
		target        string
		depth         int
		timeout       time.Duration
		respectRobots bool
	}{
		{
			name:          "basic crawl with robots respect",
			target:        "https://example.com",
			depth:         3,
			timeout:       30 * time.Second,
			respectRobots: true,
		},
		{
			name:          "basic crawl without robots respect",
			target:        "https://example.com",
			depth:         3,
			timeout:       30 * time.Second,
			respectRobots: false,
		},
		{
			name:          "shallow crawl",
			target:        "https://test.com",
			depth:         1,
			timeout:       10 * time.Second,
			respectRobots: true,
		},
		{
			name:          "deep crawl",
			target:        "https://example.com",
			depth:         5,
			timeout:       60 * time.Second,
			respectRobots: true,
		},
		{
			name:          "short timeout crawl",
			target:        "https://example.com",
			depth:         2,
			timeout:       5 * time.Second,
			respectRobots: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			authConfig := &auth.AuthConfig{}
			rateLimitConfig := ratelimit.Config{}

			result := executeCrawl(ctx, tt.target, tt.depth, tt.timeout, tt.respectRobots, 5, false, authConfig, rateLimitConfig, nil, nil)

			// Verify result is not nil
			if result == nil {
				t.Fatal("executeCrawl returned nil")
			}

			// The result should be a crawler.CrawlResult
			// We can't check the exact type without importing crawler,
			// but we can verify it's not nil and has expected structure
			resultMap, ok := result.(map[string]interface{})
			if ok {
				// If it's a map, it might be an error result
				if errMsg, hasErr := resultMap["error"]; hasErr {
					t.Logf("Crawl returned error (expected for unreachable targets): %v", errMsg)
				}
			}
		})
	}
}

// TestExecuteCrawlWithAuth tests executeCrawl with authentication
func TestExecuteCrawlWithAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{
		BearerToken: "test-token",
		Cookies:     []string{"session=xyz"},
	}
	rateLimitConfig := ratelimit.Config{}

	result := executeCrawl(ctx, "https://example.com", 3, 30*time.Second, true, 5, false, authConfig, rateLimitConfig, nil, nil)

	if result == nil {
		t.Fatal("executeCrawl with auth returned nil")
	}
}

// TestExecuteCrawlWithRateLimit tests executeCrawl with rate limiting
func TestExecuteCrawlWithRateLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{}
	rateLimitConfig := ratelimit.Config{
		RequestsPerSecond: 2.0,
	}

	result := executeCrawl(ctx, "https://example.com", 2, 20*time.Second, true, 5, false, authConfig, rateLimitConfig, nil, nil)

	if result == nil {
		t.Fatal("executeCrawl with rate limit returned nil")
	}
}

// TestExecuteAPI tests the executeAPI function
func TestExecuteAPI(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		specFile string
		dryRun   bool
		timeout  int
	}{
		{
			name:     "API discovery mode",
			target:   "https://api.example.com",
			specFile: "",
			dryRun:   false,
			timeout:  30,
		},
		{
			name:     "API discovery with dry run",
			target:   "https://api.example.com",
			specFile: "",
			dryRun:   true,
			timeout:  30,
		},
		{
			name:     "spec parsing mode",
			target:   "",
			specFile: "/nonexistent/spec.yaml",
			dryRun:   true,
			timeout:  30,
		},
		{
			name:     "spec with testing",
			target:   "",
			specFile: "/nonexistent/openapi.json",
			dryRun:   false,
			timeout:  60,
		},
		{
			name:     "short timeout",
			target:   "https://api.test.com",
			specFile: "",
			dryRun:   false,
			timeout:  5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			authConfig := &auth.AuthConfig{}
			rateLimitConfig := ratelimit.Config{}

			result := executeAPI(ctx, tt.target, tt.specFile, tt.dryRun, tt.timeout, authConfig, rateLimitConfig, nil)

			// Verify result is not nil
			if result == nil {
				t.Fatal("executeAPI returned nil")
			}

			// Check if result is an error map (for invalid spec files)
			resultMap, ok := result.(map[string]interface{})
			if ok && tt.specFile != "" {
				// If spec_file was provided, we might get an error map
				if errMsg, hasErr := resultMap["error"]; hasErr {
					// This is expected for nonexistent files
					if !strings.Contains(errMsg.(string), "error") && !strings.Contains(errMsg.(string), "failed") {
						t.Logf("Expected error for nonexistent spec file: %v", errMsg)
					}
				}
			}
		})
	}
}

// TestExecuteAPIWithAuth tests executeAPI with authentication
func TestExecuteAPIWithAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{
		BearerToken: "api-token",
		AuthHeader:  "X-API-Key: secret",
	}
	rateLimitConfig := ratelimit.Config{}

	result := executeAPI(ctx, "https://api.example.com", "", false, 30, authConfig, rateLimitConfig, nil)

	if result == nil {
		t.Fatal("executeAPI with auth returned nil")
	}
}

// TestExecuteAPIWithRateLimit tests executeAPI with rate limiting
func TestExecuteAPIWithRateLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{}
	rateLimitConfig := ratelimit.Config{
		RequestsPerSecond: 10.0,
	}

	result := executeAPI(ctx, "https://api.example.com", "", true, 30, authConfig, rateLimitConfig, nil)

	if result == nil {
		t.Fatal("executeAPI with rate limit returned nil")
	}
}

// TestExecuteIntercept tests the executeIntercept function
func TestExecuteIntercept(t *testing.T) {
	tests := []struct {
		name              string
		port              int
		duration          time.Duration
		saveFile          string
		httpsInterception bool
		maxRequests       int
	}{
		{
			name:              "basic intercept HTTP only",
			port:              9093,
			duration:          1 * time.Second,
			saveFile:          "",
			httpsInterception: false,
			maxRequests:       0,
		},
		{
			name:              "intercept with save file",
			port:              9094,
			duration:          1 * time.Second,
			saveFile:          "/tmp/intercept_test.json",
			httpsInterception: false,
			maxRequests:       0,
		},
		{
			name:              "intercept with max requests",
			port:              9095,
			duration:          5 * time.Second,
			saveFile:          "",
			httpsInterception: false,
			maxRequests:       5,
		},
		{
			name:              "short duration intercept",
			port:              9096,
			duration:          500 * time.Millisecond,
			saveFile:          "",
			httpsInterception: false,
			maxRequests:       0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tt.duration+2*time.Second)
			defer cancel()

			result := executeIntercept(ctx, tt.port, tt.duration, tt.saveFile, tt.httpsInterception, tt.maxRequests, nil)

			// Verify result is not nil
			if result == nil {
				t.Fatal("executeIntercept returned nil")
			}

			// Check if result is a map (could be success or error)
			resultMap, ok := result.(map[string]interface{})
			if ok {
				// Verify port is included in result
				if port, hasPort := resultMap["port"]; hasPort {
					portInt, portOk := port.(int)
					if portOk && portInt != tt.port {
						t.Errorf("Expected port %d, got %d", tt.port, portInt)
					}
				}

				// Check for error in result
				if errMsg, hasErr := resultMap["error"]; hasErr {
					// Errors are expected for port conflicts or initialization issues
					t.Logf("Intercept returned error (may be expected): %v", errMsg)
				}
			}
		})
	}
}

// TestExecuteInterceptHTTPS tests HTTPS interception
func TestExecuteInterceptHTTPS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := executeIntercept(ctx, 9097, 1*time.Second, "", true, 0, nil)

	if result == nil {
		t.Fatal("executeIntercept with HTTPS returned nil")
	}

	// HTTPS interception requires CA setup, so we may get an error
	resultMap, ok := result.(map[string]interface{})
	if ok {
		if errMsg, hasErr := resultMap["error"]; hasErr {
			// This is expected if CA is not set up
			t.Logf("HTTPS interception error (expected if CA not initialized): %v", errMsg)
		}

		// Verify https_enabled field is present
		if httpsEnabled, hasHTTPS := resultMap["https_enabled"]; hasHTTPS {
			if enabled, ok := httpsEnabled.(bool); ok && enabled {
				t.Log("HTTPS interception was successfully enabled")
			}
		}
	}
}

// TestExecuteInterceptContextCancellation tests context cancellation during intercept
func TestExecuteInterceptContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Start intercept with a longer duration than the context timeout
	result := executeIntercept(ctx, 9098, 10*time.Second, "", false, 0, nil)

	// Result should be returned even if context is canceled
	if result == nil {
		t.Fatal("executeIntercept should return a result even with canceled context")
	}
}

// TestExecuteInterceptMaxRequestsReached tests max_requests functionality
func TestExecuteInterceptMaxRequestsReached(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Set max_requests to a low value
	result := executeIntercept(ctx, 9099, 5*time.Second, "", false, 1, nil)

	if result == nil {
		t.Fatal("executeIntercept with max_requests returned nil")
	}

	// Result should be valid even if max_requests is set
	resultMap, ok := result.(map[string]interface{})
	if ok {
		if port, hasPort := resultMap["port"]; hasPort {
			if portInt, ok := port.(int); ok && portInt != 9099 {
				t.Errorf("Expected port 9099, got %d", portInt)
			}
		}
	}
}

// TestCompleteScanResultJSONMarshaling tests JSON marshaling of scan results
func TestCompleteScanResultJSONMarshaling(t *testing.T) {
	scanResult := CompleteScanResult{
		Target:      "https://example.com",
		PassiveOnly: true,
		Errors:      []string{"error1", "error2"},
	}

	data, err := json.Marshal(scanResult)
	if err != nil {
		t.Fatalf("Failed to marshal CompleteScanResult: %v", err)
	}

	var unmarshaled CompleteScanResult
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal CompleteScanResult: %v", err)
	}

	if unmarshaled.Target != scanResult.Target {
		t.Errorf("Target mismatch after marshal/unmarshal")
	}

	if unmarshaled.PassiveOnly != scanResult.PassiveOnly {
		t.Errorf("PassiveOnly mismatch after marshal/unmarshal")
	}

	if len(unmarshaled.Errors) != len(scanResult.Errors) {
		t.Errorf("Errors count mismatch after marshal/unmarshal")
	}
}

// TestReconResultJSONMarshaling tests JSON marshaling of recon results
func TestReconResultJSONMarshaling(t *testing.T) {
	reconResult := ReconResult{
		Target:  "example.com",
		Methods: []string{"DNS", "TLS"},
		Status:  "completed",
	}

	data, err := json.Marshal(reconResult)
	if err != nil {
		t.Fatalf("Failed to marshal ReconResult: %v", err)
	}

	var unmarshaled ReconResult
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal ReconResult: %v", err)
	}

	if unmarshaled.Target != reconResult.Target {
		t.Errorf("Target mismatch after marshal/unmarshal")
	}

	if unmarshaled.Status != reconResult.Status {
		t.Errorf("Status mismatch after marshal/unmarshal")
	}
}

// TestExecuteVerify tests the executeVerify function
func TestExecuteVerify(t *testing.T) {
	tests := []struct {
		name        string
		findingType string
		findingURL  string
		parameter   string
		payload     string
		maxRetries  int
		delay       time.Duration
		expectError bool
	}{
		{
			name:        "xss verification",
			findingType: "xss",
			findingURL:  "https://example.com/test",
			parameter:   "q",
			payload:     "<script>alert('XSS')</script>",
			maxRetries:  3,
			delay:       100 * time.Millisecond,
			expectError: false,
		},
		{
			name:        "sqli verification",
			findingType: "sqli",
			findingURL:  "https://example.com/query",
			parameter:   "id",
			payload:     "' OR '1'='1",
			maxRetries:  3,
			delay:       100 * time.Millisecond,
			expectError: false,
		},
		{
			name:        "ssrf verification",
			findingType: "ssrf",
			findingURL:  "https://example.com/fetch",
			parameter:   "url",
			payload:     "http://169.254.169.254/latest/meta-data",
			maxRetries:  3,
			delay:       100 * time.Millisecond,
			expectError: false,
		},
		{
			name:        "cmdi verification",
			findingType: "cmdi",
			findingURL:  "https://example.com/exec",
			parameter:   "cmd",
			payload:     "; ls -la",
			maxRetries:  3,
			delay:       100 * time.Millisecond,
			expectError: false,
		},
		{
			name:        "pathtraversal verification",
			findingType: "pathtraversal",
			findingURL:  "https://example.com/file",
			parameter:   "path",
			payload:     "../../../../etc/passwd",
			maxRetries:  3,
			delay:       100 * time.Millisecond,
			expectError: false,
		},
		{
			name:        "redirect verification",
			findingType: "redirect",
			findingURL:  "https://example.com/redirect",
			parameter:   "target",
			payload:     "//evil.com",
			maxRetries:  3,
			delay:       100 * time.Millisecond,
			expectError: false,
		},
		{
			name:        "csrf verification",
			findingType: "csrf",
			findingURL:  "https://example.com/form",
			parameter:   "missing_token",
			payload:     "",
			maxRetries:  3,
			delay:       100 * time.Millisecond,
			expectError: false,
		},
		{
			name:        "invalid finding type",
			findingType: "invalid",
			findingURL:  "https://example.com/test",
			parameter:   "param",
			payload:     "test",
			maxRetries:  3,
			delay:       100 * time.Millisecond,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			authConfig := &auth.AuthConfig{}
			rateLimitConfig := ratelimit.Config{}

			result, err := executeVerify(ctx, tt.findingType, tt.findingURL, tt.parameter, tt.payload, tt.maxRetries, tt.delay, authConfig, rateLimitConfig, nil)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for invalid finding type, got nil")
				}
				if !strings.Contains(err.Error(), "unsupported finding type") {
					t.Errorf("Expected 'unsupported finding type' error, got: %v", err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Fatal("executeVerify returned nil result")
			}

			// Verify result is a VerificationResult
			verifyResult, ok := result.(*scanner.VerificationResult)
			if !ok {
				t.Fatalf("Expected *scanner.VerificationResult type, got %T", result)
			}

			// Basic validation of verification result structure
			if verifyResult.Attempts < 0 {
				t.Errorf("Attempts should be non-negative, got %d", verifyResult.Attempts)
			}

			if verifyResult.Confidence < 0.0 || verifyResult.Confidence > 1.0 {
				t.Errorf("Confidence should be between 0.0 and 1.0, got %f", verifyResult.Confidence)
			}

			if verifyResult.Explanation == "" {
				t.Error("Explanation should not be empty")
			}
		})
	}
}

// TestExecuteVerifyWithAuth tests executeVerify with authentication
func TestExecuteVerifyWithAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{
		BearerToken: "test-token",
		BasicAuth:   "user:pass",
		Cookies:     []string{"session=abc123"},
	}
	rateLimitConfig := ratelimit.Config{}

	result, err := executeVerify(ctx, "xss", "https://example.com/test", "q", "<script>alert(1)</script>", 3, 100*time.Millisecond, authConfig, rateLimitConfig, nil)

	if err != nil {
		t.Errorf("Unexpected error with auth: %v", err)
	}

	if result == nil {
		t.Fatal("executeVerify with auth returned nil")
	}

	verifyResult, ok := result.(*scanner.VerificationResult)
	if !ok {
		t.Fatalf("Expected *scanner.VerificationResult type, got %T", result)
	}

	if verifyResult.Attempts < 0 {
		t.Errorf("Attempts should be non-negative, got %d", verifyResult.Attempts)
	}
}

// TestExecuteVerifyWithRateLimit tests executeVerify with rate limiting
func TestExecuteVerifyWithRateLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{}
	rateLimitConfig := ratelimit.Config{
		RequestsPerSecond: 5.0,
	}

	result, err := executeVerify(ctx, "sqli", "https://example.com/query", "id", "' OR '1'='1", 3, 100*time.Millisecond, authConfig, rateLimitConfig, nil)

	if err != nil {
		t.Errorf("Unexpected error with rate limit: %v", err)
	}

	if result == nil {
		t.Fatal("executeVerify with rate limit returned nil")
	}

	verifyResult, ok := result.(*scanner.VerificationResult)
	if !ok {
		t.Fatalf("Expected *scanner.VerificationResult type, got %T", result)
	}

	if verifyResult.Attempts < 0 {
		t.Errorf("Attempts should be non-negative, got %d", verifyResult.Attempts)
	}
}

// TestExecuteVerifyContextCancellation tests context cancellation in executeVerify
func TestExecuteVerifyContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	authConfig := &auth.AuthConfig{}
	rateLimitConfig := ratelimit.Config{}

	result, err := executeVerify(ctx, "xss", "https://example.com/test", "q", "<script>alert(1)</script>", 3, 100*time.Millisecond, authConfig, rateLimitConfig, nil)

	// Result should be returned even if context is canceled
	if result == nil && err == nil {
		t.Fatal("executeVerify should return a result or error with canceled context")
	}

	if result != nil {
		verifyResult, ok := result.(*scanner.VerificationResult)
		if !ok {
			t.Fatalf("Expected *scanner.VerificationResult type, got %T", result)
		}

		// Basic structure should be populated
		if verifyResult.Explanation == "" {
			t.Error("Explanation should be populated")
		}
	}
}

// TestExecuteVerifyAllFindingTypes tests all supported finding types
func TestExecuteVerifyAllFindingTypes(t *testing.T) {
	findingTypes := []string{"xss", "sqli", "ssrf", "cmdi", "pathtraversal", "redirect", "csrf"}

	for _, findingType := range findingTypes {
		t.Run(findingType, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			authConfig := &auth.AuthConfig{}
			rateLimitConfig := ratelimit.Config{}

			// Use appropriate parameter based on finding type
			parameter := "param"
			payload := "test"
			if findingType == "csrf" {
				parameter = "missing_token"
				payload = ""
			}

			result, err := executeVerify(ctx, findingType, "https://example.com/test", parameter, payload, 2, 50*time.Millisecond, authConfig, rateLimitConfig, nil)

			if err != nil {
				t.Errorf("Unexpected error for %s: %v", findingType, err)
				return
			}

			if result == nil {
				t.Fatalf("executeVerify returned nil for %s", findingType)
			}

			verifyResult, ok := result.(*scanner.VerificationResult)
			if !ok {
				t.Fatalf("Expected *scanner.VerificationResult type for %s, got %T", findingType, result)
			}

			// Verify result structure
			if verifyResult.Attempts < 0 {
				t.Errorf("%s: Attempts should be non-negative, got %d", findingType, verifyResult.Attempts)
			}

			if verifyResult.Confidence < 0.0 || verifyResult.Confidence > 1.0 {
				t.Errorf("%s: Confidence should be between 0.0 and 1.0, got %f", findingType, verifyResult.Confidence)
			}

			if verifyResult.Explanation == "" {
				t.Errorf("%s: Explanation should not be empty", findingType)
			}
		})
	}
}

// TestExecuteHeaders tests the executeHeaders function
func TestExecuteHeaders(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		timeout    int
		wantTarget string
	}{
		{
			name:       "basic headers scan",
			target:     "https://example.com",
			timeout:    30,
			wantTarget: "https://example.com",
		},
		{
			name:       "headers scan with short timeout",
			target:     "https://test.com",
			timeout:    5,
			wantTarget: "https://test.com",
		},
		{
			name:       "headers scan with long timeout",
			target:     "https://example.org",
			timeout:    60,
			wantTarget: "https://example.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			authConfig := &auth.AuthConfig{}
			rateLimitConfig := ratelimit.Config{}

			result := executeHeaders(ctx, tt.target, tt.timeout, authConfig, rateLimitConfig, nil)

			// Verify result is not nil
			if result == nil {
				t.Fatal("executeHeaders returned nil")
			}

			// Verify result structure
			headerResult, ok := result.(*scanner.HeaderScanResult)
			if !ok {
				t.Fatalf("Expected *scanner.HeaderScanResult type, got %T", result)
			}

			if headerResult.Target != tt.wantTarget {
				t.Errorf("Expected target %s, got %s", tt.wantTarget, headerResult.Target)
			}

			// Headers should be checked
			if headerResult.Headers == nil {
				t.Error("Headers should not be nil")
			}

			// Cookies should be initialized
			if headerResult.Cookies == nil {
				t.Error("Cookies should not be nil")
			}

			// CORS should be initialized
			if headerResult.CORS == nil {
				t.Error("CORS should not be nil")
			}

			// Summary should be populated (may be 0 if request failed)
			// Just verify the structure exists
			_ = headerResult.Summary
		})
	}
}

// TestExecuteHeadersWithAuth tests executeHeaders with authentication
func TestExecuteHeadersWithAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{
		BearerToken: "test-token",
		BasicAuth:   "user:pass",
		Cookies:     []string{"session=abc123"},
	}
	rateLimitConfig := ratelimit.Config{}

	result := executeHeaders(ctx, "https://example.com", 30, authConfig, rateLimitConfig, nil)

	if result == nil {
		t.Fatal("executeHeaders with auth returned nil")
	}

	headerResult, ok := result.(*scanner.HeaderScanResult)
	if !ok {
		t.Fatalf("Expected *scanner.HeaderScanResult type, got %T", result)
	}

	if headerResult.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", headerResult.Target)
	}
}

// TestExecuteHeadersWithRateLimit tests executeHeaders with rate limiting
func TestExecuteHeadersWithRateLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{}
	rateLimitConfig := ratelimit.Config{
		RequestsPerSecond: 5.0,
	}

	result := executeHeaders(ctx, "https://example.com", 30, authConfig, rateLimitConfig, nil)

	if result == nil {
		t.Fatal("executeHeaders with rate limit returned nil")
	}

	headerResult, ok := result.(*scanner.HeaderScanResult)
	if !ok {
		t.Fatalf("Expected *scanner.HeaderScanResult type, got %T", result)
	}

	if headerResult.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", headerResult.Target)
	}
}

// TestExecuteHeadersContextCancellation tests context cancellation in executeHeaders
func TestExecuteHeadersContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	authConfig := &auth.AuthConfig{}
	rateLimitConfig := ratelimit.Config{}

	result := executeHeaders(ctx, "https://example.com", 30, authConfig, rateLimitConfig, nil)

	// Result should still be returned even if context is canceled
	if result == nil {
		t.Fatal("executeHeaders should return a result even with canceled context")
	}

	headerResult, ok := result.(*scanner.HeaderScanResult)
	if !ok {
		t.Fatalf("Expected *scanner.HeaderScanResult type, got %T", result)
	}

	// Basic structure should be populated
	if headerResult.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", headerResult.Target)
	}
}

// TestHeaderScanResultJSONMarshaling tests JSON marshaling of header scan results
func TestHeaderScanResultJSONMarshaling(t *testing.T) {
	headerResult := scanner.HeaderScanResult{
		Target:  "https://example.com",
		Headers: []scanner.HeaderFinding{},
		Cookies: []scanner.CookieFinding{},
		CORS:    []scanner.CORSFinding{},
		Summary: scanner.ScanSummary{
			TotalHeaders:   7,
			MissingHeaders: 2,
		},
		Errors: []string{},
	}

	data, err := json.Marshal(headerResult)
	if err != nil {
		t.Fatalf("Failed to marshal HeaderScanResult: %v", err)
	}

	var unmarshaled scanner.HeaderScanResult
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal HeaderScanResult: %v", err)
	}

	if unmarshaled.Target != headerResult.Target {
		t.Errorf("Target mismatch after marshal/unmarshal")
	}

	if unmarshaled.Summary.TotalHeaders != headerResult.Summary.TotalHeaders {
		t.Errorf("TotalHeaders mismatch after marshal/unmarshal")
	}
}

// TestExecuteCrawlWithCompact tests executeCrawl with compact mode enabled
func TestExecuteCrawlWithCompact(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{}
	rateLimitConfig := ratelimit.Config{}

	// Test with compact=true (default)
	result := executeCrawl(ctx, "https://example.com", 2, 20*time.Second, true, 5, true, authConfig, rateLimitConfig, nil, nil)

	if result == nil {
		t.Fatal("executeCrawl with compact=true returned nil")
	}

	// With compact=true, we should get a CompactCrawlResult
	compactResult, ok := result.(*CompactCrawlResult)
	if !ok {
		t.Fatalf("Expected *CompactCrawlResult type with compact=true, got %T", result)
	}

	// Verify compact result structure
	if compactResult.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", compactResult.Target)
	}

	// Statistics should be present
	if compactResult.Statistics.TotalURLs < 0 {
		t.Error("Statistics.TotalURLs should be non-negative")
	}

	// Forms should be preserved
	if compactResult.Forms == nil {
		t.Error("Forms should be initialized")
	}

	// RobotsDisallow should be preserved
	if compactResult.RobotsDisallow == nil {
		t.Error("RobotsDisallow should be initialized")
	}

	// SitemapURLs should be preserved
	if compactResult.SitemapURLs == nil {
		t.Error("SitemapURLs should be initialized")
	}

	// Errors should be preserved
	if compactResult.Errors == nil {
		t.Error("Errors should be initialized")
	}
}

// TestExecuteCrawlWithoutCompact tests executeCrawl with compact mode disabled
func TestExecuteCrawlWithoutCompact(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authConfig := &auth.AuthConfig{}
	rateLimitConfig := ratelimit.Config{}

	// Test with compact=false
	result := executeCrawl(ctx, "https://example.com", 2, 20*time.Second, true, 5, false, authConfig, rateLimitConfig, nil, nil)

	if result == nil {
		t.Fatal("executeCrawl with compact=false returned nil")
	}

	// With compact=false, we should NOT get a CompactCrawlResult
	if _, ok := result.(*CompactCrawlResult); ok {
		t.Error("Should not get CompactCrawlResult when compact=false")
	}
}

// TestCompactCrawlResultTransformation tests the compact transformation logic
func TestCompactCrawlResultTransformation(t *testing.T) {
	// Create a mock CrawlResult with large data
	mockResult := &crawler.CrawlResult{
		Target: "https://example.com",
		Statistics: crawler.CrawlStats{
			TotalURLs:       250,
			InternalURLs:    200,
			ExternalURLs:    50,
			FormsFound:      5,
			ResourcesFound:  1000,
			MaxDepthReached: 3,
		},
		Forms: []crawler.FormInfo{
			{Action: "/login", Method: "POST", Page: "https://example.com/login"},
			{Action: "/search", Method: "GET", Page: "https://example.com/search"},
		},
		Resources:      make([]crawler.ResourceInfo, 1000),
		InternalLinks:  make([]crawler.LinkInfo, 200),
		ExternalLinks:  make([]crawler.LinkInfo, 50),
		RobotsDisallow: []string{"/admin", "/private"},
		SitemapURLs:    []string{"https://example.com/sitemap.xml"},
		Errors:         []string{"error1", "error2"},
	}

	// Populate resources with different types
	for i := 0; i < 500; i++ {
		mockResult.Resources[i] = crawler.ResourceInfo{
			URL:  fmt.Sprintf("https://example.com/js/file%d.js", i),
			Type: "js",
			Page: "https://example.com",
		}
	}
	for i := 500; i < 750; i++ {
		mockResult.Resources[i] = crawler.ResourceInfo{
			URL:  fmt.Sprintf("https://example.com/css/file%d.css", i),
			Type: "css",
			Page: "https://example.com",
		}
	}
	for i := 750; i < 1000; i++ {
		mockResult.Resources[i] = crawler.ResourceInfo{
			URL:  fmt.Sprintf("https://example.com/img/file%d.png", i),
			Type: "image",
			Page: "https://example.com",
		}
	}

	// Populate links
	for i := 0; i < 200; i++ {
		mockResult.InternalLinks[i] = crawler.LinkInfo{
			URL:      fmt.Sprintf("https://example.com/page%d", i),
			External: false,
			Depth:    1,
		}
	}
	for i := 0; i < 50; i++ {
		mockResult.ExternalLinks[i] = crawler.LinkInfo{
			URL:      fmt.Sprintf("https://external.com/page%d", i),
			External: true,
			Depth:    1,
		}
	}

	// Transform to compact format
	compact := compactCrawlResult(mockResult)

	// Verify compact result
	if compact == nil {
		t.Fatal("compactCrawlResult returned nil")
	}

	// Target should be preserved
	if compact.Target != mockResult.Target {
		t.Errorf("Expected target %s, got %s", mockResult.Target, compact.Target)
	}

	// Statistics should be preserved
	if compact.Statistics.TotalURLs != mockResult.Statistics.TotalURLs {
		t.Errorf("Expected TotalURLs %d, got %d", mockResult.Statistics.TotalURLs, compact.Statistics.TotalURLs)
	}

	// Forms should be preserved completely
	if len(compact.Forms) != len(mockResult.Forms) {
		t.Errorf("Expected %d forms, got %d", len(mockResult.Forms), len(compact.Forms))
	}

	// Resources should be summarized
	if compact.ResourcesSummary == nil {
		t.Fatal("ResourcesSummary should not be nil")
	}
	if compact.ResourcesSummary.Total != 1000 {
		t.Errorf("Expected 1000 total resources, got %d", compact.ResourcesSummary.Total)
	}
	if compact.ResourcesSummary.Types["js"] != 500 {
		t.Errorf("Expected 500 js resources, got %d", compact.ResourcesSummary.Types["js"])
	}
	if compact.ResourcesSummary.Types["css"] != 250 {
		t.Errorf("Expected 250 css resources, got %d", compact.ResourcesSummary.Types["css"])
	}
	if compact.ResourcesSummary.Types["image"] != 250 {
		t.Errorf("Expected 250 image resources, got %d", compact.ResourcesSummary.Types["image"])
	}

	// Internal links should be summarized with sample
	if compact.InternalLinksSummary == nil {
		t.Fatal("InternalLinksSummary should not be nil")
	}
	if compact.InternalLinksSummary.Total != 200 {
		t.Errorf("Expected 200 total internal links, got %d", compact.InternalLinksSummary.Total)
	}
	if len(compact.InternalLinksSummary.Sample) != 10 {
		t.Errorf("Expected 10 sample internal links, got %d", len(compact.InternalLinksSummary.Sample))
	}

	// External links should be summarized with sample
	if compact.ExternalLinksSummary == nil {
		t.Fatal("ExternalLinksSummary should not be nil")
	}
	if compact.ExternalLinksSummary.Total != 50 {
		t.Errorf("Expected 50 total external links, got %d", compact.ExternalLinksSummary.Total)
	}
	if len(compact.ExternalLinksSummary.Sample) != 10 {
		t.Errorf("Expected 10 sample external links, got %d", len(compact.ExternalLinksSummary.Sample))
	}

	// RobotsDisallow should be preserved
	if len(compact.RobotsDisallow) != len(mockResult.RobotsDisallow) {
		t.Errorf("Expected %d robots disallow rules, got %d", len(mockResult.RobotsDisallow), len(compact.RobotsDisallow))
	}

	// SitemapURLs should be preserved
	if len(compact.SitemapURLs) != len(mockResult.SitemapURLs) {
		t.Errorf("Expected %d sitemap URLs, got %d", len(mockResult.SitemapURLs), len(compact.SitemapURLs))
	}

	// Errors should be preserved
	if len(compact.Errors) != len(mockResult.Errors) {
		t.Errorf("Expected %d errors, got %d", len(mockResult.Errors), len(compact.Errors))
	}
}

// TestCompactCrawlResultWithSmallData tests compact transformation with small datasets
func TestCompactCrawlResultWithSmallData(t *testing.T) {
	// Create a result with fewer than 10 links
	mockResult := &crawler.CrawlResult{
		Target: "https://example.com",
		Statistics: crawler.CrawlStats{
			TotalURLs:       5,
			InternalURLs:    3,
			ExternalURLs:    2,
			FormsFound:      0,
			ResourcesFound:  5,
			MaxDepthReached: 1,
		},
		InternalLinks: []crawler.LinkInfo{
			{URL: "https://example.com/page1", External: false},
			{URL: "https://example.com/page2", External: false},
			{URL: "https://example.com/page3", External: false},
		},
		ExternalLinks: []crawler.LinkInfo{
			{URL: "https://external.com/page1", External: true},
			{URL: "https://external.com/page2", External: true},
		},
		Resources: []crawler.ResourceInfo{
			{URL: "https://example.com/app.js", Type: "js"},
			{URL: "https://example.com/style.css", Type: "css"},
			{URL: "https://example.com/logo.png", Type: "image"},
			{URL: "https://example.com/icon.png", Type: "image"},
			{URL: "https://example.com/main.js", Type: "js"},
		},
	}

	compact := compactCrawlResult(mockResult)

	if compact == nil {
		t.Fatal("compactCrawlResult returned nil")
	}

	// Internal links sample should contain all 3 links (less than 10)
	if compact.InternalLinksSummary == nil {
		t.Fatal("InternalLinksSummary should not be nil")
	}
	if len(compact.InternalLinksSummary.Sample) != 3 {
		t.Errorf("Expected 3 sample internal links, got %d", len(compact.InternalLinksSummary.Sample))
	}

	// External links sample should contain all 2 links (less than 10)
	if compact.ExternalLinksSummary == nil {
		t.Fatal("ExternalLinksSummary should not be nil")
	}
	if len(compact.ExternalLinksSummary.Sample) != 2 {
		t.Errorf("Expected 2 sample external links, got %d", len(compact.ExternalLinksSummary.Sample))
	}

	// Resources summary should show correct types
	if compact.ResourcesSummary == nil {
		t.Fatal("ResourcesSummary should not be nil")
	}
	if compact.ResourcesSummary.Types["js"] != 2 {
		t.Errorf("Expected 2 js resources, got %d", compact.ResourcesSummary.Types["js"])
	}
	if compact.ResourcesSummary.Types["css"] != 1 {
		t.Errorf("Expected 1 css resource, got %d", compact.ResourcesSummary.Types["css"])
	}
	if compact.ResourcesSummary.Types["image"] != 2 {
		t.Errorf("Expected 2 image resources, got %d", compact.ResourcesSummary.Types["image"])
	}
}

// TestCompactCrawlResultWithNilInput tests compact transformation with nil input
func TestCompactCrawlResultWithNilInput(t *testing.T) {
	compact := compactCrawlResult(nil)
	if compact != nil {
		t.Error("compactCrawlResult should return nil for nil input")
	}
}

// TestCompactCrawlResultJSONMarshaling tests JSON marshaling of compact crawl results
func TestCompactCrawlResultJSONMarshaling(t *testing.T) {
	compactResult := CompactCrawlResult{
		Target: "https://example.com",
		Statistics: crawler.CrawlStats{
			TotalURLs:       100,
			InternalURLs:    80,
			ExternalURLs:    20,
			FormsFound:      5,
			ResourcesFound:  500,
			MaxDepthReached: 3,
		},
		ResourcesSummary: &ResourcesSummary{
			Total: 500,
			Types: map[string]int{"js": 200, "css": 100, "image": 200},
		},
		InternalLinksSummary: &LinksSummary{
			Total:  80,
			Sample: []string{"https://example.com/page1", "https://example.com/page2"},
		},
		ExternalLinksSummary: &LinksSummary{
			Total:  20,
			Sample: []string{"https://external.com/page1"},
		},
		RobotsDisallow: []string{"/admin"},
		SitemapURLs:    []string{"https://example.com/sitemap.xml"},
		Errors:         []string{},
	}

	data, err := json.Marshal(compactResult)
	if err != nil {
		t.Fatalf("Failed to marshal CompactCrawlResult: %v", err)
	}

	var unmarshaled CompactCrawlResult
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal CompactCrawlResult: %v", err)
	}

	if unmarshaled.Target != compactResult.Target {
		t.Errorf("Target mismatch after marshal/unmarshal")
	}

	if unmarshaled.Statistics.TotalURLs != compactResult.Statistics.TotalURLs {
		t.Errorf("TotalURLs mismatch after marshal/unmarshal")
	}

	if unmarshaled.ResourcesSummary.Total != compactResult.ResourcesSummary.Total {
		t.Errorf("ResourcesSummary.Total mismatch after marshal/unmarshal")
	}

	if unmarshaled.InternalLinksSummary.Total != compactResult.InternalLinksSummary.Total {
		t.Errorf("InternalLinksSummary.Total mismatch after marshal/unmarshal")
	}
}

// TestCompactCrawlResultOutputSize tests that compact output is significantly smaller
func TestCompactCrawlResultOutputSize(t *testing.T) {
	// Create a large mock result
	mockResult := &crawler.CrawlResult{
		Target: "https://example.com",
		Statistics: crawler.CrawlStats{
			TotalURLs:       1000,
			InternalURLs:    800,
			ExternalURLs:    200,
			FormsFound:      10,
			ResourcesFound:  2000,
			MaxDepthReached: 3,
		},
		Forms:          make([]crawler.FormInfo, 10),
		Resources:      make([]crawler.ResourceInfo, 2000),
		InternalLinks:  make([]crawler.LinkInfo, 800),
		ExternalLinks:  make([]crawler.LinkInfo, 200),
		RobotsDisallow: []string{"/admin", "/private"},
		SitemapURLs:    []string{"https://example.com/sitemap.xml"},
	}

	// Populate with data
	for i := 0; i < 2000; i++ {
		mockResult.Resources[i] = crawler.ResourceInfo{
			URL:  fmt.Sprintf("https://example.com/resources/very-long-resource-name-%d.js", i),
			Type: "js",
			Page: "https://example.com/page",
		}
	}
	for i := 0; i < 800; i++ {
		mockResult.InternalLinks[i] = crawler.LinkInfo{
			URL:      fmt.Sprintf("https://example.com/very-long-page-name-%d", i),
			External: false,
		}
	}
	for i := 0; i < 200; i++ {
		mockResult.ExternalLinks[i] = crawler.LinkInfo{
			URL:      fmt.Sprintf("https://external-domain.com/very-long-page-name-%d", i),
			External: true,
		}
	}

	// Marshal full result
	fullData, err := json.Marshal(mockResult)
	if err != nil {
		t.Fatalf("Failed to marshal full result: %v", err)
	}

	// Transform and marshal compact result
	compact := compactCrawlResult(mockResult)
	compactData, err := json.Marshal(compact)
	if err != nil {
		t.Fatalf("Failed to marshal compact result: %v", err)
	}

	fullSize := len(fullData)
	compactSize := len(compactData)

	t.Logf("Full result size: %d bytes", fullSize)
	t.Logf("Compact result size: %d bytes", compactSize)
	t.Logf("Size reduction: %.2f%%", float64(fullSize-compactSize)/float64(fullSize)*100)

	// Compact should be significantly smaller (at least 80% reduction for this test data)
	if compactSize >= fullSize/5 {
		t.Errorf("Compact result should be much smaller. Full: %d, Compact: %d", fullSize, compactSize)
	}

	// Compact should be under a reasonable size limit (e.g., 10KB for this test)
	if compactSize > 10000 {
		t.Errorf("Compact result should be under 10KB, got %d bytes", compactSize)
	}
}
