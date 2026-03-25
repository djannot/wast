package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
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

			result := executeRecon(ctx, tt.target, tt.timeout, tt.includeSubdomains, nil)

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
	result := executeRecon(ctx, "example.com", 30*time.Second, true, nil)

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

			result := executeScan(ctx, tt.target, tt.timeout, tt.safeMode, tt.verifyFindings, false, 2, 5, 5, authConfig, rateLimitConfig, nil)

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

	result := executeScan(ctx, "https://example.com", 30, true, false, false, 2, 5, 5, authConfig, rateLimitConfig, nil)

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

	result := executeScan(ctx, "https://example.com", 30, true, false, false, 2, 5, 5, authConfig, rateLimitConfig, nil)

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

			result := executeCrawl(ctx, tt.target, tt.depth, tt.timeout, tt.respectRobots, 5, authConfig, rateLimitConfig, nil)

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

	result := executeCrawl(ctx, "https://example.com", 3, 30*time.Second, true, 5, authConfig, rateLimitConfig, nil)

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

	result := executeCrawl(ctx, "https://example.com", 2, 20*time.Second, true, 5, authConfig, rateLimitConfig, nil)

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
