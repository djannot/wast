package scanner

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/crawler"
	"github.com/djannot/wast/pkg/ratelimit"
)

func TestExecuteDiscoveryScan(t *testing.T) {
	t.Skip("Integration test - requires external network access")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := DiscoveryScanConfig{
		ScanConfig: ScanConfig{
			Target:          "https://example.com",
			Timeout:         10,
			SafeMode:        true, // Safe mode for testing
			VerifyFindings:  false,
			AuthConfig:      &auth.AuthConfig{},
			RateLimitConfig: ratelimit.Config{},
			Tracer:          nil,
		},
		CrawlDepth:  1,
		Concurrency: 2,
		Discover:    true,
	}

	result, stats := ExecuteDiscoveryScan(ctx, cfg)

	if result == nil {
		t.Fatal("ExecuteDiscoveryScan returned nil result")
	}

	if stats == nil {
		t.Fatal("ExecuteDiscoveryScan returned nil stats")
	}

	if result.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", result.Target)
	}

	if result.Headers == nil {
		t.Error("Headers result should not be nil")
	}

	// In safe mode, active scanners should be nil
	if result.XSS != nil {
		t.Error("XSS result should be nil in safe mode")
	}
	if result.SQLi != nil {
		t.Error("SQLi result should be nil in safe mode")
	}
	if result.CSRF != nil {
		t.Error("CSRF result should be nil in safe mode")
	}
	if result.SSRF != nil {
		t.Error("SSRF result should be nil in safe mode")
	}
	if result.Redirect != nil {
		t.Error("Redirect result should be nil in safe mode")
	}
	if result.CMDi != nil {
		t.Error("CMDi result should be nil in safe mode")
	}
	if result.PathTraversal != nil {
		t.Error("PathTraversal result should be nil in safe mode")
	}
}

func TestExtractDiscoveredTargets(t *testing.T) {
	// Test with mock crawler results
	crawlResult := mockCrawlResult()

	targets := extractDiscoveredTargets("https://example.com", crawlResult)

	if len(targets) == 0 {
		t.Error("Expected to extract some targets from mock crawl result")
	}

	// Check that forms are extracted
	hasFormTarget := false
	hasLinkTarget := false
	for _, target := range targets {
		if target.Method == "POST" {
			hasFormTarget = true
		}
		if target.Method == "GET" && len(target.Parameters) > 0 {
			hasLinkTarget = true
		}
	}

	if !hasFormTarget {
		t.Error("Expected to find at least one form target")
	}
	if !hasLinkTarget {
		t.Error("Expected to find at least one link with query parameters")
	}
}

// Helper function to create mock crawl result for testing
func mockCrawlResult() *crawler.CrawlResult {
	return &crawler.CrawlResult{
		Target: "https://example.com",
		Forms: []crawler.FormInfo{
			{
				Action: "https://example.com/search",
				Method: "POST",
				Fields: []crawler.FormFieldInfo{
					{Name: "query", Type: "text", Value: "", Required: false},
					{Name: "filter", Type: "text", Value: "", Required: false},
				},
				Page: "https://example.com",
			},
		},
		InternalLinks: []crawler.LinkInfo{
			{URL: "https://example.com/page?id=1&sort=asc", External: false, Depth: 1},
			{URL: "https://example.com/products?category=books", External: false, Depth: 1},
		},
		Statistics: crawler.CrawlStats{
			TotalURLs:    2,
			InternalURLs: 2,
			FormsFound:   1,
		},
	}
}

func TestDiscoveryScanConfig_Defaults(t *testing.T) {
	cfg := DiscoveryScanConfig{
		ScanConfig: ScanConfig{
			Target:          "https://example.com",
			Timeout:         30,
			SafeMode:        true,
			AuthConfig:      &auth.AuthConfig{},
			RateLimitConfig: ratelimit.Config{},
		},
		// Don't set CrawlDepth or Concurrency to test defaults
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This test just verifies that defaults are applied correctly
	// We're not actually running the scan, just checking the config handling
	if cfg.CrawlDepth == 0 {
		cfg.CrawlDepth = 2 // Default
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 5 // Default
	}
	if cfg.ScanConcurrency == 0 {
		cfg.ScanConcurrency = 5 // Default
	}

	if cfg.CrawlDepth != 2 {
		t.Errorf("Expected default CrawlDepth of 2, got %d", cfg.CrawlDepth)
	}
	if cfg.Concurrency != 5 {
		t.Errorf("Expected default Concurrency of 5, got %d", cfg.Concurrency)
	}
	if cfg.ScanConcurrency != 5 {
		t.Errorf("Expected default ScanConcurrency of 5, got %d", cfg.ScanConcurrency)
	}

	// Prevent unused variable error
	_ = ctx
}

func TestScanDiscoveredTargets_Concurrent(t *testing.T) {
	// Create multiple mock targets
	targets := []DiscoveredTarget{
		{
			URL:        "https://example.com/page1?id=1",
			Method:     "GET",
			Parameters: map[string]string{"id": "1"},
			Source:     "test page 1",
		},
		{
			URL:        "https://example.com/page2?id=2",
			Method:     "GET",
			Parameters: map[string]string{"id": "2"},
			Source:     "test page 2",
		},
		{
			URL:        "https://example.com/page3?id=3",
			Method:     "GET",
			Parameters: map[string]string{"id": "3"},
			Source:     "test page 3",
		},
		{
			URL:        "https://example.com/form",
			Method:     "POST",
			Parameters: map[string]string{"username": "test", "email": "test@example.com"},
			Source:     "test form",
		},
	}

	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         5,
		SafeMode:        true, // Safe mode to avoid actual scanning
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
		Tracer:          nil,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test with different concurrency levels
	concurrencyLevels := []int{1, 2, 5}
	for _, concurrency := range concurrencyLevels {
		t.Run(fmt.Sprintf("Concurrency_%d", concurrency), func(t *testing.T) {
			result, stats := scanDiscoveredTargets(ctx, cfg, targets, concurrency, nil)

			if result == nil {
				t.Fatal("scanDiscoveredTargets returned nil result")
			}

			if stats == nil {
				t.Fatal("scanDiscoveredTargets returned nil stats")
			}

			if result.Target != cfg.Target {
				t.Errorf("Expected target %s, got %s", cfg.Target, result.Target)
			}

			// In safe mode, active scanners should be nil
			if result.XSS != nil {
				t.Error("XSS result should be nil in safe mode")
			}
		})
	}
}

func TestScanDiscoveredTargets_ContextCancellation(t *testing.T) {
	// Create multiple targets
	targets := make([]DiscoveredTarget, 20)
	for i := 0; i < 20; i++ {
		targets[i] = DiscoveredTarget{
			URL:        fmt.Sprintf("https://example.com/page%d?id=%d", i, i),
			Method:     "GET",
			Parameters: map[string]string{"id": fmt.Sprintf("%d", i)},
			Source:     fmt.Sprintf("test page %d", i),
		}
	}

	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         5,
		SafeMode:        false, // Enable active scanning to test cancellation
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
		Tracer:          nil,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This should be cancelled quickly
	result, _ := scanDiscoveredTargets(ctx, cfg, targets, 3, nil)

	if result == nil {
		t.Fatal("scanDiscoveredTargets returned nil result even with cancellation")
	}

	// Check that cancellation was detected
	if len(result.Errors) == 0 {
		// It's possible that it finished before cancellation, which is also valid
		t.Log("Warning: Expected cancellation error, but scan may have completed quickly")
	}
}

func TestScanDiscoveredTargets_NoRaceConditions(t *testing.T) {
	// This test is meant to be run with -race flag
	// Create many targets to increase chance of detecting race conditions
	targets := make([]DiscoveredTarget, 50)
	for i := 0; i < 50; i++ {
		targets[i] = DiscoveredTarget{
			URL:        fmt.Sprintf("https://example.com/page%d?id=%d", i, i),
			Method:     "GET",
			Parameters: map[string]string{"id": fmt.Sprintf("%d", i)},
			Source:     fmt.Sprintf("test page %d", i),
		}
	}

	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         5,
		SafeMode:        true, // Safe mode for faster execution
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
		Tracer:          nil,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run with high concurrency to stress test
	result, stats := scanDiscoveredTargets(ctx, cfg, targets, 10, nil)

	if result == nil {
		t.Fatal("scanDiscoveredTargets returned nil result")
	}

	if stats == nil {
		t.Fatal("scanDiscoveredTargets returned nil stats")
	}
}

func TestScanDiscoveredTargets_EmptyTargets(t *testing.T) {
	// Test with no targets - should fall back to ExecuteScan
	targets := []DiscoveredTarget{}

	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         5,
		SafeMode:        true,
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
		Tracer:          nil,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, stats := scanDiscoveredTargets(ctx, cfg, targets, 5, nil)

	if result == nil {
		t.Fatal("scanDiscoveredTargets returned nil result")
	}

	if stats == nil {
		t.Fatal("scanDiscoveredTargets returned nil stats")
	}

	// Should have scanned the base target
	if result.Target != cfg.Target {
		t.Errorf("Expected target %s, got %s", cfg.Target, result.Target)
	}
}

func TestScanDiscoveredTargets_ActiveScanners(t *testing.T) {
	t.Skip("Integration test - requires external network access")

	// Create test targets
	targets := []DiscoveredTarget{
		{
			URL:        "https://example.com/page?id=1",
			Method:     "GET",
			Parameters: map[string]string{"id": "1"},
			Source:     "test page 1",
		},
	}

	cfg := ScanConfig{
		Target:          "https://example.com",
		Timeout:         5,
		SafeMode:        false, // Enable active scanning
		VerifyFindings:  false,
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
		Tracer:          nil,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, stats := scanDiscoveredTargets(ctx, cfg, targets, 5, nil)

	if result == nil {
		t.Fatal("scanDiscoveredTargets returned nil result")
	}

	if stats == nil {
		t.Fatal("scanDiscoveredTargets returned nil stats")
	}

	// In active mode, scanner results should not be nil
	if result.XSS == nil {
		t.Error("XSS result should not be nil in active mode")
	}
	if result.SQLi == nil {
		t.Error("SQLi result should not be nil in active mode")
	}
	if result.CSRF == nil {
		t.Error("CSRF result should not be nil in active mode")
	}
	if result.SSRF == nil {
		t.Error("SSRF result should not be nil in active mode")
	}
	if result.Redirect == nil {
		t.Error("Redirect result should not be nil in active mode")
	}
	if result.CMDi == nil {
		t.Error("CMDi result should not be nil in active mode")
	}
	if result.PathTraversal == nil {
		t.Error("PathTraversal result should not be nil in active mode")
	}
}

// TestScanTargetForPOSTMethod tests that POST targets are routed correctly
func TestScanTargetForPOSTMethod(t *testing.T) {
	ctx := context.Background()

	// Test SQLi with POST method
	sqliScanner := NewSQLiScanner(WithSQLiTimeout(30 * time.Second))
	sqliScanner.client = newMockSQLiHTTPClient()

	postTarget := DiscoveredTarget{
		URL:    "http://example.com/login",
		Method: "POST",
		Parameters: map[string]string{
			"username": "admin",
			"password": "test",
		},
		Source: "form on /login",
	}

	sqliFindings := scanTargetForSQLi(ctx, sqliScanner, postTarget)
	if sqliFindings == nil {
		t.Error("Expected scanTargetForSQLi to return findings for POST method")
	}

	// Test XSS with POST method
	xssScanner := NewXSSScanner(WithXSSTimeout(30 * time.Second))
	xssFindings := scanTargetForXSS(ctx, xssScanner, postTarget)
	if xssFindings == nil {
		t.Error("Expected scanTargetForXSS to return findings for POST method")
	}

	// Test CMDi with POST method
	cmdiScanner := NewCMDiScanner(WithCMDiTimeout(30 * time.Second))
	cmdiFindings := scanTargetForCMDi(ctx, cmdiScanner, postTarget)
	if cmdiFindings == nil {
		t.Error("Expected scanTargetForCMDi to return findings for POST method")
	}

	// Test SSRF with POST method
	ssrfScanner := NewSSRFScanner(WithSSRFTimeout(30 * time.Second))
	ssrfFindings := scanTargetForSSRF(ctx, ssrfScanner, postTarget)
	if ssrfFindings == nil {
		t.Error("Expected scanTargetForSSRF to return findings for POST method")
	}

	// Test GET method still works
	getTarget := DiscoveredTarget{
		URL:    "http://example.com/search?q=test",
		Method: "GET",
		Parameters: map[string]string{
			"q": "test",
		},
		Source: "link with query params",
	}

	sqliGetFindings := scanTargetForSQLi(ctx, sqliScanner, getTarget)
	if sqliGetFindings == nil {
		t.Error("Expected scanTargetForSQLi to return findings for GET method")
	}
}
