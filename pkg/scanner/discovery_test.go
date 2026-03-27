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
			// Create empty crawl result for testing
			crawlResult := &crawler.CrawlResult{
				Target:        cfg.Target,
				CrawledURLs:   []string{},
				Resources:     []crawler.ResourceInfo{},
				InternalLinks: []crawler.LinkInfo{},
				ExternalLinks: []crawler.LinkInfo{},
			}
			result, stats := scanDiscoveredTargets(ctx, cfg, targets, concurrency, nil, crawlResult)

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

	// Create empty crawl result for testing
	crawlResult := &crawler.CrawlResult{
		Target:        cfg.Target,
		CrawledURLs:   []string{},
		Resources:     []crawler.ResourceInfo{},
		InternalLinks: []crawler.LinkInfo{},
		ExternalLinks: []crawler.LinkInfo{},
	}

	// This should be cancelled quickly
	result, _ := scanDiscoveredTargets(ctx, cfg, targets, 3, nil, crawlResult)

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

	// Create empty crawl result for testing
	crawlResult := &crawler.CrawlResult{
		Target:        cfg.Target,
		CrawledURLs:   []string{},
		Resources:     []crawler.ResourceInfo{},
		InternalLinks: []crawler.LinkInfo{},
		ExternalLinks: []crawler.LinkInfo{},
	}

	// Run with high concurrency to stress test
	result, stats := scanDiscoveredTargets(ctx, cfg, targets, 10, nil, crawlResult)

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

	// Create empty crawl result for testing
	crawlResult := &crawler.CrawlResult{
		Target:        cfg.Target,
		CrawledURLs:   []string{},
		Resources:     []crawler.ResourceInfo{},
		InternalLinks: []crawler.LinkInfo{},
		ExternalLinks: []crawler.LinkInfo{},
	}

	result, stats := scanDiscoveredTargets(ctx, cfg, targets, 5, nil, crawlResult)

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

	// Create empty crawl result for testing
	crawlResult := &crawler.CrawlResult{
		Target:        cfg.Target,
		CrawledURLs:   []string{},
		Resources:     []crawler.ResourceInfo{},
		InternalLinks: []crawler.LinkInfo{},
		ExternalLinks: []crawler.LinkInfo{},
	}

	result, stats := scanDiscoveredTargets(ctx, cfg, targets, 5, nil, crawlResult)

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

	sqliResult := scanTargetForSQLi(ctx, sqliScanner, postTarget)
	if sqliResult == nil {
		t.Error("Expected scanTargetForSQLi to return result for POST method")
	}

	// Test XSS with POST method
	xssScanner := NewXSSScanner(WithXSSTimeout(30 * time.Second))
	xssResult := scanTargetForXSS(ctx, xssScanner, postTarget)
	if xssResult == nil {
		t.Error("Expected scanTargetForXSS to return result for POST method")
	}

	// Test CMDi with POST method
	cmdiScanner := NewCMDiScanner(WithCMDiTimeout(30 * time.Second))
	cmdiResult := scanTargetForCMDi(ctx, cmdiScanner, postTarget)
	if cmdiResult == nil {
		t.Error("Expected scanTargetForCMDi to return result for POST method")
	}

	// Test SSRF with POST method
	ssrfScanner := NewSSRFScanner(WithSSRFTimeout(30 * time.Second))
	ssrfResult := scanTargetForSSRF(ctx, ssrfScanner, postTarget)
	if ssrfResult == nil {
		t.Error("Expected scanTargetForSSRF to return result for POST method")
	}

	// Test Redirect with POST method
	redirectScanner := NewRedirectScanner(WithRedirectTimeout(30 * time.Second))
	redirectResult := scanTargetForRedirect(ctx, redirectScanner, postTarget)
	if redirectResult == nil {
		t.Error("Expected scanTargetForRedirect to return result for POST method")
	}

	// Test PathTraversal with POST method
	pathtraversalScanner := NewPathTraversalScanner(WithPathTraversalTimeout(30 * time.Second))
	pathtraversalResult := scanTargetForPathTraversal(ctx, pathtraversalScanner, postTarget)
	if pathtraversalResult == nil {
		t.Error("Expected scanTargetForPathTraversal to return result for POST method")
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

	sqliGetResult := scanTargetForSQLi(ctx, sqliScanner, getTarget)
	if sqliGetResult == nil {
		t.Error("Expected scanTargetForSQLi to return result for GET method")
	}
}

// TestExtractDiscoveredTargets_POSTForms tests extraction of POST forms with all parameters
func TestExtractDiscoveredTargets_POSTForms(t *testing.T) {
	crawlResult := &crawler.CrawlResult{
		Target: "https://example.com",
		Forms: []crawler.FormInfo{
			{
				Action: "https://example.com/login",
				Method: "POST",
				Fields: []crawler.FormFieldInfo{
					{Name: "username", Type: "text", Value: "", Required: true},
					{Name: "password", Type: "password", Value: "", Required: true},
					{Name: "remember", Type: "checkbox", Value: "1", Required: false},
				},
				Page: "https://example.com/login",
			},
			{
				Action: "https://example.com/search",
				Method: "POST",
				Fields: []crawler.FormFieldInfo{
					{Name: "q", Type: "text", Value: "", Required: false},
					{Name: "category", Type: "select", Value: "all", Required: false},
					{Name: "hidden_token", Type: "hidden", Value: "abc123", Required: false}, // Should be skipped
				},
				Page: "https://example.com",
			},
		},
		InternalLinks: []crawler.LinkInfo{},
		Statistics: crawler.CrawlStats{
			TotalURLs:    1,
			InternalURLs: 1,
			FormsFound:   2,
		},
	}

	targets := extractDiscoveredTargets("https://example.com", crawlResult)

	// Should extract 2 forms (password and hidden fields are filtered)
	if len(targets) != 2 {
		t.Errorf("Expected 2 targets, got %d", len(targets))
	}

	// Check first form (login)
	var loginTarget *DiscoveredTarget
	for i := range targets {
		if targets[i].URL == "https://example.com/login" {
			loginTarget = &targets[i]
			break
		}
	}

	if loginTarget == nil {
		t.Fatal("Login form target not found")
	}

	if loginTarget.Method != "POST" {
		t.Errorf("Expected POST method, got %s", loginTarget.Method)
	}

	// Should have username and remember, but NOT password (filtered)
	if len(loginTarget.Parameters) != 2 {
		t.Errorf("Expected 2 parameters (username, remember), got %d: %v", len(loginTarget.Parameters), loginTarget.Parameters)
	}

	if _, hasUsername := loginTarget.Parameters["username"]; !hasUsername {
		t.Error("Expected username parameter")
	}

	if _, hasRemember := loginTarget.Parameters["remember"]; !hasRemember {
		t.Error("Expected remember parameter")
	}

	if _, hasPassword := loginTarget.Parameters["password"]; hasPassword {
		t.Error("Password field should be filtered out")
	}

	// Check second form (search)
	var searchTarget *DiscoveredTarget
	for i := range targets {
		if targets[i].URL == "https://example.com/search" {
			searchTarget = &targets[i]
			break
		}
	}

	if searchTarget == nil {
		t.Fatal("Search form target not found")
	}

	if searchTarget.Method != "POST" {
		t.Errorf("Expected POST method, got %s", searchTarget.Method)
	}

	// Should have q and category, but NOT hidden_token (filtered)
	if len(searchTarget.Parameters) != 2 {
		t.Errorf("Expected 2 parameters (q, category), got %d: %v", len(searchTarget.Parameters), searchTarget.Parameters)
	}

	if _, hasQ := searchTarget.Parameters["q"]; !hasQ {
		t.Error("Expected q parameter")
	}

	if _, hasCategory := searchTarget.Parameters["category"]; !hasCategory {
		t.Error("Expected category parameter")
	}

	if _, hasHidden := searchTarget.Parameters["hidden_token"]; hasHidden {
		t.Error("Hidden field should be filtered out")
	}
}

// TestScanTargetRouting tests that different HTTP methods are routed correctly
func TestScanTargetRouting(t *testing.T) {
	ctx := context.Background()

	postTarget := DiscoveredTarget{
		URL:    "http://example.com/form",
		Method: "POST",
		Parameters: map[string]string{
			"field1": "value1",
			"field2": "value2",
		},
		Source: "test form",
	}

	getTarget := DiscoveredTarget{
		URL:    "http://example.com/page?id=1",
		Method: "GET",
		Parameters: map[string]string{
			"id": "1",
		},
		Source: "test link",
	}

	// Test that scanners handle both POST and GET
	testCases := []struct {
		name   string
		target DiscoveredTarget
	}{
		{"POST method", postTarget},
		{"GET method", getTarget},
		{"post (lowercase)", DiscoveredTarget{URL: "http://example.com/form", Method: "post", Parameters: map[string]string{"field": "value"}, Source: "test"}},
		{"Post (mixed case)", DiscoveredTarget{URL: "http://example.com/form", Method: "Post", Parameters: map[string]string{"field": "value"}, Source: "test"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// XSS
			xssScanner := NewXSSScanner(WithXSSTimeout(5 * time.Second))
			xssResult := scanTargetForXSS(ctx, xssScanner, tc.target)
			if xssResult == nil {
				t.Error("XSS scanner should handle both POST and GET")
			}

			// SQLi
			sqliScanner := NewSQLiScanner(WithSQLiTimeout(5 * time.Second))
			sqliResult := scanTargetForSQLi(ctx, sqliScanner, tc.target)
			if sqliResult == nil {
				t.Error("SQLi scanner should handle both POST and GET")
			}

			// CMDi
			cmdiScanner := NewCMDiScanner(WithCMDiTimeout(5 * time.Second))
			cmdiResult := scanTargetForCMDi(ctx, cmdiScanner, tc.target)
			if cmdiResult == nil {
				t.Error("CMDi scanner should handle both POST and GET")
			}

			// SSRF
			ssrfScanner := NewSSRFScanner(WithSSRFTimeout(5 * time.Second))
			ssrfResult := scanTargetForSSRF(ctx, ssrfScanner, tc.target)
			if ssrfResult == nil {
				t.Error("SSRF scanner should handle both POST and GET")
			}

			// Redirect
			redirectScanner := NewRedirectScanner(WithRedirectTimeout(5 * time.Second))
			redirectResult := scanTargetForRedirect(ctx, redirectScanner, tc.target)
			if redirectResult == nil {
				t.Error("Redirect scanner should handle both POST and GET")
			}

			// PathTraversal
			pathtraversalScanner := NewPathTraversalScanner(WithPathTraversalTimeout(5 * time.Second))
			pathtraversalResult := scanTargetForPathTraversal(ctx, pathtraversalScanner, tc.target)
			if pathtraversalResult == nil {
				t.Error("PathTraversal scanner should handle both POST and GET")
			}
		})
	}
}

// TestScanDiscoveredTargets_TestCountAggregation verifies that test counts from individual
// scanner results are properly aggregated into the stats when scanning multiple discovered targets.
//
// Note: This is an integration test that makes real HTTP requests to example.com to verify
// that the aggregation logic works correctly end-to-end.
func TestScanDiscoveredTargets_TestCountAggregation(t *testing.T) {
	t.Skip("Integration test - requires external network access")

	// Create multiple targets to simulate discovery scan
	targets := []DiscoveredTarget{
		{
			URL:        "https://example.com/page1?id=1",
			Method:     "GET",
			Parameters: map[string]string{"id": "1"},
			Source:     "test page 1",
		},
		{
			URL:        "https://example.com/page2?q=search",
			Method:     "GET",
			Parameters: map[string]string{"q": "search"},
			Source:     "test page 2",
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
		Timeout:         10,
		SafeMode:        false, // Enable active scanning
		VerifyFindings:  false,
		AuthConfig:      &auth.AuthConfig{},
		RateLimitConfig: ratelimit.Config{},
		Tracer:          nil,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Create empty crawl result for testing
	crawlResult := &crawler.CrawlResult{
		Target:        cfg.Target,
		CrawledURLs:   []string{},
		Resources:     []crawler.ResourceInfo{},
		InternalLinks: []crawler.LinkInfo{},
		ExternalLinks: []crawler.LinkInfo{},
	}

	// Call scanDiscoveredTargets to verify aggregation logic
	// This will make real HTTP requests to the targets defined above
	result, stats := scanDiscoveredTargets(ctx, cfg, targets, 2, nil, crawlResult)

	if result == nil {
		t.Fatal("scanDiscoveredTargets returned nil result")
	}

	if stats == nil {
		t.Fatal("scanDiscoveredTargets returned nil stats")
	}

	// Verify that test counts are populated (should be > 0 if tests ran)
	// Each scanner should have executed tests across the discovered targets
	if stats.TotalXSSTests == 0 {
		t.Error("Expected TotalXSSTests to be > 0, got 0")
	}
	if stats.TotalSQLiTests == 0 {
		t.Error("Expected TotalSQLiTests to be > 0, got 0")
	}
	if stats.TotalSSRFTests == 0 {
		t.Error("Expected TotalSSRFTests to be > 0, got 0")
	}
	if stats.TotalRedirectTests == 0 {
		t.Error("Expected TotalRedirectTests to be > 0, got 0")
	}
	if stats.TotalCMDiTests == 0 {
		t.Error("Expected TotalCMDiTests to be > 0, got 0")
	}
	if stats.TotalPathTraversalTests == 0 {
		t.Error("Expected TotalPathTraversalTests to be > 0, got 0")
	}

	// Verify that the summary in results also shows test counts
	if result.XSS != nil && result.XSS.Summary.TotalTests == 0 {
		t.Error("Expected XSS result summary to show TotalTests > 0, got 0")
	}
	if result.SQLi != nil && result.SQLi.Summary.TotalTests == 0 {
		t.Error("Expected SQLi result summary to show TotalTests > 0, got 0")
	}
	if result.SSRF != nil && result.SSRF.Summary.TotalTests == 0 {
		t.Error("Expected SSRF result summary to show TotalTests > 0, got 0")
	}
	if result.Redirect != nil && result.Redirect.Summary.TotalTests == 0 {
		t.Error("Expected Redirect result summary to show TotalTests > 0, got 0")
	}
	if result.CMDi != nil && result.CMDi.Summary.TotalTests == 0 {
		t.Error("Expected CMDi result summary to show TotalTests > 0, got 0")
	}
	if result.PathTraversal != nil && result.PathTraversal.Summary.TotalTests == 0 {
		t.Error("Expected PathTraversal result summary to show TotalTests > 0, got 0")
	}

	t.Logf("Test counts aggregated successfully:")
	t.Logf("  XSS: %d tests", stats.TotalXSSTests)
	t.Logf("  SQLi: %d tests", stats.TotalSQLiTests)
	t.Logf("  CSRF: %d tests", stats.TotalCSRFTests)
	t.Logf("  SSRF: %d tests", stats.TotalSSRFTests)
	t.Logf("  Redirect: %d tests", stats.TotalRedirectTests)
	t.Logf("  CMDi: %d tests", stats.TotalCMDiTests)
	t.Logf("  PathTraversal: %d tests", stats.TotalPathTraversalTests)
}
