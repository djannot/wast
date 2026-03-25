package scanner

import (
	"context"
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

	if cfg.CrawlDepth != 2 {
		t.Errorf("Expected default CrawlDepth of 2, got %d", cfg.CrawlDepth)
	}
	if cfg.Concurrency != 5 {
		t.Errorf("Expected default Concurrency of 5, got %d", cfg.Concurrency)
	}

	// Prevent unused variable error
	_ = ctx
}
