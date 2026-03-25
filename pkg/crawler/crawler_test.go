package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/ratelimit"
)

// MockHTTPClient implements the HTTPClient interface for testing.
type MockHTTPClient struct {
	Responses map[string]string
	Errors    map[string]error
	Requests  []*http.Request
	mu        sync.Mutex
}

// NewMockHTTPClient creates a new MockHTTPClient.
func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{
		Responses: make(map[string]string),
		Errors:    make(map[string]error),
		Requests:  make([]*http.Request, 0),
	}
}

// AddResponse adds a mock response for a URL.
func (m *MockHTTPClient) AddResponse(url string, statusCode int, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Responses[url] = body
}

// AddError adds a mock error for a URL.
func (m *MockHTTPClient) AddError(url string, err error) {
	m.Errors[url] = err
}

// Do performs the mock HTTP request.
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Requests = append(m.Requests, req)
	url := req.URL.String()

	if err, ok := m.Errors[url]; ok {
		return nil, err
	}

	if body, ok := m.Responses[url]; ok {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	}

	// Default: 404
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("Not Found")),
		Header:     make(http.Header),
	}, nil
}

func TestCrawler_Crawl_BasicPage(t *testing.T) {
	mockClient := NewMockHTTPClient()

	// Add mock responses
	mockClient.AddResponse("https://example.com/robots.txt", 404, "")
	mockClient.AddResponse("https://example.com", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Test Page</title></head>
		<body>
			<a href="/page1">Page 1</a>
			<a href="/page2">Page 2</a>
			<a href="https://external.com">External</a>
		</body>
		</html>
	`)
	mockClient.AddResponse("https://example.com/page1", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Page 1</title></head>
		<body>
			<a href="/page3">Page 3</a>
		</body>
		</html>
	`)
	mockClient.AddResponse("https://example.com/page2", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Page 2</title></head>
		<body>
			<p>Content</p>
		</body>
		</html>
	`)
	mockClient.AddResponse("https://example.com/page3", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Page 3</title></head>
		<body>
			<p>Content</p>
		</body>
		</html>
	`)

	crawler := NewCrawler(
		WithHTTPClient(mockClient),
		WithMaxDepth(3),
		WithRespectRobots(true),
	)

	ctx := context.Background()
	result := crawler.Crawl(ctx, "https://example.com")

	// Check crawled URLs
	if len(result.CrawledURLs) == 0 {
		t.Error("Expected at least one crawled URL")
	}

	// Check internal links
	if len(result.InternalLinks) < 2 {
		t.Errorf("Expected at least 2 internal links, got %d", len(result.InternalLinks))
	}

	// Check external links
	found := false
	for _, link := range result.ExternalLinks {
		if strings.Contains(link.URL, "external.com") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find external link to external.com")
	}

	// Check statistics
	if result.Statistics.TotalURLs == 0 {
		t.Error("Expected TotalURLs > 0")
	}
}

func TestCrawler_Crawl_WithForms(t *testing.T) {
	mockClient := NewMockHTTPClient()

	mockClient.AddResponse("https://example.com/robots.txt", 404, "")
	mockClient.AddResponse("https://example.com", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Form Page</title></head>
		<body>
			<form action="/login" method="POST">
				<input type="text" name="username" required>
				<input type="password" name="password" required>
				<input type="submit" value="Login">
			</form>
			<form action="/search" method="GET">
				<input type="text" name="q">
				<input type="submit" value="Search">
			</form>
		</body>
		</html>
	`)

	crawler := NewCrawler(
		WithHTTPClient(mockClient),
		WithMaxDepth(1),
	)

	ctx := context.Background()
	result := crawler.Crawl(ctx, "https://example.com")

	if len(result.Forms) != 2 {
		t.Errorf("Expected 2 forms, got %d", len(result.Forms))
	}

	// Check first form (login)
	var loginForm *FormInfo
	for i, f := range result.Forms {
		if strings.Contains(f.Action, "login") {
			loginForm = &result.Forms[i]
			break
		}
	}

	if loginForm == nil {
		t.Error("Expected to find login form")
	} else {
		if loginForm.Method != "POST" {
			t.Errorf("Expected login form method POST, got %s", loginForm.Method)
		}
		if len(loginForm.Fields) != 3 {
			t.Errorf("Expected 3 fields in login form, got %d", len(loginForm.Fields))
		}
	}
}

func TestCrawler_Crawl_WithResources(t *testing.T) {
	mockClient := NewMockHTTPClient()

	mockClient.AddResponse("https://example.com/robots.txt", 404, "")
	mockClient.AddResponse("https://example.com", 200, `
		<!DOCTYPE html>
		<html>
		<head>
			<title>Resource Page</title>
			<link rel="stylesheet" href="/style.css">
			<script src="/app.js"></script>
		</head>
		<body>
			<img src="/logo.png" alt="Logo">
			<script src="/analytics.js"></script>
		</body>
		</html>
	`)

	crawler := NewCrawler(
		WithHTTPClient(mockClient),
		WithMaxDepth(1),
	)

	ctx := context.Background()
	result := crawler.Crawl(ctx, "https://example.com")

	// Count resource types
	jsCount := 0
	cssCount := 0
	imageCount := 0
	for _, res := range result.Resources {
		switch res.Type {
		case "js":
			jsCount++
		case "css":
			cssCount++
		case "image":
			imageCount++
		}
	}

	if jsCount != 2 {
		t.Errorf("Expected 2 JS resources, got %d", jsCount)
	}
	if cssCount != 1 {
		t.Errorf("Expected 1 CSS resource, got %d", cssCount)
	}
	if imageCount != 1 {
		t.Errorf("Expected 1 image resource, got %d", imageCount)
	}
}

func TestCrawler_Crawl_RespectRobots(t *testing.T) {
	mockClient := NewMockHTTPClient()

	mockClient.AddResponse("https://example.com/robots.txt", 200, `
User-agent: *
Disallow: /admin
Disallow: /private/
Allow: /admin/public
	`)
	mockClient.AddResponse("https://example.com", 200, `
		<!DOCTYPE html>
		<html>
		<body>
			<a href="/page1">Page 1</a>
			<a href="/admin">Admin</a>
			<a href="/private/secret">Secret</a>
		</body>
		</html>
	`)
	mockClient.AddResponse("https://example.com/page1", 200, `<html><body>Page 1</body></html>`)
	mockClient.AddResponse("https://example.com/admin", 200, `<html><body>Admin</body></html>`)
	mockClient.AddResponse("https://example.com/private/secret", 200, `<html><body>Secret</body></html>`)

	crawler := NewCrawler(
		WithHTTPClient(mockClient),
		WithMaxDepth(2),
		WithRespectRobots(true),
	)

	ctx := context.Background()
	result := crawler.Crawl(ctx, "https://example.com")

	// Check that robots disallow rules were captured
	if len(result.RobotsDisallow) == 0 {
		t.Error("Expected robots disallow rules to be captured")
	}

	// /admin and /private/ should NOT be crawled
	for _, url := range result.CrawledURLs {
		if strings.Contains(url, "/admin") || strings.Contains(url, "/private/") {
			t.Errorf("Should not have crawled disallowed URL: %s", url)
		}
	}
}

func TestCrawler_Crawl_IgnoreRobots(t *testing.T) {
	mockClient := NewMockHTTPClient()

	mockClient.AddResponse("https://example.com/robots.txt", 200, `
User-agent: *
Disallow: /admin
	`)
	mockClient.AddResponse("https://example.com", 200, `
		<!DOCTYPE html>
		<html>
		<body>
			<a href="/admin">Admin</a>
		</body>
		</html>
	`)
	mockClient.AddResponse("https://example.com/admin", 200, `<html><body>Admin</body></html>`)

	crawler := NewCrawler(
		WithHTTPClient(mockClient),
		WithMaxDepth(2),
		WithRespectRobots(false),
	)

	ctx := context.Background()
	result := crawler.Crawl(ctx, "https://example.com")

	// When ignoring robots, /admin should be crawled
	found := false
	for _, url := range result.CrawledURLs {
		if strings.Contains(url, "/admin") {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected /admin to be crawled when ignoring robots.txt")
	}
}

func TestCrawler_Crawl_MaxDepth(t *testing.T) {
	mockClient := NewMockHTTPClient()

	mockClient.AddResponse("https://example.com/robots.txt", 404, "")
	mockClient.AddResponse("https://example.com", 200, `<html><body><a href="/level1">L1</a></body></html>`)
	mockClient.AddResponse("https://example.com/level1", 200, `<html><body><a href="/level2">L2</a></body></html>`)
	mockClient.AddResponse("https://example.com/level2", 200, `<html><body><a href="/level3">L3</a></body></html>`)
	mockClient.AddResponse("https://example.com/level3", 200, `<html><body>End</body></html>`)

	// Test with maxDepth=1
	crawler := NewCrawler(
		WithHTTPClient(mockClient),
		WithMaxDepth(1),
	)

	ctx := context.Background()
	result := crawler.Crawl(ctx, "https://example.com")

	// Should only crawl depth 0 and 1
	if result.Statistics.MaxDepthReached > 1 {
		t.Errorf("Expected max depth reached to be <= 1, got %d", result.Statistics.MaxDepthReached)
	}

	// Level2 and Level3 should not be crawled
	for _, url := range result.CrawledURLs {
		if strings.Contains(url, "level2") || strings.Contains(url, "level3") {
			t.Errorf("Should not have crawled beyond max depth: %s", url)
		}
	}
}

func TestCrawler_WithOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		c := NewCrawler()
		if c.userAgent == "" {
			t.Error("Expected default user agent to be set")
		}
		if c.timeout != 30*time.Second {
			t.Errorf("Expected default timeout of 30s, got %v", c.timeout)
		}
		if c.maxDepth != 3 {
			t.Errorf("Expected default max depth of 3, got %d", c.maxDepth)
		}
		if !c.respectRobots {
			t.Error("Expected default respectRobots to be true")
		}
	})

	t.Run("custom user agent", func(t *testing.T) {
		c := NewCrawler(WithUserAgent("CustomBot/1.0"))
		if c.userAgent != "CustomBot/1.0" {
			t.Errorf("Expected custom user agent, got %s", c.userAgent)
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		c := NewCrawler(WithTimeout(60 * time.Second))
		if c.timeout != 60*time.Second {
			t.Errorf("Expected timeout of 60s, got %v", c.timeout)
		}
	})

	t.Run("custom max depth", func(t *testing.T) {
		c := NewCrawler(WithMaxDepth(5))
		if c.maxDepth != 5 {
			t.Errorf("Expected max depth of 5, got %d", c.maxDepth)
		}
	})

	t.Run("custom http client", func(t *testing.T) {
		mock := NewMockHTTPClient()
		c := NewCrawler(WithHTTPClient(mock))
		if c.client != mock {
			t.Error("Expected custom HTTP client to be set")
		}
	})
}

func TestCrawlResult_String(t *testing.T) {
	result := &CrawlResult{
		Target:      "https://example.com",
		CrawledURLs: []string{"https://example.com", "https://example.com/page1"},
		InternalLinks: []LinkInfo{
			{URL: "https://example.com/page1", Text: "Page 1", Depth: 1},
		},
		ExternalLinks: []LinkInfo{
			{URL: "https://external.com", External: true},
		},
		Forms: []FormInfo{
			{Action: "/login", Method: "POST", Fields: []FormFieldInfo{{Name: "user"}}},
		},
		Resources: []ResourceInfo{
			{URL: "/style.css", Type: "css"},
		},
		RobotsDisallow: []string{"/admin"},
		Statistics: CrawlStats{
			TotalURLs:       2,
			InternalURLs:    1,
			ExternalURLs:    1,
			FormsFound:      1,
			ResourcesFound:  1,
			MaxDepthReached: 1,
		},
	}

	str := result.String()

	// Check that all sections are present
	checks := []string{
		"example.com",
		"Statistics",
		"Crawled URLs",
		"Internal Links",
		"External Links",
		"Forms Found",
		"Static Resources",
		"Robots.txt Disallowed",
	}

	for _, check := range checks {
		if !strings.Contains(str, check) {
			t.Errorf("String should contain %q", check)
		}
	}
}

func TestCrawlResult_HasResults(t *testing.T) {
	tests := []struct {
		name   string
		result *CrawlResult
		want   bool
	}{
		{
			name:   "no results",
			result: &CrawlResult{Target: "https://example.com"},
			want:   false,
		},
		{
			name: "with crawled URLs",
			result: &CrawlResult{
				Target:      "https://example.com",
				CrawledURLs: []string{"https://example.com"},
			},
			want: true,
		},
		{
			name: "with internal links",
			result: &CrawlResult{
				Target:        "https://example.com",
				InternalLinks: []LinkInfo{{URL: "/page1"}},
			},
			want: true,
		},
		{
			name: "with forms",
			result: &CrawlResult{
				Target: "https://example.com",
				Forms:  []FormInfo{{Action: "/login"}},
			},
			want: true,
		},
		{
			name: "only errors",
			result: &CrawlResult{
				Target: "https://example.com",
				Errors: []string{"error"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasResults(); got != tt.want {
				t.Errorf("HasResults() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRobotsData_ParseRobots(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		wantDisallow []string
		wantAllow    []string
		wantSitemaps []string
	}{
		{
			name: "basic robots.txt",
			content: `
User-agent: *
Disallow: /admin
Disallow: /private/
Allow: /public
Sitemap: https://example.com/sitemap.xml
`,
			wantDisallow: []string{"/admin", "/private/"},
			wantAllow:    []string{"/public"},
			wantSitemaps: []string{"https://example.com/sitemap.xml"},
		},
		{
			name: "with comments",
			content: `
# This is a robots.txt file
User-agent: *
# Disallow admin
Disallow: /admin
`,
			wantDisallow: []string{"/admin"},
			wantAllow:    []string{},
			wantSitemaps: []string{},
		},
		{
			name:         "empty content",
			content:      "",
			wantDisallow: []string{},
			wantAllow:    []string{},
			wantSitemaps: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := ParseRobots(strings.NewReader(tt.content))

			if len(data.Disallow) != len(tt.wantDisallow) {
				t.Errorf("Disallow count: got %d, want %d", len(data.Disallow), len(tt.wantDisallow))
			}
			if len(data.Allow) != len(tt.wantAllow) {
				t.Errorf("Allow count: got %d, want %d", len(data.Allow), len(tt.wantAllow))
			}
			if len(data.Sitemaps) != len(tt.wantSitemaps) {
				t.Errorf("Sitemaps count: got %d, want %d", len(data.Sitemaps), len(tt.wantSitemaps))
			}
		})
	}
}

func TestRobotsData_IsAllowed(t *testing.T) {
	tests := []struct {
		name     string
		robots   *RobotsData
		path     string
		expected bool
	}{
		{
			name:     "no rules - allowed",
			robots:   &RobotsData{},
			path:     "/anything",
			expected: true,
		},
		{
			name: "disallowed path",
			robots: &RobotsData{
				Disallow: []string{"/admin"},
			},
			path:     "/admin",
			expected: false,
		},
		{
			name: "disallowed prefix",
			robots: &RobotsData{
				Disallow: []string{"/admin"},
			},
			path:     "/admin/users",
			expected: false,
		},
		{
			name: "allowed path",
			robots: &RobotsData{
				Disallow: []string{"/admin"},
			},
			path:     "/public",
			expected: true,
		},
		{
			name: "allow overrides disallow",
			robots: &RobotsData{
				Disallow: []string{"/admin"},
				Allow:    []string{"/admin/public"},
			},
			path:     "/admin/public",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.robots.IsAllowed(tt.path); got != tt.expected {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestGetRobotsURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com", "https://example.com/robots.txt"},
		{"https://example.com/page", "https://example.com/robots.txt"},
		{"http://example.com:8080", "http://example.com:8080/robots.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := GetRobotsURL(tt.input)
			if err != nil {
				t.Errorf("GetRobotsURL(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("GetRobotsURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com", "https://example.com"},
		{"https://example.com/", "https://example.com/"},
		{"https://example.com/page/", "https://example.com/page"},
		{"https://example.com/page#section", "https://example.com/page"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := normalizeURL(tt.input); got != tt.want {
				t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidLink(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"/page", true},
		{"https://example.com", true},
		{"", false},
		{"javascript:void(0)", false},
		{"mailto:test@example.com", false},
		{"tel:+1234567890", false},
		{"#section", false},
		{"data:text/html,<h1>Test</h1>", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isValidLink(tt.input); got != tt.want {
				t.Errorf("isValidLink(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCrawler_Crawl_ContextCancellation(t *testing.T) {
	mockClient := NewMockHTTPClient()

	mockClient.AddResponse("https://example.com/robots.txt", 404, "")
	mockClient.AddResponse("https://example.com", 200, `
		<!DOCTYPE html>
		<html>
		<body>
			<a href="/page1">Page 1</a>
		</body>
		</html>
	`)

	crawler := NewCrawler(
		WithHTTPClient(mockClient),
		WithMaxDepth(1),
	)

	// Create an already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := crawler.Crawl(ctx, "https://example.com")

	// Should have an error about cancellation
	hasError := false
	for _, err := range result.Errors {
		if strings.Contains(err, "cancelled") || strings.Contains(err, "canceled") {
			hasError = true
			break
		}
	}

	if !hasError {
		t.Error("Expected cancellation error in result")
	}
}

func TestCrawler_Crawl_InvalidURL(t *testing.T) {
	crawler := NewCrawler()

	ctx := context.Background()
	result := crawler.Crawl(ctx, "://invalid-url")

	// Should have an error about invalid URL
	if len(result.Errors) == 0 {
		t.Error("Expected error for invalid URL")
	}
}

func TestCrawler_Crawl_ConcurrentCrawling(t *testing.T) {
	mockClient := NewMockHTTPClient()

	// Add mock responses for a network of pages
	mockClient.AddResponse("https://example.com/robots.txt", 404, "")
	mockClient.AddResponse("https://example.com", 200, `
		<!DOCTYPE html>
		<html>
		<body>
			<a href="/page1">Page 1</a>
			<a href="/page2">Page 2</a>
			<a href="/page3">Page 3</a>
		</body>
		</html>
	`)
	mockClient.AddResponse("https://example.com/page1", 200, `<html><body><a href="/page1a">Page 1A</a></body></html>`)
	mockClient.AddResponse("https://example.com/page2", 200, `<html><body><a href="/page2a">Page 2A</a></body></html>`)
	mockClient.AddResponse("https://example.com/page3", 200, `<html><body><a href="/page3a">Page 3A</a></body></html>`)
	mockClient.AddResponse("https://example.com/page1a", 200, `<html><body>Page 1A Content</body></html>`)
	mockClient.AddResponse("https://example.com/page2a", 200, `<html><body>Page 2A Content</body></html>`)
	mockClient.AddResponse("https://example.com/page3a", 200, `<html><body>Page 3A Content</body></html>`)

	// Test with different concurrency levels
	concurrencyLevels := []int{1, 3, 10}

	for _, concurrency := range concurrencyLevels {
		t.Run(fmt.Sprintf("concurrency=%d", concurrency), func(t *testing.T) {
			crawler := NewCrawler(
				WithHTTPClient(mockClient),
				WithMaxDepth(3),
				WithConcurrency(concurrency),
			)

			ctx := context.Background()
			result := crawler.Crawl(ctx, "https://example.com")

			// Verify that all pages were crawled
			if len(result.CrawledURLs) == 0 {
				t.Error("Expected at least one crawled URL")
			}

			// Verify that internal links were discovered
			if len(result.InternalLinks) < 3 {
				t.Errorf("Expected at least 3 internal links, got %d", len(result.InternalLinks))
			}

			// Verify statistics
			if result.Statistics.TotalURLs == 0 {
				t.Error("Expected TotalURLs > 0")
			}
		})
	}
}

func TestCrawler_WithConcurrency(t *testing.T) {
	t.Run("default concurrency", func(t *testing.T) {
		c := NewCrawler()
		if c.concurrency != 5 {
			t.Errorf("Expected default concurrency of 5, got %d", c.concurrency)
		}
	})

	t.Run("custom concurrency", func(t *testing.T) {
		c := NewCrawler(WithConcurrency(10))
		if c.concurrency != 10 {
			t.Errorf("Expected concurrency of 10, got %d", c.concurrency)
		}
	})

	t.Run("zero concurrency ignored", func(t *testing.T) {
		c := NewCrawler(WithConcurrency(0))
		if c.concurrency != 5 {
			t.Errorf("Expected default concurrency of 5 when 0 is provided, got %d", c.concurrency)
		}
	})

	t.Run("negative concurrency ignored", func(t *testing.T) {
		c := NewCrawler(WithConcurrency(-1))
		if c.concurrency != 5 {
			t.Errorf("Expected default concurrency of 5 when negative is provided, got %d", c.concurrency)
		}
	})
}

func TestCrawler_Crawl_ConcurrentWithRateLimiting(t *testing.T) {
	mockClient := NewMockHTTPClient()

	mockClient.AddResponse("https://example.com/robots.txt", 404, "")
	mockClient.AddResponse("https://example.com", 200, `
		<!DOCTYPE html>
		<html>
		<body>
			<a href="/page1">Page 1</a>
			<a href="/page2">Page 2</a>
		</body>
		</html>
	`)
	mockClient.AddResponse("https://example.com/page1", 200, `<html><body>Page 1</body></html>`)
	mockClient.AddResponse("https://example.com/page2", 200, `<html><body>Page 2</body></html>`)

	// Create rate limiter (5 requests per second)
	rateLimitConfig := ratelimit.Config{RequestsPerSecond: 5}

	crawler := NewCrawler(
		WithHTTPClient(mockClient),
		WithMaxDepth(2),
		WithConcurrency(3),
		WithRateLimitConfig(rateLimitConfig),
	)

	ctx := context.Background()
	result := crawler.Crawl(ctx, "https://example.com")

	// Verify that pages were crawled
	if len(result.CrawledURLs) == 0 {
		t.Error("Expected at least one crawled URL")
	}

	// Should have crawled all available pages
	if result.Statistics.TotalURLs < 3 {
		t.Errorf("Expected at least 3 crawled URLs with rate limiting, got %d", result.Statistics.TotalURLs)
	}
}

func TestCrawler_Crawl_WithSitemap(t *testing.T) {
	mockClient := NewMockHTTPClient()

	// robots.txt with sitemap reference
	mockClient.AddResponse("https://example.com/robots.txt", 200, `User-agent: *
Disallow: /admin
Sitemap: https://example.com/sitemap.xml`)

	// sitemap.xml with URLs
	mockClient.AddResponse("https://example.com/sitemap.xml", 200, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url><loc>https://example.com/page1</loc></url>
	<url><loc>https://example.com/page2</loc></url>
	<url><loc>https://example.com/page3</loc></url>
</urlset>`)

	// Home page
	mockClient.AddResponse("https://example.com", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Home</title></head>
		<body><h1>Home</h1></body>
		</html>
	`)

	// Pages from sitemap
	mockClient.AddResponse("https://example.com/page1", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Page 1</title></head>
		<body><h1>Page 1</h1></body>
		</html>
	`)
	mockClient.AddResponse("https://example.com/page2", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Page 2</title></head>
		<body><h1>Page 2</h1></body>
		</html>
	`)
	mockClient.AddResponse("https://example.com/page3", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Page 3</title></head>
		<body><h1>Page 3</h1></body>
		</html>
	`)

	crawler := NewCrawler(
		WithHTTPClient(mockClient),
		WithMaxDepth(2),
		WithRespectRobots(true),
	)

	ctx := context.Background()
	result := crawler.Crawl(ctx, "https://example.com")

	// Verify sitemap URLs were discovered
	if len(result.SitemapURLs) != 3 {
		t.Errorf("Expected 3 sitemap URLs, got %d", len(result.SitemapURLs))
	}

	expectedSitemapURLs := []string{
		"https://example.com/page1",
		"https://example.com/page2",
		"https://example.com/page3",
	}

	for _, expectedURL := range expectedSitemapURLs {
		found := false
		for _, url := range result.SitemapURLs {
			if url == expectedURL {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected sitemap URL %s not found in result", expectedURL)
		}
	}

	// Verify URLs from sitemap are actually crawled
	if result.Statistics.TotalURLs < 4 { // Home + 3 sitemap pages
		t.Errorf("Expected at least 4 crawled URLs, got %d", result.Statistics.TotalURLs)
	}
}

func TestCrawler_Crawl_WithSitemapIndex(t *testing.T) {
	mockClient := NewMockHTTPClient()

	// robots.txt with sitemap index reference
	mockClient.AddResponse("https://example.com/robots.txt", 200, `User-agent: *
Sitemap: https://example.com/sitemap-index.xml`)

	// sitemap index
	mockClient.AddResponse("https://example.com/sitemap-index.xml", 200, `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<sitemap><loc>https://example.com/sitemap1.xml</loc></sitemap>
	<sitemap><loc>https://example.com/sitemap2.xml</loc></sitemap>
</sitemapindex>`)

	// nested sitemaps
	mockClient.AddResponse("https://example.com/sitemap1.xml", 200, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url><loc>https://example.com/page1</loc></url>
	<url><loc>https://example.com/page2</loc></url>
</urlset>`)

	mockClient.AddResponse("https://example.com/sitemap2.xml", 200, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url><loc>https://example.com/page3</loc></url>
	<url><loc>https://example.com/page4</loc></url>
</urlset>`)

	// Home page
	mockClient.AddResponse("https://example.com", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Home</title></head>
		<body><h1>Home</h1></body>
		</html>
	`)

	// Pages from sitemaps
	for i := 1; i <= 4; i++ {
		url := fmt.Sprintf("https://example.com/page%d", i)
		mockClient.AddResponse(url, 200, fmt.Sprintf(`
			<!DOCTYPE html>
			<html>
			<head><title>Page %d</title></head>
			<body><h1>Page %d</h1></body>
			</html>
		`, i, i))
	}

	crawler := NewCrawler(
		WithHTTPClient(mockClient),
		WithMaxDepth(2),
		WithRespectRobots(true),
	)

	ctx := context.Background()
	result := crawler.Crawl(ctx, "https://example.com")

	// Verify sitemap URLs were discovered from both nested sitemaps
	if len(result.SitemapURLs) != 4 {
		t.Errorf("Expected 4 sitemap URLs, got %d", len(result.SitemapURLs))
	}

	// Verify URLs from all sitemaps are crawled
	if result.Statistics.TotalURLs < 5 { // Home + 4 sitemap pages
		t.Errorf("Expected at least 5 crawled URLs, got %d", result.Statistics.TotalURLs)
	}
}

func TestCrawler_Crawl_SitemapDomainFiltering(t *testing.T) {
	mockClient := NewMockHTTPClient()

	// robots.txt with sitemap reference
	mockClient.AddResponse("https://example.com/robots.txt", 200, `User-agent: *
Sitemap: https://example.com/sitemap.xml`)

	// sitemap.xml with URLs from different domains
	mockClient.AddResponse("https://example.com/sitemap.xml", 200, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url><loc>https://example.com/page1</loc></url>
	<url><loc>https://external.com/page2</loc></url>
	<url><loc>https://example.com/page3</loc></url>
</urlset>`)

	// Home page
	mockClient.AddResponse("https://example.com", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Home</title></head>
		<body><h1>Home</h1></body>
		</html>
	`)

	// Same-domain pages
	mockClient.AddResponse("https://example.com/page1", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Page 1</title></head>
		<body><h1>Page 1</h1></body>
		</html>
	`)
	mockClient.AddResponse("https://example.com/page3", 200, `
		<!DOCTYPE html>
		<html>
		<head><title>Page 3</title></head>
		<body><h1>Page 3</h1></body>
		</html>
	`)

	crawler := NewCrawler(
		WithHTTPClient(mockClient),
		WithMaxDepth(2),
		WithRespectRobots(true),
	)

	ctx := context.Background()
	result := crawler.Crawl(ctx, "https://example.com")

	// Verify only same-domain URLs are included in sitemap results
	// Should be 2 URLs (page1 and page3), NOT page2 from external.com
	if len(result.SitemapURLs) != 2 {
		t.Errorf("Expected 2 sitemap URLs (domain filtered), got %d", len(result.SitemapURLs))
	}

	// Verify external URL is not in the sitemap results
	for _, url := range result.SitemapURLs {
		if strings.Contains(url, "external.com") {
			t.Error("External domain URL should not be in sitemap results")
		}
	}

	// Verify only same-domain pages are crawled
	for _, url := range result.CrawledURLs {
		if strings.Contains(url, "external.com") {
			t.Error("External domain URL should not be crawled from sitemap")
		}
	}
}
