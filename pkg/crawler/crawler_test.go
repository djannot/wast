package crawler

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// MockHTTPClient implements the HTTPClient interface for testing.
type MockHTTPClient struct {
	Responses map[string]*http.Response
	Errors    map[string]error
	Requests  []*http.Request
}

// NewMockHTTPClient creates a new MockHTTPClient.
func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{
		Responses: make(map[string]*http.Response),
		Errors:    make(map[string]error),
		Requests:  make([]*http.Request, 0),
	}
}

// AddResponse adds a mock response for a URL.
func (m *MockHTTPClient) AddResponse(url string, statusCode int, body string) {
	m.Responses[url] = &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// AddError adds a mock error for a URL.
func (m *MockHTTPClient) AddError(url string, err error) {
	m.Errors[url] = err
}

// Do performs the mock HTTP request.
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.Requests = append(m.Requests, req)
	url := req.URL.String()

	if err, ok := m.Errors[url]; ok {
		return nil, err
	}

	if resp, ok := m.Responses[url]; ok {
		// Create a fresh body for each request (since bodies can only be read once)
		if originalResp, exists := m.Responses[url]; exists {
			body, _ := io.ReadAll(originalResp.Body)
			resp.Body = io.NopCloser(strings.NewReader(string(body)))
			// Reset the original response body for future calls
			m.Responses[url].Body = io.NopCloser(strings.NewReader(string(body)))
		}
		return resp, nil
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
