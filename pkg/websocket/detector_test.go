package websocket

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/crawler"
)

// mockHTTPClient implements HTTPClient for testing.
type mockHTTPClient struct {
	responses map[string]*http.Response
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if resp, ok := m.responses[req.URL.String()]; ok {
		return resp, nil
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func newMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestNewDetector(t *testing.T) {
	tests := []struct {
		name string
		opts []DetectorOption
	}{
		{
			name: "default detector",
			opts: nil,
		},
		{
			name: "with custom options",
			opts: []DetectorOption{
				WithDetectorUserAgent("TestAgent/1.0"),
				WithDetectorTimeout(10 * time.Second),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewDetector(tt.opts...)
			if detector == nil {
				t.Fatal("NewDetector returned nil")
			}
			if detector.client == nil {
				t.Error("detector.client is nil")
			}
			if detector.userAgent == "" {
				t.Error("detector.userAgent is empty")
			}
		})
	}
}

func TestDetectFromContent(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name          string
		content       string
		sourcePage    string
		wantEndpoints int
		wantSecure    int
		wantInsecure  int
	}{
		{
			name:          "detect new WebSocket with ws://",
			content:       `new WebSocket("ws://example.com/socket")`,
			sourcePage:    "https://example.com",
			wantEndpoints: 1,
			wantSecure:    0,
			wantInsecure:  1,
		},
		{
			name:          "detect new WebSocket with wss://",
			content:       `new WebSocket("wss://example.com/socket")`,
			sourcePage:    "https://example.com",
			wantEndpoints: 1,
			wantSecure:    1,
			wantInsecure:  0,
		},
		{
			name: "detect multiple WebSocket endpoints",
			content: `
				const ws1 = new WebSocket("ws://example.com/chat");
				const ws2 = new WebSocket("wss://example.com/notifications");
			`,
			sourcePage:    "https://example.com",
			wantEndpoints: 2,
			wantSecure:    1,
			wantInsecure:  1,
		},
		{
			name:          "detect URL pattern ws://",
			content:       `const url = "ws://example.com/api/websocket";`,
			sourcePage:    "https://example.com",
			wantEndpoints: 1,
			wantSecure:    0,
			wantInsecure:  1,
		},
		{
			name:          "detect URL pattern wss://",
			content:       `const endpoint = "wss://secure.example.com/stream";`,
			sourcePage:    "https://example.com",
			wantEndpoints: 1,
			wantSecure:    1,
			wantInsecure:  0,
		},
		{
			name:          "no WebSocket endpoints",
			content:       `const url = "https://example.com/api";`,
			sourcePage:    "https://example.com",
			wantEndpoints: 0,
			wantSecure:    0,
			wantInsecure:  0,
		},
		{
			name: "complex JavaScript with WebSocket",
			content: `
				function connectWebSocket() {
					const socket = new WebSocket('wss://example.com/realtime');
					socket.onopen = function() {
						console.log('Connected');
					};
				}
			`,
			sourcePage:    "https://example.com",
			wantEndpoints: 1,
			wantSecure:    1,
			wantInsecure:  0,
		},
		{
			name: "WebSocket with protocol",
			content: `
				new WebSocket("wss://example.com/socket");
				headers['Sec-WebSocket-Protocol']: 'chat, superchat'
			`,
			sourcePage:    "https://example.com",
			wantEndpoints: 1,
			wantSecure:    1,
			wantInsecure:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoints := detector.DetectFromContent(tt.content, tt.sourcePage)

			if len(endpoints) != tt.wantEndpoints {
				t.Errorf("got %d endpoints, want %d", len(endpoints), tt.wantEndpoints)
			}

			secureCount := 0
			insecureCount := 0
			for _, ep := range endpoints {
				if ep.IsSecure {
					secureCount++
				} else {
					insecureCount++
				}

				if ep.SourcePage != tt.sourcePage {
					t.Errorf("endpoint source page = %q, want %q", ep.SourcePage, tt.sourcePage)
				}

				if !strings.HasPrefix(ep.URL, "ws://") && !strings.HasPrefix(ep.URL, "wss://") {
					t.Errorf("invalid WebSocket URL: %s", ep.URL)
				}
			}

			if secureCount != tt.wantSecure {
				t.Errorf("got %d secure endpoints, want %d", secureCount, tt.wantSecure)
			}

			if insecureCount != tt.wantInsecure {
				t.Errorf("got %d insecure endpoints, want %d", insecureCount, tt.wantInsecure)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	// Create mock HTTP client with responses
	mockClient := &mockHTTPClient{
		responses: map[string]*http.Response{
			"https://example.com/app.js": newMockResponse(http.StatusOK,
				`new WebSocket("ws://example.com/socket")`),
			"https://example.com/secure.js": newMockResponse(http.StatusOK,
				`new WebSocket("wss://example.com/secure-socket")`),
			"https://example.com/page1": newMockResponse(http.StatusOK,
				`<script>const ws = new WebSocket("ws://example.com/chat");</script>`),
			"https://example.com/page2": newMockResponse(http.StatusOK,
				`<script>const ws = new WebSocket("wss://example.com/notifications");</script>`),
		},
	}

	detector := NewDetector(WithDetectorHTTPClient(mockClient))

	crawlResult := &crawler.CrawlResult{
		Target: "https://example.com",
		CrawledURLs: []string{
			"https://example.com/page1",
			"https://example.com/page2",
		},
		Resources: []crawler.ResourceInfo{
			{
				URL:  "https://example.com/app.js",
				Type: "javascript",
				Page: "https://example.com",
			},
			{
				URL:  "https://example.com/secure.js",
				Type: "script",
				Page: "https://example.com/page1",
			},
		},
	}

	ctx := context.Background()
	result := detector.Detect(ctx, crawlResult)

	if result == nil {
		t.Fatal("Detect returned nil")
	}

	if result.Target != crawlResult.Target {
		t.Errorf("target = %q, want %q", result.Target, crawlResult.Target)
	}

	// Should detect endpoints from both JavaScript resources and HTML pages
	if len(result.Endpoints) == 0 {
		t.Error("no endpoints detected")
	}

	// Check statistics
	if result.Statistics.TotalEndpoints != len(result.Endpoints) {
		t.Errorf("TotalEndpoints = %d, want %d", result.Statistics.TotalEndpoints, len(result.Endpoints))
	}

	if result.Statistics.PagesScanned == 0 {
		t.Error("PagesScanned should be > 0")
	}

	// Verify secure and insecure counts
	expectedSecure := 0
	expectedInsecure := 0
	for _, ep := range result.Endpoints {
		if ep.IsSecure {
			expectedSecure++
		} else {
			expectedInsecure++
		}
	}

	if result.Statistics.SecureEndpoints != expectedSecure {
		t.Errorf("SecureEndpoints = %d, want %d", result.Statistics.SecureEndpoints, expectedSecure)
	}

	if result.Statistics.InsecureEndpoints != expectedInsecure {
		t.Errorf("InsecureEndpoints = %d, want %d", result.Statistics.InsecureEndpoints, expectedInsecure)
	}
}

func TestDetectWithEmptyCrawlResult(t *testing.T) {
	detector := NewDetector()

	crawlResult := &crawler.CrawlResult{
		Target:      "https://example.com",
		CrawledURLs: []string{},
		Resources:   []crawler.ResourceInfo{},
	}

	ctx := context.Background()
	result := detector.Detect(ctx, crawlResult)

	if result == nil {
		t.Fatal("Detect returned nil")
	}

	if len(result.Endpoints) != 0 {
		t.Errorf("expected 0 endpoints, got %d", len(result.Endpoints))
	}

	if result.Statistics.TotalEndpoints != 0 {
		t.Errorf("TotalEndpoints = %d, want 0", result.Statistics.TotalEndpoints)
	}
}

func TestDetectDeduplication(t *testing.T) {
	// Test that duplicate endpoints are not added twice
	mockClient := &mockHTTPClient{
		responses: map[string]*http.Response{
			"https://example.com/page1": newMockResponse(http.StatusOK,
				`<script>new WebSocket("ws://example.com/socket");</script>`),
			"https://example.com/page2": newMockResponse(http.StatusOK,
				`<script>new WebSocket("ws://example.com/socket");</script>`),
		},
	}

	detector := NewDetector(WithDetectorHTTPClient(mockClient))

	crawlResult := &crawler.CrawlResult{
		Target: "https://example.com",
		CrawledURLs: []string{
			"https://example.com/page1",
			"https://example.com/page2",
		},
	}

	ctx := context.Background()
	result := detector.Detect(ctx, crawlResult)

	// Should detect the same endpoint from both pages but deduplicate
	// Actually, deduplication is based on URL + SourcePage, so we should get 2
	if len(result.Endpoints) != 2 {
		t.Errorf("expected 2 endpoints (same URL from different pages), got %d", len(result.Endpoints))
	}
}

func TestDetectInJavaScript(t *testing.T) {
	mockClient := &mockHTTPClient{
		responses: map[string]*http.Response{
			"https://example.com/test.js": newMockResponse(http.StatusOK,
				`const socket = new WebSocket("wss://example.com/api");`),
		},
	}

	detector := NewDetector(WithDetectorHTTPClient(mockClient))

	ctx := context.Background()
	endpoints := detector.detectInJavaScript(ctx, "https://example.com/test.js", "https://example.com")

	if len(endpoints) == 0 {
		t.Fatal("no endpoints detected from JavaScript")
	}

	if endpoints[0].URL != "wss://example.com/api" {
		t.Errorf("URL = %q, want %q", endpoints[0].URL, "wss://example.com/api")
	}

	if endpoints[0].DetectionMethod != "javascript" && endpoints[0].DetectionMethod != "url_pattern" {
		t.Errorf("unexpected detection method: %s", endpoints[0].DetectionMethod)
	}
}

func TestDetectInPage(t *testing.T) {
	mockClient := &mockHTTPClient{
		responses: map[string]*http.Response{
			"https://example.com/page": newMockResponse(http.StatusOK, `
				<html>
				<body>
					<script>
						var ws = new WebSocket("ws://example.com/live");
					</script>
				</body>
				</html>
			`),
		},
	}

	detector := NewDetector(WithDetectorHTTPClient(mockClient))

	ctx := context.Background()
	endpoints := detector.detectInPage(ctx, "https://example.com/page")

	if len(endpoints) == 0 {
		t.Fatal("no endpoints detected from page")
	}

	if endpoints[0].SourcePage != "https://example.com/page" {
		t.Errorf("SourcePage = %q, want %q", endpoints[0].SourcePage, "https://example.com/page")
	}
}

func TestDetect404Response(t *testing.T) {
	mockClient := &mockHTTPClient{
		responses: map[string]*http.Response{
			"https://example.com/missing.js": newMockResponse(http.StatusNotFound, ""),
		},
	}

	detector := NewDetector(WithDetectorHTTPClient(mockClient))

	ctx := context.Background()
	endpoints := detector.detectInJavaScript(ctx, "https://example.com/missing.js", "https://example.com")

	// Should return empty slice for 404 responses
	if len(endpoints) != 0 {
		t.Errorf("expected 0 endpoints for 404 response, got %d", len(endpoints))
	}
}

func TestExtractWebSocketURLsEdgeCases(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name          string
		content       string
		wantEndpoints int
	}{
		{
			name:          "single quotes",
			content:       `new WebSocket('ws://example.com/socket')`,
			wantEndpoints: 1,
		},
		{
			name:          "double quotes",
			content:       `new WebSocket("ws://example.com/socket")`,
			wantEndpoints: 1,
		},
		{
			name:          "with query parameters",
			content:       `new WebSocket("wss://example.com/socket?token=abc123")`,
			wantEndpoints: 1,
		},
		{
			name:          "with path segments",
			content:       `new WebSocket("ws://example.com/api/v1/websocket")`,
			wantEndpoints: 1,
		},
		{
			name:          "whitespace variations",
			content:       `new   WebSocket  (  "ws://example.com/socket"  )`,
			wantEndpoints: 1,
		},
		{
			name:          "no WebSocket",
			content:       `const http = new XMLHttpRequest();`,
			wantEndpoints: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoints := detector.DetectFromContent(tt.content, "test-page")
			if len(endpoints) != tt.wantEndpoints {
				t.Errorf("got %d endpoints, want %d", len(endpoints), tt.wantEndpoints)
			}
		})
	}
}

func TestWebSocketEndpointFields(t *testing.T) {
	detector := NewDetector()

	content := `new WebSocket("wss://example.com/socket")`
	endpoints := detector.DetectFromContent(content, "https://example.com/page")

	if len(endpoints) == 0 {
		t.Fatal("no endpoints detected")
	}

	ep := endpoints[0]

	if ep.URL != "wss://example.com/socket" {
		t.Errorf("URL = %q, want %q", ep.URL, "wss://example.com/socket")
	}

	if ep.SourcePage != "https://example.com/page" {
		t.Errorf("SourcePage = %q, want %q", ep.SourcePage, "https://example.com/page")
	}

	if !ep.IsSecure {
		t.Error("IsSecure = false, want true for wss://")
	}

	if ep.DetectionMethod == "" {
		t.Error("DetectionMethod is empty")
	}

	if ep.Context == "" {
		t.Error("Context is empty")
	}
}

func TestDetectorOptions(t *testing.T) {
	mockClient := &mockHTTPClient{
		responses: map[string]*http.Response{},
	}

	detector := NewDetector(
		WithDetectorHTTPClient(mockClient),
		WithDetectorUserAgent("TestAgent"),
		WithDetectorTimeout(5*time.Second),
		WithDetectorAuth(&auth.AuthConfig{}),
		WithDetectorRateLimiter(nil),
		WithDetectorTracer(nil),
	)

	if detector.client != mockClient {
		t.Error("client not set correctly")
	}

	if detector.userAgent != "TestAgent" {
		t.Errorf("userAgent = %q, want %q", detector.userAgent, "TestAgent")
	}

	if detector.timeout != 5*time.Second {
		t.Errorf("timeout = %v, want %v", detector.timeout, 5*time.Second)
	}
}

func TestDefaultHTTPClient(t *testing.T) {
	client := NewDefaultHTTPClient(10 * time.Second)
	if client == nil {
		t.Fatal("NewDefaultHTTPClient returned nil")
	}
	if client.client == nil {
		t.Error("client.client is nil")
	}
}

func TestDetectionResultStatistics(t *testing.T) {
	result := &DetectionResult{
		Target: "https://example.com",
		Endpoints: []WebSocketEndpoint{
			{URL: "ws://example.com/1", IsSecure: false},
			{URL: "wss://example.com/2", IsSecure: true},
			{URL: "ws://example.com/3", IsSecure: false},
		},
		Statistics: DetectionStatistics{
			TotalEndpoints:    3,
			SecureEndpoints:   1,
			InsecureEndpoints: 2,
			PagesScanned:      5,
		},
	}

	if result.Statistics.TotalEndpoints != 3 {
		t.Errorf("TotalEndpoints = %d, want 3", result.Statistics.TotalEndpoints)
	}

	if result.Statistics.SecureEndpoints != 1 {
		t.Errorf("SecureEndpoints = %d, want 1", result.Statistics.SecureEndpoints)
	}

	if result.Statistics.InsecureEndpoints != 2 {
		t.Errorf("InsecureEndpoints = %d, want 2", result.Statistics.InsecureEndpoints)
	}
}
