package crawler

import (
	"context"
	"testing"
	"time"
)

func TestDefaultHeadlessConfig(t *testing.T) {
	config := DefaultHeadlessConfig()

	if config == nil {
		t.Fatal("DefaultHeadlessConfig returned nil")
	}

	if config.Enabled {
		t.Error("Default config should have Enabled=false")
	}

	if config.Timeout != DefaultHeadlessTimeout {
		t.Errorf("Expected timeout %v, got %v", DefaultHeadlessTimeout, config.Timeout)
	}

	if config.PoolSize != DefaultPoolSize {
		t.Errorf("Expected pool size %d, got %d", DefaultPoolSize, config.PoolSize)
	}

	if !config.JavaScriptEnabled {
		t.Error("JavaScript should be enabled by default")
	}

	if !config.DisableImages {
		t.Error("Images should be disabled by default for performance")
	}
}

func TestDetectJavaScriptRendering_ReactApp(t *testing.T) {
	reactHTML := `<!DOCTYPE html>
<html>
<head>
    <title>React App</title>
    <script src="/static/js/react.js"></script>
    <script src="/static/js/react-dom.js"></script>
</head>
<body>
    <div id="root"></div>
    <script src="/static/js/main.js"></script>
</body>
</html>`

	if !DetectJavaScriptRendering(reactHTML) {
		t.Error("Expected to detect React app as JavaScript-rendered")
	}
}

func TestDetectJavaScriptRendering_VueApp(t *testing.T) {
	vueHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Vue App</title>
    <script src="https://cdn.jsdelivr.net/npm/vue@3"></script>
</head>
<body>
    <div id="app"></div>
</body>
</html>`

	if !DetectJavaScriptRendering(vueHTML) {
		t.Error("Expected to detect Vue app as JavaScript-rendered")
	}
}

func TestDetectJavaScriptRendering_AngularApp(t *testing.T) {
	// Angular detection works via "angular" keyword in scripts or ng-app
	angularHTML := `<!DOCTYPE html>
<html ng-app="myApp">
<head>
    <script src="https://ajax.googleapis.com/ajax/libs/angular/1.8.2/angular.min.js"></script>
</head>
<body>
    <div ng-controller="MainCtrl">
        <p>{{ message }}</p>
    </div>
</body>
</html>`

	if !DetectJavaScriptRendering(angularHTML) {
		t.Error("Expected to detect Angular app as JavaScript-rendered")
	}
}

func TestDetectJavaScriptRendering_NextJS(t *testing.T) {
	nextHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Next.js App</title>
</head>
<body>
    <div id="__next">
        <p>Loading...</p>
    </div>
    <script src="/_next/static/chunks/webpack.js"></script>
</body>
</html>`

	if !DetectJavaScriptRendering(nextHTML) {
		t.Error("Expected to detect Next.js app as JavaScript-rendered")
	}
}

func TestDetectJavaScriptRendering_StaticHTML(t *testing.T) {
	staticHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Static Page</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <header>
        <h1>Welcome to My Site</h1>
    </header>
    <main>
        <article>
            <h2>Article Title</h2>
            <p>This is a static HTML page with lots of content already rendered on the server.</p>
            <p>It has multiple paragraphs and sections.</p>
        </article>
        <aside>
            <h3>Sidebar</h3>
            <ul>
                <li>Link 1</li>
                <li>Link 2</li>
                <li>Link 3</li>
            </ul>
        </aside>
    </main>
    <footer>
        <p>Copyright 2024</p>
    </footer>
</body>
</html>`

	if DetectJavaScriptRendering(staticHTML) {
		t.Error("Expected to NOT detect static HTML as JavaScript-rendered")
	}
}

func TestDetectJavaScriptRendering_EmptyBodyWithFramework(t *testing.T) {
	emptyWithReact := `<!DOCTYPE html>
<html>
<head>
    <script src="react.js"></script>
</head>
<body>
    <div id="root"></div>
</body>
</html>`

	if !DetectJavaScriptRendering(emptyWithReact) {
		t.Error("Expected to detect empty body with framework as JavaScript-rendered")
	}
}

func TestDetectJavaScriptRendering_MinimalContent(t *testing.T) {
	minimalHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Simple Page</title>
</head>
<body>
    <h1>Hello</h1>
</body>
</html>`

	if DetectJavaScriptRendering(minimalHTML) {
		t.Error("Expected to NOT detect minimal static content as JavaScript-rendered")
	}
}

func TestRemoveScriptAndStyleTags(t *testing.T) {
	html := `<html>
<head>
    <style>body { color: red; }</style>
    <script>console.log('test');</script>
</head>
<body>
    <p>Content</p>
    <script>alert('hi');</script>
</body>
</html>`

	result := removeScriptAndStyleTags(html)

	if contains(result, "<script>") || contains(result, "</script>") {
		t.Error("Script tags were not removed")
	}

	if contains(result, "<style>") || contains(result, "</style>") {
		t.Error("Style tags were not removed")
	}

	if !contains(result, "<p>Content</p>") {
		t.Error("Content was incorrectly removed")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestHeadlessBrowserOptions(t *testing.T) {
	tests := []struct {
		name   string
		option Option
		check  func(*Crawler) bool
	}{
		{
			name:   "WithHeadless enables headless mode",
			option: WithHeadless(true),
			check: func(c *Crawler) bool {
				return c.headlessConfig != nil && c.headlessConfig.Enabled
			},
		},
		{
			name:   "WithHeadlessTimeout sets timeout",
			option: WithHeadlessTimeout(60 * time.Second),
			check: func(c *Crawler) bool {
				return c.headlessConfig != nil && c.headlessConfig.Timeout == 60*time.Second
			},
		},
		{
			name:   "WithWaitForSelector sets selector",
			option: WithWaitForSelector("#content"),
			check: func(c *Crawler) bool {
				return c.headlessConfig != nil && c.headlessConfig.WaitForSelector == "#content"
			},
		},
		{
			name:   "WithHeadlessPoolSize sets pool size",
			option: WithHeadlessPoolSize(4),
			check: func(c *Crawler) bool {
				return c.headlessConfig != nil && c.headlessConfig.PoolSize == 4
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCrawler(tt.option)
			if !tt.check(c) {
				t.Errorf("Option %s did not apply correctly", tt.name)
			}
		})
	}
}

func TestHeadlessConfigOption(t *testing.T) {
	config := &HeadlessConfig{
		Enabled:         true,
		Timeout:         45 * time.Second,
		NetworkIdleTime: 3 * time.Second,
		PoolSize:        3,
		DisableImages:   false,
	}

	c := NewCrawler(WithHeadlessConfig(config))

	if c.headlessConfig != config {
		t.Error("WithHeadlessConfig did not set config correctly")
	}

	if c.headlessConfig.Timeout != 45*time.Second {
		t.Errorf("Expected timeout 45s, got %v", c.headlessConfig.Timeout)
	}

	if c.headlessConfig.PoolSize != 3 {
		t.Errorf("Expected pool size 3, got %d", c.headlessConfig.PoolSize)
	}
}

func TestCrawlerWithHeadlessDisabled(t *testing.T) {
	c := NewCrawler(WithHeadless(false))

	// Headless browser should not be initialized when disabled
	if c.headlessBrowser != nil {
		t.Error("Headless browser should not be initialized when disabled")
	}
}

// TestHeadlessBrowserIntegration tests the integration with actual HTML fetching
// This test uses the mock HTTP client to avoid external dependencies
func TestHeadlessBrowserIntegration(t *testing.T) {
	// Create a mock HTTP client using the existing structure
	mockClient := NewMockHTTPClient()
	mockClient.AddResponse("https://spa.example.com", 200, `<!DOCTYPE html>
<html>
<head><script src="react.js"></script></head>
<body><div id="root"></div></body>
</html>`)

	// Create crawler with headless disabled (to test HTTP-only path)
	c := NewCrawler(
		WithHTTPClient(mockClient),
		WithHeadless(false),
	)

	ctx := context.Background()
	content, err := c.fetchPage(ctx, "https://spa.example.com")

	if err != nil {
		t.Fatalf("Failed to fetch page: %v", err)
	}

	if !contains(content, "id=\"root\"") {
		t.Error("Expected to find root div in content")
	}
}

func TestDetectJavaScriptRendering_MultipleFrameworkMarkers(t *testing.T) {
	// Page with multiple framework indicators
	multiFramework := `<!DOCTYPE html>
<html>
<head>
    <script src="react.js"></script>
    <script src="vue.js"></script>
</head>
<body>
    <div id="app">
        <p>Some content</p>
    </div>
</body>
</html>`

	if !DetectJavaScriptRendering(multiFramework) {
		t.Error("Expected to detect page with multiple framework markers")
	}
}

func TestDetectJavaScriptRendering_DataReactRoot(t *testing.T) {
	reactRootHTML := `<!DOCTYPE html>
<html>
<body>
    <div id="root" data-reactroot="">
        <div>Loading...</div>
    </div>
</body>
</html>`

	if !DetectJavaScriptRendering(reactRootHTML) {
		t.Error("Expected to detect data-reactroot attribute")
	}
}

func TestDetectJavaScriptRendering_ServerRendered(t *testing.T) {
	serverRendered := `<!DOCTYPE html>
<html>
<body>
    <div id="app" data-server-rendered="true">
        <p>Server-rendered content</p>
    </div>
</body>
</html>`

	if !DetectJavaScriptRendering(serverRendered) {
		t.Error("Expected to detect data-server-rendered attribute")
	}
}

func TestHeadlessPoolSize_InvalidValue(t *testing.T) {
	// Test that invalid pool size (0 or negative) is ignored
	c := NewCrawler(WithHeadlessPoolSize(0))

	// Should use default pool size
	if c.headlessConfig == nil {
		// Pool size of 0 should not create a config
		return
	}

	// If config was created, it should still have default value
	if c.headlessConfig.PoolSize == 0 {
		t.Error("Pool size should not be set to 0")
	}
}

func TestHeadlessConfig_UserAgent(t *testing.T) {
	customUA := "CustomBot/1.0"
	config := DefaultHeadlessConfig()
	config.Enabled = true
	config.UserAgent = customUA

	c := NewCrawler(
		WithUserAgent(customUA),
		WithHeadlessConfig(config),
	)

	if c.headlessConfig.UserAgent != customUA {
		t.Errorf("Expected user agent %s, got %s", customUA, c.headlessConfig.UserAgent)
	}
}
