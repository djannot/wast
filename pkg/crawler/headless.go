// Package crawler provides web crawling functionality for reconnaissance operations.
package crawler

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

const (
	// DefaultHeadlessTimeout is the default timeout for headless browser operations
	DefaultHeadlessTimeout = 30 * time.Second

	// DefaultNetworkIdleTimeout is the time to wait for network idle
	DefaultNetworkIdleTimeout = 2 * time.Second

	// DefaultPoolSize is the default size of the browser pool
	DefaultPoolSize = 2

	// DefaultMaxMemoryMB is the default memory limit per browser instance in MB
	DefaultMaxMemoryMB = 512
)

// HeadlessConfig contains configuration for headless browser operations.
type HeadlessConfig struct {
	Enabled           bool          // Whether headless mode is enabled
	Timeout           time.Duration // Timeout for page load operations
	NetworkIdleTime   time.Duration // Time to wait for network idle
	WaitForSelector   string        // Optional CSS selector to wait for
	PoolSize          int           // Number of browser instances to pool
	MaxMemoryMB       int           // Maximum memory per browser instance
	DisableImages     bool          // Whether to disable image loading
	UserAgent         string        // User agent override for headless mode
	JavaScriptEnabled bool          // Whether to enable JavaScript (default true)
}

// DefaultHeadlessConfig returns a default headless configuration.
func DefaultHeadlessConfig() *HeadlessConfig {
	return &HeadlessConfig{
		Enabled:           false,
		Timeout:           DefaultHeadlessTimeout,
		NetworkIdleTime:   DefaultNetworkIdleTimeout,
		PoolSize:          DefaultPoolSize,
		MaxMemoryMB:       DefaultMaxMemoryMB,
		DisableImages:     true, // Disable images by default for performance
		JavaScriptEnabled: true,
	}
}

// browserPool manages a pool of browser contexts for concurrent crawling.
type browserPool struct {
	config   *HeadlessConfig
	contexts chan context.Context
	cancels  []context.CancelFunc
	mu       sync.Mutex
}

// newBrowserPool creates a new browser pool with the specified configuration.
func newBrowserPool(config *HeadlessConfig) (*browserPool, error) {
	pool := &browserPool{
		config:   config,
		contexts: make(chan context.Context, config.PoolSize),
		cancels:  make([]context.CancelFunc, 0, config.PoolSize),
	}

	// Create browser instances
	for i := 0; i < config.PoolSize; i++ {
		if err := pool.addBrowser(); err != nil {
			pool.Close()
			return nil, fmt.Errorf("failed to create browser instance %d: %w", i, err)
		}
	}

	return pool, nil
}

// addBrowser adds a new browser instance to the pool.
func (p *browserPool) addBrowser() error {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.DisableGPU,
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
	)

	// Configure user agent if specified
	if p.config.UserAgent != "" {
		opts = append(opts, chromedp.UserAgent(p.config.UserAgent))
	}

	// Disable images if configured
	if p.config.DisableImages {
		opts = append(opts, chromedp.Flag("blink-settings", "imagesEnabled=false"))
	}

	// Create allocator context
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// Create browser context
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)

	// Combine cancel functions
	cancel := func() {
		browserCancel()
		allocCancel()
	}

	p.mu.Lock()
	p.cancels = append(p.cancels, cancel)
	p.mu.Unlock()

	// Add to pool
	p.contexts <- browserCtx

	return nil
}

// Get retrieves a browser context from the pool.
func (p *browserPool) Get() context.Context {
	return <-p.contexts
}

// Put returns a browser context to the pool.
func (p *browserPool) Put(ctx context.Context) {
	select {
	case p.contexts <- ctx:
	default:
		// Pool is full, this shouldn't happen but handle gracefully
	}
}

// Close closes all browser instances in the pool.
func (p *browserPool) Close() {
	close(p.contexts)
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, cancel := range p.cancels {
		cancel()
	}
}

// HeadlessBrowser provides headless browser functionality for JavaScript rendering.
type HeadlessBrowser struct {
	config *HeadlessConfig
	pool   *browserPool
}

// NewHeadlessBrowser creates a new headless browser instance with the given configuration.
func NewHeadlessBrowser(config *HeadlessConfig) (*HeadlessBrowser, error) {
	if config == nil {
		config = DefaultHeadlessConfig()
	}

	pool, err := newBrowserPool(config)
	if err != nil {
		return nil, err
	}

	return &HeadlessBrowser{
		config: config,
		pool:   pool,
	}, nil
}

// FetchPage fetches a page using the headless browser and returns the rendered HTML.
func (hb *HeadlessBrowser) FetchPage(ctx context.Context, url string) (string, error) {
	// Get a browser context from the pool
	browserCtx := hb.pool.Get()
	defer hb.pool.Put(browserCtx)

	// Create a timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, hb.config.Timeout)
	defer cancel()

	// Combine contexts
	ctx = timeoutCtx

	var htmlContent string

	// Enable network events for monitoring
	chromedp.ListenTarget(browserCtx, func(ev interface{}) {
		// Monitor network events for future use (e.g., detecting when loading finished)
		if _, ok := ev.(*network.EventLoadingFinished); ok {
			// Network activity detected
		}
	})

	// Navigate and wait for page to load
	tasks := chromedp.Tasks{
		network.Enable(),
		chromedp.Navigate(url),
	}

	// Wait for network idle if configured
	if hb.config.NetworkIdleTime > 0 {
		tasks = append(tasks, chromedp.ActionFunc(func(ctx context.Context) error {
			deadline := time.Now().Add(hb.config.NetworkIdleTime)
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ticker.C:
					if time.Now().After(deadline) {
						return nil
					}
				}
			}
		}))
	}

	// Wait for custom selector if specified
	if hb.config.WaitForSelector != "" {
		tasks = append(tasks, chromedp.WaitVisible(hb.config.WaitForSelector, chromedp.ByQuery))
	}

	// Get the rendered HTML
	tasks = append(tasks, chromedp.ActionFunc(func(ctx context.Context) error {
		node, err := dom.GetDocument().Do(ctx)
		if err != nil {
			return err
		}
		htmlContent, err = dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
		return err
	}))

	// Run the tasks
	if err := chromedp.Run(browserCtx, tasks); err != nil {
		return "", fmt.Errorf("headless browser error: %w", err)
	}

	return htmlContent, nil
}

// Close closes the headless browser and releases resources.
func (hb *HeadlessBrowser) Close() {
	if hb.pool != nil {
		hb.pool.Close()
	}
}

// DetectJavaScriptRendering analyzes HTML content to detect if it's likely JavaScript-rendered.
// Returns true if the page appears to use client-side rendering.
func DetectJavaScriptRendering(htmlContent string) bool {
	lowercaseHTML := strings.ToLower(htmlContent)

	// Check for common SPA framework markers
	frameworks := []string{
		"react", "reactdom",
		"vue", "vuejs",
		"angular", "ng-app", "ng-controller",
		"ember",
		"backbone",
		"next.js", "nuxt",
	}

	frameworkCount := 0
	for _, framework := range frameworks {
		if strings.Contains(lowercaseHTML, framework) {
			frameworkCount++
		}
	}

	// Check for empty or minimal body content
	// Extract body content (simple approach)
	bodyStart := strings.Index(lowercaseHTML, "<body")
	bodyEnd := strings.Index(lowercaseHTML, "</body>")

	if bodyStart != -1 && bodyEnd != -1 && bodyEnd > bodyStart {
		bodyContent := lowercaseHTML[bodyStart:bodyEnd]

		// Remove script and style tags for content analysis
		bodyContent = removeScriptAndStyleTags(bodyContent)

		// Count visible content
		visibleContent := strings.TrimSpace(bodyContent)
		visibleContent = strings.ReplaceAll(visibleContent, "\n", "")
		visibleContent = strings.ReplaceAll(visibleContent, "\t", "")
		visibleContent = strings.ReplaceAll(visibleContent, " ", "")

		// If body has very little content (less than 200 chars without tags)
		// and framework markers exist, likely JavaScript-rendered
		if len(visibleContent) < 200 && frameworkCount > 0 {
			return true
		}
	}

	// Check for root div patterns common in SPAs
	spaRootPatterns := []string{
		"id=\"root\"",
		"id=\"app\"",
		"id=\"__next\"",
		"id=\"__nuxt\"",
		"data-reactroot",
		"data-server-rendered",
	}

	for _, pattern := range spaRootPatterns {
		if strings.Contains(lowercaseHTML, pattern) {
			return true
		}
	}

	// If multiple framework markers found, likely JavaScript-heavy
	return frameworkCount >= 2
}

// removeScriptAndStyleTags removes script and style tags from HTML for content analysis.
func removeScriptAndStyleTags(html string) string {
	result := html

	// Remove script tags
	for {
		start := strings.Index(result, "<script")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "</script>")
		if end == -1 {
			break
		}
		result = result[:start] + result[start+end+9:]
	}

	// Remove style tags
	for {
		start := strings.Index(result, "<style")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "</style>")
		if end == -1 {
			break
		}
		result = result[:start] + result[start+end+8:]
	}

	return result
}
