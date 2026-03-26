// Package crawler provides web crawling functionality for reconnaissance operations.
package crawler

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/html"
)

// HTTPClient defines the interface for HTTP operations, allowing for mock implementations in tests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DefaultHTTPClient wraps the standard http.Client.
type DefaultHTTPClient struct {
	client *http.Client
}

// NewDefaultHTTPClient creates a new DefaultHTTPClient with the given timeout.
func NewDefaultHTTPClient(timeout time.Duration) *DefaultHTTPClient {
	return &DefaultHTTPClient{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Allow up to 10 redirects
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// Do performs an HTTP request.
func (c *DefaultHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

const (
	// MaxSitemapsFromRobots limits the number of sitemaps fetched from robots.txt
	MaxSitemapsFromRobots = 5

	// MaxSitemapIndexDepth limits nesting of sitemap indexes
	MaxSitemapIndexDepth = 1

	// MaxSitemapsPerIndex limits sitemaps fetched from a single index
	MaxSitemapsPerIndex = 5
)

// ProgressCallback is a function called to report progress during crawling.
type ProgressCallback func(visited int, discovered int, phase string)

// Crawler performs web crawling operations.
type Crawler struct {
	client           HTTPClient
	userAgent        string
	timeout          time.Duration
	maxDepth         int
	respectRobots    bool
	robotsData       *RobotsData
	authConfig       *auth.AuthConfig
	rateLimiter      ratelimit.Limiter
	concurrency      int
	tracer           trace.Tracer
	progressCallback ProgressCallback
}

// Option is a function that configures a Crawler.
type Option func(*Crawler)

// WithHTTPClient sets a custom HTTP client for the crawler.
func WithHTTPClient(c HTTPClient) Option {
	return func(cr *Crawler) {
		cr.client = c
	}
}

// WithUserAgent sets the user agent string for the crawler.
func WithUserAgent(ua string) Option {
	return func(cr *Crawler) {
		cr.userAgent = ua
	}
}

// WithTimeout sets the timeout for HTTP requests.
func WithTimeout(d time.Duration) Option {
	return func(cr *Crawler) {
		cr.timeout = d
	}
}

// WithMaxDepth sets the maximum crawl depth.
func WithMaxDepth(depth int) Option {
	return func(cr *Crawler) {
		cr.maxDepth = depth
	}
}

// WithRespectRobots sets whether to respect robots.txt rules.
func WithRespectRobots(respect bool) Option {
	return func(cr *Crawler) {
		cr.respectRobots = respect
	}
}

// WithAuth sets the authentication configuration for the crawler.
func WithAuth(config *auth.AuthConfig) Option {
	return func(cr *Crawler) {
		cr.authConfig = config
	}
}

// WithRateLimiter sets a rate limiter for the crawler.
func WithRateLimiter(limiter ratelimit.Limiter) Option {
	return func(cr *Crawler) {
		cr.rateLimiter = limiter
	}
}

// WithRateLimitConfig sets rate limiting from a configuration.
func WithRateLimitConfig(cfg ratelimit.Config) Option {
	return func(cr *Crawler) {
		cr.rateLimiter = ratelimit.NewLimiterFromConfig(cfg)
	}
}

// WithTracer sets the OpenTelemetry tracer for the crawler.
func WithTracer(tracer trace.Tracer) Option {
	return func(cr *Crawler) {
		cr.tracer = tracer
	}
}

// WithConcurrency sets the number of concurrent workers for crawling.
func WithConcurrency(n int) Option {
	return func(cr *Crawler) {
		if n > 0 {
			cr.concurrency = n
		}
	}
}

// WithProgressCallback sets a callback function to receive progress updates.
func WithProgressCallback(cb ProgressCallback) Option {
	return func(cr *Crawler) {
		cr.progressCallback = cb
	}
}

// NewCrawler creates a new Crawler with the given options.
func NewCrawler(opts ...Option) *Crawler {
	c := &Crawler{
		userAgent:     "WAST/1.0 (Web Application Security Testing)",
		timeout:       30 * time.Second,
		maxDepth:      3,
		respectRobots: true,
		concurrency:   5, // Default to 5 workers
	}

	for _, opt := range opts {
		opt(c)
	}

	// Create default HTTP client if not set
	if c.client == nil {
		c.client = NewDefaultHTTPClient(c.timeout)
	}

	return c
}

// queueItem represents an item in the crawl queue.
type queueItem struct {
	url   string
	depth int
}

// Crawl performs a web crawl starting from the given target URL.
func (c *Crawler) Crawl(ctx context.Context, targetURL string) *CrawlResult {
	// Create tracing span if tracer is available
	if c.tracer != nil {
		var span trace.Span
		ctx, span = c.tracer.Start(ctx, "wast.crawl")
		defer span.End()
	}

	result := &CrawlResult{
		Target:        targetURL,
		CrawledURLs:   make([]string, 0),
		InternalLinks: make([]LinkInfo, 0),
		ExternalLinks: make([]LinkInfo, 0),
		Forms:         make([]FormInfo, 0),
		Resources:     make([]ResourceInfo, 0),
		Errors:        make([]string, 0),
	}

	// Parse and validate target URL
	baseURL, err := url.Parse(targetURL)
	if err != nil {
		result.Errors = append(result.Errors, "Invalid target URL: "+err.Error())
		return result
	}

	// Ensure scheme is set
	if baseURL.Scheme == "" {
		baseURL.Scheme = "https"
		targetURL = baseURL.String()
	}

	// Fetch and parse robots.txt if respecting robots
	var sitemapURLs []string
	if c.respectRobots {
		sitemapURLs = c.fetchRobots(ctx, baseURL, result)
	}

	// Initialize visited set and tracking maps with mutex protection
	var mu sync.Mutex
	visited := make(map[string]bool)
	visited[normalizeURL(targetURL)] = true
	seenInternalLinks := make(map[string]bool)
	seenExternalLinks := make(map[string]bool)

	// Create work queue channel with large buffer to avoid blocking
	workQueue := make(chan queueItem, 1000)

	// Create context for worker cancellation
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// WaitGroup to track active workers
	var wg sync.WaitGroup

	// Track active items being processed
	var activeItems sync.WaitGroup

	// Start worker pool
	for i := 0; i < c.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.worker(workerCtx, workQueue, baseURL, &mu, visited, seenInternalLinks, seenExternalLinks, result, &activeItems)
		}()
	}

	// Enqueue initial URL
	activeItems.Add(1)
	workQueue <- queueItem{url: targetURL, depth: 0}

	// Enqueue sitemap URLs at depth 0
	for _, sitemapURL := range sitemapURLs {
		normalizedURL := normalizeURL(sitemapURL)
		mu.Lock()
		if !visited[normalizedURL] {
			visited[normalizedURL] = true
			mu.Unlock()
			activeItems.Add(1)
			workQueue <- queueItem{url: sitemapURL, depth: 0}
		} else {
			mu.Unlock()
		}
	}

	// Monitor for completion - close queue when no more work
	go func() {
		activeItems.Wait()
		close(workQueue)
	}()

	// Wait for all workers to complete
	wg.Wait()

	// Check if context was cancelled
	if ctx.Err() != nil {
		mu.Lock()
		result.Errors = append(result.Errors, "Crawl cancelled: "+ctx.Err().Error())
		mu.Unlock()
	}

	c.updateStatistics(result)
	return result
}

// worker processes items from the work queue concurrently.
func (c *Crawler) worker(ctx context.Context, workQueue chan queueItem, baseURL *url.URL,
	mu *sync.Mutex, visited, seenInternalLinks, seenExternalLinks map[string]bool, result *CrawlResult, activeItems *sync.WaitGroup) {

	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-workQueue:
			if !ok {
				return
			}

			// Process this item
			c.processItem(ctx, item, baseURL, mu, visited, seenInternalLinks, seenExternalLinks, result, activeItems, workQueue)
		}
	}
}

// processItem processes a single crawl item.
func (c *Crawler) processItem(ctx context.Context, item queueItem, baseURL *url.URL,
	mu *sync.Mutex, visited, seenInternalLinks, seenExternalLinks map[string]bool, result *CrawlResult, activeItems *sync.WaitGroup, workQueue chan queueItem) {

	// Mark this item as done when finished
	defer activeItems.Done()

	// Skip if beyond max depth
	if item.depth > c.maxDepth {
		return
	}

	// Check robots.txt
	if c.respectRobots && c.robotsData != nil {
		parsedURL, _ := url.Parse(item.url)
		if parsedURL != nil && !c.robotsData.IsAllowed(parsedURL.Path) {
			return
		}
	}

	// Fetch the page
	pageContent, err := c.fetchPage(ctx, item.url)
	if err != nil {
		mu.Lock()
		result.Errors = append(result.Errors, "Failed to fetch "+item.url+": "+err.Error())
		mu.Unlock()
		return
	}

	mu.Lock()
	result.CrawledURLs = append(result.CrawledURLs, item.url)
	if item.depth > result.Statistics.MaxDepthReached {
		result.Statistics.MaxDepthReached = item.depth
	}

	// Report progress if callback is set
	if c.progressCallback != nil {
		visited := len(result.CrawledURLs)
		discovered := len(result.InternalLinks)
		mu.Unlock()
		c.progressCallback(visited, discovered, "crawling")
		mu.Lock()
	}
	mu.Unlock()

	// Parse HTML and extract information
	links, forms, resources := c.parseHTML(pageContent, item.url, baseURL)

	// Process links
	for _, link := range links {
		linkURL, err := url.Parse(link.URL)
		if err != nil {
			continue
		}

		// Resolve relative URLs
		resolvedURL := baseURL.ResolveReference(linkURL)
		link.URL = resolvedURL.String()

		// Check if internal or external
		if isSameDomain(baseURL, resolvedURL) {
			link.External = false
			link.Depth = item.depth + 1

			normalizedURL := normalizeURL(link.URL)

			mu.Lock()
			shouldAddLink := !seenInternalLinks[normalizedURL]
			if shouldAddLink {
				seenInternalLinks[normalizedURL] = true
				result.InternalLinks = append(result.InternalLinks, link)
			}

			// Add to queue if not visited and within depth
			shouldEnqueue := !visited[normalizedURL] && item.depth < c.maxDepth
			if shouldEnqueue {
				visited[normalizedURL] = true
			}
			mu.Unlock()

			if shouldEnqueue {
				activeItems.Add(1)
				select {
				case workQueue <- queueItem{url: link.URL, depth: item.depth + 1}:
				case <-ctx.Done():
					activeItems.Done()
					return
				}
			}
		} else {
			link.External = true
			link.Depth = item.depth

			mu.Lock()
			if !seenExternalLinks[link.URL] {
				seenExternalLinks[link.URL] = true
				result.ExternalLinks = append(result.ExternalLinks, link)
			}
			mu.Unlock()
		}
	}

	// Add forms
	mu.Lock()
	pageURL, _ := url.Parse(item.url)
	for _, form := range forms {
		form.Page = item.url
		// Resolve form action URL relative to the current page (not the base target)
		if form.Action != "" && !strings.HasPrefix(form.Action, "http") {
			actionURL, err := url.Parse(form.Action)
			if err == nil {
				if pageURL != nil {
					form.Action = pageURL.ResolveReference(actionURL).String()
				} else {
					form.Action = baseURL.ResolveReference(actionURL).String()
				}
			}
		}
		// If action is empty, use the current page URL (HTML spec default)
		if form.Action == "" {
			form.Action = item.url
		}
		result.Forms = append(result.Forms, form)
	}
	mu.Unlock()

	// Add resources
	mu.Lock()
	for _, res := range resources {
		res.Page = item.url
		// Resolve resource URL
		if !strings.HasPrefix(res.URL, "http") {
			resURL, err := url.Parse(res.URL)
			if err == nil {
				res.URL = baseURL.ResolveReference(resURL).String()
			}
		}
		result.Resources = append(result.Resources, res)
	}
	mu.Unlock()
}

// fetchRobots fetches and parses robots.txt for the target domain.
// It also fetches and parses any sitemaps referenced in robots.txt.
// Returns a list of URLs discovered in sitemaps.
func (c *Crawler) fetchRobots(ctx context.Context, baseURL *url.URL, result *CrawlResult) []string {
	robotsURL, err := GetRobotsURL(baseURL.String())
	if err != nil {
		return nil
	}

	content, err := c.fetchPage(ctx, robotsURL)
	if err != nil {
		// robots.txt not found or error - that's fine, continue crawling
		return nil
	}

	c.robotsData = ParseRobots(strings.NewReader(content))
	result.RobotsDisallow = c.robotsData.Disallow

	// Process sitemaps found in robots.txt
	sitemapURLs := make([]string, 0)

	// Limit the number of sitemaps to fetch to avoid DoS
	sitemapsToFetch := c.robotsData.Sitemaps
	if len(sitemapsToFetch) > MaxSitemapsFromRobots {
		sitemapsToFetch = sitemapsToFetch[:MaxSitemapsFromRobots]
	}

	for _, sitemapURL := range sitemapsToFetch {
		urls := c.fetchAndParseSitemap(ctx, sitemapURL, baseURL)
		sitemapURLs = append(sitemapURLs, urls...)
	}

	result.SitemapURLs = sitemapURLs
	return sitemapURLs
}

// fetchAndParseSitemap fetches a sitemap and parses it for URLs.
// It handles both standard sitemaps and sitemap indexes.
// For sitemap indexes, it recursively fetches referenced sitemaps (up to a limit).
func (c *Crawler) fetchAndParseSitemap(ctx context.Context, sitemapURL string, baseURL *url.URL) []string {
	return c.fetchAndParseSitemapWithDepth(ctx, sitemapURL, baseURL, 0, MaxSitemapIndexDepth)
}

func (c *Crawler) fetchAndParseSitemapWithDepth(ctx context.Context, sitemapURL string, baseURL *url.URL, currentDepth, maxDepth int) []string {
	allURLs := make([]string, 0)

	// Fetch sitemap content
	content, err := c.fetchPage(ctx, sitemapURL)
	if err != nil {
		// Sitemap not found or error - continue without it
		return allURLs
	}

	// Parse the sitemap to determine type and extract URLs
	urlsetURLs, sitemapIndexURLs := ParseSitemapBoth(strings.NewReader(content))

	if len(sitemapIndexURLs) > 0 && currentDepth < maxDepth {
		// This is a sitemap index - fetch the referenced sitemaps
		for i, nestedURL := range sitemapIndexURLs {
			if i >= MaxSitemapsPerIndex {
				break
			}
			nestedURLs := c.fetchAndParseSitemapWithDepth(ctx, nestedURL, baseURL, currentDepth+1, maxDepth)
			allURLs = append(allURLs, nestedURLs...)
		}
	} else {
		// Regular sitemap - filter URLs by domain
		for _, urlStr := range urlsetURLs {
			parsedURL, err := url.Parse(urlStr)
			if err != nil {
				continue
			}
			// Only add URLs that are on the same domain
			if isSameDomain(baseURL, parsedURL) {
				allURLs = append(allURLs, urlStr)
			}
		}
	}

	return allURLs
}

// fetchPage fetches the content of a URL.
func (c *Crawler) fetchPage(ctx context.Context, targetURL string) (string, error) {
	// Apply rate limiting before making the request
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return "", err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// Apply authentication configuration
	if c.authConfig != nil {
		c.authConfig.ApplyToRequest(req)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Handle rate limiting (HTTP 429)
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", &httpError{statusCode: resp.StatusCode}
	}

	if resp.StatusCode != http.StatusOK {
		return "", &httpError{statusCode: resp.StatusCode}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// httpError represents an HTTP error with status code.
type httpError struct {
	statusCode int
}

func (e *httpError) Error() string {
	return http.StatusText(e.statusCode)
}

// parseHTML extracts links, forms, and resources from HTML content.
func (c *Crawler) parseHTML(content, pageURL string, baseURL *url.URL) ([]LinkInfo, []FormInfo, []ResourceInfo) {
	links := make([]LinkInfo, 0)
	forms := make([]FormInfo, 0)
	resources := make([]ResourceInfo, 0)

	doc, err := html.Parse(strings.NewReader(content))
	if err != nil {
		return links, forms, resources
	}

	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				link := extractLink(n)
				if link.URL != "" && isValidLink(link.URL) {
					links = append(links, link)
				}
			case "form":
				form := extractForm(n)
				forms = append(forms, form)
			case "script":
				res := extractScriptResource(n)
				if res.URL != "" {
					resources = append(resources, res)
				}
			case "link":
				res := extractLinkResource(n)
				if res.URL != "" {
					resources = append(resources, res)
				}
			case "img":
				res := extractImageResource(n)
				if res.URL != "" {
					resources = append(resources, res)
				}
			}
		}

		for child := n.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}

	visit(doc)
	return links, forms, resources
}

// extractLink extracts link information from an <a> tag.
func extractLink(n *html.Node) LinkInfo {
	link := LinkInfo{}
	for _, attr := range n.Attr {
		switch attr.Key {
		case "href":
			link.URL = attr.Val
		case "rel":
			link.Rel = attr.Val
		}
	}
	// Extract text content
	link.Text = extractTextContent(n)
	return link
}

// extractForm extracts form information from a <form> tag.
func extractForm(n *html.Node) FormInfo {
	form := FormInfo{
		Method: "GET", // Default method
		Fields: make([]FormFieldInfo, 0),
	}

	for _, attr := range n.Attr {
		switch attr.Key {
		case "action":
			form.Action = attr.Val
		case "method":
			form.Method = strings.ToUpper(attr.Val)
		}
	}

	// Extract form fields
	var extractFields func(*html.Node)
	extractFields = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "input", "textarea", "select":
				field := extractFormField(node)
				form.Fields = append(form.Fields, field)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			extractFields(child)
		}
	}
	extractFields(n)

	return form
}

// extractFormField extracts form field information.
func extractFormField(n *html.Node) FormFieldInfo {
	field := FormFieldInfo{
		Type: "text", // Default type for input
	}

	if n.Data == "textarea" {
		field.Type = "textarea"
	} else if n.Data == "select" {
		field.Type = "select"
	}

	for _, attr := range n.Attr {
		switch attr.Key {
		case "name":
			field.Name = attr.Val
		case "type":
			field.Type = attr.Val
		case "value":
			field.Value = attr.Val
		case "required":
			field.Required = true
		}
	}

	return field
}

// extractScriptResource extracts resource information from a <script> tag.
func extractScriptResource(n *html.Node) ResourceInfo {
	res := ResourceInfo{Type: "js"}
	for _, attr := range n.Attr {
		if attr.Key == "src" {
			res.URL = attr.Val
			break
		}
	}
	return res
}

// extractLinkResource extracts resource information from a <link> tag.
func extractLinkResource(n *html.Node) ResourceInfo {
	res := ResourceInfo{}
	for _, attr := range n.Attr {
		switch attr.Key {
		case "href":
			res.URL = attr.Val
		case "rel":
			if attr.Val == "stylesheet" {
				res.Type = "css"
			} else if attr.Val == "icon" || attr.Val == "shortcut icon" {
				res.Type = "icon"
			} else {
				res.Type = attr.Val
			}
		}
	}
	return res
}

// extractImageResource extracts resource information from an <img> tag.
func extractImageResource(n *html.Node) ResourceInfo {
	res := ResourceInfo{Type: "image"}
	for _, attr := range n.Attr {
		if attr.Key == "src" {
			res.URL = attr.Val
			break
		}
	}
	return res
}

// extractTextContent extracts text content from an HTML node.
func extractTextContent(n *html.Node) string {
	var text strings.Builder
	var extract func(*html.Node)
	extract = func(node *html.Node) {
		if node.Type == html.TextNode {
			text.WriteString(strings.TrimSpace(node.Data))
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			extract(child)
		}
	}
	extract(n)
	return strings.TrimSpace(text.String())
}

// isSameDomain checks if two URLs are on the same domain.
func isSameDomain(base, target *url.URL) bool {
	return strings.EqualFold(base.Host, target.Host)
}

// normalizeURL normalizes a URL for comparison (removes fragment, trailing slash).
func normalizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Remove fragment
	parsed.Fragment = ""

	// Remove trailing slash from path (but keep root /)
	if len(parsed.Path) > 1 {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	}

	return parsed.String()
}

// isValidLink checks if a link URL is valid for crawling.
func isValidLink(link string) bool {
	// Skip empty links
	if link == "" {
		return false
	}

	// Skip javascript and mailto links
	if strings.HasPrefix(link, "javascript:") ||
		strings.HasPrefix(link, "mailto:") ||
		strings.HasPrefix(link, "tel:") ||
		strings.HasPrefix(link, "#") ||
		strings.HasPrefix(link, "data:") {
		return false
	}

	return true
}

// updateStatistics updates the statistics in the crawl result.
func (c *Crawler) updateStatistics(result *CrawlResult) {
	result.Statistics.TotalURLs = len(result.CrawledURLs)
	result.Statistics.InternalURLs = len(result.InternalLinks)
	result.Statistics.ExternalURLs = len(result.ExternalLinks)
	result.Statistics.FormsFound = len(result.Forms)
	result.Statistics.ResourcesFound = len(result.Resources)
}
