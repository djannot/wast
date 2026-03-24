// Package crawler provides web crawling functionality for reconnaissance operations.
package crawler

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

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

// Crawler performs web crawling operations.
type Crawler struct {
	client        HTTPClient
	userAgent     string
	timeout       time.Duration
	maxDepth      int
	respectRobots bool
	robotsData    *RobotsData
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

// NewCrawler creates a new Crawler with the given options.
func NewCrawler(opts ...Option) *Crawler {
	c := &Crawler{
		userAgent:     "WAST/1.0 (Web Application Security Testing)",
		timeout:       30 * time.Second,
		maxDepth:      3,
		respectRobots: true,
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
	if c.respectRobots {
		c.fetchRobots(ctx, baseURL, result)
	}

	// Initialize BFS queue and visited set
	queue := []queueItem{{url: targetURL, depth: 0}}
	visited := make(map[string]bool)
	visited[normalizeURL(targetURL)] = true

	// Track unique links to avoid duplicates in results
	seenInternalLinks := make(map[string]bool)
	seenExternalLinks := make(map[string]bool)

	// BFS crawl
	for len(queue) > 0 {
		// Check context cancellation
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, "Crawl cancelled: "+ctx.Err().Error())
			c.updateStatistics(result)
			return result
		default:
		}

		// Dequeue
		item := queue[0]
		queue = queue[1:]

		// Skip if beyond max depth
		if item.depth > c.maxDepth {
			continue
		}

		// Check robots.txt
		if c.respectRobots && c.robotsData != nil {
			parsedURL, _ := url.Parse(item.url)
			if parsedURL != nil && !c.robotsData.IsAllowed(parsedURL.Path) {
				continue
			}
		}

		// Fetch the page
		pageContent, err := c.fetchPage(ctx, item.url)
		if err != nil {
			result.Errors = append(result.Errors, "Failed to fetch "+item.url+": "+err.Error())
			continue
		}

		result.CrawledURLs = append(result.CrawledURLs, item.url)

		// Update max depth reached
		if item.depth > result.Statistics.MaxDepthReached {
			result.Statistics.MaxDepthReached = item.depth
		}

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
				if !seenInternalLinks[normalizedURL] {
					seenInternalLinks[normalizedURL] = true
					result.InternalLinks = append(result.InternalLinks, link)
				}

				// Add to queue if not visited and within depth
				if !visited[normalizedURL] && item.depth < c.maxDepth {
					visited[normalizedURL] = true
					queue = append(queue, queueItem{url: link.URL, depth: item.depth + 1})
				}
			} else {
				link.External = true
				link.Depth = item.depth

				if !seenExternalLinks[link.URL] {
					seenExternalLinks[link.URL] = true
					result.ExternalLinks = append(result.ExternalLinks, link)
				}
			}
		}

		// Add forms
		for _, form := range forms {
			form.Page = item.url
			// Resolve form action URL
			if form.Action != "" && !strings.HasPrefix(form.Action, "http") {
				actionURL, err := url.Parse(form.Action)
				if err == nil {
					form.Action = baseURL.ResolveReference(actionURL).String()
				}
			}
			result.Forms = append(result.Forms, form)
		}

		// Add resources
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
	}

	c.updateStatistics(result)
	return result
}

// fetchRobots fetches and parses robots.txt for the target domain.
func (c *Crawler) fetchRobots(ctx context.Context, baseURL *url.URL, result *CrawlResult) {
	robotsURL, err := GetRobotsURL(baseURL.String())
	if err != nil {
		return
	}

	content, err := c.fetchPage(ctx, robotsURL)
	if err != nil {
		// robots.txt not found or error - that's fine, continue crawling
		return
	}

	c.robotsData = ParseRobots(strings.NewReader(content))
	result.RobotsDisallow = c.robotsData.Disallow
}

// fetchPage fetches the content of a URL.
func (c *Crawler) fetchPage(ctx context.Context, targetURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

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
