// Package websocket provides WebSocket endpoint detection and security scanning functionality.
package websocket

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/crawler"
	"github.com/djannot/wast/pkg/ratelimit"
	"go.opentelemetry.io/otel/trace"
)

// HTTPClient defines the interface for HTTP operations.
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

// Detector identifies WebSocket endpoints from crawl results and page content.
type Detector struct {
	client      HTTPClient
	userAgent   string
	timeout     time.Duration
	authConfig  *auth.AuthConfig
	rateLimiter ratelimit.Limiter
	tracer      trace.Tracer
}

// DetectorOption is a function that configures a Detector.
type DetectorOption func(*Detector)

// WithDetectorHTTPClient sets a custom HTTP client for the detector.
func WithDetectorHTTPClient(c HTTPClient) DetectorOption {
	return func(d *Detector) {
		d.client = c
	}
}

// WithDetectorUserAgent sets the user agent string for the detector.
func WithDetectorUserAgent(ua string) DetectorOption {
	return func(d *Detector) {
		d.userAgent = ua
	}
}

// WithDetectorTimeout sets the timeout for HTTP requests.
func WithDetectorTimeout(t time.Duration) DetectorOption {
	return func(d *Detector) {
		d.timeout = t
	}
}

// WithDetectorAuth sets the authentication configuration.
func WithDetectorAuth(config *auth.AuthConfig) DetectorOption {
	return func(d *Detector) {
		d.authConfig = config
	}
}

// WithDetectorRateLimiter sets a rate limiter for the detector.
func WithDetectorRateLimiter(limiter ratelimit.Limiter) DetectorOption {
	return func(d *Detector) {
		d.rateLimiter = limiter
	}
}

// WithDetectorTracer sets the OpenTelemetry tracer.
func WithDetectorTracer(tracer trace.Tracer) DetectorOption {
	return func(d *Detector) {
		d.tracer = tracer
	}
}

// NewDetector creates a new WebSocket endpoint detector.
func NewDetector(opts ...DetectorOption) *Detector {
	d := &Detector{
		userAgent: "WAST/1.0 (Web Application Security Testing)",
		timeout:   30 * time.Second,
	}

	for _, opt := range opts {
		opt(d)
	}

	// Create default HTTP client if not set
	if d.client == nil {
		d.client = NewDefaultHTTPClient(d.timeout)
	}

	return d
}

// WebSocketEndpoint represents a detected WebSocket endpoint.
type WebSocketEndpoint struct {
	URL              string   `json:"url" yaml:"url"`
	DetectionMethod  string   `json:"detection_method" yaml:"detection_method"`                       // "javascript", "upgrade_header", "url_pattern"
	SourcePage       string   `json:"source_page" yaml:"source_page"`                                 // Where it was found
	Context          string   `json:"context,omitempty" yaml:"context,omitempty"`                     // Surrounding code/text
	IsSecure         bool     `json:"is_secure" yaml:"is_secure"`                                     // wss:// vs ws://
	DetectedProtocol []string `json:"detected_protocol,omitempty" yaml:"detected_protocol,omitempty"` // Detected Sec-WebSocket-Protocol values
}

// DetectionResult contains the results of WebSocket endpoint detection.
type DetectionResult struct {
	Target     string              `json:"target" yaml:"target"`
	Endpoints  []WebSocketEndpoint `json:"endpoints,omitempty" yaml:"endpoints,omitempty"`
	Errors     []string            `json:"errors,omitempty" yaml:"errors,omitempty"`
	Statistics DetectionStatistics `json:"statistics" yaml:"statistics"`
}

// DetectionStatistics contains statistics about the detection operation.
type DetectionStatistics struct {
	TotalEndpoints    int `json:"total_endpoints" yaml:"total_endpoints"`
	SecureEndpoints   int `json:"secure_endpoints" yaml:"secure_endpoints"`
	InsecureEndpoints int `json:"insecure_endpoints" yaml:"insecure_endpoints"`
	PagesScanned      int `json:"pages_scanned" yaml:"pages_scanned"`
}

// Detect identifies WebSocket endpoints from crawl results.
func (d *Detector) Detect(ctx context.Context, crawlResult *crawler.CrawlResult) *DetectionResult {
	// Create tracing span if tracer is available
	if d.tracer != nil {
		var span trace.Span
		ctx, span = d.tracer.Start(ctx, "wast.websocket.detect")
		defer span.End()
	}

	result := &DetectionResult{
		Target:    crawlResult.Target,
		Endpoints: make([]WebSocketEndpoint, 0),
		Errors:    make([]string, 0),
	}

	// Track unique endpoints to avoid duplicates
	seen := make(map[string]bool)

	// 1. Scan JavaScript resources for WebSocket instantiations
	for _, resource := range crawlResult.Resources {
		if resource.Type == "script" || resource.Type == "javascript" {
			result.Statistics.PagesScanned++
			endpoints := d.detectInJavaScript(ctx, resource.URL, resource.Page)
			for _, ep := range endpoints {
				key := ep.URL + "|" + ep.SourcePage
				if !seen[key] {
					seen[key] = true
					result.Endpoints = append(result.Endpoints, ep)
				}
			}
		}
	}

	// 2. Scan HTML pages for inline JavaScript with WebSocket
	for _, url := range crawlResult.CrawledURLs {
		result.Statistics.PagesScanned++
		endpoints := d.detectInPage(ctx, url)
		for _, ep := range endpoints {
			key := ep.URL + "|" + ep.SourcePage
			if !seen[key] {
				seen[key] = true
				result.Endpoints = append(result.Endpoints, ep)
			}
		}
	}

	// Calculate statistics
	result.Statistics.TotalEndpoints = len(result.Endpoints)
	for _, ep := range result.Endpoints {
		if ep.IsSecure {
			result.Statistics.SecureEndpoints++
		} else {
			result.Statistics.InsecureEndpoints++
		}
	}

	return result
}

// detectInJavaScript scans JavaScript content for WebSocket instantiations.
func (d *Detector) detectInJavaScript(ctx context.Context, scriptURL, sourcePage string) []WebSocketEndpoint {
	endpoints := make([]WebSocketEndpoint, 0)

	// Apply rate limiting if configured
	if d.rateLimiter != nil {
		d.rateLimiter.Wait(ctx)
	}

	// Fetch the JavaScript file
	req, err := http.NewRequestWithContext(ctx, "GET", scriptURL, nil)
	if err != nil {
		return endpoints
	}

	req.Header.Set("User-Agent", d.userAgent)

	// Apply authentication if configured
	if d.authConfig != nil && !d.authConfig.IsEmpty() {
		d.authConfig.ApplyToRequest(req)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return endpoints
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return endpoints
	}

	// Read the response body
	buf := make([]byte, 1024*1024) // 1MB limit for JS files
	n, _ := resp.Body.Read(buf)
	content := string(buf[:n])

	return d.extractWebSocketURLs(content, sourcePage)
}

// detectInPage scans an HTML page for WebSocket usage.
func (d *Detector) detectInPage(ctx context.Context, pageURL string) []WebSocketEndpoint {
	endpoints := make([]WebSocketEndpoint, 0)

	// Apply rate limiting if configured
	if d.rateLimiter != nil {
		d.rateLimiter.Wait(ctx)
	}

	// Fetch the HTML page
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return endpoints
	}

	req.Header.Set("User-Agent", d.userAgent)

	// Apply authentication if configured
	if d.authConfig != nil && !d.authConfig.IsEmpty() {
		d.authConfig.ApplyToRequest(req)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return endpoints
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return endpoints
	}

	// Read the response body
	buf := make([]byte, 2*1024*1024) // 2MB limit for HTML pages
	n, _ := resp.Body.Read(buf)
	content := string(buf[:n])

	return d.extractWebSocketURLs(content, pageURL)
}

// extractWebSocketURLs extracts WebSocket URLs from content using regex patterns.
func (d *Detector) extractWebSocketURLs(content, sourcePage string) []WebSocketEndpoint {
	endpoints := make([]WebSocketEndpoint, 0)
	seenURLs := make(map[string]bool)

	// Pattern 1: new WebSocket("ws://..." or "wss://...")
	wsNewPattern := regexp.MustCompile(`new\s+WebSocket\s*\(\s*["']([^"']+)["']`)
	matches := wsNewPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			wsURL := match[1]
			if strings.HasPrefix(wsURL, "ws://") || strings.HasPrefix(wsURL, "wss://") {
				if !seenURLs[wsURL] {
					seenURLs[wsURL] = true
					isSecure := strings.HasPrefix(wsURL, "wss://")
					endpoints = append(endpoints, WebSocketEndpoint{
						URL:             wsURL,
						DetectionMethod: "javascript",
						SourcePage:      sourcePage,
						Context:         match[0],
						IsSecure:        isSecure,
					})
				}
			}
		}
	}

	// Pattern 2: WebSocket URL in variable assignment or object property
	// Only add if not already found by pattern 1
	wsURLPattern := regexp.MustCompile(`(wss?://[^\s"'\)<>]+)`)
	matches = wsURLPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 1 {
			wsURL := match[1]
			if !seenURLs[wsURL] {
				seenURLs[wsURL] = true
				isSecure := strings.HasPrefix(wsURL, "wss://")

				// Extract context (surrounding 50 characters)
				contextStart := strings.LastIndex(content[:strings.Index(content, wsURL)], "\n")
				if contextStart == -1 {
					contextStart = 0
				}
				contextEnd := strings.Index(content[strings.Index(content, wsURL):], "\n")
				if contextEnd == -1 {
					contextEnd = len(content)
				} else {
					contextEnd += strings.Index(content, wsURL)
				}

				context := content[contextStart:contextEnd]

				endpoints = append(endpoints, WebSocketEndpoint{
					URL:             wsURL,
					DetectionMethod: "url_pattern",
					SourcePage:      sourcePage,
					Context:         strings.TrimSpace(context),
					IsSecure:        isSecure,
				})
			}
		}
	}

	// Pattern 3: Detect Sec-WebSocket-Protocol in JavaScript
	protocolPattern := regexp.MustCompile(`["']Sec-WebSocket-Protocol["']\s*:\s*["']([^"']+)["']`)
	matches = protocolPattern.FindAllStringSubmatch(content, -1)
	if len(matches) > 0 && len(endpoints) > 0 {
		// Add detected protocols to the last endpoint found
		for _, match := range matches {
			if len(match) >= 2 {
				endpoints[len(endpoints)-1].DetectedProtocol = append(
					endpoints[len(endpoints)-1].DetectedProtocol,
					match[1],
				)
			}
		}
	}

	return endpoints
}

// DetectFromContent detects WebSocket URLs from raw content (for testing or direct analysis).
func (d *Detector) DetectFromContent(content, sourcePage string) []WebSocketEndpoint {
	return d.extractWebSocketURLs(content, sourcePage)
}
