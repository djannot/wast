package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/djannot/wast/pkg/api"
	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/crawler"
	"github.com/djannot/wast/pkg/dns"
	"github.com/djannot/wast/pkg/proxy"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/scanner"
	"github.com/djannot/wast/pkg/tls"
	"go.opentelemetry.io/otel/trace"
)

// ReconResult represents the result of a reconnaissance operation.
type ReconResult struct {
	Target  string         `json:"target,omitempty" yaml:"target,omitempty"`
	Methods []string       `json:"methods,omitempty" yaml:"methods,omitempty"`
	Status  string         `json:"status,omitempty" yaml:"status,omitempty"`
	DNS     *dns.DNSResult `json:"dns,omitempty" yaml:"dns,omitempty"`
	TLS     *tls.TLSResult `json:"tls,omitempty" yaml:"tls,omitempty"`
}

// CompleteScanResult is deprecated. Use scanner.IntermediateScanResult instead.
// Kept for backward compatibility.
type CompleteScanResult = scanner.IntermediateScanResult

// ReconProgressCallback is a function called to report progress during reconnaissance.
type ReconProgressCallback func(phase string, message string)

// executeRecon performs reconnaissance on a target domain.
func executeRecon(ctx context.Context, target string, timeout time.Duration, includeSubdomains bool, tracer trace.Tracer, progressCallback ReconProgressCallback) interface{} {
	// Create tracing span if tracer is available
	if tracer != nil {
		var span trace.Span
		ctx, span = tracer.Start(ctx, "wast.recon")
		defer span.End()
	}

	// Perform DNS enumeration
	if progressCallback != nil {
		progressCallback("dns", "Performing DNS enumeration")
	}
	enumerator := dns.NewEnumerator(dns.WithTimeout(timeout))
	dnsResult := enumerator.Enumerate(target)

	// Perform subdomain discovery if enabled
	if includeSubdomains {
		if progressCallback != nil {
			progressCallback("subdomain_discovery", "Discovering subdomains")
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		discoverer := dns.NewSubdomainDiscoverer(dns.WithSubdomainTimeout(timeout))
		subs, subErrs := discoverer.Discover(ctx, target)
		dnsResult.Subdomains = subs
		dnsResult.Errors = append(dnsResult.Errors, subErrs...)
	}

	// Perform TLS certificate analysis
	if progressCallback != nil {
		progressCallback("tls", "Analyzing TLS certificate")
	}
	analyzer := tls.NewCertAnalyzer(tls.WithTimeout(timeout))
	tlsResult := analyzer.Analyze(target)

	result := ReconResult{
		Target: target,
		DNS:    dnsResult,
		TLS:    tlsResult,
	}

	return result
}

// executeScan performs security scanning on a target URL.
func executeScan(ctx context.Context, target string, timeout int, safeMode bool, verifyFindings bool, discover bool, depth int, concurrency int, scanConcurrency int, authConfig *auth.AuthConfig, rateLimitConfig ratelimit.Config, tracer trace.Tracer, progressCallback scanner.ProgressCallback) interface{} {
	// Create tracing span if tracer is available
	if tracer != nil {
		var span trace.Span
		ctx, span = tracer.Start(ctx, "wast.scan")
		defer span.End()
	}

	// If discovery mode is enabled, use discovery scan
	if discover {
		discoveryCfg := scanner.DiscoveryScanConfig{
			ScanConfig: scanner.ScanConfig{
				Target:          target,
				Timeout:         timeout,
				SafeMode:        safeMode,
				VerifyFindings:  verifyFindings,
				AuthConfig:      authConfig,
				RateLimitConfig: rateLimitConfig,
				Tracer:          tracer,
			},
			CrawlDepth:       depth,
			Concurrency:      concurrency,
			ScanConcurrency:  scanConcurrency,
			Discover:         true,
			ProgressCallback: progressCallback,
		}
		unifiedResult, _ := scanner.ExecuteDiscoveryScan(ctx, discoveryCfg)
		return unifiedResult
	}

	// Create scan configuration
	scanCfg := scanner.ScanConfig{
		Target:          target,
		Timeout:         timeout,
		SafeMode:        safeMode,
		VerifyFindings:  verifyFindings,
		AuthConfig:      authConfig,
		RateLimitConfig: rateLimitConfig,
		Tracer:          tracer,
	}

	// Execute the scan using the shared executor
	unifiedResult, _ := scanner.ExecuteScan(ctx, scanCfg)

	return unifiedResult
}

// executeCrawl performs web crawling on a target URL.
func executeCrawl(ctx context.Context, target string, depth int, timeout time.Duration, respectRobots bool, concurrency int, compact bool, authConfig *auth.AuthConfig, rateLimitConfig ratelimit.Config, tracer trace.Tracer, progressCallback crawler.ProgressCallback) interface{} {
	// Create tracing span if tracer is available
	if tracer != nil {
		var span trace.Span
		ctx, span = tracer.Start(ctx, "wast.mcp.crawl")
		defer span.End()
	}

	// Create crawler with configured options
	opts := []crawler.Option{
		crawler.WithMaxDepth(depth),
		crawler.WithTimeout(timeout),
		crawler.WithUserAgent("WAST/1.0 (Web Application Security Testing)"),
		crawler.WithRespectRobots(respectRobots),
		crawler.WithConcurrency(concurrency),
	}

	// Add authentication if configured
	if !authConfig.IsEmpty() {
		opts = append(opts, crawler.WithAuth(authConfig))
	}

	// Add rate limiting if configured
	if rateLimitConfig.IsEnabled() {
		opts = append(opts, crawler.WithRateLimitConfig(rateLimitConfig))
	}

	// Add tracer if configured
	if tracer != nil {
		opts = append(opts, crawler.WithTracer(tracer))
	}

	// Add progress callback if configured
	if progressCallback != nil {
		opts = append(opts, crawler.WithProgressCallback(progressCallback))
	}

	c := crawler.NewCrawler(opts...)

	// Create context with timeout
	crawlCtx, cancel := context.WithTimeout(ctx, timeout*time.Duration(depth+1))
	defer cancel()

	// Perform the crawl
	result := c.Crawl(crawlCtx, target)

	// Apply compact transformation if requested
	if compact {
		return compactCrawlResult(result)
	}

	return result
}

// executeAPI performs API discovery and testing.
func executeAPI(ctx context.Context, target string, specFile string, dryRun bool, timeout int, authConfig *auth.AuthConfig, rateLimitConfig ratelimit.Config, tracer trace.Tracer) interface{} {
	// Create tracing span if tracer is available
	if tracer != nil {
		var span trace.Span
		ctx, span = tracer.Start(ctx, "wast.api")
		defer span.End()
	}
	// If --spec is provided, parse the specification and optionally test endpoints
	if specFile != "" {
		// Parse the specification
		spec, err := api.ParseSpec(specFile)
		if err != nil {
			return map[string]interface{}{
				"error":     err.Error(),
				"spec_file": specFile,
			}
		}

		// Build tester options
		opts := []api.TesterOption{
			api.WithTimeout(time.Duration(timeout) * time.Second),
			api.WithDryRun(dryRun),
			api.WithRespectRateLimits(false),
		}

		// Add authentication if configured
		if !authConfig.IsEmpty() {
			opts = append(opts, api.WithAuth(authConfig))
		}

		// Add rate limiting if configured
		if rateLimitConfig.IsEnabled() {
			opts = append(opts, api.WithRateLimitConfig(rateLimitConfig))
		}

		// Create tester and run tests
		tester := api.NewTester(opts...)
		result := tester.TestAll(ctx, spec)

		return result
	}

	// Target URL provided - perform API discovery
	// Build discoverer options
	opts := []api.DiscovererOption{
		api.WithDiscovererTimeout(time.Duration(timeout) * time.Second),
	}

	// Add authentication if configured
	if !authConfig.IsEmpty() {
		opts = append(opts, api.WithDiscovererAuth(authConfig))
	}

	// Add rate limiting if configured
	if rateLimitConfig.IsEnabled() {
		opts = append(opts, api.WithDiscovererRateLimitConfig(rateLimitConfig))
	}

	// Create discoverer and run discovery
	discoverer := api.NewDiscoverer(opts...)
	result := discoverer.Discover(ctx, target)

	return result
}

// executeIntercept performs traffic interception on the specified port.
func executeIntercept(ctx context.Context, port int, duration time.Duration, saveFile string, httpsInterception bool, maxRequests int, tracer trace.Tracer) interface{} {
	// Create tracing span if tracer is available
	if tracer != nil {
		var span trace.Span
		ctx, span = tracer.Start(ctx, "wast.intercept")
		defer span.End()
	}
	// Create a context with timeout based on duration
	timeoutCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	// Build proxy options
	opts := []proxy.Option{
		proxy.WithPort(port),
	}

	// Add save file if specified
	if saveFile != "" {
		opts = append(opts, proxy.WithSaveFile(saveFile))
	}

	// Handle HTTPS interception if requested
	if httpsInterception {
		// Initialize or load CA for HTTPS interception
		config := proxy.DefaultCAConfig()
		ca := proxy.NewCertificateAuthority(config)

		// Check if CA exists, initialize if not
		if !ca.IsInitialized() {
			if err := ca.Initialize(); err != nil {
				// Return error result if CA initialization fails
				return map[string]interface{}{
					"error":         fmt.Sprintf("Failed to initialize CA for HTTPS interception: %v", err),
					"port":          port,
					"https_enabled": false,
					"message":       "HTTPS interception disabled due to CA initialization failure. Run 'wast intercept --init-ca' to set up HTTPS interception manually.",
				}
			}
		} else {
			// Load existing CA
			if err := ca.Load(); err != nil {
				// Return error result if CA loading fails
				return map[string]interface{}{
					"error":         fmt.Sprintf("Failed to load CA certificate: %v", err),
					"port":          port,
					"https_enabled": false,
					"message":       "HTTPS interception disabled due to CA loading failure.",
				}
			}
		}

		opts = append(opts, proxy.WithCA(ca))
	}

	// Create the proxy
	p := proxy.NewProxy(opts...)

	// If max_requests is specified, we need to monitor traffic and cancel when reached
	if maxRequests > 0 {
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-timeoutCtx.Done():
					return
				case <-ticker.C:
					stats := p.GetStats()
					if stats.TotalRequests >= maxRequests {
						cancel()
						return
					}
				}
			}
		}()
	}

	// Start the proxy
	result, err := p.Start(timeoutCtx)
	if err != nil {
		// Return error information
		return map[string]interface{}{
			"error": fmt.Sprintf("Proxy error: %v", err),
			"port":  port,
		}
	}

	return result
}

// executeHeaders performs passive security header analysis on a target URL.
func executeHeaders(ctx context.Context, target string, timeout int, authConfig *auth.AuthConfig, rateLimitConfig ratelimit.Config, tracer trace.Tracer) interface{} {
	// Create tracing span if tracer is available
	if tracer != nil {
		var span trace.Span
		ctx, span = tracer.Start(ctx, "wast.headers")
		defer span.End()
	}

	// Build scanner options
	opts := []scanner.Option{
		scanner.WithTimeout(time.Duration(timeout) * time.Second),
	}

	// Add authentication if configured
	if !authConfig.IsEmpty() {
		opts = append(opts, scanner.WithAuth(authConfig))
	}

	// Add rate limiting if configured
	if rateLimitConfig.IsEnabled() {
		opts = append(opts, scanner.WithRateLimitConfig(rateLimitConfig))
	}

	// Add tracer if configured
	if tracer != nil {
		opts = append(opts, scanner.WithTracer(tracer))
	}

	// Create headers scanner
	headersScanner := scanner.NewHTTPHeadersScanner(opts...)

	// Perform the scan
	result := headersScanner.Scan(ctx, target)

	return result
}

// executeVerify verifies an individual security finding with payload variants.
func executeVerify(ctx context.Context, findingType string, findingURL string, parameter string, payload string, maxRetries int, delay time.Duration, authConfig *auth.AuthConfig, rateLimitConfig ratelimit.Config, tracer trace.Tracer) (interface{}, error) {
	// Create tracing span if tracer is available
	if tracer != nil {
		var span trace.Span
		ctx, span = tracer.Start(ctx, "wast.verify")
		defer span.End()
	}

	// Create verification config
	verifyConfig := scanner.VerificationConfig{
		Enabled:    true,
		MaxRetries: maxRetries,
		Delay:      delay,
	}

	// Common scanner options
	timeout := 30 * time.Second

	// Create rate limiter if configured
	var rateLimiter ratelimit.Limiter
	if rateLimitConfig.IsEnabled() {
		rateLimiter = ratelimit.NewLimiterFromConfig(rateLimitConfig)
	}

	// Execute verification based on finding type
	switch findingType {
	case "ssrf":
		ssrfScanner := scanner.NewSSRFScanner(
			scanner.WithSSRFTimeout(timeout),
			scanner.WithSSRFAuth(authConfig),
			scanner.WithSSRFRateLimiter(rateLimiter),
			scanner.WithSSRFTracer(tracer),
		)
		finding := &scanner.SSRFFinding{
			URL:       findingURL,
			Parameter: parameter,
			Payload:   payload,
		}
		return ssrfScanner.VerifyFinding(ctx, finding, verifyConfig)

	case "sqli":
		sqliScanner := scanner.NewSQLiScanner(
			scanner.WithSQLiTimeout(timeout),
			scanner.WithSQLiAuth(authConfig),
			scanner.WithSQLiRateLimiter(rateLimiter),
			scanner.WithSQLiTracer(tracer),
		)
		finding := &scanner.SQLiFinding{
			URL:       findingURL,
			Parameter: parameter,
			Payload:   payload,
		}
		return sqliScanner.VerifyFinding(ctx, finding, verifyConfig)

	case "xss":
		xssScanner := scanner.NewXSSScanner(
			scanner.WithXSSTimeout(timeout),
			scanner.WithXSSAuth(authConfig),
			scanner.WithXSSRateLimiter(rateLimiter),
			scanner.WithXSSTracer(tracer),
		)
		finding := &scanner.XSSFinding{
			URL:       findingURL,
			Parameter: parameter,
			Payload:   payload,
		}
		return xssScanner.VerifyFinding(ctx, finding, verifyConfig)

	case "cmdi":
		cmdiScanner := scanner.NewCMDiScanner(
			scanner.WithCMDiTimeout(timeout),
			scanner.WithCMDiAuth(authConfig),
			scanner.WithCMDiRateLimiter(rateLimiter),
			scanner.WithCMDiTracer(tracer),
		)
		finding := &scanner.CMDiFinding{
			URL:       findingURL,
			Parameter: parameter,
			Payload:   payload,
		}
		return cmdiScanner.VerifyFinding(ctx, finding, verifyConfig)

	case "pathtraversal":
		pathTraversalScanner := scanner.NewPathTraversalScanner(
			scanner.WithPathTraversalTimeout(timeout),
			scanner.WithPathTraversalAuth(authConfig),
			scanner.WithPathTraversalRateLimiter(rateLimiter),
			scanner.WithPathTraversalTracer(tracer),
		)
		finding := &scanner.PathTraversalFinding{
			URL:       findingURL,
			Parameter: parameter,
			Payload:   payload,
		}
		return pathTraversalScanner.VerifyFinding(ctx, finding, verifyConfig)

	case "redirect":
		redirectScanner := scanner.NewRedirectScanner(
			scanner.WithRedirectTimeout(timeout),
			scanner.WithRedirectAuth(authConfig),
			scanner.WithRedirectRateLimiter(rateLimiter),
			scanner.WithRedirectTracer(tracer),
		)
		finding := &scanner.RedirectFinding{
			URL:       findingURL,
			Parameter: parameter,
			Payload:   payload,
		}
		return redirectScanner.VerifyFinding(ctx, finding, verifyConfig)

	case "csrf":
		csrfScanner := scanner.NewCSRFScanner(
			scanner.WithCSRFTimeout(timeout),
			scanner.WithCSRFAuth(authConfig),
			scanner.WithCSRFRateLimiter(rateLimiter),
			scanner.WithCSRFTracer(tracer),
		)
		finding := &scanner.CSRFFinding{
			FormAction: findingURL,
			FormPage:   findingURL,
			Type:       parameter, // For CSRF, parameter is the finding type (missing_token, missing_samesite, etc.)
		}
		return csrfScanner.VerifyFinding(ctx, finding, verifyConfig)

	default:
		return nil, fmt.Errorf("unsupported finding type: %s", findingType)
	}
}

// CompactCrawlResult represents a compact version of CrawlResult with summarized data.
type CompactCrawlResult struct {
	Target              string                   `json:"target" yaml:"target"`
	Statistics          crawler.CrawlStats       `json:"statistics" yaml:"statistics"`
	Forms               []crawler.FormInfo       `json:"forms,omitempty" yaml:"forms,omitempty"`
	ResourcesSummary    *ResourcesSummary        `json:"resources_summary,omitempty" yaml:"resources_summary,omitempty"`
	InternalLinksSummary *LinksSummary            `json:"internal_links_summary,omitempty" yaml:"internal_links_summary,omitempty"`
	ExternalLinksSummary *LinksSummary            `json:"external_links_summary,omitempty" yaml:"external_links_summary,omitempty"`
	RobotsDisallow      []string                 `json:"robots_disallow,omitempty" yaml:"robots_disallow,omitempty"`
	SitemapURLs         []string                 `json:"sitemap_urls,omitempty" yaml:"sitemap_urls,omitempty"`
	Errors              []string                 `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// ResourcesSummary provides a compact summary of resources.
type ResourcesSummary struct {
	Total int            `json:"total" yaml:"total"`
	Types map[string]int `json:"types" yaml:"types"`
}

// LinksSummary provides a compact summary of links.
type LinksSummary struct {
	Total  int      `json:"total" yaml:"total"`
	Sample []string `json:"sample,omitempty" yaml:"sample,omitempty"`
}

// compactCrawlResult transforms a CrawlResult into a compact format.
func compactCrawlResult(result *crawler.CrawlResult) *CompactCrawlResult {
	if result == nil {
		return nil
	}

	// Initialize compact result with preserved fields
	compact := &CompactCrawlResult{
		Target:     result.Target,
		Statistics: result.Statistics,
	}

	// Preserve forms completely
	if result.Forms != nil {
		compact.Forms = result.Forms
	} else {
		compact.Forms = []crawler.FormInfo{}
	}

	// Preserve robots disallow rules
	if result.RobotsDisallow != nil {
		compact.RobotsDisallow = result.RobotsDisallow
	} else {
		compact.RobotsDisallow = []string{}
	}

	// Preserve sitemap URLs
	if result.SitemapURLs != nil {
		compact.SitemapURLs = result.SitemapURLs
	} else {
		compact.SitemapURLs = []string{}
	}

	// Preserve errors
	if result.Errors != nil {
		compact.Errors = result.Errors
	} else {
		compact.Errors = []string{}
	}

	// Summarize resources by type
	if len(result.Resources) > 0 {
		resourceTypes := make(map[string]int)
		for _, res := range result.Resources {
			resourceTypes[res.Type]++
		}
		compact.ResourcesSummary = &ResourcesSummary{
			Total: len(result.Resources),
			Types: resourceTypes,
		}
	}

	// Summarize internal links with sample
	if len(result.InternalLinks) > 0 {
		sampleSize := 10
		if len(result.InternalLinks) < sampleSize {
			sampleSize = len(result.InternalLinks)
		}
		sample := make([]string, sampleSize)
		for i := 0; i < sampleSize; i++ {
			sample[i] = result.InternalLinks[i].URL
		}
		compact.InternalLinksSummary = &LinksSummary{
			Total:  len(result.InternalLinks),
			Sample: sample,
		}
	}

	// Summarize external links with sample
	if len(result.ExternalLinks) > 0 {
		sampleSize := 10
		if len(result.ExternalLinks) < sampleSize {
			sampleSize = len(result.ExternalLinks)
		}
		sample := make([]string, sampleSize)
		for i := 0; i < sampleSize; i++ {
			sample[i] = result.ExternalLinks[i].URL
		}
		compact.ExternalLinksSummary = &LinksSummary{
			Total:  len(result.ExternalLinks),
			Sample: sample,
		}
	}

	return compact
}
