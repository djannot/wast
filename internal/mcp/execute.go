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
)

// ReconResult represents the result of a reconnaissance operation.
type ReconResult struct {
	Target  string         `json:"target,omitempty" yaml:"target,omitempty"`
	Methods []string       `json:"methods,omitempty" yaml:"methods,omitempty"`
	Status  string         `json:"status,omitempty" yaml:"status,omitempty"`
	DNS     *dns.DNSResult `json:"dns,omitempty" yaml:"dns,omitempty"`
	TLS     *tls.TLSResult `json:"tls,omitempty" yaml:"tls,omitempty"`
}

// CompleteScanResult represents the combined results of all security scans.
type CompleteScanResult struct {
	Target      string                    `json:"target" yaml:"target"`
	PassiveOnly bool                      `json:"passive_only" yaml:"passive_only"`
	Headers     *scanner.HeaderScanResult `json:"headers,omitempty" yaml:"headers,omitempty"`
	XSS         *scanner.XSSScanResult    `json:"xss,omitempty" yaml:"xss,omitempty"`
	SQLi        *scanner.SQLiScanResult   `json:"sqli,omitempty" yaml:"sqli,omitempty"`
	CSRF        *scanner.CSRFScanResult   `json:"csrf,omitempty" yaml:"csrf,omitempty"`
	Errors      []string                  `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// executeRecon performs reconnaissance on a target domain.
func executeRecon(ctx context.Context, target string, timeout time.Duration, includeSubdomains bool) interface{} {
	// Perform DNS enumeration
	enumerator := dns.NewEnumerator(dns.WithTimeout(timeout))
	dnsResult := enumerator.Enumerate(target)

	// Perform subdomain discovery if enabled
	if includeSubdomains {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		discoverer := dns.NewSubdomainDiscoverer(dns.WithSubdomainTimeout(timeout))
		subs, subErrs := discoverer.Discover(ctx, target)
		dnsResult.Subdomains = subs
		dnsResult.Errors = append(dnsResult.Errors, subErrs...)
	}

	// Perform TLS certificate analysis
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
func executeScan(ctx context.Context, target string, timeout int, safeMode bool, authConfig *auth.AuthConfig, rateLimitConfig ratelimit.Config) interface{} {
	// Create scanner options
	headerOpts := []scanner.Option{
		scanner.WithTimeout(time.Duration(timeout) * time.Second),
	}
	xssOpts := []scanner.XSSOption{
		scanner.WithXSSTimeout(time.Duration(timeout) * time.Second),
	}
	sqliOpts := []scanner.SQLiOption{
		scanner.WithSQLiTimeout(time.Duration(timeout) * time.Second),
	}
	csrfOpts := []scanner.CSRFOption{
		scanner.WithCSRFTimeout(time.Duration(timeout) * time.Second),
	}

	// Add authentication if configured
	if !authConfig.IsEmpty() {
		headerOpts = append(headerOpts, scanner.WithAuth(authConfig))
		xssOpts = append(xssOpts, scanner.WithXSSAuth(authConfig))
		sqliOpts = append(sqliOpts, scanner.WithSQLiAuth(authConfig))
		csrfOpts = append(csrfOpts, scanner.WithCSRFAuth(authConfig))
	}

	// Add rate limiting if configured
	if rateLimitConfig.IsEnabled() {
		headerOpts = append(headerOpts, scanner.WithRateLimitConfig(rateLimitConfig))
		xssOpts = append(xssOpts, scanner.WithXSSRateLimitConfig(rateLimitConfig))
		sqliOpts = append(sqliOpts, scanner.WithSQLiRateLimitConfig(rateLimitConfig))
		csrfOpts = append(csrfOpts, scanner.WithCSRFRateLimitConfig(rateLimitConfig))
	}

	// Create scanners
	headerScanner := scanner.NewHTTPHeadersScanner(headerOpts...)

	// Perform the scans
	headerResult := headerScanner.Scan(ctx, target)

	// Initialize result structure
	combinedResult := CompleteScanResult{
		Target:      target,
		PassiveOnly: safeMode,
		Headers:     headerResult,
		Errors:      make([]string, 0),
	}

	// Aggregate errors from header scan
	if len(headerResult.Errors) > 0 {
		combinedResult.Errors = append(combinedResult.Errors, headerResult.Errors...)
	}

	// Only perform active scans if safe mode is disabled
	if !safeMode {
		xssScanner := scanner.NewXSSScanner(xssOpts...)
		sqliScanner := scanner.NewSQLiScanner(sqliOpts...)
		csrfScanner := scanner.NewCSRFScanner(csrfOpts...)

		xssResult := xssScanner.Scan(ctx, target)
		sqliResult := sqliScanner.Scan(ctx, target)
		csrfResult := csrfScanner.Scan(ctx, target)

		combinedResult.XSS = xssResult
		combinedResult.SQLi = sqliResult
		combinedResult.CSRF = csrfResult

		// Aggregate errors from active scans
		if len(xssResult.Errors) > 0 {
			combinedResult.Errors = append(combinedResult.Errors, xssResult.Errors...)
		}
		if len(sqliResult.Errors) > 0 {
			combinedResult.Errors = append(combinedResult.Errors, sqliResult.Errors...)
		}
		if len(csrfResult.Errors) > 0 {
			combinedResult.Errors = append(combinedResult.Errors, csrfResult.Errors...)
		}
	}

	return combinedResult
}

// executeCrawl performs web crawling on a target URL.
func executeCrawl(ctx context.Context, target string, depth int, timeout time.Duration, respectRobots bool, authConfig *auth.AuthConfig, rateLimitConfig ratelimit.Config) interface{} {
	// Create crawler with configured options
	opts := []crawler.Option{
		crawler.WithMaxDepth(depth),
		crawler.WithTimeout(timeout),
		crawler.WithUserAgent("WAST/1.0 (Web Application Security Testing)"),
		crawler.WithRespectRobots(respectRobots),
	}

	// Add authentication if configured
	if !authConfig.IsEmpty() {
		opts = append(opts, crawler.WithAuth(authConfig))
	}

	// Add rate limiting if configured
	if rateLimitConfig.IsEnabled() {
		opts = append(opts, crawler.WithRateLimitConfig(rateLimitConfig))
	}

	c := crawler.NewCrawler(opts...)

	// Create context with timeout
	crawlCtx, cancel := context.WithTimeout(ctx, timeout*time.Duration(depth+1))
	defer cancel()

	// Perform the crawl
	result := c.Crawl(crawlCtx, target)

	return result
}

// executeAPI performs API discovery and testing.
func executeAPI(ctx context.Context, target string, specFile string, dryRun bool, timeout int, authConfig *auth.AuthConfig, rateLimitConfig ratelimit.Config) interface{} {
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
func executeIntercept(ctx context.Context, port int, duration time.Duration, saveFile string, httpsInterception bool, maxRequests int) interface{} {
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
