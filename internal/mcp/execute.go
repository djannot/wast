package mcp

import (
	"context"
	"fmt"
	"sync"
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
	SSRF        *scanner.SSRFScanResult   `json:"ssrf,omitempty" yaml:"ssrf,omitempty"`
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
func executeScan(ctx context.Context, target string, timeout int, safeMode bool, verifyFindings bool, authConfig *auth.AuthConfig, rateLimitConfig ratelimit.Config) interface{} {
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
	ssrfOpts := []scanner.SSRFOption{
		scanner.WithSSRFTimeout(time.Duration(timeout) * time.Second),
	}

	// Add authentication if configured
	if !authConfig.IsEmpty() {
		headerOpts = append(headerOpts, scanner.WithAuth(authConfig))
		xssOpts = append(xssOpts, scanner.WithXSSAuth(authConfig))
		sqliOpts = append(sqliOpts, scanner.WithSQLiAuth(authConfig))
		csrfOpts = append(csrfOpts, scanner.WithCSRFAuth(authConfig))
		ssrfOpts = append(ssrfOpts, scanner.WithSSRFAuth(authConfig))
	}

	// Add rate limiting if configured
	if rateLimitConfig.IsEnabled() {
		headerOpts = append(headerOpts, scanner.WithRateLimitConfig(rateLimitConfig))
		xssOpts = append(xssOpts, scanner.WithXSSRateLimitConfig(rateLimitConfig))
		sqliOpts = append(sqliOpts, scanner.WithSQLiRateLimitConfig(rateLimitConfig))
		csrfOpts = append(csrfOpts, scanner.WithCSRFRateLimitConfig(rateLimitConfig))
		ssrfOpts = append(ssrfOpts, scanner.WithSSRFRateLimitConfig(rateLimitConfig))
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
		ssrfScanner := scanner.NewSSRFScanner(ssrfOpts...)

		var wg sync.WaitGroup
		var xssResult *scanner.XSSScanResult
		var sqliResult *scanner.SQLiScanResult
		var csrfResult *scanner.CSRFScanResult
		var ssrfResult *scanner.SSRFScanResult

		wg.Add(4)
		go func() {
			defer wg.Done()
			xssResult = xssScanner.Scan(ctx, target)
		}()
		go func() {
			defer wg.Done()
			sqliResult = sqliScanner.Scan(ctx, target)
		}()
		go func() {
			defer wg.Done()
			csrfResult = csrfScanner.Scan(ctx, target)
		}()
		go func() {
			defer wg.Done()
			ssrfResult = ssrfScanner.Scan(ctx, target)
		}()
		wg.Wait()

		// Verify findings if enabled
		if verifyFindings {
			verifyConfig := scanner.VerificationConfig{
				Enabled:    true,
				MaxRetries: 3,
				Delay:      500 * time.Millisecond,
			}

			// Verify XSS findings
			for i := range xssResult.Findings {
				result, err := xssScanner.VerifyFinding(ctx, &xssResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					xssResult.Findings[i].Verified = result.Verified
					xssResult.Findings[i].VerificationAttempts = result.Attempts
					// Update confidence based on verification
					if result.Verified && result.Confidence > 0.8 {
						xssResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						xssResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						xssResult.Findings[i].Confidence = "low"
					}
				}
			}

			// Verify SQLi findings
			for i := range sqliResult.Findings {
				result, err := sqliScanner.VerifyFinding(ctx, &sqliResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					sqliResult.Findings[i].Verified = result.Verified
					sqliResult.Findings[i].VerificationAttempts = result.Attempts
					// Update confidence based on verification
					if result.Verified && result.Confidence > 0.8 {
						sqliResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						sqliResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						sqliResult.Findings[i].Confidence = "low"
					}
				}
			}

			// Verify CSRF findings
			for i := range csrfResult.Findings {
				result, err := csrfScanner.VerifyFinding(ctx, &csrfResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					csrfResult.Findings[i].Verified = result.Verified
					csrfResult.Findings[i].VerificationAttempts = result.Attempts
				}
			}

			// Filter out unverified findings if verification was enabled
			verifiedXSSFindings := make([]scanner.XSSFinding, 0)
			for _, finding := range xssResult.Findings {
				if finding.Verified {
					verifiedXSSFindings = append(verifiedXSSFindings, finding)
				}
			}
			xssResult.Findings = verifiedXSSFindings
			xssResult.Summary.VulnerabilitiesFound = len(verifiedXSSFindings)

			verifiedSQLiFindings := make([]scanner.SQLiFinding, 0)
			for _, finding := range sqliResult.Findings {
				if finding.Verified {
					verifiedSQLiFindings = append(verifiedSQLiFindings, finding)
				}
			}
			sqliResult.Findings = verifiedSQLiFindings
			sqliResult.Summary.VulnerabilitiesFound = len(verifiedSQLiFindings)

			verifiedCSRFFindings := make([]scanner.CSRFFinding, 0)
			for _, finding := range csrfResult.Findings {
				if finding.Verified {
					verifiedCSRFFindings = append(verifiedCSRFFindings, finding)
				}
			}
			csrfResult.Findings = verifiedCSRFFindings
			csrfResult.Summary.VulnerableForms = len(verifiedCSRFFindings)

			// Verify SSRF findings
			for i := range ssrfResult.Findings {
				result, err := ssrfScanner.VerifyFinding(ctx, &ssrfResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					ssrfResult.Findings[i].Verified = result.Verified
					ssrfResult.Findings[i].VerificationAttempts = result.Attempts
					// Update confidence based on verification
					if result.Verified && result.Confidence > 0.8 {
						ssrfResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						ssrfResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						ssrfResult.Findings[i].Confidence = "low"
					}
				}
			}

			verifiedSSRFFindings := make([]scanner.SSRFFinding, 0)
			for _, finding := range ssrfResult.Findings {
				if finding.Verified {
					verifiedSSRFFindings = append(verifiedSSRFFindings, finding)
				}
			}
			ssrfResult.Findings = verifiedSSRFFindings
			ssrfResult.Summary.VulnerabilitiesFound = len(verifiedSSRFFindings)
		}

		combinedResult.XSS = xssResult
		combinedResult.SQLi = sqliResult
		combinedResult.CSRF = csrfResult
		combinedResult.SSRF = ssrfResult

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
		if len(ssrfResult.Errors) > 0 {
			combinedResult.Errors = append(combinedResult.Errors, ssrfResult.Errors...)
		}
	}

	// Create unified result with correlation and risk scoring
	unifiedResult := scanner.NewUnifiedScanResult(
		target,
		safeMode,
		headerResult,
		combinedResult.XSS,
		combinedResult.SQLi,
		combinedResult.CSRF,
		combinedResult.SSRF,
		combinedResult.Errors,
	)

	return unifiedResult
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
