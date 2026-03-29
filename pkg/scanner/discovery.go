// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/djannot/wast/pkg/crawler"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/websocket"
)

// ProgressCallback is a function called to report progress during scanning.
type ProgressCallback func(completed int, total int, phase string)

// DiscoveredTarget represents a discovered endpoint to scan.
type DiscoveredTarget struct {
	URL        string            // The URL to scan
	Method     string            // HTTP method (GET, POST, etc.)
	Parameters map[string]string // Parameters to test (field name -> default value)
	Source     string            // Where this target was discovered (e.g., "form on /page", "link query params")
}

// DiscoveryScanConfig extends ScanConfig with discovery-specific options.
type DiscoveryScanConfig struct {
	ScanConfig
	CrawlDepth       int              // Maximum depth for crawling (default: 2)
	Concurrency      int              // Number of concurrent workers for crawling (default: 5)
	ScanConcurrency  int              // Number of concurrent workers for scanning discovered targets (default: 5)
	Discover         bool             // Enable discovery mode
	ProgressCallback ProgressCallback // Optional callback to report progress
}

// ExecuteDiscoveryScan performs crawl-then-scan workflow.
// It first crawls the target to discover forms and links with query parameters,
// then scans all discovered endpoints.
func ExecuteDiscoveryScan(ctx context.Context, cfg DiscoveryScanConfig) (*UnifiedScanResult, *ScanStats) {
	// Set default crawl depth if not specified
	if cfg.CrawlDepth <= 0 {
		cfg.CrawlDepth = 2
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.ScanConcurrency <= 0 {
		cfg.ScanConcurrency = 5
	}

	// Create crawler with configured options
	crawlerOpts := []crawler.Option{
		crawler.WithMaxDepth(cfg.CrawlDepth),
		crawler.WithTimeout(time.Duration(cfg.Timeout) * time.Second),
		crawler.WithUserAgent("WAST/1.0 (Web Application Security Testing)"),
		crawler.WithRespectRobots(false),
		crawler.WithConcurrency(cfg.Concurrency),
		// Exclude session-destructive endpoints. Visiting a logout URL during
		// crawl would invalidate the authenticated session (PHPSESSID) used by
		// all subsequent scanners, causing auth-gated vulnerabilities to go
		// undetected because every scanner request would be redirected to the
		// login page.
		crawler.WithExcludedURLPatterns([]string{
			"logout", "log-out", "logoff", "log-off", "signout", "sign-out",
		}),
	}

	// Add authentication if configured
	if cfg.AuthConfig != nil && !cfg.AuthConfig.IsEmpty() {
		crawlerOpts = append(crawlerOpts, crawler.WithAuth(cfg.AuthConfig))
	}

	// Add shared HTTP client if configured so the crawler uses the same cookie jar
	// as the rest of the scan pipeline. Go's http.Client does not copy Cookie headers
	// to redirect requests — only cookie jar cookies are sent automatically on
	// redirects — so passing the shared client here ensures authenticated session
	// state is maintained throughout the crawl phase.
	if cfg.HTTPClient != nil {
		crawlerOpts = append(crawlerOpts, crawler.WithHTTPClient(cfg.HTTPClient))
	}

	// Add rate limiting if configured
	if cfg.RateLimitConfig.IsEnabled() {
		crawlerOpts = append(crawlerOpts, crawler.WithRateLimitConfig(cfg.RateLimitConfig))
	}

	// Add tracer if configured
	if cfg.Tracer != nil {
		crawlerOpts = append(crawlerOpts, crawler.WithTracer(cfg.Tracer))
	}

	// Add progress callback for crawling phase
	if cfg.ProgressCallback != nil {
		crawlerOpts = append(crawlerOpts, crawler.WithProgressCallback(func(visited, discovered int, phase string) {
			cfg.ProgressCallback(visited, 0, "crawling")
		}))
	}

	c := crawler.NewCrawler(crawlerOpts...)

	// Perform the crawl
	crawlCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Timeout*cfg.CrawlDepth+60)*time.Second)
	defer cancel()

	crawlResult := c.Crawl(crawlCtx, cfg.Target)

	// Extract discovered targets from crawl results
	targets := extractDiscoveredTargets(cfg.Target, crawlResult)

	// Scan all discovered targets
	return scanDiscoveredTargets(ctx, cfg.ScanConfig, targets, cfg.ScanConcurrency, cfg.ProgressCallback, crawlResult)
}

// extractDiscoveredTargets extracts scannable targets from crawl results.
func extractDiscoveredTargets(baseTarget string, result *crawler.CrawlResult) []DiscoveredTarget {
	targets := make([]DiscoveredTarget, 0)
	seen := make(map[string]bool)

	// Extract from forms
	for _, form := range result.Forms {
		// Skip empty form actions
		if form.Action == "" {
			continue
		}

		// Build parameters from form fields
		params := make(map[string]string)
		for _, field := range form.Fields {
			// Skip password, file, hidden, and action-button fields.
			// Submit/button/reset/image inputs are action triggers, not data
			// fields, and should never be used as injection targets.  More
			// importantly, some forms (e.g. DVWA's CSRF page) rely on the
			// presence of a submit-button name parameter to trigger side-effects
			// (password changes).  Scanning those forms while omitting the
			// actual data fields but retaining the submit button would trigger
			// the side effect with empty data values – e.g. changing the admin
			// password to MD5(''), which breaks all subsequent login attempts.
			if field.Type == "password" || field.Type == "file" || field.Type == "hidden" ||
				field.Type == "submit" || field.Type == "button" || field.Type == "reset" || field.Type == "image" {
				continue
			}
			// Skip fields whose name suggests they are password fields regardless of
			// input type.  Some apps (e.g. DVWA's CSRF page) use type="text" for
			// password fields to demonstrate vulnerabilities.  Submitting injection
			// payloads to those fields causes real side-effects (e.g. changing the
			// account password), which invalidates authenticated sessions used by
			// subsequent scanner requests and test cases.
			fieldNameLower := strings.ToLower(field.Name)
			if strings.Contains(fieldNameLower, "password") || strings.Contains(fieldNameLower, "passwd") {
				continue
			}
			if field.Name != "" {
				params[field.Name] = field.Value
			}
		}

		// Only add if there are testable parameters
		if len(params) > 0 {
			key := fmt.Sprintf("%s:%s", form.Action, form.Method)
			if !seen[key] {
				seen[key] = true
				targets = append(targets, DiscoveredTarget{
					URL:        form.Action,
					Method:     form.Method,
					Parameters: params,
					Source:     fmt.Sprintf("form on %s", form.Page),
				})
			}
		}
	}

	// Extract from internal links with query parameters
	for _, link := range result.InternalLinks {
		parsedURL, err := url.Parse(link.URL)
		if err != nil {
			continue
		}

		queryParams := parsedURL.Query()
		if len(queryParams) == 0 {
			continue
		}

		// Build parameters map from query string
		params := make(map[string]string)
		for paramName, values := range queryParams {
			if len(values) > 0 {
				params[paramName] = values[0]
			} else {
				params[paramName] = ""
			}
		}

		key := fmt.Sprintf("%s:GET", link.URL)
		if !seen[key] {
			seen[key] = true
			targets = append(targets, DiscoveredTarget{
				URL:        link.URL,
				Method:     "GET",
				Parameters: params,
				Source:     "internal link with query parameters",
			})
		}
	}

	return targets
}

// scanDiscoveredTargets scans all discovered targets and aggregates results.
func scanDiscoveredTargets(ctx context.Context, cfg ScanConfig, targets []DiscoveredTarget, scanConcurrency int, progressCallback ProgressCallback, crawlResult *crawler.CrawlResult) (*UnifiedScanResult, *ScanStats) {
	// If no targets discovered, fall back to scanning the base target
	if len(targets) == 0 {
		return ExecuteScan(ctx, cfg)
	}

	// Track completed scans for progress reporting
	var completedScans int
	totalTargets := len(targets)
	var progressMutex sync.Mutex

	// Create scanner options
	headerOpts := []Option{
		WithTimeout(time.Duration(cfg.Timeout) * time.Second),
	}
	xssOpts := []XSSOption{
		WithXSSTimeout(time.Duration(cfg.Timeout) * time.Second),
	}
	sqliOpts := []SQLiOption{
		WithSQLiTimeout(time.Duration(cfg.Timeout) * time.Second),
	}
	nosqliOpts := []NoSQLiOption{
		WithNoSQLiTimeout(time.Duration(cfg.Timeout) * time.Second),
	}
	csrfOpts := []CSRFOption{
		WithCSRFTimeout(time.Duration(cfg.Timeout) * time.Second),
	}
	ssrfOpts := []SSRFOption{
		WithSSRFTimeout(time.Duration(cfg.Timeout) * time.Second),
		WithSSRFOnlyProvidedParams(true), // Only test discovered parameters from crawl, don't invent parameters
	}
	redirectOpts := []RedirectOption{
		WithRedirectTimeout(time.Duration(cfg.Timeout) * time.Second),
	}
	cmdiOpts := []CMDiOption{
		WithCMDiTimeout(time.Duration(cfg.Timeout) * time.Second),
	}
	pathtraversalOpts := []PathTraversalOption{
		WithPathTraversalTimeout(time.Duration(cfg.Timeout) * time.Second),
	}
	sstiOpts := []SSTIOption{
		WithSSTITimeout(time.Duration(cfg.Timeout) * time.Second),
	}
	xxeOpts := []XXEOption{
		WithXXETimeout(time.Duration(cfg.Timeout) * time.Second),
	}

	// Add authentication if configured
	if cfg.AuthConfig != nil && !cfg.AuthConfig.IsEmpty() {
		headerOpts = append(headerOpts, WithAuth(cfg.AuthConfig))
		xssOpts = append(xssOpts, WithXSSAuth(cfg.AuthConfig))
		sqliOpts = append(sqliOpts, WithSQLiAuth(cfg.AuthConfig))
		nosqliOpts = append(nosqliOpts, WithNoSQLiAuth(cfg.AuthConfig))
		csrfOpts = append(csrfOpts, WithCSRFAuth(cfg.AuthConfig))
		ssrfOpts = append(ssrfOpts, WithSSRFAuth(cfg.AuthConfig))
		redirectOpts = append(redirectOpts, WithRedirectAuth(cfg.AuthConfig))
		cmdiOpts = append(cmdiOpts, WithCMDiAuth(cfg.AuthConfig))
		pathtraversalOpts = append(pathtraversalOpts, WithPathTraversalAuth(cfg.AuthConfig))
		sstiOpts = append(sstiOpts, WithSSTIAuth(cfg.AuthConfig))
		xxeOpts = append(xxeOpts, WithXXEAuth(cfg.AuthConfig))
	}

	// Propagate shared HTTP client (with cookie jar) to all scanners when provided.
	// This ensures session cookies (e.g. PHPSESSID) and rotating CSRF tokens are
	// handled correctly across all scanner invocations instead of using stale
	// per-request Cookie headers.
	if cfg.HTTPClient != nil {
		headerOpts = append(headerOpts, WithHTTPClient(cfg.HTTPClient))
		xssOpts = append(xssOpts, WithXSSHTTPClient(cfg.HTTPClient))
		sqliOpts = append(sqliOpts, WithSQLiHTTPClient(cfg.HTTPClient))
		nosqliOpts = append(nosqliOpts, WithNoSQLiHTTPClient(cfg.HTTPClient))
		csrfOpts = append(csrfOpts, WithCSRFHTTPClient(cfg.HTTPClient))
		ssrfOpts = append(ssrfOpts, WithSSRFHTTPClient(cfg.HTTPClient))
		// The redirect scanner MUST use a no-redirect client: it detects open redirects
		// by inspecting raw 3xx status codes and Location headers. Passing the shared
		// client directly would silently disable redirect detection because the default
		// client follows redirects and the scanner would only ever see a final 200.
		// We share the cookie jar so session cookies remain valid, but override
		// CheckRedirect to prevent automatic redirect-following.
		noRedirectClient := &http.Client{
			Jar:     cfg.HTTPClient.Jar,
			Timeout: cfg.HTTPClient.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		redirectOpts = append(redirectOpts, WithRedirectHTTPClient(noRedirectClient))
		cmdiOpts = append(cmdiOpts, WithCMDiHTTPClient(cfg.HTTPClient))
		pathtraversalOpts = append(pathtraversalOpts, WithPathTraversalHTTPClient(cfg.HTTPClient))
		sstiOpts = append(sstiOpts, WithSSTIHTTPClient(cfg.HTTPClient))
		xxeOpts = append(xxeOpts, WithXXEHTTPClient(cfg.HTTPClient))
	}

	// Add rate limiting if configured
	if cfg.RateLimitConfig.IsEnabled() {
		headerOpts = append(headerOpts, WithRateLimitConfig(cfg.RateLimitConfig))
		xssOpts = append(xssOpts, WithXSSRateLimitConfig(cfg.RateLimitConfig))
		sqliOpts = append(sqliOpts, WithSQLiRateLimitConfig(cfg.RateLimitConfig))
		nosqliOpts = append(nosqliOpts, WithNoSQLiRateLimitConfig(cfg.RateLimitConfig))
		csrfOpts = append(csrfOpts, WithCSRFRateLimitConfig(cfg.RateLimitConfig))
		ssrfOpts = append(ssrfOpts, WithSSRFRateLimitConfig(cfg.RateLimitConfig))
		redirectOpts = append(redirectOpts, WithRedirectRateLimitConfig(cfg.RateLimitConfig))
		cmdiOpts = append(cmdiOpts, WithCMDiRateLimitConfig(cfg.RateLimitConfig))
		pathtraversalOpts = append(pathtraversalOpts, WithPathTraversalRateLimitConfig(cfg.RateLimitConfig))
		sstiOpts = append(sstiOpts, WithSSTIRateLimitConfig(cfg.RateLimitConfig))
		xxeOpts = append(xxeOpts, WithXXERateLimitConfig(cfg.RateLimitConfig))
	}

	// Add tracer if configured (for MCP)
	if cfg.Tracer != nil {
		headerOpts = append(headerOpts, WithTracer(cfg.Tracer))
		xssOpts = append(xssOpts, WithXSSTracer(cfg.Tracer))
		sqliOpts = append(sqliOpts, WithSQLiTracer(cfg.Tracer))
		nosqliOpts = append(nosqliOpts, WithNoSQLiTracer(cfg.Tracer))
		csrfOpts = append(csrfOpts, WithCSRFTracer(cfg.Tracer))
		ssrfOpts = append(ssrfOpts, WithSSRFTracer(cfg.Tracer))
		redirectOpts = append(redirectOpts, WithRedirectTracer(cfg.Tracer))
		cmdiOpts = append(cmdiOpts, WithCMDiTracer(cfg.Tracer))
		pathtraversalOpts = append(pathtraversalOpts, WithPathTraversalTracer(cfg.Tracer))
		sstiOpts = append(sstiOpts, WithSSTITracer(cfg.Tracer))
		xxeOpts = append(xxeOpts, WithXXETracer(cfg.Tracer))
	}

	// Add callback server if configured (for out-of-band XXE detection)
	if cfg.CallbackURL != "" {
		callbackServer := createCallbackServer(cfg.CallbackURL)
		if callbackServer != nil {
			xxeOpts = append(xxeOpts, WithXXECallbackServer(callbackServer))
		}
	}

	// Create scanners
	headerScanner := NewHTTPHeadersScanner(headerOpts...)

	// Perform header scan on base target only (not on every discovered URL)
	headerResult := headerScanner.Scan(ctx, cfg.Target)

	// Initialize aggregated result
	intermediateResult := IntermediateScanResult{
		Target:      cfg.Target,
		PassiveOnly: cfg.SafeMode,
		Headers:     headerResult,
		Errors:      make([]string, 0),
	}

	// Aggregate errors from header scan
	if len(headerResult.Errors) > 0 {
		intermediateResult.Errors = append(intermediateResult.Errors, headerResult.Errors...)
	}

	// Initialize stats
	stats := &ScanStats{}

	// Only perform active scans if safe mode is disabled
	if !cfg.SafeMode {
		xssScanner := NewXSSScanner(xssOpts...)
		sqliScanner := NewSQLiScanner(sqliOpts...)
		nosqliScanner := NewNoSQLiScanner(nosqliOpts...)
		csrfScanner := NewCSRFScanner(csrfOpts...)
		ssrfScanner := NewSSRFScanner(ssrfOpts...)
		redirectScanner := NewRedirectScanner(redirectOpts...)
		cmdiScanner := NewCMDiScanner(cmdiOpts...)
		pathtraversalScanner := NewPathTraversalScanner(pathtraversalOpts...)
		sstiScanner := NewSSTIScanner(sstiOpts...)
		xxeScanner := NewXXEScanner(xxeOpts...)

		// Aggregate findings from all targets
		allXSSFindings := make([]XSSFinding, 0)
		allSQLiFindings := make([]SQLiFinding, 0)
		allNoSQLiFindings := make([]NoSQLiFinding, 0)
		allCSRFFindings := make([]CSRFFinding, 0)
		allSSRFFindings := make([]SSRFFinding, 0)
		allRedirectFindings := make([]RedirectFinding, 0)
		allCMDiFindings := make([]CMDiFinding, 0)
		allPathTraversalFindings := make([]PathTraversalFinding, 0)
		allSSTIFindings := make([]SSTIFinding, 0)
		allXXEFindings := make([]XXEFinding, 0)
		var mu sync.Mutex

		// Create buffered channel for target distribution
		targetQueue := make(chan DiscoveredTarget, len(targets))

		// Create context for workers
		workerCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// WaitGroup to track active workers
		var wg sync.WaitGroup

		// Start worker pool for concurrent scanning
		for i := 0; i < scanConcurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for target := range targetQueue {
					// Check context cancellation
					select {
					case <-workerCtx.Done():
						return
					default:
					}

					// Scan this target with its discovered parameters
					xssResult := scanTargetForXSS(workerCtx, xssScanner, target)
					sqliResult := scanTargetForSQLi(workerCtx, sqliScanner, target)
					nosqliResult := scanTargetForNoSQLi(workerCtx, nosqliScanner, target)
					csrfResult := scanTargetForCSRF(workerCtx, csrfScanner, target)
					ssrfResult := scanTargetForSSRF(workerCtx, ssrfScanner, target)
					redirectResult := scanTargetForRedirect(workerCtx, redirectScanner, target)
					cmdiResult := scanTargetForCMDi(workerCtx, cmdiScanner, target)
					pathtraversalResult := scanTargetForPathTraversal(workerCtx, pathtraversalScanner, target)
					sstiResult := scanTargetForSSTI(workerCtx, sstiScanner, target)
					xxeResult := scanTargetForXXE(workerCtx, xxeScanner, target)

					// Add source information to findings
					for i := range xssResult.Findings {
						xssResult.Findings[i].Evidence = fmt.Sprintf("Source: %s | %s", target.Source, xssResult.Findings[i].Evidence)
					}
					for i := range sqliResult.Findings {
						sqliResult.Findings[i].Evidence = fmt.Sprintf("Source: %s | %s", target.Source, sqliResult.Findings[i].Evidence)
					}
					for i := range nosqliResult.Findings {
						nosqliResult.Findings[i].Evidence = fmt.Sprintf("Source: %s | %s", target.Source, nosqliResult.Findings[i].Evidence)
					}
					for i := range csrfResult.Findings {
						csrfResult.Findings[i].FormAction = target.URL
					}
					for i := range ssrfResult.Findings {
						ssrfResult.Findings[i].Evidence = fmt.Sprintf("Source: %s | %s", target.Source, ssrfResult.Findings[i].Evidence)
					}
					for i := range redirectResult.Findings {
						redirectResult.Findings[i].Evidence = fmt.Sprintf("Source: %s | %s", target.Source, redirectResult.Findings[i].Evidence)
					}
					for i := range cmdiResult.Findings {
						cmdiResult.Findings[i].Evidence = fmt.Sprintf("Source: %s | %s", target.Source, cmdiResult.Findings[i].Evidence)
					}
					for i := range pathtraversalResult.Findings {
						pathtraversalResult.Findings[i].Evidence = fmt.Sprintf("Source: %s | %s", target.Source, pathtraversalResult.Findings[i].Evidence)
					}
					for i := range sstiResult.Findings {
						sstiResult.Findings[i].Evidence = fmt.Sprintf("Source: %s | %s", target.Source, sstiResult.Findings[i].Evidence)
					}
					for i := range xxeResult.Findings {
						xxeResult.Findings[i].Evidence = fmt.Sprintf("Source: %s | %s", target.Source, xxeResult.Findings[i].Evidence)
					}

					// Thread-safe aggregation of findings and test counts
					mu.Lock()
					allXSSFindings = append(allXSSFindings, xssResult.Findings...)
					allSQLiFindings = append(allSQLiFindings, sqliResult.Findings...)
					allNoSQLiFindings = append(allNoSQLiFindings, nosqliResult.Findings...)
					allCSRFFindings = append(allCSRFFindings, csrfResult.Findings...)
					allSSRFFindings = append(allSSRFFindings, ssrfResult.Findings...)
					allRedirectFindings = append(allRedirectFindings, redirectResult.Findings...)
					allCMDiFindings = append(allCMDiFindings, cmdiResult.Findings...)
					allPathTraversalFindings = append(allPathTraversalFindings, pathtraversalResult.Findings...)
					allSSTIFindings = append(allSSTIFindings, sstiResult.Findings...)
					allXXEFindings = append(allXXEFindings, xxeResult.Findings...)

					// Accumulate test counts from each scanner's summary
					stats.TotalXSSTests += xssResult.Summary.TotalTests
					stats.TotalSQLiTests += sqliResult.Summary.TotalTests
					stats.TotalNoSQLiTests += nosqliResult.Summary.TotalTests
					stats.TotalCSRFTests += csrfResult.Summary.TotalFormsTested
					stats.TotalSSRFTests += ssrfResult.Summary.TotalTests
					stats.TotalRedirectTests += redirectResult.Summary.TotalTests
					stats.TotalCMDiTests += cmdiResult.Summary.TotalTests
					stats.TotalPathTraversalTests += pathtraversalResult.Summary.TotalTests
					stats.TotalSSTITests += sstiResult.Summary.TotalTests
					stats.TotalXXETests += xxeResult.Summary.TotalTests
					mu.Unlock()

					// Report progress if callback is set
					if progressCallback != nil {
						progressMutex.Lock()
						completedScans++
						currentCompleted := completedScans
						progressMutex.Unlock()
						progressCallback(currentCompleted, totalTargets, "scanning")
					}
				}
			}()
		}

		// Enqueue all targets
		for _, target := range targets {
			select {
			case <-ctx.Done():
				intermediateResult.Errors = append(intermediateResult.Errors, "Scan cancelled")
				close(targetQueue)
				wg.Wait()
				goto skipVerification
			case targetQueue <- target:
			}
		}
		close(targetQueue)

		// Wait for all workers to complete
		wg.Wait()

		// Check if context was cancelled during scanning
		if ctx.Err() != nil {
			mu.Lock()
			intermediateResult.Errors = append(intermediateResult.Errors, "Scan cancelled: "+ctx.Err().Error())
			mu.Unlock()
		}

	skipVerification:
		// Set findings counts from aggregated results (before verification filtering).
		// This ensures stats reflect actual findings regardless of VerifyFindings setting.
		stats.TotalXSSFindings = len(allXSSFindings)
		stats.TotalSQLiFindings = len(allSQLiFindings)
		stats.TotalNoSQLiFindings = len(allNoSQLiFindings)
		stats.TotalCSRFFindings = len(allCSRFFindings)
		stats.TotalSSRFFindings = len(allSSRFFindings)
		stats.TotalRedirectFindings = len(allRedirectFindings)
		stats.TotalCMDiFindings = len(allCMDiFindings)
		stats.TotalPathTraversalFindings = len(allPathTraversalFindings)
		stats.TotalSSTIFindings = len(allSSTIFindings)
		stats.TotalXXEFindings = len(allXXEFindings)

		// Create result structures with accumulated test counts
		xssResult := &XSSScanResult{
			Target:   cfg.Target,
			Findings: allXSSFindings,
			Summary: XSSSummary{
				TotalTests:           stats.TotalXSSTests,
				VulnerabilitiesFound: len(allXSSFindings),
			},
			Errors: []string{},
		}

		sqliResult := &SQLiScanResult{
			Target:   cfg.Target,
			Findings: allSQLiFindings,
			Summary: SQLiSummary{
				TotalTests:           stats.TotalSQLiTests,
				VulnerabilitiesFound: len(allSQLiFindings),
			},
			Errors: []string{},
		}

		nosqliResult := &NoSQLiScanResult{
			Target:   cfg.Target,
			Findings: allNoSQLiFindings,
			Summary: NoSQLiSummary{
				TotalTests:           stats.TotalNoSQLiTests,
				VulnerabilitiesFound: len(allNoSQLiFindings),
			},
			Errors: []string{},
		}

		csrfResult := &CSRFScanResult{
			Target:   cfg.Target,
			Findings: allCSRFFindings,
			Summary: CSRFSummary{
				TotalFormsTested: stats.TotalCSRFTests,
				VulnerableForms:  len(allCSRFFindings),
			},
			Errors: []string{},
		}

		ssrfResult := &SSRFScanResult{
			Target:   cfg.Target,
			Findings: allSSRFFindings,
			Summary: SSRFSummary{
				TotalTests:           stats.TotalSSRFTests,
				VulnerabilitiesFound: len(allSSRFFindings),
			},
			Errors: []string{},
		}

		redirectResult := &RedirectScanResult{
			Target:   cfg.Target,
			Findings: allRedirectFindings,
			Summary: RedirectSummary{
				TotalTests:           stats.TotalRedirectTests,
				VulnerabilitiesFound: len(allRedirectFindings),
			},
			Errors: []string{},
		}

		cmdiResult := &CMDiScanResult{
			Target:   cfg.Target,
			Findings: allCMDiFindings,
			Summary: CMDiSummary{
				TotalTests:           stats.TotalCMDiTests,
				VulnerabilitiesFound: len(allCMDiFindings),
			},
			Errors: []string{},
		}

		pathtraversalResult := &PathTraversalScanResult{
			Target:   cfg.Target,
			Findings: allPathTraversalFindings,
			Summary: PathTraversalSummary{
				TotalTests:           stats.TotalPathTraversalTests,
				VulnerabilitiesFound: len(allPathTraversalFindings),
			},
			Errors: []string{},
		}

		sstiResult := &SSTIScanResult{
			Target:   cfg.Target,
			Findings: allSSTIFindings,
			Summary: SSTISummary{
				TotalTests:           stats.TotalSSTITests,
				VulnerabilitiesFound: len(allSSTIFindings),
			},
			Errors: []string{},
		}

		xxeResult := &XXEScanResult{
			Target:   cfg.Target,
			Findings: allXXEFindings,
			Summary: XXESummary{
				TotalTests:           stats.TotalXXETests,
				VulnerabilitiesFound: len(allXXEFindings),
			},
			Errors: []string{},
		}

		// Verify findings if enabled
		if cfg.VerifyFindings {
			verifyConfig := VerificationConfig{
				Enabled:    true,
				MaxRetries: 3,
				Delay:      500 * time.Millisecond,
			}

			// Track findings before verification
			stats.TotalXSSFindings = len(xssResult.Findings)
			stats.TotalSQLiFindings = len(sqliResult.Findings)
			stats.TotalNoSQLiFindings = len(nosqliResult.Findings)
			stats.TotalCSRFFindings = len(csrfResult.Findings)
			stats.TotalSSRFFindings = len(ssrfResult.Findings)
			stats.TotalRedirectFindings = len(redirectResult.Findings)
			stats.TotalCMDiFindings = len(cmdiResult.Findings)
			stats.TotalPathTraversalFindings = len(pathtraversalResult.Findings)
			stats.TotalSSTIFindings = len(sstiResult.Findings)
			stats.TotalXXEFindings = len(xxeResult.Findings)

			// Verify findings (similar to ExecuteScan)
			// Verify XSS findings
			for i := range xssResult.Findings {
				result, err := xssScanner.VerifyFinding(ctx, &xssResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					xssResult.Findings[i].Verified = result.Verified
					xssResult.Findings[i].VerificationAttempts = result.Attempts
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
					if result.Verified && result.Confidence > 0.8 {
						sqliResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						sqliResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						sqliResult.Findings[i].Confidence = "low"
					}
				}
			}

			// Verify NoSQLi findings
			for i := range nosqliResult.Findings {
				result, err := nosqliScanner.VerifyFinding(ctx, &nosqliResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					nosqliResult.Findings[i].Verified = result.Verified
					nosqliResult.Findings[i].VerificationAttempts = result.Attempts
					if result.Verified && result.Confidence > 0.8 {
						nosqliResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						nosqliResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						nosqliResult.Findings[i].Confidence = "low"
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

			// Verify SSRF findings
			for i := range ssrfResult.Findings {
				result, err := ssrfScanner.VerifyFinding(ctx, &ssrfResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					ssrfResult.Findings[i].Verified = result.Verified
					ssrfResult.Findings[i].VerificationAttempts = result.Attempts
					if result.Verified && result.Confidence > 0.8 {
						ssrfResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						ssrfResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						ssrfResult.Findings[i].Confidence = "low"
					}
				}
			}

			// Verify Redirect findings
			for i := range redirectResult.Findings {
				result, err := redirectScanner.VerifyFinding(ctx, &redirectResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					redirectResult.Findings[i].Verified = result.Verified
					redirectResult.Findings[i].VerificationAttempts = result.Attempts
					if result.Verified && result.Confidence > 0.8 {
						redirectResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						redirectResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						redirectResult.Findings[i].Confidence = "low"
					}
				}
			}

			// Verify CMDi findings
			for i := range cmdiResult.Findings {
				result, err := cmdiScanner.VerifyFinding(ctx, &cmdiResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					cmdiResult.Findings[i].Verified = result.Verified
					cmdiResult.Findings[i].VerificationAttempts = result.Attempts
					if result.Verified && result.Confidence > 0.8 {
						cmdiResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						cmdiResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						cmdiResult.Findings[i].Confidence = "low"
					}
				}
			}

			// Verify PathTraversal findings
			for i := range pathtraversalResult.Findings {
				result, err := pathtraversalScanner.VerifyFinding(ctx, &pathtraversalResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					pathtraversalResult.Findings[i].Verified = result.Verified
					pathtraversalResult.Findings[i].VerificationAttempts = result.Attempts
					if result.Verified && result.Confidence > 0.8 {
						pathtraversalResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						pathtraversalResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						pathtraversalResult.Findings[i].Confidence = "low"
					}
				}
			}

			// Verify SSTI findings
			for i := range sstiResult.Findings {
				result, err := sstiScanner.VerifyFinding(ctx, &sstiResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					sstiResult.Findings[i].Verified = result.Verified
					if result.Verified && result.Confidence > 0.8 {
						sstiResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						sstiResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						sstiResult.Findings[i].Confidence = "low"
					}
				}
			}

			// Verify XXE findings
			for i := range xxeResult.Findings {
				result, err := xxeScanner.VerifyFinding(ctx, &xxeResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					xxeResult.Findings[i].Verified = result.Verified
					xxeResult.Findings[i].VerificationAttempts = result.Attempts
					if result.Verified && result.Confidence > 0.8 {
						xxeResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						xxeResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						xxeResult.Findings[i].Confidence = "low"
					}
				}
			}

			// Filter out unverified findings
			verifiedXSSFindings := make([]XSSFinding, 0)
			for _, finding := range xssResult.Findings {
				if finding.Verified {
					verifiedXSSFindings = append(verifiedXSSFindings, finding)
				}
			}
			xssResult.Findings = verifiedXSSFindings
			xssResult.Summary.VulnerabilitiesFound = len(verifiedXSSFindings)

			verifiedSQLiFindings := make([]SQLiFinding, 0)
			for _, finding := range sqliResult.Findings {
				if finding.Verified {
					verifiedSQLiFindings = append(verifiedSQLiFindings, finding)
				}
			}
			sqliResult.Findings = verifiedSQLiFindings
			sqliResult.Summary.VulnerabilitiesFound = len(verifiedSQLiFindings)

			verifiedNoSQLiFindings := make([]NoSQLiFinding, 0)
			for _, finding := range nosqliResult.Findings {
				if finding.Verified {
					verifiedNoSQLiFindings = append(verifiedNoSQLiFindings, finding)
				}
			}
			nosqliResult.Findings = verifiedNoSQLiFindings
			nosqliResult.Summary.VulnerabilitiesFound = len(verifiedNoSQLiFindings)

			verifiedCSRFFindings := make([]CSRFFinding, 0)
			for _, finding := range csrfResult.Findings {
				if finding.Verified {
					verifiedCSRFFindings = append(verifiedCSRFFindings, finding)
				}
			}
			csrfResult.Findings = verifiedCSRFFindings
			csrfResult.Summary.VulnerableForms = len(verifiedCSRFFindings)

			verifiedSSRFFindings := make([]SSRFFinding, 0)
			for _, finding := range ssrfResult.Findings {
				if finding.Verified {
					verifiedSSRFFindings = append(verifiedSSRFFindings, finding)
				}
			}
			ssrfResult.Findings = verifiedSSRFFindings
			ssrfResult.Summary.VulnerabilitiesFound = len(verifiedSSRFFindings)

			verifiedRedirectFindings := make([]RedirectFinding, 0)
			for _, finding := range redirectResult.Findings {
				if finding.Verified {
					verifiedRedirectFindings = append(verifiedRedirectFindings, finding)
				}
			}
			redirectResult.Findings = verifiedRedirectFindings
			redirectResult.Summary.VulnerabilitiesFound = len(verifiedRedirectFindings)

			verifiedCMDiFindings := make([]CMDiFinding, 0)
			for _, finding := range cmdiResult.Findings {
				if finding.Verified {
					verifiedCMDiFindings = append(verifiedCMDiFindings, finding)
				}
			}
			cmdiResult.Findings = verifiedCMDiFindings
			cmdiResult.Summary.VulnerabilitiesFound = len(verifiedCMDiFindings)

			verifiedPathTraversalFindings := make([]PathTraversalFinding, 0)
			for _, finding := range pathtraversalResult.Findings {
				if finding.Verified {
					verifiedPathTraversalFindings = append(verifiedPathTraversalFindings, finding)
				}
			}
			pathtraversalResult.Findings = verifiedPathTraversalFindings
			pathtraversalResult.Summary.VulnerabilitiesFound = len(verifiedPathTraversalFindings)

			verifiedSSTIFindings := make([]SSTIFinding, 0)
			for _, finding := range sstiResult.Findings {
				if finding.Verified {
					verifiedSSTIFindings = append(verifiedSSTIFindings, finding)
				}
			}
			sstiResult.Findings = verifiedSSTIFindings
			sstiResult.Summary.VulnerabilitiesFound = len(verifiedSSTIFindings)

			verifiedXXEFindings := make([]XXEFinding, 0)
			for _, finding := range xxeResult.Findings {
				if finding.Verified {
					verifiedXXEFindings = append(verifiedXXEFindings, finding)
				}
			}
			xxeResult.Findings = verifiedXXEFindings
			xxeResult.Summary.VulnerabilitiesFound = len(verifiedXXEFindings)
		}

		intermediateResult.XSS = xssResult
		intermediateResult.SQLi = sqliResult
		intermediateResult.NoSQLi = nosqliResult
		intermediateResult.CSRF = csrfResult
		intermediateResult.SSRF = ssrfResult
		intermediateResult.Redirect = redirectResult
		intermediateResult.CMDi = cmdiResult
		intermediateResult.PathTraversal = pathtraversalResult
		intermediateResult.SSTI = sstiResult
		intermediateResult.XXE = xxeResult
	}

	// Perform WebSocket detection and scanning
	var websocketResult *WebSocketScanResult
	detectorOpts := []websocket.DetectorOption{
		websocket.WithDetectorTimeout(time.Duration(cfg.Timeout) * time.Second),
	}
	if cfg.AuthConfig != nil && !cfg.AuthConfig.IsEmpty() {
		detectorOpts = append(detectorOpts, websocket.WithDetectorAuth(cfg.AuthConfig))
	}
	if cfg.RateLimitConfig.IsEnabled() {
		limiter := ratelimit.NewLimiterFromConfig(cfg.RateLimitConfig)
		detectorOpts = append(detectorOpts, websocket.WithDetectorRateLimiter(limiter))
	}
	if cfg.Tracer != nil {
		detectorOpts = append(detectorOpts, websocket.WithDetectorTracer(cfg.Tracer))
	}

	detector := websocket.NewDetector(detectorOpts...)
	detectionResult := detector.Detect(ctx, crawlResult)

	// Build scanner options
	scannerOpts := []websocket.ScannerOption{
		websocket.WithScannerTimeout(time.Duration(cfg.Timeout) * time.Second),
		websocket.WithActiveMode(!cfg.SafeMode), // Active mode if not in safe mode
	}
	if cfg.AuthConfig != nil && !cfg.AuthConfig.IsEmpty() {
		scannerOpts = append(scannerOpts, websocket.WithScannerAuth(cfg.AuthConfig))
	}
	if cfg.RateLimitConfig.IsEnabled() {
		limiter := ratelimit.NewLimiterFromConfig(cfg.RateLimitConfig)
		scannerOpts = append(scannerOpts, websocket.WithScannerRateLimiter(limiter))
	}
	if cfg.Tracer != nil {
		scannerOpts = append(scannerOpts, websocket.WithScannerTracer(cfg.Tracer))
	}

	// Scan detected WebSocket endpoints
	securityScanner := websocket.NewSecurityScanner(scannerOpts...)
	wsScanResult := securityScanner.Scan(ctx, detectionResult)

	// Convert to aggregator-compatible format
	websocketResult = &WebSocketScanResult{
		Findings: make([]WebSocketFinding, len(wsScanResult.Findings)),
		Summary: WebSocketSummary{
			TotalEndpoints:      wsScanResult.Summary.TotalEndpoints,
			VulnerableEndpoints: wsScanResult.Summary.VulnerableEndpoints,
			HighSeverityCount:   wsScanResult.Summary.HighSeverityCount,
			MediumSeverityCount: wsScanResult.Summary.MediumSeverityCount,
			LowSeverityCount:    wsScanResult.Summary.LowSeverityCount,
		},
	}

	// Copy findings
	for i, finding := range wsScanResult.Findings {
		websocketResult.Findings[i] = WebSocketFinding{
			URL:         finding.URL,
			FindingType: finding.FindingType,
			Severity:    finding.Severity,
			Description: finding.Description,
			Confidence:  finding.Confidence,
			RuleID:      finding.RuleID,
		}
	}

	// Create unified result
	unifiedResult := NewUnifiedScanResult(
		cfg.Target,
		cfg.SafeMode,
		intermediateResult.Headers,
		intermediateResult.XSS,
		intermediateResult.SQLi,
		intermediateResult.NoSQLi,
		intermediateResult.CSRF,
		intermediateResult.SSRF,
		intermediateResult.Redirect,
		intermediateResult.CMDi,
		intermediateResult.PathTraversal,
		intermediateResult.SSTI,
		intermediateResult.XXE,
		websocketResult,
		intermediateResult.Errors,
	)

	return unifiedResult, stats
}

// buildURLWithParams constructs a URL with discovered parameters embedded as query params.
// This ensures scanners test the actual parameters found during crawling instead of
// falling back to invented/guessed parameter names.
func buildURLWithParams(target DiscoveredTarget) string {
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return target.URL
	}

	// Strip fragment (e.g., "#" from form action="#") — it's not sent to the server
	parsedURL.Fragment = ""

	if len(target.Parameters) == 0 {
		return parsedURL.String()
	}

	// Merge discovered parameters into the URL's query string.
	// Existing query params from the URL take precedence.
	q := parsedURL.Query()
	for name, value := range target.Parameters {
		if _, exists := q[name]; !exists {
			if value == "" {
				value = "1"
			}
			q.Set(name, value)
		}
	}
	parsedURL.RawQuery = q.Encode()

	return parsedURL.String()
}

// scanTargetForXSS scans a single discovered target for XSS vulnerabilities.
func scanTargetForXSS(ctx context.Context, scanner *XSSScanner, target DiscoveredTarget) *XSSScanResult {
	// Route based on HTTP method
	if strings.EqualFold(target.Method, "POST") {
		return scanner.ScanPOST(ctx, target.URL, target.Parameters)
	}
	// Default to GET
	targetURL := buildURLWithParams(target)
	return scanner.Scan(ctx, targetURL)
}

// scanTargetForSQLi scans a single discovered target for SQL injection vulnerabilities.
func scanTargetForSQLi(ctx context.Context, scanner *SQLiScanner, target DiscoveredTarget) *SQLiScanResult {
	// Route based on HTTP method
	if strings.EqualFold(target.Method, "POST") {
		return scanner.ScanPOST(ctx, target.URL, target.Parameters)
	}
	// Default to GET
	targetURL := buildURLWithParams(target)
	return scanner.Scan(ctx, targetURL)
}

// scanTargetForNoSQLi scans a single discovered target for NoSQL injection vulnerabilities.
func scanTargetForNoSQLi(ctx context.Context, scanner *NoSQLiScanner, target DiscoveredTarget) *NoSQLiScanResult {
	// Route based on HTTP method
	if strings.EqualFold(target.Method, "POST") {
		return scanner.ScanPOST(ctx, target.URL, target.Parameters)
	}
	// Default to GET
	targetURL := buildURLWithParams(target)
	return scanner.Scan(ctx, targetURL)
}

// scanTargetForCSRF scans a single discovered target for CSRF vulnerabilities.
func scanTargetForCSRF(ctx context.Context, scanner *CSRFScanner, target DiscoveredTarget) *CSRFScanResult {
	// Only scan POST forms for CSRF
	if !strings.EqualFold(target.Method, "POST") {
		return &CSRFScanResult{
			Target:   target.URL,
			Findings: []CSRFFinding{},
			Summary:  CSRFSummary{},
			Errors:   []string{},
		}
	}

	// Parse URL to get the page that contains the form
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return &CSRFScanResult{
			Target:   target.URL,
			Findings: []CSRFFinding{},
			Summary:  CSRFSummary{},
			Errors:   []string{},
		}
	}

	// Scan the page containing the form
	return scanner.Scan(ctx, fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path))
}

// scanTargetForSSRF scans a single discovered target for SSRF vulnerabilities.
func scanTargetForSSRF(ctx context.Context, scanner *SSRFScanner, target DiscoveredTarget) *SSRFScanResult {
	// Route based on HTTP method
	if strings.EqualFold(target.Method, "POST") {
		return scanner.ScanPOST(ctx, target.URL, target.Parameters)
	}
	// Default to GET
	targetURL := buildURLWithParams(target)
	return scanner.Scan(ctx, targetURL)
}

// scanTargetForRedirect scans a single discovered target for Open Redirect vulnerabilities.
func scanTargetForRedirect(ctx context.Context, scanner *RedirectScanner, target DiscoveredTarget) *RedirectScanResult {
	// Route based on HTTP method
	if strings.EqualFold(target.Method, "POST") {
		return scanner.ScanPOST(ctx, target.URL, target.Parameters)
	}
	// Default to GET
	targetURL := buildURLWithParams(target)
	return scanner.Scan(ctx, targetURL)
}

// scanTargetForCMDi scans a single discovered target for Command Injection vulnerabilities.
func scanTargetForCMDi(ctx context.Context, scanner *CMDiScanner, target DiscoveredTarget) *CMDiScanResult {
	// Route based on HTTP method
	if strings.EqualFold(target.Method, "POST") {
		return scanner.ScanPOST(ctx, target.URL, target.Parameters)
	}
	// Default to GET
	targetURL := buildURLWithParams(target)
	return scanner.Scan(ctx, targetURL)
}

// scanTargetForPathTraversal scans a single discovered target for Path Traversal vulnerabilities.
func scanTargetForPathTraversal(ctx context.Context, scanner *PathTraversalScanner, target DiscoveredTarget) *PathTraversalScanResult {
	// Route based on HTTP method
	if strings.EqualFold(target.Method, "POST") {
		return scanner.ScanPOST(ctx, target.URL, target.Parameters)
	}
	// Default to GET
	targetURL := buildURLWithParams(target)
	return scanner.Scan(ctx, targetURL)
}

// scanTargetForSSTI scans a single discovered target for SSTI vulnerabilities.
func scanTargetForSSTI(ctx context.Context, scanner *SSTIScanner, target DiscoveredTarget) *SSTIScanResult {
	// Route based on HTTP method
	if strings.EqualFold(target.Method, "POST") {
		return scanner.ScanPOST(ctx, target.URL, target.Parameters)
	}
	// Default to GET
	targetURL := buildURLWithParams(target)
	return scanner.Scan(ctx, targetURL)
}

// scanTargetForXXE scans a single discovered target for XXE vulnerabilities.
func scanTargetForXXE(ctx context.Context, scanner *XXEScanner, target DiscoveredTarget) *XXEScanResult {
	// XXE scanner discovers XML endpoints internally; provide the base URL with params
	targetURL := buildURLWithParams(target)
	return scanner.Scan(ctx, targetURL)
}
