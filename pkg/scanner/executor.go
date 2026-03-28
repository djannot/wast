// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/callback"
	"github.com/djannot/wast/pkg/ratelimit"
	"go.opentelemetry.io/otel/trace"
)

// ScanConfig encapsulates all parameters needed for scan execution.
type ScanConfig struct {
	Target          string
	Timeout         int
	SafeMode        bool
	VerifyFindings  bool
	AuthConfig      *auth.AuthConfig
	RateLimitConfig ratelimit.Config
	Tracer          trace.Tracer // optional, for MCP tracing
	CallbackURL     string       // optional, for out-of-band SSRF detection
}

// IntermediateScanResult represents the combined results of all security scans
// before creating the unified result.
type IntermediateScanResult struct {
	Target        string
	PassiveOnly   bool
	Headers       *HeaderScanResult
	XSS           *XSSScanResult
	SQLi          *SQLiScanResult
	CSRF          *CSRFScanResult
	SSRF          *SSRFScanResult
	Redirect      *RedirectScanResult
	CMDi          *CMDiScanResult
	PathTraversal *PathTraversalScanResult
	SSTI          *SSTIScanResult
	XXE           *XXEScanResult
	Errors        []string
}

// ScanStats tracks statistics about the verification process.
type ScanStats struct {
	TotalXSSFindings           int
	TotalSQLiFindings          int
	TotalCSRFFindings          int
	TotalSSRFFindings          int
	TotalRedirectFindings      int
	TotalCMDiFindings          int
	TotalPathTraversalFindings int
	TotalSSTIFindings          int
	TotalXXEFindings           int
	TotalXSSTests              int
	TotalSQLiTests             int
	TotalCSRFTests             int
	TotalSSRFTests             int
	TotalRedirectTests         int
	TotalCMDiTests             int
	TotalPathTraversalTests    int
	TotalSSTITests             int
	TotalXXETests              int
}

// ExecuteScan performs the complete scan workflow.
// It orchestrates the execution of all security scans (headers, XSS, SQLi, CSRF, SSRF),
// performs verification if enabled, and returns a unified result.
func ExecuteScan(ctx context.Context, cfg ScanConfig) (*UnifiedScanResult, *ScanStats) {
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
	csrfOpts := []CSRFOption{
		WithCSRFTimeout(time.Duration(cfg.Timeout) * time.Second),
	}
	ssrfOpts := []SSRFOption{
		WithSSRFTimeout(time.Duration(cfg.Timeout) * time.Second),
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
		csrfOpts = append(csrfOpts, WithCSRFAuth(cfg.AuthConfig))
		ssrfOpts = append(ssrfOpts, WithSSRFAuth(cfg.AuthConfig))
		redirectOpts = append(redirectOpts, WithRedirectAuth(cfg.AuthConfig))
		cmdiOpts = append(cmdiOpts, WithCMDiAuth(cfg.AuthConfig))
		pathtraversalOpts = append(pathtraversalOpts, WithPathTraversalAuth(cfg.AuthConfig))
		sstiOpts = append(sstiOpts, WithSSTIAuth(cfg.AuthConfig))
		xxeOpts = append(xxeOpts, WithXXEAuth(cfg.AuthConfig))
	}

	// Add rate limiting if configured
	if cfg.RateLimitConfig.IsEnabled() {
		headerOpts = append(headerOpts, WithRateLimitConfig(cfg.RateLimitConfig))
		xssOpts = append(xssOpts, WithXSSRateLimitConfig(cfg.RateLimitConfig))
		sqliOpts = append(sqliOpts, WithSQLiRateLimitConfig(cfg.RateLimitConfig))
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
		csrfOpts = append(csrfOpts, WithCSRFTracer(cfg.Tracer))
		ssrfOpts = append(ssrfOpts, WithSSRFTracer(cfg.Tracer))
		redirectOpts = append(redirectOpts, WithRedirectTracer(cfg.Tracer))
		cmdiOpts = append(cmdiOpts, WithCMDiTracer(cfg.Tracer))
		pathtraversalOpts = append(pathtraversalOpts, WithPathTraversalTracer(cfg.Tracer))
		sstiOpts = append(sstiOpts, WithSSTITracer(cfg.Tracer))
		xxeOpts = append(xxeOpts, WithXXETracer(cfg.Tracer))
	}

	// Add callback server if configured (for out-of-band SSRF and XXE detection)
	if cfg.CallbackURL != "" {
		// Parse callback URL to create callback server configuration
		callbackServer := createCallbackServer(cfg.CallbackURL)
		if callbackServer != nil {
			ssrfOpts = append(ssrfOpts, WithSSRFCallbackServer(callbackServer))
			xxeOpts = append(xxeOpts, WithXXECallbackServer(callbackServer))
		}
	}

	// Create scanners
	headerScanner := NewHTTPHeadersScanner(headerOpts...)

	// Perform the header scan
	headerResult := headerScanner.Scan(ctx, cfg.Target)

	// Initialize result structure
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
		csrfScanner := NewCSRFScanner(csrfOpts...)
		ssrfScanner := NewSSRFScanner(ssrfOpts...)
		redirectScanner := NewRedirectScanner(redirectOpts...)
		cmdiScanner := NewCMDiScanner(cmdiOpts...)
		pathtraversalScanner := NewPathTraversalScanner(pathtraversalOpts...)
		sstiScanner := NewSSTIScanner(sstiOpts...)
		xxeScanner := NewXXEScanner(xxeOpts...)

		var wg sync.WaitGroup
		var xssResult *XSSScanResult
		var sqliResult *SQLiScanResult
		var csrfResult *CSRFScanResult
		var ssrfResult *SSRFScanResult
		var redirectResult *RedirectScanResult
		var cmdiResult *CMDiScanResult
		var pathtraversalResult *PathTraversalScanResult
		var sstiResult *SSTIScanResult
		var xxeResult *XXEScanResult

		// Run scans in parallel
		wg.Add(9)
		go func() {
			defer wg.Done()
			xssResult = xssScanner.Scan(ctx, cfg.Target)
		}()
		go func() {
			defer wg.Done()
			sqliResult = sqliScanner.Scan(ctx, cfg.Target)
		}()
		go func() {
			defer wg.Done()
			csrfResult = csrfScanner.Scan(ctx, cfg.Target)
		}()
		go func() {
			defer wg.Done()
			ssrfResult = ssrfScanner.Scan(ctx, cfg.Target)
		}()
		go func() {
			defer wg.Done()
			redirectResult = redirectScanner.Scan(ctx, cfg.Target)
		}()
		go func() {
			defer wg.Done()
			cmdiResult = cmdiScanner.Scan(ctx, cfg.Target)
		}()
		go func() {
			defer wg.Done()
			pathtraversalResult = pathtraversalScanner.Scan(ctx, cfg.Target)
		}()
		go func() {
			defer wg.Done()
			sstiResult = sstiScanner.Scan(ctx, cfg.Target)
		}()
		go func() {
			defer wg.Done()
			xxeResult = xxeScanner.Scan(ctx, cfg.Target)
		}()
		wg.Wait()

		// Verify findings if enabled
		if cfg.VerifyFindings {
			verifyConfig := VerificationConfig{
				Enabled:    true,
				MaxRetries: 3,
				Delay:      500 * time.Millisecond,
			}

			// Track findings before verification for reporting
			stats.TotalXSSFindings = len(xssResult.Findings)
			stats.TotalSQLiFindings = len(sqliResult.Findings)
			stats.TotalCSRFFindings = len(csrfResult.Findings)
			stats.TotalSSRFFindings = len(ssrfResult.Findings)
			stats.TotalRedirectFindings = len(redirectResult.Findings)
			stats.TotalCMDiFindings = len(cmdiResult.Findings)
			stats.TotalPathTraversalFindings = len(pathtraversalResult.Findings)
			stats.TotalSSTIFindings = len(sstiResult.Findings)
			stats.TotalXXEFindings = len(xxeResult.Findings)

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
			// Note: CSRF findings don't have a confidence field like other vulnerability types
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

			// Verify Redirect findings
			for i := range redirectResult.Findings {
				result, err := redirectScanner.VerifyFinding(ctx, &redirectResult.Findings[i], verifyConfig)
				if err == nil && result != nil {
					redirectResult.Findings[i].Verified = result.Verified
					redirectResult.Findings[i].VerificationAttempts = result.Attempts
					// Update confidence based on verification
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
					// Update confidence based on verification
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
					// Update confidence based on verification
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
					// Update confidence based on verification
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
					// Update confidence based on verification
					if result.Verified && result.Confidence > 0.8 {
						xxeResult.Findings[i].Confidence = "high"
					} else if result.Verified && result.Confidence > 0.5 {
						xxeResult.Findings[i].Confidence = "medium"
					} else if !result.Verified {
						xxeResult.Findings[i].Confidence = "low"
					}
				}
			}

			// Filter out unverified findings when verification is enabled
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
		intermediateResult.CSRF = csrfResult
		intermediateResult.SSRF = ssrfResult
		intermediateResult.Redirect = redirectResult
		intermediateResult.CMDi = cmdiResult
		intermediateResult.PathTraversal = pathtraversalResult
		intermediateResult.SSTI = sstiResult
		intermediateResult.XXE = xxeResult

		// Aggregate errors from active scans
		if len(xssResult.Errors) > 0 {
			intermediateResult.Errors = append(intermediateResult.Errors, xssResult.Errors...)
		}
		if len(sqliResult.Errors) > 0 {
			intermediateResult.Errors = append(intermediateResult.Errors, sqliResult.Errors...)
		}
		if len(csrfResult.Errors) > 0 {
			intermediateResult.Errors = append(intermediateResult.Errors, csrfResult.Errors...)
		}
		if len(ssrfResult.Errors) > 0 {
			intermediateResult.Errors = append(intermediateResult.Errors, ssrfResult.Errors...)
		}
		if len(redirectResult.Errors) > 0 {
			intermediateResult.Errors = append(intermediateResult.Errors, redirectResult.Errors...)
		}
		if len(cmdiResult.Errors) > 0 {
			intermediateResult.Errors = append(intermediateResult.Errors, cmdiResult.Errors...)
		}
		if len(pathtraversalResult.Errors) > 0 {
			intermediateResult.Errors = append(intermediateResult.Errors, pathtraversalResult.Errors...)
		}
		if len(sstiResult.Errors) > 0 {
			intermediateResult.Errors = append(intermediateResult.Errors, sstiResult.Errors...)
		}
		if len(xxeResult.Errors) > 0 {
			intermediateResult.Errors = append(intermediateResult.Errors, xxeResult.Errors...)
		}
	}

	// Create unified result with correlation and risk scoring
	unifiedResult := NewUnifiedScanResult(
		cfg.Target,
		cfg.SafeMode,
		intermediateResult.Headers,
		intermediateResult.XSS,
		intermediateResult.SQLi,
		intermediateResult.CSRF,
		intermediateResult.SSRF,
		intermediateResult.Redirect,
		intermediateResult.CMDi,
		intermediateResult.PathTraversal,
		intermediateResult.SSTI,
		intermediateResult.XXE,
		nil, // WebSocket results (to be added in discovery mode)
		intermediateResult.Errors,
	)

	return unifiedResult, stats
}

// CalculateFilteredCount calculates the number of findings that were filtered out during verification.
func CalculateFilteredCount(stats *ScanStats, result *UnifiedScanResult) int {
	if stats == nil || result == nil {
		return 0
	}

	verifiedXSSCount := 0
	if result.XSS != nil {
		verifiedXSSCount = len(result.XSS.Findings)
	}

	verifiedSQLiCount := 0
	if result.SQLi != nil {
		verifiedSQLiCount = len(result.SQLi.Findings)
	}

	verifiedCSRFCount := 0
	if result.CSRF != nil {
		verifiedCSRFCount = len(result.CSRF.Findings)
	}

	verifiedSSRFCount := 0
	if result.SSRF != nil {
		verifiedSSRFCount = len(result.SSRF.Findings)
	}

	verifiedRedirectCount := 0
	if result.Redirect != nil {
		verifiedRedirectCount = len(result.Redirect.Findings)
	}

	verifiedCMDiCount := 0
	if result.CMDi != nil {
		verifiedCMDiCount = len(result.CMDi.Findings)
	}

	verifiedPathTraversalCount := 0
	if result.PathTraversal != nil {
		verifiedPathTraversalCount = len(result.PathTraversal.Findings)
	}

	verifiedXXECount := 0
	if result.XXE != nil {
		verifiedXXECount = len(result.XXE.Findings)
	}

	totalFiltered := (stats.TotalXSSFindings - verifiedXSSCount) +
		(stats.TotalSQLiFindings - verifiedSQLiCount) +
		(stats.TotalCSRFFindings - verifiedCSRFCount) +
		(stats.TotalSSRFFindings - verifiedSSRFCount) +
		(stats.TotalRedirectFindings - verifiedRedirectCount) +
		(stats.TotalCMDiFindings - verifiedCMDiCount) +
		(stats.TotalPathTraversalFindings - verifiedPathTraversalCount) +
		(stats.TotalXXEFindings - verifiedXXECount)

	return totalFiltered
}

// FormatFilteredMessage creates a formatted message about filtered findings.
func FormatFilteredMessage(filteredCount int) string {
	if filteredCount > 0 {
		return fmt.Sprintf("ℹ️  Verification: %d findings excluded due to failed verification", filteredCount)
	}
	return ""
}

// createCallbackServer creates a callback server from a callback URL.
// The URL should be in the format: http://callback.example.com:8888
// This creates a client that connects to an already-running callback server.
func createCallbackServer(callbackURL string) CallbackServer {
	// For now, we create a simple remote callback client
	// In a full implementation, this would connect to the running callback server
	return &remoteCallbackClient{
		baseURL: callbackURL,
	}
}

// remoteCallbackClient is a simple client that generates callback URLs
// for a remote callback server. It doesn't actually connect to the server,
// just generates the URLs that the target application will call.
type remoteCallbackClient struct {
	baseURL string
	server  *callback.Server
	mu      sync.Mutex
}

func (c *remoteCallbackClient) GenerateCallbackID() string {
	// Generate a unique ID for this callback
	c.mu.Lock()
	defer c.mu.Unlock()

	// Initialize server if not already done
	if c.server == nil {
		c.server = callback.NewServer(callback.Config{
			BaseURL: c.baseURL,
		})
	}

	return c.server.GenerateCallbackID()
}

func (c *remoteCallbackClient) GetHTTPCallbackURL(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.server == nil {
		c.server = callback.NewServer(callback.Config{
			BaseURL: c.baseURL,
		})
	}

	return c.server.GetHTTPCallbackURL(id)
}

func (c *remoteCallbackClient) GetDNSCallbackDomain(id string) string {
	// DNS callbacks not supported in remote client mode
	return ""
}

func (c *remoteCallbackClient) WaitForCallback(ctx context.Context, id string, timeout time.Duration) (callback.CallbackEvent, bool) {
	c.mu.Lock()
	if c.server == nil {
		c.server = callback.NewServer(callback.Config{
			BaseURL: c.baseURL,
		})
	}
	server := c.server
	c.mu.Unlock()

	return server.WaitForCallback(ctx, id, timeout)
}
