// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/djannot/wast/pkg/auth"
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
}

// IntermediateScanResult represents the combined results of all security scans
// before creating the unified result.
type IntermediateScanResult struct {
	Target      string
	PassiveOnly bool
	Headers     *HeaderScanResult
	XSS         *XSSScanResult
	SQLi        *SQLiScanResult
	CSRF        *CSRFScanResult
	SSRF        *SSRFScanResult
	Redirect    *RedirectScanResult
	CMDi        *CMDiScanResult
	Errors      []string
}

// ScanStats tracks statistics about the verification process.
type ScanStats struct {
	TotalXSSFindings      int
	TotalSQLiFindings     int
	TotalCSRFFindings     int
	TotalSSRFFindings     int
	TotalRedirectFindings int
	TotalCMDiFindings     int
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

	// Add authentication if configured
	if cfg.AuthConfig != nil && !cfg.AuthConfig.IsEmpty() {
		headerOpts = append(headerOpts, WithAuth(cfg.AuthConfig))
		xssOpts = append(xssOpts, WithXSSAuth(cfg.AuthConfig))
		sqliOpts = append(sqliOpts, WithSQLiAuth(cfg.AuthConfig))
		csrfOpts = append(csrfOpts, WithCSRFAuth(cfg.AuthConfig))
		ssrfOpts = append(ssrfOpts, WithSSRFAuth(cfg.AuthConfig))
		redirectOpts = append(redirectOpts, WithRedirectAuth(cfg.AuthConfig))
		cmdiOpts = append(cmdiOpts, WithCMDiAuth(cfg.AuthConfig))
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

		var wg sync.WaitGroup
		var xssResult *XSSScanResult
		var sqliResult *SQLiScanResult
		var csrfResult *CSRFScanResult
		var ssrfResult *SSRFScanResult
		var redirectResult *RedirectScanResult
		var cmdiResult *CMDiScanResult

		// Run scans in parallel
		wg.Add(6)
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
		}

		intermediateResult.XSS = xssResult
		intermediateResult.SQLi = sqliResult
		intermediateResult.CSRF = csrfResult
		intermediateResult.SSRF = ssrfResult
		intermediateResult.Redirect = redirectResult
		intermediateResult.CMDi = cmdiResult

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

	totalFiltered := (stats.TotalXSSFindings - verifiedXSSCount) +
		(stats.TotalSQLiFindings - verifiedSQLiCount) +
		(stats.TotalCSRFFindings - verifiedCSRFCount) +
		(stats.TotalSSRFFindings - verifiedSSRFCount) +
		(stats.TotalRedirectFindings - verifiedRedirectCount) +
		(stats.TotalCMDiFindings - verifiedCMDiCount)

	return totalFiltered
}

// FormatFilteredMessage creates a formatted message about filtered findings.
func FormatFilteredMessage(filteredCount int) string {
	if filteredCount > 0 {
		return fmt.Sprintf("ℹ️  Verification: %d findings excluded due to failed verification", filteredCount)
	}
	return ""
}
