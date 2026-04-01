// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/callback"
	"github.com/djannot/wast/pkg/ratelimit"
	"go.opentelemetry.io/otel/trace"
)

// ValidScannerNames lists all recognized scanner names (lowercase).
// Used for validation and help text.
var ValidScannerNames = []string{
	"xss", "sqli", "nosqli", "csrf", "ssrf",
	"redirect", "cmdi", "pathtraversal", "ssti", "xxe", "headers",
}

// ValidateScanners checks that every name in the provided slice is a known
// scanner name (case-insensitive). If any name is invalid it returns an error
// that lists all valid names.
func ValidateScanners(names []string) error {
	valid := make(map[string]bool, len(ValidScannerNames))
	for _, n := range ValidScannerNames {
		valid[n] = true
	}
	var invalid []string
	for _, n := range names {
		if !valid[strings.ToLower(n)] {
			invalid = append(invalid, n)
		}
	}
	if len(invalid) > 0 {
		return fmt.Errorf("unknown scanner(s): %s. Valid scanners: %s",
			strings.Join(invalid, ", "),
			strings.Join(ValidScannerNames, ", "))
	}
	return nil
}

// isScannerEnabled returns true when the given scanner name is enabled
// according to the Scanners filter. If the filter is empty every scanner
// is enabled (backward-compatible default).
func isScannerEnabled(name string, scanners []string) bool {
	if len(scanners) == 0 {
		return true
	}
	lower := strings.ToLower(name)
	for _, s := range scanners {
		if strings.ToLower(s) == lower {
			return true
		}
	}
	return false
}

// ScanConfig encapsulates all parameters needed for scan execution.
type ScanConfig struct {
	Target               string
	Timeout              int
	SafeMode             bool
	VerifyFindings       bool
	Scanners             []string // optional list of scanner names to run; empty means all
	AuthConfig           *auth.AuthConfig
	RateLimitConfig      ratelimit.Config
	Tracer               trace.Tracer // optional, for MCP tracing
	CallbackURL          string       // optional, for out-of-band SSRF detection
	HTTPClient           *http.Client // optional, shared HTTP client with cookie jar for session handling
	RedirectCanaryDomain string       // optional, canary domain for redirect payloads (defaults to "example.com")
}

// IntermediateScanResult represents the combined results of all security scans
// before creating the unified result.
type IntermediateScanResult struct {
	Target        string
	PassiveOnly   bool
	Headers       *HeaderScanResult
	XSS           *XSSScanResult
	SQLi          *SQLiScanResult
	NoSQLi        *NoSQLiScanResult
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
	TotalNoSQLiFindings        int
	TotalCSRFFindings          int
	TotalSSRFFindings          int
	TotalRedirectFindings      int
	TotalCMDiFindings          int
	TotalPathTraversalFindings int
	TotalSSTIFindings          int
	TotalXXEFindings           int
	TotalXSSTests              int
	TotalSQLiTests             int
	TotalNoSQLiTests           int
	TotalCSRFTests             int
	TotalSSRFTests             int
	TotalRedirectTests         int
	TotalCMDiTests             int
	TotalPathTraversalTests    int
	TotalSSTITests             int
	TotalXXETests              int
}

// CommonScannerConfig holds shared configuration that applies uniformly to all active
// scanner instances. It is derived from ScanConfig and used by buildXxxOpts helpers
// to avoid duplicating the same auth/client/rate-limit/tracer logic for each scanner.
type CommonScannerConfig struct {
	Timeout    time.Duration
	AuthConfig *auth.AuthConfig
	// HTTPClient is the shared client (with cookie jar). The redirect scanner receives a
	// special no-redirect variant; all other scanners receive this client as-is.
	HTTPClient      *http.Client
	RateLimitConfig ratelimit.Config
	Tracer          trace.Tracer
	ActiveMode      bool // true when safe mode is disabled (enables active verification)
}

// activeScanEntry bundles the per-scanner closures needed for the common execution
// pipeline. Each scanner type creates one entry; the slice of entries is then used
// for parallel scanning, verification, filtering, and error aggregation without
// any per-type switch/if chains.
type activeScanEntry struct {
	name string
	// scan executes the scanner against target and stores the typed result
	// inside the closure-captured variable.
	scan func(ctx context.Context, target string)
	// verifyAll verifies every finding for this scanner, updating Verified /
	// VerificationAttempts / Confidence fields in the captured result.
	verifyAll func(ctx context.Context, cfg VerificationConfig)
	// filterVerified removes unverified findings from the captured result and
	// updates the summary count.
	filterVerified func()
	// getErrors returns any scan-time errors from the captured result.
	getErrors func() []string
	// totalFindings returns the total number of raw findings (before filtering).
	// Must be called after scan() and before filterVerified().
	totalFindings func() int
}

// applyConfidenceFromResult updates a finding's Confidence string using the standard
// three-tier logic (high/medium/low) derived from a VerificationResult. It is shared
// by all scanners that expose a Confidence field.
//
// Mapping:
//   - Verified && Confidence > 0.8  → "high"
//   - Verified && Confidence > 0.5  → "medium"
//   - all other cases (not verified, or verified with Confidence ≤ 0.5) → "low"
func applyConfidenceFromResult(confidence *string, vr *VerificationResult) {
	if vr.Verified && vr.Confidence > 0.8 {
		*confidence = "high"
	} else if vr.Verified && vr.Confidence > 0.5 {
		*confidence = "medium"
	} else {
		// Covers !vr.Verified and the edge case vr.Verified && vr.Confidence <= 0.5.
		*confidence = "low"
	}
}

// ─── option builders ──────────────────────────────────────────────────────────
//
// buildBaseOpts (defined in base.go) constructs the shared BaseOption slice
// from a CommonScannerConfig. Scanner-specific extras (callback servers,
// active mode, no-redirect client) are passed as extra options to the
// NewXxxScannerFromBase constructors below.

// ─── ExecuteScan ──────────────────────────────────────────────────────────────

// ExecuteScan performs the complete scan workflow.
// It orchestrates the execution of all security scans (headers, XSS, SQLi, CSRF, SSRF),
// performs verification if enabled, and returns a unified result.
func ExecuteScan(ctx context.Context, cfg ScanConfig) (*UnifiedScanResult, *ScanStats) {
	common := CommonScannerConfig{
		Timeout:         time.Duration(cfg.Timeout) * time.Second,
		AuthConfig:      cfg.AuthConfig,
		HTTPClient:      cfg.HTTPClient,
		RateLimitConfig: cfg.RateLimitConfig,
		Tracer:          cfg.Tracer,
		ActiveMode:      !cfg.SafeMode,
	}

	baseOpts := buildBaseOpts(common)

	// Perform the passive header scan (skipped when --scanners is set and
	// does not include "headers").
	var headerResult *HeaderScanResult
	if isScannerEnabled("headers", cfg.Scanners) {
		headerScanner := NewHTTPHeadersScannerFromBase(baseOpts)
		headerResult = headerScanner.Scan(ctx, cfg.Target)
	}

	intermediateResult := IntermediateScanResult{
		Target:      cfg.Target,
		PassiveOnly: cfg.SafeMode,
		Headers:     headerResult,
		Errors:      make([]string, 0),
	}
	if headerResult != nil && len(headerResult.Errors) > 0 {
		intermediateResult.Errors = append(intermediateResult.Errors, headerResult.Errors...)
	}

	stats := &ScanStats{}

	// Only perform active scans if safe mode is disabled.
	if !cfg.SafeMode {
		// ── scanner instantiation ──────────────────────────────────────────
		// Each scanner is created here (place 1 of 2 when adding a new scanner).
		// All scanners share the same baseOpts for cross-cutting concerns;
		// scanner-specific extras are passed as additional options.
		xssScanner := NewXSSScannerFromBase(baseOpts)
		sqliScanner := NewSQLiScannerFromBase(baseOpts)
		nosqliScanner := NewNoSQLiScannerFromBase(baseOpts)
		csrfScanner := NewCSRFScannerFromBase(baseOpts, WithCSRFActiveMode(common.ActiveMode))

		// SSRF: attach callback server if a callback URL is configured.
		var ssrfExtraOpts []SSRFOption
		if cfg.CallbackURL != "" {
			if cb := createCallbackServer(cfg.CallbackURL); cb != nil {
				ssrfExtraOpts = append(ssrfExtraOpts, WithSSRFCallbackServer(cb))
			}
		}
		ssrfScanner := NewSSRFScannerFromBase(baseOpts, ssrfExtraOpts...)

		// Redirect: override HTTP client to disable redirect-following so that
		// 3xx status codes and Location headers are visible to the scanner.
		var redirectExtraOpts []RedirectOption
		if common.HTTPClient != nil {
			noRedirectClient := &http.Client{
				Jar:     common.HTTPClient.Jar,
				Timeout: common.HTTPClient.Timeout,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			redirectExtraOpts = append(redirectExtraOpts, WithRedirectHTTPClient(noRedirectClient))
		}
		if cfg.RedirectCanaryDomain != "" {
			redirectExtraOpts = append(redirectExtraOpts, WithRedirectCanaryDomain(cfg.RedirectCanaryDomain))
		}
		redirectScanner := NewRedirectScannerFromBase(baseOpts, redirectExtraOpts...)

		cmdiScanner := NewCMDiScannerFromBase(baseOpts)
		pathtraversalScanner := NewPathTraversalScannerFromBase(baseOpts)
		sstiScanner := NewSSTIScannerFromBase(baseOpts)

		// XXE: attach callback server if a callback URL is configured.
		var xxeExtraOpts []XXEOption
		if cfg.CallbackURL != "" {
			if cb := createCallbackServer(cfg.CallbackURL); cb != nil {
				xxeExtraOpts = append(xxeExtraOpts, WithXXECallbackServer(cb))
			}
		}
		xxeScanner := NewXXEScannerFromBase(baseOpts, xxeExtraOpts...)

		// Typed result variables captured by the closure entries below.
		var xssResult *XSSScanResult
		var sqliResult *SQLiScanResult
		var nosqliResult *NoSQLiScanResult
		var csrfResult *CSRFScanResult
		var ssrfResult *SSRFScanResult
		var redirectResult *RedirectScanResult
		var cmdiResult *CMDiScanResult
		var pathtraversalResult *PathTraversalScanResult
		var sstiResult *SSTIScanResult
		var xxeResult *XXEScanResult

		// ── activeScanEntry registry ───────────────────────────────────────
		// Each entry encapsulates all operations for one scanner.  The unified
		// pipeline below iterates this slice for parallel scanning, verification,
		// filtering, and error aggregation — no per-type code duplication needed.
		entries := []activeScanEntry{
			{
				name: "XSS",
				scan: func(ctx context.Context, target string) {
					xssResult = xssScanner.Scan(ctx, target)
				},
				verifyAll: func(ctx context.Context, cfg VerificationConfig) {
					for i := range xssResult.Findings {
						vr, err := xssScanner.VerifyFinding(ctx, &xssResult.Findings[i], cfg)
						if err == nil && vr != nil {
							xssResult.Findings[i].Verified = vr.Verified
							xssResult.Findings[i].VerificationAttempts = vr.Attempts
							applyConfidenceFromResult(&xssResult.Findings[i].Confidence, vr)
						}
					}
				},
				filterVerified: func() {
					verified := make([]XSSFinding, 0, len(xssResult.Findings))
					for _, f := range xssResult.Findings {
						if f.Verified {
							verified = append(verified, f)
						}
					}
					xssResult.Findings = verified
					xssResult.Summary.VulnerabilitiesFound = len(verified)
				},
				getErrors:     func() []string { return xssResult.Errors },
				totalFindings: func() int { return len(xssResult.Findings) },
			},
			{
				name: "SQLi",
				scan: func(ctx context.Context, target string) {
					sqliResult = sqliScanner.Scan(ctx, target)
				},
				verifyAll: func(ctx context.Context, cfg VerificationConfig) {
					for i := range sqliResult.Findings {
						vr, err := sqliScanner.VerifyFinding(ctx, &sqliResult.Findings[i], cfg)
						if err == nil && vr != nil {
							sqliResult.Findings[i].Verified = vr.Verified
							sqliResult.Findings[i].VerificationAttempts = vr.Attempts
							applyConfidenceFromResult(&sqliResult.Findings[i].Confidence, vr)
						}
					}
				},
				filterVerified: func() {
					verified := make([]SQLiFinding, 0, len(sqliResult.Findings))
					for _, f := range sqliResult.Findings {
						if f.Verified {
							verified = append(verified, f)
						}
					}
					sqliResult.Findings = verified
					sqliResult.Summary.VulnerabilitiesFound = len(verified)
				},
				getErrors:     func() []string { return sqliResult.Errors },
				totalFindings: func() int { return len(sqliResult.Findings) },
			},
			{
				name: "NoSQLi",
				scan: func(ctx context.Context, target string) {
					nosqliResult = nosqliScanner.Scan(ctx, target)
				},
				verifyAll: func(ctx context.Context, cfg VerificationConfig) {
					for i := range nosqliResult.Findings {
						vr, err := nosqliScanner.VerifyFinding(ctx, &nosqliResult.Findings[i], cfg)
						if err == nil && vr != nil {
							nosqliResult.Findings[i].Verified = vr.Verified
							nosqliResult.Findings[i].VerificationAttempts = vr.Attempts
							applyConfidenceFromResult(&nosqliResult.Findings[i].Confidence, vr)
						}
					}
				},
				filterVerified: func() {
					verified := make([]NoSQLiFinding, 0, len(nosqliResult.Findings))
					for _, f := range nosqliResult.Findings {
						if f.Verified {
							verified = append(verified, f)
						}
					}
					nosqliResult.Findings = verified
					nosqliResult.Summary.VulnerabilitiesFound = len(verified)
				},
				getErrors:     func() []string { return nosqliResult.Errors },
				totalFindings: func() int { return len(nosqliResult.Findings) },
			},
			{
				// CSRF findings do not have a Confidence field; only Verified and
				// VerificationAttempts are updated. Summary uses VulnerableForms.
				name: "CSRF",
				scan: func(ctx context.Context, target string) {
					csrfResult = csrfScanner.Scan(ctx, target)
				},
				verifyAll: func(ctx context.Context, cfg VerificationConfig) {
					for i := range csrfResult.Findings {
						vr, err := csrfScanner.VerifyFinding(ctx, &csrfResult.Findings[i], cfg)
						if err == nil && vr != nil {
							csrfResult.Findings[i].Verified = vr.Verified
							csrfResult.Findings[i].VerificationAttempts = vr.Attempts
						}
					}
				},
				filterVerified: func() {
					verified := make([]CSRFFinding, 0, len(csrfResult.Findings))
					for _, f := range csrfResult.Findings {
						if f.Verified {
							verified = append(verified, f)
						}
					}
					csrfResult.Findings = verified
					csrfResult.Summary.VulnerableForms = len(verified)
				},
				getErrors:     func() []string { return csrfResult.Errors },
				totalFindings: func() int { return len(csrfResult.Findings) },
			},
			{
				name: "SSRF",
				scan: func(ctx context.Context, target string) {
					ssrfResult = ssrfScanner.Scan(ctx, target)
				},
				verifyAll: func(ctx context.Context, cfg VerificationConfig) {
					for i := range ssrfResult.Findings {
						vr, err := ssrfScanner.VerifyFinding(ctx, &ssrfResult.Findings[i], cfg)
						if err == nil && vr != nil {
							ssrfResult.Findings[i].Verified = vr.Verified
							ssrfResult.Findings[i].VerificationAttempts = vr.Attempts
							applyConfidenceFromResult(&ssrfResult.Findings[i].Confidence, vr)
						}
					}
				},
				filterVerified: func() {
					verified := make([]SSRFFinding, 0, len(ssrfResult.Findings))
					for _, f := range ssrfResult.Findings {
						if f.Verified {
							verified = append(verified, f)
						}
					}
					ssrfResult.Findings = verified
					ssrfResult.Summary.VulnerabilitiesFound = len(verified)
				},
				getErrors:     func() []string { return ssrfResult.Errors },
				totalFindings: func() int { return len(ssrfResult.Findings) },
			},
			{
				name: "Redirect",
				scan: func(ctx context.Context, target string) {
					redirectResult = redirectScanner.Scan(ctx, target)
				},
				verifyAll: func(ctx context.Context, cfg VerificationConfig) {
					for i := range redirectResult.Findings {
						vr, err := redirectScanner.VerifyFinding(ctx, &redirectResult.Findings[i], cfg)
						if err == nil && vr != nil {
							redirectResult.Findings[i].Verified = vr.Verified
							redirectResult.Findings[i].VerificationAttempts = vr.Attempts
							applyConfidenceFromResult(&redirectResult.Findings[i].Confidence, vr)
						}
					}
				},
				filterVerified: func() {
					verified := make([]RedirectFinding, 0, len(redirectResult.Findings))
					for _, f := range redirectResult.Findings {
						if f.Verified {
							verified = append(verified, f)
						}
					}
					redirectResult.Findings = verified
					redirectResult.Summary.VulnerabilitiesFound = len(verified)
				},
				getErrors:     func() []string { return redirectResult.Errors },
				totalFindings: func() int { return len(redirectResult.Findings) },
			},
			{
				name: "CMDi",
				scan: func(ctx context.Context, target string) {
					cmdiResult = cmdiScanner.Scan(ctx, target)
				},
				verifyAll: func(ctx context.Context, cfg VerificationConfig) {
					for i := range cmdiResult.Findings {
						vr, err := cmdiScanner.VerifyFinding(ctx, &cmdiResult.Findings[i], cfg)
						if err == nil && vr != nil {
							cmdiResult.Findings[i].Verified = vr.Verified
							cmdiResult.Findings[i].VerificationAttempts = vr.Attempts
							applyConfidenceFromResult(&cmdiResult.Findings[i].Confidence, vr)
						}
					}
				},
				filterVerified: func() {
					verified := make([]CMDiFinding, 0, len(cmdiResult.Findings))
					for _, f := range cmdiResult.Findings {
						if f.Verified {
							verified = append(verified, f)
						}
					}
					cmdiResult.Findings = verified
					cmdiResult.Summary.VulnerabilitiesFound = len(verified)
				},
				getErrors:     func() []string { return cmdiResult.Errors },
				totalFindings: func() int { return len(cmdiResult.Findings) },
			},
			{
				name: "PathTraversal",
				scan: func(ctx context.Context, target string) {
					pathtraversalResult = pathtraversalScanner.Scan(ctx, target)
				},
				verifyAll: func(ctx context.Context, cfg VerificationConfig) {
					for i := range pathtraversalResult.Findings {
						vr, err := pathtraversalScanner.VerifyFinding(ctx, &pathtraversalResult.Findings[i], cfg)
						if err == nil && vr != nil {
							pathtraversalResult.Findings[i].Verified = vr.Verified
							pathtraversalResult.Findings[i].VerificationAttempts = vr.Attempts
							applyConfidenceFromResult(&pathtraversalResult.Findings[i].Confidence, vr)
						}
					}
				},
				filterVerified: func() {
					verified := make([]PathTraversalFinding, 0, len(pathtraversalResult.Findings))
					for _, f := range pathtraversalResult.Findings {
						if f.Verified {
							verified = append(verified, f)
						}
					}
					pathtraversalResult.Findings = verified
					pathtraversalResult.Summary.VulnerabilitiesFound = len(verified)
				},
				getErrors:     func() []string { return pathtraversalResult.Errors },
				totalFindings: func() int { return len(pathtraversalResult.Findings) },
			},
			{
				// SSTI findings have Confidence but no VerificationAttempts field.
				name: "SSTI",
				scan: func(ctx context.Context, target string) {
					sstiResult = sstiScanner.Scan(ctx, target)
				},
				verifyAll: func(ctx context.Context, cfg VerificationConfig) {
					for i := range sstiResult.Findings {
						vr, err := sstiScanner.VerifyFinding(ctx, &sstiResult.Findings[i], cfg)
						if err == nil && vr != nil {
							sstiResult.Findings[i].Verified = vr.Verified
							applyConfidenceFromResult(&sstiResult.Findings[i].Confidence, vr)
						}
					}
				},
				filterVerified: func() {
					verified := make([]SSTIFinding, 0, len(sstiResult.Findings))
					for _, f := range sstiResult.Findings {
						if f.Verified {
							verified = append(verified, f)
						}
					}
					sstiResult.Findings = verified
					sstiResult.Summary.VulnerabilitiesFound = len(verified)
				},
				getErrors:     func() []string { return sstiResult.Errors },
				totalFindings: func() int { return len(sstiResult.Findings) },
			},
			{
				name: "XXE",
				scan: func(ctx context.Context, target string) {
					xxeResult = xxeScanner.Scan(ctx, target)
				},
				verifyAll: func(ctx context.Context, cfg VerificationConfig) {
					for i := range xxeResult.Findings {
						vr, err := xxeScanner.VerifyFinding(ctx, &xxeResult.Findings[i], cfg)
						if err == nil && vr != nil {
							xxeResult.Findings[i].Verified = vr.Verified
							xxeResult.Findings[i].VerificationAttempts = vr.Attempts
							applyConfidenceFromResult(&xxeResult.Findings[i].Confidence, vr)
						}
					}
				},
				filterVerified: func() {
					verified := make([]XXEFinding, 0, len(xxeResult.Findings))
					for _, f := range xxeResult.Findings {
						if f.Verified {
							verified = append(verified, f)
						}
					}
					xxeResult.Findings = verified
					xxeResult.Summary.VulnerabilitiesFound = len(verified)
				},
				getErrors:     func() []string { return xxeResult.Errors },
				totalFindings: func() int { return len(xxeResult.Findings) },
			},
		}

		// ── scanner filtering ─────────────────────────────────────────────
		// If the caller specified a subset of scanners, keep only matching entries.
		if len(cfg.Scanners) > 0 {
			filtered := make([]activeScanEntry, 0, len(entries))
			for _, e := range entries {
				if isScannerEnabled(e.name, cfg.Scanners) {
					filtered = append(filtered, e)
				}
			}
			entries = filtered
		}

		// ── parallel scan ──────────────────────────────────────────────────
		var wg sync.WaitGroup
		wg.Add(len(entries))
		for i := range entries {
			e := &entries[i]
			go func() {
				defer wg.Done()
				e.scan(ctx, cfg.Target)
			}()
		}
		wg.Wait()

		// ── verification ───────────────────────────────────────────────────
		if cfg.VerifyFindings {
			verifyConfig := VerificationConfig{
				Enabled:    true,
				MaxRetries: 3,
				Delay:      500 * time.Millisecond,
			}

			// Build a name→entry map so that pre-verification finding counts
			// are looked up by scanner name rather than by slice position.
			// This makes the stats block resilient to insertion or reordering of
			// entries — a mismatched mapping now fails loudly (nil-map lookup
			// returning the zero activeScanEntry) rather than silently corrupting
			// statistics.
			entryByName := make(map[string]*activeScanEntry, len(entries))
			for i := range entries {
				entryByName[entries[i].name] = &entries[i]
			}

			// Capture pre-verification finding counts for stats reporting.
			// NoSQLi also records its TotalTests from the summary (scanner-specific stat).
			stats.TotalXSSFindings = entryByName["XSS"].totalFindings()
			stats.TotalSQLiFindings = entryByName["SQLi"].totalFindings()
			stats.TotalNoSQLiFindings = entryByName["NoSQLi"].totalFindings()
			stats.TotalNoSQLiTests = nosqliResult.Summary.TotalTests
			stats.TotalCSRFFindings = entryByName["CSRF"].totalFindings()
			stats.TotalSSRFFindings = entryByName["SSRF"].totalFindings()
			stats.TotalRedirectFindings = entryByName["Redirect"].totalFindings()
			stats.TotalCMDiFindings = entryByName["CMDi"].totalFindings()
			stats.TotalPathTraversalFindings = entryByName["PathTraversal"].totalFindings()
			stats.TotalSSTIFindings = entryByName["SSTI"].totalFindings()
			stats.TotalXXEFindings = entryByName["XXE"].totalFindings()

			// Verify and filter all scanners uniformly.
			for _, e := range entries {
				e.verifyAll(ctx, verifyConfig)
				e.filterVerified()
			}
		}

		// ── result assignment ──────────────────────────────────────────────
		// Assign typed results to the intermediate result struct
		// (place 2 of 2 when adding a new scanner).
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

		// ── error aggregation ──────────────────────────────────────────────
		// Collect errors from all active scanners via the common interface.
		for _, e := range entries {
			if errs := e.getErrors(); len(errs) > 0 {
				intermediateResult.Errors = append(intermediateResult.Errors, errs...)
			}
		}
	}

	// Create unified result with correlation and risk scoring.
	unifiedResult := NewUnifiedScanResult(ScanResultOptions{
		Target:        cfg.Target,
		PassiveOnly:   cfg.SafeMode,
		Headers:       intermediateResult.Headers,
		XSS:           intermediateResult.XSS,
		SQLi:          intermediateResult.SQLi,
		NoSQLi:        intermediateResult.NoSQLi,
		CSRF:          intermediateResult.CSRF,
		SSRF:          intermediateResult.SSRF,
		Redirect:      intermediateResult.Redirect,
		CMDi:          intermediateResult.CMDi,
		PathTraversal: intermediateResult.PathTraversal,
		SSTI:          intermediateResult.SSTI,
		XXE:           intermediateResult.XXE,
		Errors:        intermediateResult.Errors,
	})

	return unifiedResult, stats
}

// ─── CalculateFilteredCount ───────────────────────────────────────────────────

// verifiedCountFromUnified aggregates the total number of findings that survived
// verification by iterating over the typed result fields of a UnifiedScanResult.
// It replaces 10 individual nil-check-and-count blocks with a single function.
func verifiedCountFromUnified(r *UnifiedScanResult) int {
	count := 0
	if r.XSS != nil {
		count += len(r.XSS.Findings)
	}
	if r.SQLi != nil {
		count += len(r.SQLi.Findings)
	}
	if r.NoSQLi != nil {
		count += len(r.NoSQLi.Findings)
	}
	if r.CSRF != nil {
		count += len(r.CSRF.Findings)
	}
	if r.SSRF != nil {
		count += len(r.SSRF.Findings)
	}
	if r.Redirect != nil {
		count += len(r.Redirect.Findings)
	}
	if r.CMDi != nil {
		count += len(r.CMDi.Findings)
	}
	if r.PathTraversal != nil {
		count += len(r.PathTraversal.Findings)
	}
	// SSTI findings are included so that verified SSTI results are correctly
	// subtracted from the pre-verification total in CalculateFilteredCount.
	if r.SSTI != nil {
		count += len(r.SSTI.Findings)
	}
	if r.XXE != nil {
		count += len(r.XXE.Findings)
	}
	return count
}

// CalculateFilteredCount calculates the number of findings that were filtered out during verification.
func CalculateFilteredCount(stats *ScanStats, result *UnifiedScanResult) int {
	if stats == nil || result == nil {
		return 0
	}

	totalBefore := stats.TotalXSSFindings +
		stats.TotalSQLiFindings +
		stats.TotalNoSQLiFindings +
		stats.TotalCSRFFindings +
		stats.TotalSSRFFindings +
		stats.TotalRedirectFindings +
		stats.TotalCMDiFindings +
		stats.TotalPathTraversalFindings +
		stats.TotalSSTIFindings +
		stats.TotalXXEFindings

	totalAfter := verifiedCountFromUnified(result)

	return totalBefore - totalAfter
}

// FormatFilteredMessage creates a formatted message about filtered findings.
func FormatFilteredMessage(filteredCount int) string {
	if filteredCount > 0 {
		return fmt.Sprintf("ℹ️  Verification: %d findings excluded due to failed verification", filteredCount)
	}
	return ""
}

// ─── callback helpers ─────────────────────────────────────────────────────────

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
