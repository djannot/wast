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
		// newActiveScanEntry (generic.go) builds each entry; only the finding
		// type, result pointer, and summary field vary per scanner.
		// CSRF: no Confidence field; summary uses VulnerableForms.
		// SSTI: Confidence but no VerificationAttempts field.
		entries := []activeScanEntry{
			newActiveScanEntry("XSS",
				func(ctx context.Context, target string) { xssResult = xssScanner.Scan(ctx, target) },
				func() []XSSFinding { return xssResult.Findings },
				func(f []XSSFinding) { xssResult.Findings = f },
				xssScanner.VerifyFinding,
				func(f *XSSFinding, vr *VerificationResult) {
					f.Verified, f.VerificationAttempts = vr.Verified, vr.Attempts
					applyConfidenceFromResult(&f.Confidence, vr)
				},
				func(f XSSFinding) bool { return f.Verified },
				func(n int) { xssResult.Summary.VulnerabilitiesFound = n },
				func() []string { return xssResult.Errors },
			),
			newActiveScanEntry("SQLi",
				func(ctx context.Context, target string) { sqliResult = sqliScanner.Scan(ctx, target) },
				func() []SQLiFinding { return sqliResult.Findings },
				func(f []SQLiFinding) { sqliResult.Findings = f },
				sqliScanner.VerifyFinding,
				func(f *SQLiFinding, vr *VerificationResult) {
					f.Verified, f.VerificationAttempts = vr.Verified, vr.Attempts
					applyConfidenceFromResult(&f.Confidence, vr)
				},
				func(f SQLiFinding) bool { return f.Verified },
				func(n int) { sqliResult.Summary.VulnerabilitiesFound = n },
				func() []string { return sqliResult.Errors },
			),
			newActiveScanEntry("NoSQLi",
				func(ctx context.Context, target string) { nosqliResult = nosqliScanner.Scan(ctx, target) },
				func() []NoSQLiFinding { return nosqliResult.Findings },
				func(f []NoSQLiFinding) { nosqliResult.Findings = f },
				nosqliScanner.VerifyFinding,
				func(f *NoSQLiFinding, vr *VerificationResult) {
					f.Verified, f.VerificationAttempts = vr.Verified, vr.Attempts
					applyConfidenceFromResult(&f.Confidence, vr)
				},
				func(f NoSQLiFinding) bool { return f.Verified },
				func(n int) { nosqliResult.Summary.VulnerabilitiesFound = n },
				func() []string { return nosqliResult.Errors },
			),
			newActiveScanEntry("CSRF",
				func(ctx context.Context, target string) { csrfResult = csrfScanner.Scan(ctx, target) },
				func() []CSRFFinding { return csrfResult.Findings },
				func(f []CSRFFinding) { csrfResult.Findings = f },
				csrfScanner.VerifyFinding,
				func(f *CSRFFinding, vr *VerificationResult) {
					f.Verified, f.VerificationAttempts = vr.Verified, vr.Attempts
				},
				func(f CSRFFinding) bool { return f.Verified },
				func(n int) { csrfResult.Summary.VulnerableForms = n },
				func() []string { return csrfResult.Errors },
			),
			newActiveScanEntry("SSRF",
				func(ctx context.Context, target string) { ssrfResult = ssrfScanner.Scan(ctx, target) },
				func() []SSRFFinding { return ssrfResult.Findings },
				func(f []SSRFFinding) { ssrfResult.Findings = f },
				ssrfScanner.VerifyFinding,
				func(f *SSRFFinding, vr *VerificationResult) {
					f.Verified, f.VerificationAttempts = vr.Verified, vr.Attempts
					applyConfidenceFromResult(&f.Confidence, vr)
				},
				func(f SSRFFinding) bool { return f.Verified },
				func(n int) { ssrfResult.Summary.VulnerabilitiesFound = n },
				func() []string { return ssrfResult.Errors },
			),
			newActiveScanEntry("Redirect",
				func(ctx context.Context, target string) { redirectResult = redirectScanner.Scan(ctx, target) },
				func() []RedirectFinding { return redirectResult.Findings },
				func(f []RedirectFinding) { redirectResult.Findings = f },
				redirectScanner.VerifyFinding,
				func(f *RedirectFinding, vr *VerificationResult) {
					f.Verified, f.VerificationAttempts = vr.Verified, vr.Attempts
					applyConfidenceFromResult(&f.Confidence, vr)
				},
				func(f RedirectFinding) bool { return f.Verified },
				func(n int) { redirectResult.Summary.VulnerabilitiesFound = n },
				func() []string { return redirectResult.Errors },
			),
			newActiveScanEntry("CMDi",
				func(ctx context.Context, target string) { cmdiResult = cmdiScanner.Scan(ctx, target) },
				func() []CMDiFinding { return cmdiResult.Findings },
				func(f []CMDiFinding) { cmdiResult.Findings = f },
				cmdiScanner.VerifyFinding,
				func(f *CMDiFinding, vr *VerificationResult) {
					f.Verified, f.VerificationAttempts = vr.Verified, vr.Attempts
					applyConfidenceFromResult(&f.Confidence, vr)
				},
				func(f CMDiFinding) bool { return f.Verified },
				func(n int) { cmdiResult.Summary.VulnerabilitiesFound = n },
				func() []string { return cmdiResult.Errors },
			),
			newActiveScanEntry("PathTraversal",
				func(ctx context.Context, target string) { pathtraversalResult = pathtraversalScanner.Scan(ctx, target) },
				func() []PathTraversalFinding { return pathtraversalResult.Findings },
				func(f []PathTraversalFinding) { pathtraversalResult.Findings = f },
				pathtraversalScanner.VerifyFinding,
				func(f *PathTraversalFinding, vr *VerificationResult) {
					f.Verified, f.VerificationAttempts = vr.Verified, vr.Attempts
					applyConfidenceFromResult(&f.Confidence, vr)
				},
				func(f PathTraversalFinding) bool { return f.Verified },
				func(n int) { pathtraversalResult.Summary.VulnerabilitiesFound = n },
				func() []string { return pathtraversalResult.Errors },
			),
			newActiveScanEntry("SSTI",
				func(ctx context.Context, target string) { sstiResult = sstiScanner.Scan(ctx, target) },
				func() []SSTIFinding { return sstiResult.Findings },
				func(f []SSTIFinding) { sstiResult.Findings = f },
				sstiScanner.VerifyFinding,
				func(f *SSTIFinding, vr *VerificationResult) {
					f.Verified = vr.Verified // SSTIFinding has no VerificationAttempts field
					applyConfidenceFromResult(&f.Confidence, vr)
				},
				func(f SSTIFinding) bool { return f.Verified },
				func(n int) { sstiResult.Summary.VulnerabilitiesFound = n },
				func() []string { return sstiResult.Errors },
			),
			newActiveScanEntry("XXE",
				func(ctx context.Context, target string) { xxeResult = xxeScanner.Scan(ctx, target) },
				func() []XXEFinding { return xxeResult.Findings },
				func(f []XXEFinding) { xxeResult.Findings = f },
				xxeScanner.VerifyFinding,
				func(f *XXEFinding, vr *VerificationResult) {
					f.Verified, f.VerificationAttempts = vr.Verified, vr.Attempts
					applyConfidenceFromResult(&f.Confidence, vr)
				},
				func(f XXEFinding) bool { return f.Verified },
				func(n int) { xxeResult.Summary.VulnerabilitiesFound = n },
				func() []string { return xxeResult.Errors },
			),
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
			// Guard each lookup: when --scanners filters entries, only selected
			// scanners are present in entryByName; missing keys return nil and
			// calling totalFindings() on nil panics.
			if e, ok := entryByName["XSS"]; ok {
				stats.TotalXSSFindings = e.totalFindings()
			}
			if e, ok := entryByName["SQLi"]; ok {
				stats.TotalSQLiFindings = e.totalFindings()
			}
			if e, ok := entryByName["NoSQLi"]; ok {
				stats.TotalNoSQLiFindings = e.totalFindings()
				if nosqliResult != nil {
					stats.TotalNoSQLiTests = nosqliResult.Summary.TotalTests
				}
			}
			if e, ok := entryByName["CSRF"]; ok {
				stats.TotalCSRFFindings = e.totalFindings()
			}
			if e, ok := entryByName["SSRF"]; ok {
				stats.TotalSSRFFindings = e.totalFindings()
			}
			if e, ok := entryByName["Redirect"]; ok {
				stats.TotalRedirectFindings = e.totalFindings()
			}
			if e, ok := entryByName["CMDi"]; ok {
				stats.TotalCMDiFindings = e.totalFindings()
			}
			if e, ok := entryByName["PathTraversal"]; ok {
				stats.TotalPathTraversalFindings = e.totalFindings()
			}
			if e, ok := entryByName["SSTI"]; ok {
				stats.TotalSSTIFindings = e.totalFindings()
			}
			if e, ok := entryByName["XXE"]; ok {
				stats.TotalXXEFindings = e.totalFindings()
			}

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
