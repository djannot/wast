package commands

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/output"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/scanner"
	"github.com/spf13/cobra"
)

// ScanResult represents the result of a security scan (for no-target case).
type ScanResult struct {
	Target       string   `json:"target,omitempty" yaml:"target,omitempty"`
	ScanTypes    []string `json:"scan_types,omitempty" yaml:"scan_types,omitempty"`
	Capabilities []string `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Status       string   `json:"status,omitempty" yaml:"status,omitempty"`
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

// NewScanCmd creates and returns the scan command.
func NewScanCmd(getFormatter func() *output.Formatter, getAuthConfig func() *auth.AuthConfig, getRateLimitConfig func() ratelimit.Config) *cobra.Command {
	var timeout int
	var safeMode bool
	var active bool
	var verify bool

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Security vulnerability scanning",
		Long: `Scan a target web application for security vulnerabilities.

The scan command performs comprehensive security testing including:

Safe Mode (Default):
  By default, only passive security checks are performed:
  - HTTP security headers analysis
  - SSL/TLS configuration review
  - Cookie security attributes
  - CORS policy validation

Active Testing (--active flag):
  When enabled, performs active vulnerability testing:
  - SQL Injection (SQLi) testing
  - Cross-Site Scripting (XSS) testing
  - Cross-Site Request Forgery (CSRF) testing

WARNING: Active testing sends potentially dangerous payloads to the target.
Only use --active on systems you own or have explicit permission to test.

Finding Verification (--verify flag):
  When enabled with active testing, reduces false positives by:
  - Re-testing findings with payload variants
  - Updating confidence levels based on verification results
  - Filtering out unverified findings from results

  WARNING: Unverified findings will be EXCLUDED from results.
  Use without --verify first to see all potential findings.
  Note: Increases scan time due to additional verification requests.

Output includes severity ratings, remediation guidance, and
CWE/CVE references where applicable.

Rate Limiting:
  Use --rate-limit or --delay to throttle requests and avoid triggering
  rate limits or DoS protection on target systems.

Examples:
  wast scan https://example.com                    # Safe mode (passive only)
  wast scan https://example.com --active           # Enable active testing
  wast scan https://example.com --safe-mode=false  # Same as --active
  wast scan https://example.com --active --verify  # Active testing with verification
  wast scan https://example.com --output json      # JSON output for AI
  wast scan https://example.com --timeout 60       # Custom timeout
  wast scan https://example.com --rate-limit 1     # 1 request per second`,
		Run: func(cmd *cobra.Command, args []string) {
			formatter := getFormatter()
			authConfig := getAuthConfig()
			rateLimitConfig := getRateLimitConfig()

			// Handle flag logic: --active overrides --safe-mode
			if active {
				safeMode = false
			}

			// Warn if --verify is used without --active
			if verify && safeMode {
				if formatter.Format() == output.FormatText {
					formatter.Info("⚠️  WARNING: --verify flag requires --active mode. Verification will be skipped.")
				}
				verify = false
			}

			target := ""
			if len(args) > 0 {
				target = args[0]
			}

			// If no target is provided, show available capabilities
			if target == "" {
				result := ScanResult{
					ScanTypes: []string{
						"header_analysis",
						"cookie_security",
						"cors_policy",
						"xss_detection",
						"sqli_detection",
						"csrf_detection",
						"ssrf_detection",
					},
					Capabilities: []string{
						"http_security_headers",
						"cookie_attribute_analysis",
						"cors_policy_validation",
						"xss_vulnerability_detection",
						"reflected_xss_testing",
						"sqli_vulnerability_detection",
						"error_based_sqli_testing",
						"boolean_based_sqli_testing",
						"csrf_token_detection",
						"csrf_samesite_validation",
						"csrf_form_analysis",
						"ssrf_vulnerability_detection",
						"ssrf_metadata_endpoint_testing",
						"ssrf_private_network_testing",
						"ssrf_protocol_smuggling_detection",
						"severity_rating",
						"remediation_guidance",
						"safe_mode_support",
					},
					Status: "No target provided. Specify a URL to perform a security scan. Use --active to enable active vulnerability testing.",
				}
				formatter.Success("scan", "Scan command - available capabilities", result)
				return
			}

			// Display warning when active testing is enabled (only in text mode)
			if !safeMode && formatter.Format() == output.FormatText {
				formatter.Info("⚠️  ACTIVE TESTING ENABLED: Sending potentially dangerous payloads to " + target + ". Ensure you have permission to test this target.")
			}

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
			ctx := context.Background()
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
				if verify {
					verifyConfig := scanner.VerificationConfig{
						Enabled:    true,
						MaxRetries: 3,
						Delay:      500 * time.Millisecond,
					}

					// Track findings before verification for reporting
					totalXSSFindings := len(xssResult.Findings)
					totalSQLiFindings := len(sqliResult.Findings)
					totalCSRFFindings := len(csrfResult.Findings)
					totalSSRFFindings := len(ssrfResult.Findings)

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

					// Filter out unverified findings when verification is enabled
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

					verifiedSSRFFindings := make([]scanner.SSRFFinding, 0)
					for _, finding := range ssrfResult.Findings {
						if finding.Verified {
							verifiedSSRFFindings = append(verifiedSSRFFindings, finding)
						}
					}
					ssrfResult.Findings = verifiedSSRFFindings
					ssrfResult.Summary.VulnerabilitiesFound = len(verifiedSSRFFindings)

					// Report filtered findings count (in text mode only)
					if formatter.Format() == output.FormatText {
						totalFiltered := (totalXSSFindings - len(verifiedXSSFindings)) +
							(totalSQLiFindings - len(verifiedSQLiFindings)) +
							(totalCSRFFindings - len(verifiedCSRFFindings)) +
							(totalSSRFFindings - len(verifiedSSRFFindings))
						if totalFiltered > 0 {
							formatter.Info(fmt.Sprintf("ℹ️  Verification: %d findings excluded due to failed verification", totalFiltered))
						}
					}
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

			// Output result based on whether it succeeded
			// In safe mode, we consider it successful if we attempted the scan (headers scanner ran)
			// In active mode, check all scanners for results
			hasResults := headerResult.HasResults()
			if !safeMode && combinedResult.XSS != nil && combinedResult.SQLi != nil && combinedResult.CSRF != nil && combinedResult.SSRF != nil {
				hasResults = hasResults || combinedResult.XSS.HasResults() || combinedResult.SQLi.HasResults() || combinedResult.CSRF.HasResults() || combinedResult.SSRF.HasResults()
			}

			// For safe mode, always return success as long as we attempted the scan
			// For active mode, return failure only if there are errors and no results from any scanner
			shouldSucceed := safeMode || !(len(combinedResult.Errors) > 0 && !hasResults)

			if shouldSucceed {
				if safeMode {
					formatter.Success("scan", "Security scan completed (passive checks only)", unifiedResult)
				} else {
					formatter.Success("scan", "Security scan completed (active testing enabled)", unifiedResult)
				}
			} else {
				formatter.Failure("scan", "Security scan failed", unifiedResult)
			}
		},
	}

	cmd.Flags().IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")
	cmd.Flags().BoolVar(&safeMode, "safe-mode", true, "Run in safe mode (passive checks only, no active vulnerability testing)")
	cmd.Flags().BoolVar(&active, "active", false, "Enable active vulnerability testing (same as --safe-mode=false)")
	cmd.Flags().BoolVar(&verify, "verify", false, "Enable finding verification to reduce false positives (requires --active)")

	return cmd
}
