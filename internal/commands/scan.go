package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/output"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/scanner"
	"github.com/djannot/wast/pkg/urlutil"
	"github.com/spf13/cobra"
)

// ScanResult represents the result of a security scan (for no-target case).
type ScanResult struct {
	Target       string   `json:"target,omitempty" yaml:"target,omitempty"`
	ScanTypes    []string `json:"scan_types,omitempty" yaml:"scan_types,omitempty"`
	Capabilities []string `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Status       string   `json:"status,omitempty" yaml:"status,omitempty"`
}

// CompleteScanResult is deprecated. Use scanner.IntermediateScanResult instead.
// Kept for backward compatibility.
type CompleteScanResult = scanner.IntermediateScanResult

// NewScanCmd creates and returns the scan command.
func NewScanCmd(getFormatter func() *output.Formatter, getAuthConfig func() *auth.AuthConfig, getRateLimitConfig func() ratelimit.Config) *cobra.Command {
	var timeout int
	var safeMode bool
	var active bool
	var verify bool
	var discover bool
	var crawlDepth int
	var concurrency int
	var scanConcurrency int
	var scanners []string
	var redirectCanaryDomain string

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
  wast scan https://example.com --rate-limit 1     # 1 request per second
  wast scan https://example.com --discover --active # Crawl then scan discovered endpoints
  wast scan https://example.com --active --scanners xss,sqli  # Run only XSS and SQLi scanners`,
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

			// Validate and normalize target URL
			validatedURL, err := urlutil.ValidateTargetURL(target)
			if err != nil {
				formatter.Failure("scan", "Invalid target URL", map[string]interface{}{
					"error": err.Error(),
				})
				return
			}
			target = validatedURL

			// Validate scanner names if provided
			if len(scanners) > 0 {
				if err := scanner.ValidateScanners(scanners); err != nil {
					formatter.Failure("scan", "Invalid --scanners flag", map[string]interface{}{
						"error":          err.Error(),
						"valid_scanners": strings.Join(scanner.ValidScannerNames, ", "),
					})
					return
				}
			}

			// Display warning when active testing is enabled (only in text mode)
			if !safeMode && formatter.Format() == output.FormatText {
				formatter.Info("⚠️  ACTIVE TESTING ENABLED: Sending potentially dangerous payloads to " + target + ". Ensure you have permission to test this target.")
			}

			// Create scan configuration
			ctx := context.Background()

			var unifiedResult *scanner.UnifiedScanResult
			var stats *scanner.ScanStats

			// If discovery mode is enabled, use discovery scan
			if discover {
				discoveryCfg := scanner.DiscoveryScanConfig{
					ScanConfig: scanner.ScanConfig{
						Target:               target,
						Timeout:              timeout,
						SafeMode:             safeMode,
						VerifyFindings:       verify,
						Scanners:             scanners,
						AuthConfig:           authConfig,
						RateLimitConfig:      rateLimitConfig,
						Tracer:               nil, // CLI doesn't use tracing
						RedirectCanaryDomain: redirectCanaryDomain,
					},
					CrawlDepth:      crawlDepth,
					Concurrency:     concurrency,
					ScanConcurrency: scanConcurrency,
					Discover:        true,
				}
				unifiedResult, stats = scanner.ExecuteDiscoveryScan(ctx, discoveryCfg)
			} else {
				scanCfg := scanner.ScanConfig{
					Target:               target,
					Timeout:              timeout,
					SafeMode:             safeMode,
					VerifyFindings:       verify,
					Scanners:             scanners,
					AuthConfig:           authConfig,
					RateLimitConfig:      rateLimitConfig,
					Tracer:               nil, // CLI doesn't use tracing
					RedirectCanaryDomain: redirectCanaryDomain,
				}
				// Execute the scan using the shared executor
				unifiedResult, stats = scanner.ExecuteScan(ctx, scanCfg)
			}

			// Report filtered findings count (in text mode only)
			if verify && formatter.Format() == output.FormatText {
				filteredCount := scanner.CalculateFilteredCount(stats, unifiedResult)
				if msg := scanner.FormatFilteredMessage(filteredCount); msg != "" {
					formatter.Info(msg)
				}
			}

			// Output result based on whether it succeeded
			// In safe mode, we consider it successful if we attempted the scan (headers scanner ran)
			// In active mode, check all scanners for results
			hasResults := unifiedResult.Headers != nil && unifiedResult.Headers.HasResults()
			if !safeMode && unifiedResult.XSS != nil && unifiedResult.SQLi != nil && unifiedResult.CSRF != nil && unifiedResult.SSRF != nil {
				hasResults = hasResults || unifiedResult.XSS.HasResults() || unifiedResult.SQLi.HasResults() || unifiedResult.CSRF.HasResults() || unifiedResult.SSRF.HasResults()
			}

			// For safe mode, always return success as long as we attempted the scan
			// For active mode, return failure only if there are errors and no results from any scanner
			shouldSucceed := safeMode || !(len(unifiedResult.Errors) > 0 && !hasResults)

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
	cmd.Flags().BoolVar(&discover, "discover", false, "First crawl the target to discover forms and endpoints, then scan all discovered attack surfaces")
	cmd.Flags().IntVar(&crawlDepth, "depth", 2, "Maximum crawl depth for discovery mode (used with --discover)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "Number of concurrent workers for the crawl phase (used with --discover)")
	cmd.Flags().IntVar(&scanConcurrency, "scan-concurrency", 5, "Number of concurrent workers for scanning discovered targets (used with --discover)")
	cmd.Flags().StringSliceVar(&scanners, "scanners", nil, fmt.Sprintf("Comma-separated list of scanners to run (e.g. xss,sqli,csrf). Valid: %s. Default: all", strings.Join(scanner.ValidScannerNames, ", ")))
	cmd.Flags().StringVar(&redirectCanaryDomain, "redirect-canary-domain", "", "Canary domain used in open-redirect payloads (default: example.com). Use a domain you control to eliminate false positives.")

	return cmd
}
