package commands

import (
	"context"
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
	Target  string                   `json:"target" yaml:"target"`
	Headers *scanner.HeaderScanResult `json:"headers,omitempty" yaml:"headers,omitempty"`
	XSS     *scanner.XSSScanResult    `json:"xss,omitempty" yaml:"xss,omitempty"`
	SQLi    *scanner.SQLiScanResult   `json:"sqli,omitempty" yaml:"sqli,omitempty"`
	CSRF    *scanner.CSRFScanResult   `json:"csrf,omitempty" yaml:"csrf,omitempty"`
	Errors  []string                  `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// NewScanCmd creates and returns the scan command.
func NewScanCmd(getFormatter func() *output.Formatter, getAuthConfig func() *auth.AuthConfig, getRateLimitConfig func() ratelimit.Config) *cobra.Command {
	var timeout int

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Security vulnerability scanning",
		Long: `Scan a target web application for security vulnerabilities.

The scan command performs comprehensive security testing including:

Vulnerability Detection:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Server-Side Request Forgery (SSRF)
  - XML External Entity (XXE)
  - Remote Code Execution (RCE)
  - Local/Remote File Inclusion (LFI/RFI)
  - Authentication and Authorization flaws
  - Security misconfigurations

Configuration Analysis:
  - HTTP security headers
  - SSL/TLS configuration
  - Cookie security attributes
  - CORS policy validation

Output includes severity ratings, remediation guidance, and
CWE/CVE references where applicable.

Rate Limiting:
  Use --rate-limit or --delay to throttle requests and avoid triggering
  rate limits or DoS protection on target systems.

Examples:
  wast scan https://example.com               # Security headers scan
  wast scan https://example.com --output json # JSON output for AI
  wast scan https://example.com --timeout 60  # Custom timeout
  wast scan https://example.com --rate-limit 1 # 1 request per second
  wast scan https://example.com --delay 1000  # 1 second delay between requests`,
		Run: func(cmd *cobra.Command, args []string) {
			formatter := getFormatter()
			authConfig := getAuthConfig()
			rateLimitConfig := getRateLimitConfig()

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
						"severity_rating",
						"remediation_guidance",
					},
					Status: "No target provided. Specify a URL to perform a comprehensive security scan.",
				}
				formatter.Success("scan", "Scan command - available capabilities", result)
				return
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
			xssScanner := scanner.NewXSSScanner(xssOpts...)
			sqliScanner := scanner.NewSQLiScanner(sqliOpts...)
			csrfScanner := scanner.NewCSRFScanner(csrfOpts...)

			// Perform the scans
			ctx := context.Background()
			headerResult := headerScanner.Scan(ctx, target)
			xssResult := xssScanner.Scan(ctx, target)
			sqliResult := sqliScanner.Scan(ctx, target)
			csrfResult := csrfScanner.Scan(ctx, target)

			// Combine results
			combinedResult := CompleteScanResult{
				Target:  target,
				Headers: headerResult,
				XSS:     xssResult,
				SQLi:    sqliResult,
				CSRF:    csrfResult,
				Errors:  make([]string, 0),
			}

			// Aggregate errors from all scans
			if len(headerResult.Errors) > 0 {
				combinedResult.Errors = append(combinedResult.Errors, headerResult.Errors...)
			}
			if len(xssResult.Errors) > 0 {
				combinedResult.Errors = append(combinedResult.Errors, xssResult.Errors...)
			}
			if len(sqliResult.Errors) > 0 {
				combinedResult.Errors = append(combinedResult.Errors, sqliResult.Errors...)
			}
			if len(csrfResult.Errors) > 0 {
				combinedResult.Errors = append(combinedResult.Errors, csrfResult.Errors...)
			}

			// Output result based on whether it succeeded
			hasResults := headerResult.HasResults() || xssResult.HasResults() || sqliResult.HasResults() || csrfResult.HasResults()
			if len(combinedResult.Errors) > 0 && !hasResults {
				formatter.Failure("scan", "Security scan failed", combinedResult)
			} else {
				formatter.Success("scan", "Security scan completed", combinedResult)
			}
		},
	}

	cmd.Flags().IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")

	return cmd
}
