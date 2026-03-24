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
					},
					Capabilities: []string{
						"http_security_headers",
						"cookie_attribute_analysis",
						"cors_policy_validation",
						"severity_rating",
						"remediation_guidance",
					},
					Status: "No target provided. Specify a URL to perform a security headers scan.",
				}
				formatter.Success("scan", "Scan command - available capabilities", result)
				return
			}

			// Create scanner with timeout option
			opts := []scanner.Option{
				scanner.WithTimeout(time.Duration(timeout) * time.Second),
			}

			// Add authentication if configured
			if !authConfig.IsEmpty() {
				opts = append(opts, scanner.WithAuth(authConfig))
			}

			// Add rate limiting if configured
			if rateLimitConfig.IsEnabled() {
				opts = append(opts, scanner.WithRateLimitConfig(rateLimitConfig))
			}

			headerScanner := scanner.NewHTTPHeadersScanner(opts...)

			// Perform the scan
			ctx := context.Background()
			result := headerScanner.Scan(ctx, target)

			// Output result based on whether it succeeded
			if len(result.Errors) > 0 && !result.HasResults() {
				formatter.Failure("scan", "Security headers scan failed", result)
			} else {
				formatter.Success("scan", "Security headers scan completed", result)
			}
		},
	}

	cmd.Flags().IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")

	return cmd
}
