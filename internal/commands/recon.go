// Package commands provides CLI command implementations for WAST.
package commands

import (
	"context"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/dns"
	"github.com/djannot/wast/pkg/output"
	"github.com/djannot/wast/pkg/tls"
	"github.com/spf13/cobra"
)

// ReconResult represents the result of a reconnaissance operation.
type ReconResult struct {
	Target  string          `json:"target,omitempty" yaml:"target,omitempty"`
	Methods []string        `json:"methods,omitempty" yaml:"methods,omitempty"`
	Status  string          `json:"status,omitempty" yaml:"status,omitempty"`
	DNS     *dns.DNSResult  `json:"dns,omitempty" yaml:"dns,omitempty"`
	TLS     *tls.TLSResult  `json:"tls,omitempty" yaml:"tls,omitempty"`
}

// NewReconCmd creates and returns the recon command.
// Note: getAuthConfig is accepted for future use when HTTP-based recon is implemented.
func NewReconCmd(getFormatter func() *output.Formatter, getAuthConfig func() *auth.AuthConfig) *cobra.Command {
	var timeout time.Duration
	var subdomains bool

	cmd := &cobra.Command{
		Use:   "recon [target]",
		Short: "Reconnaissance and information gathering",
		Long: `Perform reconnaissance and information gathering on a target.

The recon command provides various methods for collecting information about
a target web application, including:

  - DNS enumeration and subdomain discovery
  - Technology fingerprinting (web server, frameworks, CMS)
  - Port scanning and service detection
  - SSL/TLS certificate analysis
  - WHOIS and domain information lookup
  - Email harvesting and OSINT gathering

This command is designed to be the first step in a security assessment,
gathering the information needed for subsequent testing phases.

Examples:
  wast recon example.com                    # Basic reconnaissance
  wast recon example.com --output json      # JSON output for AI agents
  wast recon example.com --verbose          # Detailed output
  wast recon example.com --timeout 30s      # Custom DNS timeout
  wast recon example.com --subdomains       # Include subdomain discovery`,
		Run: func(cmd *cobra.Command, args []string) {
			formatter := getFormatter()

			target := ""
			if len(args) > 0 {
				target = args[0]
			}

			// If no target is provided, show available methods
			if target == "" {
				result := ReconResult{
					Methods: []string{
						"dns_enumeration",
						"technology_fingerprinting",
						"port_scanning",
						"ssl_analysis",
						"whois_lookup",
					},
					Status: "No target provided. Specify a domain to perform reconnaissance.",
				}
				formatter.Success("recon", "Reconnaissance command - available methods", result)
				return
			}

			// Perform DNS enumeration
			enumerator := dns.NewEnumerator(dns.WithTimeout(timeout))
			dnsResult := enumerator.Enumerate(target)

			// Perform subdomain discovery if enabled
			if subdomains {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
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

			// Determine message based on results
			message := "Reconnaissance completed"
			hasIssues := false
			if !dnsResult.HasRecords() && len(dnsResult.Errors) > 0 {
				hasIssues = true
			}
			if !tlsResult.HasCertificate() && len(tlsResult.Errors) > 0 {
				hasIssues = true
			}
			if hasIssues {
				message = "Reconnaissance completed with some errors"
			}
			if tlsResult.HasSecurityIssues() {
				message = "Reconnaissance completed - security issues found"
			}

			formatter.Success("recon", message, result)
		},
	}

	// Add flags
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "Timeout for DNS queries")
	cmd.Flags().BoolVar(&subdomains, "subdomains", false, "Enable subdomain discovery via CT logs and zone transfer")

	return cmd
}
