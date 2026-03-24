// Package commands provides CLI command implementations for WAST.
package commands

import (
	"time"

	"github.com/djannot/wast/pkg/dns"
	"github.com/djannot/wast/pkg/output"
	"github.com/spf13/cobra"
)

// ReconResult represents the result of a reconnaissance operation.
type ReconResult struct {
	Target  string          `json:"target,omitempty" yaml:"target,omitempty"`
	Methods []string        `json:"methods,omitempty" yaml:"methods,omitempty"`
	Status  string          `json:"status,omitempty" yaml:"status,omitempty"`
	DNS     *dns.DNSResult  `json:"dns,omitempty" yaml:"dns,omitempty"`
}

// NewReconCmd creates and returns the recon command.
func NewReconCmd(getFormatter func() *output.Formatter) *cobra.Command {
	var timeout time.Duration

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
  wast recon example.com --timeout 30s      # Custom DNS timeout`,
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

			result := ReconResult{
				Target: target,
				DNS:    dnsResult,
			}

			// Determine message based on results
			message := "DNS enumeration completed"
			if !dnsResult.HasRecords() {
				if len(dnsResult.Errors) > 0 {
					message = "DNS enumeration completed with errors"
				} else {
					message = "DNS enumeration completed - no records found"
				}
			}

			formatter.Success("recon", message, result)
		},
	}

	// Add flags
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "Timeout for DNS queries")

	return cmd
}
