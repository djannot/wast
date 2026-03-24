// Package main provides the CLI entry point for WAST (Web Application Security Testing).
package main

import (
	"fmt"
	"os"

	"github.com/djannot/wast/internal/commands"
	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/output"
	"github.com/spf13/cobra"
)

// Version information - set at build time
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Global flags
var (
	outputFormat string
	quiet        bool
	verbose      bool
	// Authentication flags
	authHeader  string
	authBearer  string
	authBasic   string
	authCookies []string
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "wast",
	Short: "WAST - Web Application Security Testing",
	Long: `WAST (Web Application Security Testing) is a modern security testing tool
designed for both AI agents and human operators.

WAST provides comprehensive web application security testing capabilities including:
  - Reconnaissance and information gathering
  - Web crawling and content discovery
  - Traffic interception and analysis
  - Security vulnerability scanning
  - API security testing

All commands support structured output formats (JSON/YAML) for seamless
AI agent integration and automation.

Examples:
  wast recon --output json         # Run reconnaissance with JSON output
  wast crawl https://example.com   # Crawl a target website
  wast scan --verbose              # Run security scan with verbose output`,
	Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Validate output format
		if !output.IsValidFormat(outputFormat) {
			fmt.Fprintf(os.Stderr, "Invalid output format: %s. Valid formats: %v\n",
				outputFormat, output.ValidFormats())
			os.Exit(1)
		}
		// Validate quiet and verbose are not both set
		if quiet && verbose {
			fmt.Fprintln(os.Stderr, "Cannot use both --quiet and --verbose")
			os.Exit(1)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Output format flag (critical for AI agent integration)
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "text",
		fmt.Sprintf("Output format (%v)", output.ValidFormats()))

	// Verbosity flags
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false,
		"Suppress all output except errors")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"Enable verbose output")

	// Authentication flags
	rootCmd.PersistentFlags().StringVar(&authHeader, "auth-header", "",
		"Custom auth header (e.g., \"Authorization: Bearer <token>\")")
	rootCmd.PersistentFlags().StringVar(&authBearer, "auth-bearer", "",
		"Bearer token (shorthand for Authorization: Bearer <token>)")
	rootCmd.PersistentFlags().StringVar(&authBasic, "auth-basic", "",
		"Basic auth credentials (format: user:pass)")
	rootCmd.PersistentFlags().StringArrayVar(&authCookies, "cookie", nil,
		"Session cookie (format: name=value, can be used multiple times)")

	// Add subcommands
	rootCmd.AddCommand(commands.NewReconCmd(getFormatter, getAuthConfig))
	rootCmd.AddCommand(commands.NewCrawlCmd(getFormatter, getAuthConfig))
	rootCmd.AddCommand(commands.NewInterceptCmd(getFormatter, getAuthConfig))
	rootCmd.AddCommand(commands.NewScanCmd(getFormatter, getAuthConfig))
	rootCmd.AddCommand(commands.NewAPICmd(getFormatter, getAuthConfig))
}

// getFormatter returns a new formatter with the current global settings.
func getFormatter() *output.Formatter {
	return output.NewFormatter(outputFormat, quiet, verbose)
}

// getAuthConfig returns the current authentication configuration.
func getAuthConfig() *auth.AuthConfig {
	return &auth.AuthConfig{
		AuthHeader:  authHeader,
		BearerToken: authBearer,
		BasicAuth:   authBasic,
		Cookies:     authCookies,
	}
}
