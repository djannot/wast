// Package main provides the CLI entry point for WAST (Web Application Security Testing).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/djannot/wast/internal/commands"
	"github.com/djannot/wast/internal/mcp"
	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/output"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/telemetry"
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
	mcpMode      bool
	// Authentication flags
	authHeader  string
	authBearer  string
	authBasic   string
	authCookies []string
	// Login flow flags
	loginURL         string
	loginUser        string
	loginPass        string
	loginUserField   string
	loginPassField   string
	loginContentType string
	loginTokenField  string
	// Rate limiting flags
	rateLimit float64
	delayMs   int
	// Telemetry flags
	telemetryEndpoint string
)

// osExit is a variable that points to os.Exit, allowing it to be overridden in tests
var osExit = os.Exit

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
			osExit(1)
		}
		// Validate quiet and verbose are not both set
		if quiet && verbose {
			fmt.Fprintln(os.Stderr, "Cannot use both --quiet and --verbose")
			osExit(1)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	// Check for --mcp flag before executing cobra command
	// This ensures MCP mode starts immediately without running other cobra logic
	for _, arg := range os.Args[1:] {
		if arg == "--mcp" {
			runMCPServer()
			return nil
		}
	}
	return rootCmd.Execute()
}

// mcpServerRunner is a variable that can be overridden in tests
var mcpServerRunner = runMCPServerImpl

// runMCPServer starts the MCP server and handles graceful shutdown.
func runMCPServer() {
	mcpServerRunner()
}

// runMCPServerImpl is the actual implementation of runMCPServer
func runMCPServerImpl() {
	runMCPServerWithContext(context.Background())
}

// runMCPServerWithContext runs the MCP server with a provided parent context
// This allows for better testing by controlling the context lifecycle
func runMCPServerWithContext(parentCtx context.Context) {
	server := mcp.NewServer()
	server.SetVersion(version)

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Initialize telemetry if configured
	var telemetryProvider *telemetry.Provider
	telemetryConfig := telemetry.ConfigFromEnv()
	telemetryConfig.ServiceVersion = version

	// Override with CLI flag if provided
	if telemetryEndpoint != "" {
		telemetryConfig.Enabled = true
		telemetryConfig.Endpoint = telemetryEndpoint
	}

	if telemetryConfig.IsEnabled() {
		var err error
		telemetryProvider, err = telemetry.NewProvider(ctx, telemetryConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to initialize telemetry: %v\n", err)
		} else {
			defer telemetryProvider.Shutdown(context.Background())
			server.SetTracer(telemetryProvider.Tracer())
		}
	}

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Run MCP server
	if err := server.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		osExit(1)
	}
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

	// MCP server mode flag
	rootCmd.PersistentFlags().BoolVar(&mcpMode, "mcp", false,
		"Run in MCP (Model Context Protocol) server mode for AI agent integration")

	// Authentication flags
	rootCmd.PersistentFlags().StringVar(&authHeader, "auth-header", "",
		"Custom auth header (e.g., \"Authorization: Bearer <token>\")")
	rootCmd.PersistentFlags().StringVar(&authBearer, "auth-bearer", "",
		"Bearer token (shorthand for Authorization: Bearer <token>)")
	rootCmd.PersistentFlags().StringVar(&authBasic, "auth-basic", "",
		"Basic auth credentials (format: user:pass)")
	rootCmd.PersistentFlags().StringArrayVar(&authCookies, "cookie", nil,
		"Session cookie (format: name=value, can be used multiple times)")

	// Login flow flags
	rootCmd.PersistentFlags().StringVar(&loginURL, "login-url", "",
		"Login endpoint URL for automated authentication")
	rootCmd.PersistentFlags().StringVar(&loginUser, "login-user", "",
		"Username for automated login")
	rootCmd.PersistentFlags().StringVar(&loginPass, "login-pass", "",
		"Password for automated login (or set WAST_LOGIN_PASS env var)")
	rootCmd.PersistentFlags().StringVar(&loginUserField, "login-user-field", "username",
		"Form field name for username (default: username)")
	rootCmd.PersistentFlags().StringVar(&loginPassField, "login-pass-field", "password",
		"Form field name for password (default: password)")
	rootCmd.PersistentFlags().StringVar(&loginContentType, "login-content-type", "",
		"Content type for login request: \"form\" (default) or \"json\"")
	rootCmd.PersistentFlags().StringVar(&loginTokenField, "login-token-field", "",
		"Dot-separated JSON path to extract a bearer token from the login response body (e.g. \"authentication.token\")")

	// Rate limiting flags
	rootCmd.PersistentFlags().Float64Var(&rateLimit, "rate-limit", 0,
		"Maximum requests per second (0 for unlimited)")
	rootCmd.PersistentFlags().IntVar(&delayMs, "delay", 0,
		"Delay between requests in milliseconds (overrides --rate-limit if both are set)")

	// Telemetry flag
	rootCmd.PersistentFlags().StringVar(&telemetryEndpoint, "telemetry-endpoint", "",
		"OpenTelemetry OTLP gRPC endpoint (e.g., localhost:4317). Can also be set via WAST_OTEL_ENDPOINT")

	// Add subcommands
	rootCmd.AddCommand(commands.NewReconCmd(getFormatter, getAuthConfig))
	rootCmd.AddCommand(commands.NewCrawlCmd(getFormatter, getAuthConfig, getRateLimitConfig))
	rootCmd.AddCommand(commands.NewInterceptCmd(getFormatter, getAuthConfig))
	rootCmd.AddCommand(commands.NewScanCmd(getFormatter, getAuthConfig, getRateLimitConfig))
	rootCmd.AddCommand(commands.NewAPICmd(getFormatter, getAuthConfig, getRateLimitConfig))
	rootCmd.AddCommand(commands.NewServeCmd(getFormatter, version))
	rootCmd.AddCommand(commands.NewMCPScanCmd(getFormatter))
}

// getFormatter returns a new formatter with the current global settings.
func getFormatter() *output.Formatter {
	return output.NewFormatter(outputFormat, quiet, verbose)
}

// getAuthConfig returns the current authentication configuration.
func getAuthConfig() *auth.AuthConfig {
	config := &auth.AuthConfig{
		AuthHeader:  authHeader,
		BearerToken: authBearer,
		BasicAuth:   authBasic,
		Cookies:     authCookies,
	}

	// Add login configuration if login URL is provided
	if loginURL != "" {
		// Prefer environment variable for password to avoid shell history exposure
		password := loginPass
		if password == "" {
			password = os.Getenv("WAST_LOGIN_PASS")
		}

		config.Login = &auth.LoginConfig{
			LoginURL:      loginURL,
			Username:      loginUser,
			Password:      password,
			UsernameField: loginUserField,
			PasswordField: loginPassField,
			ContentType:   loginContentType,
			TokenField:    loginTokenField,
		}
	}

	return config
}

// getRateLimitConfig returns the current rate limiting configuration.
func getRateLimitConfig() ratelimit.Config {
	return ratelimit.Config{
		RequestsPerSecond: rateLimit,
		DelayMs:           delayMs,
	}
}
