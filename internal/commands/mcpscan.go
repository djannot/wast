package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/djannot/wast/pkg/callback"
	"github.com/djannot/wast/pkg/mcpscan"
	"github.com/djannot/wast/pkg/output"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// NewMCPScanCmd creates and returns the mcpscan command with its subcommands.
func NewMCPScanCmd(getFormatter func() *output.Formatter) *cobra.Command {
	var timeout int
	var activeMode bool
	var ssrfCallbackHost string

	cmd := &cobra.Command{
		Use:   "mcpscan",
		Short: "MCP server security scanning",
		Long: `Scan Model Context Protocol (MCP) servers for security vulnerabilities.

MCP servers expose tools via JSON-RPC 2.0 over stdio, SSE, or HTTP transports.
They represent a new attack surface as AI tooling proliferates. Attack vectors
include parameter injection, prompt injection in tool descriptions, excessive
permissions, and missing authentication.

Passive checks (always run):
  - Schema analysis: missing validation, undocumented parameters
  - Prompt injection: AI-directed instructions, hidden Unicode, base64 payloads
  - Permission auditing: dangerous capabilities (shell exec, FS access, etc.)
  - Tool shadowing: name collisions and typosquatting across tools

Active checks (opt-in via --active):
  - Injection testing: SQLi, CMDi, path traversal through tool parameters
  - Data exposure: scan tool responses for leaked credentials, keys, paths
  - SSRF: probe URL-accepting parameters with internal network targets
  - Auth bypass: test unauthenticated access for HTTP/SSE servers

Examples:
  wast mcpscan stdio -- npx @modelcontextprotocol/server-filesystem /tmp
  wast mcpscan sse https://example.com/sse
  wast mcpscan http https://example.com/mcp
  wast mcpscan http https://example.com/mcp --active
  wast mcpscan discover
  wast mcpscan discover --network https://example.com`,
	}

	cmd.PersistentFlags().IntVar(&timeout, "timeout", 30,
		"Per-request timeout in seconds")
	cmd.PersistentFlags().BoolVar(&activeMode, "active", false,
		"Enable active checks (injection, SSRF, data exposure, auth bypass). "+
			"WARNING: sends potentially dangerous payloads to the target server.")
	cmd.PersistentFlags().StringVar(&ssrfCallbackHost, "ssrf-callback-host", "",
		"Base URL of a publicly reachable callback server for blind SSRF detection "+
			"(e.g. http://your-server:8888). Requires --active. The port from this URL is "+
			"used to start a local HTTP listener; the full URL is sent as the probe address.")

	// stdio subcommand
	stdioCmd := &cobra.Command{
		Use:   "stdio [flags] -- <command> [args...]",
		Short: "Scan an MCP server via stdio transport",
		Long: `Connect to and scan a stdio-based MCP server.

The command and its arguments follow a -- separator.

Examples:
  wast mcpscan stdio -- npx @modelcontextprotocol/server-filesystem /tmp
  wast mcpscan stdio -- python -m my_mcp_server
  wast mcpscan stdio --active -- node server.js`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("stdio requires a command to run (e.g., wast mcpscan stdio -- npx my-server)")
			}
			formatter := getFormatter()

			if activeMode {
				fmt.Fprintln(os.Stderr, "⚠️  ACTIVE TESTING ENABLED: sending potentially dangerous payloads to the MCP server.")
			}

			cfg := mcpscan.ScanConfig{
				Transport:  mcpscan.TransportStdio,
				Target:     args[0],
				Args:       args[1:],
				Timeout:    time.Duration(timeout) * time.Second,
				ActiveMode: activeMode,
			}

			if activeMode && ssrfCallbackHost != "" {
				cbSrv, cbErr := startCallbackServer(cmd.Context(), ssrfCallbackHost)
				if cbErr != nil {
					return fmt.Errorf("failed to start SSRF callback server: %w", cbErr)
				}
				defer cbSrv.Stop(context.Background()) //nolint:errcheck
				cfg.SSRFCallbackServer = cbSrv
				fmt.Fprintf(os.Stderr, "[ssrf] OOB callback server listening, base URL: %s\n", ssrfCallbackHost)
			}

			return runMCPScan(cmd.Context(), cfg, formatter)
		},
	}

	// sse subcommand
	sseCmd := &cobra.Command{
		Use:   "sse <url>",
		Short: "Scan an MCP server via SSE transport",
		Long: `Connect to and scan an SSE-based MCP server.

Examples:
  wast mcpscan sse https://example.com/sse
  wast mcpscan sse https://example.com/sse --active`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			formatter := getFormatter()

			if activeMode {
				fmt.Fprintln(os.Stderr, "⚠️  ACTIVE TESTING ENABLED: sending potentially dangerous payloads to the MCP server.")
			}

			cfg := mcpscan.ScanConfig{
				Transport:  mcpscan.TransportSSE,
				Target:     args[0],
				Timeout:    time.Duration(timeout) * time.Second,
				ActiveMode: activeMode,
			}

			if activeMode && ssrfCallbackHost != "" {
				cbSrv, cbErr := startCallbackServer(cmd.Context(), ssrfCallbackHost)
				if cbErr != nil {
					return fmt.Errorf("failed to start SSRF callback server: %w", cbErr)
				}
				defer cbSrv.Stop(context.Background()) //nolint:errcheck
				cfg.SSRFCallbackServer = cbSrv
				fmt.Fprintf(os.Stderr, "[ssrf] OOB callback server listening, base URL: %s\n", ssrfCallbackHost)
			}

			return runMCPScan(cmd.Context(), cfg, formatter)
		},
	}

	// http subcommand
	httpCmd := &cobra.Command{
		Use:   "http <url>",
		Short: "Scan an MCP server via HTTP transport",
		Long: `Connect to and scan an HTTP-based MCP server.

Examples:
  wast mcpscan http https://example.com/mcp
  wast mcpscan http https://example.com/mcp --active`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			formatter := getFormatter()

			if activeMode {
				fmt.Fprintln(os.Stderr, "⚠️  ACTIVE TESTING ENABLED: sending potentially dangerous payloads to the MCP server.")
			}

			cfg := mcpscan.ScanConfig{
				Transport:  mcpscan.TransportHTTP,
				Target:     args[0],
				Timeout:    time.Duration(timeout) * time.Second,
				ActiveMode: activeMode,
			}

			if activeMode && ssrfCallbackHost != "" {
				cbSrv, cbErr := startCallbackServer(cmd.Context(), ssrfCallbackHost)
				if cbErr != nil {
					return fmt.Errorf("failed to start SSRF callback server: %w", cbErr)
				}
				defer cbSrv.Stop(context.Background()) //nolint:errcheck
				cfg.SSRFCallbackServer = cbSrv
				fmt.Fprintf(os.Stderr, "[ssrf] OOB callback server listening, base URL: %s\n", ssrfCallbackHost)
			}

			return runMCPScan(cmd.Context(), cfg, formatter)
		},
	}

	// discover subcommand
	var networkTarget string
	var projectDir string
	var deepMode bool
	var registryMode bool
	var registryTransport string

	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover MCP servers from local configs and network probes",
		Long: `Discover MCP servers configured on the local system.

Checks known MCP config file locations:
  - Claude Desktop: ~/.config/Claude/claude_desktop_config.json
  - Claude Code: ~/.claude.json, .mcp.json
  - Cursor: ~/.cursor/mcp.json
  - VS Code: .vscode/mcp.json
  - Windsurf: ~/.codeium/windsurf/mcp_config.json
  - Cline: ~/Library/Application Support/Code/User/...

Use --network to probe for MCP endpoints on an HTTP target:
  wast mcpscan discover --network example.com

Use --network with --deep to enumerate subdomains first (CT logs, zone
transfers), then probe each discovered subdomain for MCP endpoints:
  wast mcpscan discover --network example.com --deep

Use --project-dir to scan a project's package.json / requirements.txt /
pyproject.toml for outdated MCP server dependencies:
  wast mcpscan discover --project-dir /path/to/project

Use --registry to pull servers directly from the public MCP registry:
  wast mcpscan discover --registry
  wast mcpscan discover --registry --registry-transport sse`,
		RunE: func(cmd *cobra.Command, args []string) error {
			formatter := getFormatter()
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			discoverer := mcpscan.NewDiscoverer()
			discoverer.ProjectDir = projectDir

			var result *mcpscan.DiscoveryResult
			if registryMode {
				// Registry discovery: pull servers from the public MCP registry.
				// --deep and --project-dir are not used in this mode; warn the user.
				if formatter.Format() == output.FormatText {
					if deepMode {
						formatter.Info("Note: --deep is ignored when --registry is set")
					}
					if projectDir != "" {
						formatter.Info("Note: --project-dir is ignored when --registry is set")
					}
					formatter.Info("Fetching MCP servers from public registry...")
				}
				result = discoverer.DiscoverFromRegistry(ctx, registryTransport)
			} else if networkTarget != "" {
				if deepMode {
					// Deep network discovery: enumerate subdomains, then probe each
					result = discoverer.DiscoverNetworkDeep(ctx, networkTarget, func(msg string) {
						if formatter.Format() == output.FormatText {
							formatter.Info(msg)
						}
					})
				} else {
					// Network-only discovery: probe the target for MCP endpoints
					result = discoverer.DiscoverNetwork(ctx, networkTarget)
				}
			} else {
				// Local discovery: scan config files and project dependencies
				result = discoverer.Discover(ctx)
			}

			if formatter.Format() == output.FormatText {
				formatter.Info(fmt.Sprintf("Checked %d sources", len(result.Sources)))
				if len(result.Servers) == 0 {
					formatter.Info("No MCP servers discovered.")
				} else {
					formatter.Info(fmt.Sprintf("Found %d MCP server(s):", len(result.Servers)))
					for i, s := range result.Servers {
						line := fmt.Sprintf("  [%d] transport=%s target=%s source=%s",
							i+1, s.Transport, s.Target, s.Source)
						if s.Name != "" {
							line += fmt.Sprintf(" name=%s", s.Name)
						}
						if s.AuthRequired {
							line += " (auth required)"
						}
						formatter.Info(line)
					}
				}
				if len(result.Findings) > 0 {
					formatter.Info(fmt.Sprintf("\nDependency findings: %d", len(result.Findings)))
					for i, f := range result.Findings {
						formatter.Info(fmt.Sprintf("  [%d] %s | %s",
							i+1, strings.ToUpper(string(f.Severity)), f.Title))
						formatter.Info("      " + f.Description)
						if f.Remediation != "" {
							formatter.Info("      Fix: " + f.Remediation)
						}
					}
				}
				for _, e := range result.Errors {
					formatter.Info(fmt.Sprintf("  warning: %s", e))
				}
			}

			formatter.Success("mcpscan discover", fmt.Sprintf("Discovery complete: %d server(s) found, %d finding(s)", len(result.Servers), len(result.Findings)), result)
			return nil
		},
	}

	discoverCmd.Flags().StringVar(&networkTarget, "network", "",
		"Domain or URL to probe for MCP endpoints (e.g., 'example.com' or 'https://example.com')")
	discoverCmd.Flags().BoolVar(&deepMode, "deep", false,
		"Enumerate subdomains via CT logs and DNS before probing (requires --network)")
	discoverCmd.Flags().StringVar(&projectDir, "project-dir", "",
		"Project directory to scan for MCP server dependencies in package.json, requirements.txt, or pyproject.toml")
	discoverCmd.Flags().BoolVar(&registryMode, "registry", false,
		"Fetch MCP servers from the public MCP registry (https://registry.modelcontextprotocol.io)")
	discoverCmd.Flags().StringVar(&registryTransport, "registry-transport", "",
		"Filter registry results by transport type: sse, http, or stdio (empty = all)")

	// scan subcommand — scan servers from discovery (inline or from file)
	var targetsFile string
	var scanDiscover bool
	var scanNetwork string
	var scanDeep bool
	var concurrency int
	var summaryOnly bool
	var openOnly bool
	var rateLimit float64
	var checkpointFile string

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan MCP servers from discovery or a targets file",
		Long: `Scan MCP servers for security vulnerabilities.

Two-step workflow (discover first, scan later):
  1. wast mcpscan discover --network example.com --deep --output json > targets.json
  2. wast mcpscan scan --targets targets.json --active

All-in-one workflow (discover and scan in one step):
  wast mcpscan scan --discover --active
  wast mcpscan scan --discover --network example.com --deep --active

Only HTTP and SSE servers are scanned automatically. Stdio servers require
local execution and should be scanned individually via 'wast mcpscan stdio'.

Examples:
  wast mcpscan scan --targets targets.json
  wast mcpscan scan --targets targets.json --active
  wast mcpscan scan --targets targets.json --summary-only
  wast mcpscan scan --discover --active
  wast mcpscan scan --discover --network example.com --deep --active`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetsFile == "" && !scanDiscover {
				return fmt.Errorf("either --targets or --discover is required")
			}
			if targetsFile != "" && scanDiscover {
				return fmt.Errorf("--targets and --discover are mutually exclusive")
			}

			formatter := getFormatter()
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			var servers []mcpscan.DiscoveredServer

			if targetsFile != "" {
				// Load servers from file
				data, err := os.ReadFile(targetsFile)
				if err != nil {
					return fmt.Errorf("failed to read targets file: %w", err)
				}
				var discovery mcpscan.DiscoveryResult
				if err := json.Unmarshal(data, &discovery); err != nil {
					return fmt.Errorf("failed to parse targets file: %w", err)
				}
				// Handle wrapped output format: {success, command, message, data: {servers: [...]}}
				if len(discovery.Servers) == 0 {
					var wrapped struct {
						Data mcpscan.DiscoveryResult `json:"data"`
					}
					if err := json.Unmarshal(data, &wrapped); err == nil && len(wrapped.Data.Servers) > 0 {
						discovery = wrapped.Data
					}
				}
				servers = discovery.Servers
			} else {
				// Inline discovery
				discoverer := mcpscan.NewDiscoverer()
				var result *mcpscan.DiscoveryResult
				if scanNetwork != "" {
					if scanDeep {
						result = discoverer.DiscoverNetworkDeep(ctx, scanNetwork, func(msg string) {
							if formatter.Format() == output.FormatText {
								formatter.Info(msg)
							}
						})
					} else {
						result = discoverer.DiscoverNetwork(ctx, scanNetwork)
					}
				} else {
					result = discoverer.Discover(ctx)
				}
				servers = result.Servers

				if formatter.Format() == output.FormatText {
					formatter.Info(fmt.Sprintf("Discovered %d MCP server(s)", len(servers)))
				}
			}

			if len(servers) == 0 {
				formatter.Info("No MCP servers to scan.")
				return nil
			}

			// Filter out auth-required servers when --open-only is set.
			var filteredCount int
			if openOnly {
				var open []mcpscan.DiscoveredServer
				for _, s := range servers {
					if s.AuthRequired {
						filteredCount++
					} else {
						open = append(open, s)
					}
				}
				if filteredCount > 0 {
					if formatter.Format() == output.FormatText {
						formatter.Info(fmt.Sprintf("Filtered out %d auth-required servers", filteredCount))
					}
				}
				servers = open
			}

			if len(servers) == 0 {
				formatter.Info("No MCP servers to scan after filtering.")
				return nil
			}

			if activeMode {
				fmt.Fprintln(os.Stderr, "⚠️  ACTIVE TESTING ENABLED: sending potentially dangerous payloads to MCP servers.")
			}

			// Clamp concurrency to at least 1.
			if concurrency < 1 {
				concurrency = 1
			}

			limiter := ratelimit.NewLimiter(rateLimit)

			var (
				mu      sync.Mutex
				records []mcpscan.BulkScanRecord
			)

			// Load checkpoint if provided — pre-populate records and build skip set.
			var (
				completedTargets map[string]bool
				ckptWriter       *mcpscan.CheckpointWriter
			)
			if checkpointFile != "" {
				// Validate the checkpoint path early so the user gets a clear error
				// before scanning starts (e.g., parent directory missing, no write permission).
				testF, valErr := os.OpenFile(checkpointFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if valErr != nil {
					return fmt.Errorf("cannot open checkpoint file %q: %w", checkpointFile, valErr)
				}
				testF.Close()

				reader := mcpscan.NewCheckpointReader(checkpointFile)
				loaded, prior, err := reader.Load()
				if err != nil {
					return fmt.Errorf("failed to load checkpoint file %q: %w", checkpointFile, err)
				}
				completedTargets = loaded
				records = append(records, prior...)

				if len(prior) > 0 {
					// Count how many of the *current* servers are already done, so
					// remaining is accurate even if the targets list changed between runs.
					var alreadyDone int
					for _, s := range servers {
						if completedTargets[s.Target] {
							alreadyDone++
						}
					}
					remaining := len(servers) - alreadyDone
					if formatter.Format() == output.FormatText {
						formatter.Info(fmt.Sprintf("Resuming: %d/%d servers already scanned, %d remaining",
							alreadyDone, len(servers), remaining))
					}
				}

				ckptWriter = mcpscan.NewCheckpointWriter(checkpointFile)
			}

			g, gctx := errgroup.WithContext(ctx)
			g.SetLimit(concurrency)

			for i, server := range servers {
				i, server := i, server // capture loop vars
				g.Go(func() error {
					// Skip servers already covered by checkpoint.
					if completedTargets[server.Target] {
						return nil
					}

					// Skip stdio servers — they need local execution
					if server.Transport == "stdio" {
						mu.Lock()
						if !summaryOnly && formatter.Format() == output.FormatText {
							formatter.Info(fmt.Sprintf("  [%d/%d] Skipping stdio server %s (use 'wast mcpscan stdio' to scan locally)",
								i+1, len(servers), server.Name))
						}
						rec := mcpscan.BulkScanRecord{
							Name:    server.Name,
							Target:  server.Target,
							Skipped: true,
						}
						records = append(records, rec)
						mu.Unlock()
						if ckptWriter != nil {
							if err := ckptWriter.Write(rec); err != nil {
								fmt.Fprintf(os.Stderr, "warning: checkpoint write failed: %v\n", err)
							}
						}
						return nil
					}

					transport := mcpscan.TransportHTTP
					if server.Transport == "sse" {
						transport = mcpscan.TransportSSE
					}

					mu.Lock()
					if !summaryOnly && formatter.Format() == output.FormatText {
						name := server.Target
						if server.Name != "" {
							name = server.Name + " (" + server.Target + ")"
						}
						formatter.Info(fmt.Sprintf("  [%d/%d] Scanning %s...", i+1, len(servers), name))
					}
					mu.Unlock()

					if err := limiter.Wait(gctx); err != nil {
						return err
					}

					cfg := mcpscan.ScanConfig{
						Transport:  transport,
						Target:     server.Target,
						Timeout:    time.Duration(timeout) * time.Second,
						ActiveMode: activeMode,
					}

					result, scanErr := runMCPScanLocked(gctx, cfg, formatter, &mu, summaryOnly)

					rec := mcpscan.BulkScanRecord{
						Name:   server.Name,
						Target: server.Target,
						Result: result,
					}

					// Populate retry metadata from the scan result (success path).
					if result != nil && result.Summary.Retries > 0 {
						rec.Retries = result.Summary.Retries
						rec.RateLimited = true
					}

					if scanErr != nil {
						rec.Errored = true
						rec.Unreachable = isUnreachableError(scanErr)

						// Detect rate-limit exhaustion on the error path.
						var rateLimitErr *mcpscan.ErrMaxRetriesExceeded
						if errors.As(scanErr, &rateLimitErr) {
							rec.Retries = rateLimitErr.Retries
							rec.RateLimited = true
						}

						mu.Lock()
						if !summaryOnly && formatter.Format() == output.FormatText {
							formatter.Info(fmt.Sprintf("    Error: %v", scanErr))
						}
						mu.Unlock()
					}

					// Surface 429-backoff events in the per-server log line.
					if rec.Retries > 0 {
						mu.Lock()
						if !summaryOnly && formatter.Format() == output.FormatText {
							formatter.Info(fmt.Sprintf("    retried %d× after 429", rec.Retries))
						}
						mu.Unlock()
					}

					mu.Lock()
					records = append(records, rec)
					mu.Unlock()

					if ckptWriter != nil {
						if err := ckptWriter.Write(rec); err != nil {
							fmt.Fprintf(os.Stderr, "warning: checkpoint write failed: %v\n", err)
						}
					}
					return nil
				})
			}

			if err := g.Wait(); err != nil {
				return err
			}

			// Build the aggregated summary from all collected records.
			bulkSummary := mcpscan.BuildBulkScanSummary(records)
			bulkSummary.Filtered = filteredCount
			bulkSummary.TotalServers += filteredCount // restore pre-filter universe count

			if formatter.Format() == output.FormatText {
				if !summaryOnly {
					formatter.Info(fmt.Sprintf("\nScanned %d/%d servers (%d stdio servers skipped)",
						bulkSummary.Scanned, len(servers), bulkSummary.Skipped))
				}
				printBulkScanSummaryText(formatter, bulkSummary)
			}

			// Collect non-nil results for structured output.
			var results []*mcpscan.MCPScanResult
			for _, rec := range records {
				if rec.Result != nil {
					results = append(results, rec.Result)
				}
			}
			bulkResult := mcpscan.BulkScanResult{
				BulkSummary: bulkSummary,
			}
			if !summaryOnly {
				bulkResult.Results = results
			}

			formatter.Success("mcpscan scan",
				fmt.Sprintf("Bulk scan complete: %d/%d servers scanned, %d finding(s)",
					bulkSummary.Scanned, len(servers), bulkSummary.TotalFindings),
				bulkResult)

			return nil
		},
	}

	scanCmd.Flags().StringVar(&targetsFile, "targets", "",
		"Path to JSON file from 'wast mcpscan discover --output json'")
	scanCmd.Flags().BoolVar(&scanDiscover, "discover", false,
		"Discover MCP servers first, then scan them (like 'wast scan --discover' for web)")
	scanCmd.Flags().StringVar(&scanNetwork, "network", "",
		"Domain or URL to probe for MCP endpoints (used with --discover)")
	scanCmd.Flags().BoolVar(&scanDeep, "deep", false,
		"Enumerate subdomains before probing (used with --discover --network)")
	scanCmd.Flags().IntVar(&concurrency, "concurrency", 5,
		"Number of servers to scan in parallel (default 5, use 1 for sequential)")
	scanCmd.Flags().BoolVar(&summaryOnly, "summary-only", false,
		"Print only the aggregated summary; suppress per-server detail (useful for large fleets)")
	scanCmd.Flags().BoolVar(&openOnly, "open-only", false,
		"Skip servers that require authentication (filter out auth-required servers before scanning)")
	scanCmd.Flags().Float64Var(&rateLimit, "rate-limit", 0,
		"Maximum requests per second across all goroutines (0 = unlimited)")
	scanCmd.Flags().StringVar(&checkpointFile, "checkpoint", "",
		"Path to checkpoint file for saving/resuming progress across bulk scans (JSONL format)")

	cmd.AddCommand(stdioCmd, sseCmd, httpCmd, discoverCmd, scanCmd)

	return cmd
}

// runMCPScanLocked executes the MCP scan and (unless summaryOnly is true) outputs
// the per-server result while holding mu for all formatter writes.
// It returns the scan result for bulk aggregation regardless of summaryOnly.
func runMCPScanLocked(ctx context.Context, cfg mcpscan.ScanConfig, formatter *output.Formatter, mu *sync.Mutex, summaryOnly bool) (*mcpscan.MCPScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	scanner := mcpscan.NewScanner(cfg)
	result, err := scanner.Scan(ctx)
	if err != nil {
		if !summaryOnly {
			mu.Lock()
			formatter.Failure("mcpscan", "Scan failed", map[string]interface{}{
				"error":     err.Error(),
				"transport": string(cfg.Transport),
				"target":    cfg.Target,
			})
			mu.Unlock()
		}
		return nil, err
	}

	if !summaryOnly {
		mu.Lock()
		defer mu.Unlock()

		if formatter.Format() == output.FormatText {
			printMCPScanResultText(formatter, result)
		}

		formatter.Success("mcpscan", fmt.Sprintf("Scan complete: %d finding(s)", result.Summary.TotalFindings), result)
	}

	return result, nil
}

// isUnreachableError reports whether err looks like a network connectivity
// failure (as opposed to an application-level error).
func isUnreachableError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, keyword := range []string{
		"connection refused",
		"no such host",
		"dial tcp",
		"i/o timeout",
		"network unreachable",
		"no route to host",
		"connection reset by peer",
		"context deadline exceeded",
	} {
		if strings.Contains(msg, keyword) {
			return true
		}
	}
	return false
}

// printBulkScanSummaryText prints the aggregated bulk scan summary in a
// human-readable format.
func printBulkScanSummaryText(formatter *output.Formatter, summary mcpscan.BulkScanSummary) {
	formatter.Info("\n══ Bulk Scan Summary ══")

	// Servers line.
	serversLine := fmt.Sprintf("Servers: %d total | %d scanned | %d auth-required | %d unreachable | %d stdio-skipped",
		summary.TotalServers, summary.Scanned, summary.AuthRequired, summary.Unreachable, summary.Skipped)
	if errored := summary.Errored - summary.Unreachable; errored > 0 {
		serversLine += fmt.Sprintf(" | %d errored", errored)
	}
	if summary.Filtered > 0 {
		serversLine += fmt.Sprintf(" | %d filtered (auth-required)", summary.Filtered)
	}
	if summary.RateLimited > 0 {
		serversLine += fmt.Sprintf(" | %d rate-limited (429)", summary.RateLimited)
	}
	formatter.Info(serversLine)

	// Findings line.
	crit := summary.BySeverity["critical"]
	high := summary.BySeverity["high"]
	med := summary.BySeverity["medium"]
	lowInfo := summary.BySeverity["low"] + summary.BySeverity["info"]

	findingsParts := []string{fmt.Sprintf("Findings: %d total", summary.TotalFindings)}
	if crit > 0 {
		findingsParts = append(findingsParts, fmt.Sprintf("%d critical", crit))
	}
	if high > 0 {
		findingsParts = append(findingsParts, fmt.Sprintf("%d high", high))
	}
	if med > 0 {
		findingsParts = append(findingsParts, fmt.Sprintf("%d medium", med))
	}
	if lowInfo > 0 {
		findingsParts = append(findingsParts, fmt.Sprintf("%d low/info", lowInfo))
	}
	formatter.Info(strings.Join(findingsParts, " | "))

	// Top findings.
	if len(summary.TopFindings) > 0 {
		formatter.Info("Top findings:")
		for i, f := range summary.TopFindings {
			formatter.Info(fmt.Sprintf("  %d. %s (%d servers)", i+1, f.Title, f.ServerCount))
		}
	}
}

// runMCPScan executes the MCP scan and outputs the result.
func runMCPScan(ctx context.Context, cfg mcpscan.ScanConfig, formatter *output.Formatter) error {
	if ctx == nil {
		ctx = context.Background()
	}

	scanner := mcpscan.NewScanner(cfg)
	result, err := scanner.Scan(ctx)
	if err != nil {
		formatter.Failure("mcpscan", "Scan failed", map[string]interface{}{
			"error":     err.Error(),
			"transport": string(cfg.Transport),
			"target":    cfg.Target,
		})
		return err
	}

	if formatter.Format() == output.FormatText {
		printMCPScanResultText(formatter, result)
	}

	formatter.Success("mcpscan", fmt.Sprintf("Scan complete: %d finding(s)", result.Summary.TotalFindings), result)
	return nil
}

// startCallbackServer creates and starts an HTTP callback server using the
// port extracted from baseURL. baseURL is the externally-reachable address
// that the target MCP server can reach (e.g. "http://203.0.113.5:8888").
func startCallbackServer(ctx context.Context, baseURL string) (*callback.Server, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid --ssrf-callback-host %q: %w", baseURL, err)
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	httpAddr := ":" + port

	srv := callback.NewServer(callback.Config{
		HTTPAddr: httpAddr,
		BaseURL:  baseURL,
	})
	if err := srv.Start(ctx); err != nil {
		return nil, fmt.Errorf("callback server start: %w", err)
	}
	return srv, nil
}

// printMCPScanResultText prints a human-readable summary of scan results.
func printMCPScanResultText(formatter *output.Formatter, result *mcpscan.MCPScanResult) {
	formatter.Info(fmt.Sprintf("Server: %s (%s transport)", result.Server.Name, result.Server.Transport))
	formatter.Info(fmt.Sprintf("Tools enumerated: %d", result.Summary.TotalTools))
	formatter.Info(fmt.Sprintf("Scan duration: %dms", result.ScanDuration.Milliseconds()))

	if result.Summary.TotalFindings == 0 {
		formatter.Info("✅ No security issues found.")
		return
	}

	formatter.Info(fmt.Sprintf("\nFindings: %d total", result.Summary.TotalFindings))

	// Print severity summary.
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := result.Summary.BySeverity[sev]; ok && count > 0 {
			formatter.Info(fmt.Sprintf("  %s: %d", strings.ToUpper(sev), count))
		}
	}

	formatter.Info("")

	// Print each finding.
	for i, f := range result.Findings {
		location := f.Tool
		if f.Parameter != "" {
			location += "." + f.Parameter
		}
		header := fmt.Sprintf("[%d] %s | %s | %s",
			i+1, strings.ToUpper(string(f.Severity)), string(f.Category), f.Title)
		if location != "" {
			header += fmt.Sprintf(" (%s)", location)
		}
		formatter.Info(header)
		formatter.Info("    " + f.Description)
		if f.Evidence != "" {
			formatter.Info("    Evidence: " + f.Evidence)
		}
		if f.Remediation != "" {
			formatter.Info("    Fix: " + f.Remediation)
		}
		formatter.Info("")
	}

	if len(result.Summary.Errors) > 0 {
		formatter.Info("Scan errors:")
		for _, e := range result.Summary.Errors {
			formatter.Info("  " + e)
		}
	}
}
