package commands

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/mcpscan"
	"github.com/djannot/wast/pkg/output"
	"github.com/spf13/cobra"
)

// NewMCPScanCmd creates and returns the mcpscan command with its subcommands.
func NewMCPScanCmd(getFormatter func() *output.Formatter) *cobra.Command {
	var timeout int
	var activeMode bool

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

			return runMCPScan(cmd.Context(), cfg, formatter)
		},
	}

	// discover subcommand
	var networkTarget string
	var projectDir string

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

Use --network to also probe for MCP endpoints on an HTTP target:
  wast mcpscan discover --network https://example.com

Use --project-dir to scan a project's package.json / requirements.txt /
pyproject.toml for outdated MCP server dependencies:
  wast mcpscan discover --project-dir /path/to/project`,
		RunE: func(cmd *cobra.Command, args []string) error {
			formatter := getFormatter()
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			discoverer := mcpscan.NewDiscoverer()
			discoverer.ProjectDir = projectDir

			var result *mcpscan.DiscoveryResult
			if networkTarget != "" {
				// Network-only discovery: probe the target for MCP endpoints
				result = discoverer.DiscoverNetwork(ctx, networkTarget)
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
		"Base URL to probe for network-accessible MCP endpoints")
	discoverCmd.Flags().StringVar(&projectDir, "project-dir", "",
		"Project directory to scan for MCP server dependencies in package.json, requirements.txt, or pyproject.toml")

	cmd.AddCommand(stdioCmd, sseCmd, httpCmd, discoverCmd)

	return cmd
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
