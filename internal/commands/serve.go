package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/djannot/wast/internal/mcp"
	"github.com/djannot/wast/pkg/callback"
	"github.com/djannot/wast/pkg/output"
	"github.com/spf13/cobra"
)

// NewServeCmd creates and returns the serve command for MCP server mode.
func NewServeCmd(getFormatter func() *output.Formatter) *cobra.Command {
	var mcpMode bool
	var callbackServerAddr string
	var callbackDNSDomain string
	var transport string
	var addr string
	var authToken string
	var corsOrigin string
	var rateLimit float64
	var maxConcurrent int

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start WAST in server mode",
		Long: `Start WAST in Model Context Protocol (MCP) server mode.

The MCP server exposes WAST's security testing capabilities as standardized tools
that can be invoked by AI agents and assistants like Claude. The server uses
JSON-RPC 2.0 over stdio (default) or Streamable HTTP transport.

Available MCP Tools:
  - wast_recon: Reconnaissance and information gathering
  - wast_scan: Security vulnerability scanning (safe mode by default)
  - wast_crawl: Web crawling and content discovery
  - wast_api: API discovery and testing

The server will run until interrupted (Ctrl+C).

Examples:
  wast serve --mcp                                        # Start MCP server (stdio)
  wast serve --mcp --transport http                       # Start MCP over HTTP on :8080
  wast serve --mcp --transport http --addr :9090          # Start MCP over HTTP on :9090
  wast serve --callback-server :8888                      # Start with HTTP callback server
  wast serve --callback-server :8888 --callback-dns-domain cb.example.com  # With DNS callbacks`,
		Run: func(cmd *cobra.Command, args []string) {
			formatter := getFormatter()

			// Set up context with cancellation
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Handle interrupt signals
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-sigChan
				cancel()
			}()

			// Start callback server if configured
			var callbackServer *callback.Server
			if callbackServerAddr != "" {
				cfg := callback.Config{
					HTTPAddr:  callbackServerAddr,
					DNSDomain: callbackDNSDomain,
					BaseURL:   fmt.Sprintf("http://localhost%s", callbackServerAddr),
				}

				callbackServer = callback.NewServer(cfg)
				if err := callbackServer.Start(ctx); err != nil {
					formatter.Error(fmt.Sprintf("Failed to start callback server: %v", err))
					os.Exit(1)
				}
				formatter.Info(fmt.Sprintf("Callback server started on %s", callbackServerAddr))

				// Stop callback server when done
				defer func() {
					if err := callbackServer.Stop(ctx); err != nil {
						formatter.Error(fmt.Sprintf("Error stopping callback server: %v", err))
					}
				}()
			}

			// Create and start MCP server
			server := mcp.NewServer()

			switch transport {
			case "http":
				if corsOrigin != "" {
					server.SetCORSOrigin(corsOrigin)
				}
				if rateLimit > 0 {
					server.SetRateLimit(rateLimit)
				}
				if maxConcurrent > 0 {
					server.SetMaxConcurrent(maxConcurrent)
				}
				if authToken != "" {
					server.SetAuthToken(authToken)
				} else {
					// Warn operators that the endpoint is unauthenticated.
					formatter.Info("WARNING: HTTP transport has no authentication. " +
						"Restrict network access or use --auth-token to require a Bearer token.")
				}
				formatter.Info(fmt.Sprintf("Starting MCP server (HTTP transport) on %s", addr))
				if err := server.ListenAndServe(ctx, addr); err != nil && err != context.Canceled {
					formatter.Error(fmt.Sprintf("MCP HTTP server error: %v", err))
					os.Exit(1)
				}
			case "stdio", "":
				if cmd.Flags().Changed("addr") {
					formatter.Info("WARNING: --addr is ignored when --transport is stdio")
				}
				if err := server.Run(ctx); err != nil && err != context.Canceled {
					formatter.Error(fmt.Sprintf("MCP server error: %v", err))
					os.Exit(1)
				}
			default:
				formatter.Error(fmt.Sprintf("unknown transport %q: must be \"stdio\" or \"http\"", transport))
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolVar(&mcpMode, "mcp", true, "Run in MCP (Model Context Protocol) server mode")
	cmd.Flags().StringVar(&callbackServerAddr, "callback-server", "", "Address for callback server (e.g., :8888)")
	cmd.Flags().StringVar(&callbackDNSDomain, "callback-dns-domain", "", "Base domain for DNS callbacks (e.g., cb.example.com)")
	cmd.Flags().StringVar(&transport, "transport", "stdio", "MCP transport type: stdio or http")
	cmd.Flags().StringVar(&addr, "addr", ":8080", "Listen address for HTTP transport (e.g., :8080, 0.0.0.0:9090)")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "Bearer token required for HTTP transport requests (recommended for any exposed endpoint)")
	cmd.Flags().StringVar(&corsOrigin, "cors-origin", "", "Allowed CORS origin for HTTP transport (e.g., \"*\" for all origins, or \"https://example.com\" for a specific origin)")
	cmd.Flags().Float64Var(&rateLimit, "rate-limit", 10, "Maximum inbound requests per second for HTTP transport (0 = disabled, default: 10)")
	cmd.Flags().IntVar(&maxConcurrent, "max-concurrent", 5, "Maximum concurrent tool executions for HTTP transport (0 = disabled, default: 5)")

	return cmd
}
