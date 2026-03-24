package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/djannot/wast/internal/mcp"
	"github.com/djannot/wast/pkg/output"
	"github.com/spf13/cobra"
)

// NewServeCmd creates and returns the serve command for MCP server mode.
func NewServeCmd(getFormatter func() *output.Formatter) *cobra.Command {
	var mcpMode bool

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start WAST in server mode",
		Long: `Start WAST in Model Context Protocol (MCP) server mode.

The MCP server exposes WAST's security testing capabilities as standardized tools
that can be invoked by AI agents and assistants like Claude. The server uses
JSON-RPC 2.0 over stdio to communicate.

Available MCP Tools:
  - wast_recon: Reconnaissance and information gathering
  - wast_scan: Security vulnerability scanning (safe mode by default)
  - wast_crawl: Web crawling and content discovery
  - wast_api: API discovery and testing

The server will run until interrupted (Ctrl+C).

Examples:
  wast serve --mcp          # Start MCP server
  wast serve                # Same as above (--mcp is default)`,
		Run: func(cmd *cobra.Command, args []string) {
			formatter := getFormatter()

			// If not in MCP mode, show error
			if !mcpMode {
				formatter.Error("serve command requires --mcp flag")
				os.Exit(1)
			}

			// Create and start MCP server
			server := mcp.NewServer()

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

			// Run MCP server
			if err := server.Run(ctx); err != nil && err != context.Canceled {
				formatter.Error(fmt.Sprintf("MCP server error: %v", err))
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolVar(&mcpMode, "mcp", true, "Run in MCP (Model Context Protocol) server mode")

	return cmd
}
