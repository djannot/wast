package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/output"
	"github.com/djannot/wast/pkg/proxy"
	"github.com/spf13/cobra"
)

// NewInterceptCmd creates and returns the intercept command.
// Note: getAuthConfig is accepted for future use when traffic modification is implemented.
func NewInterceptCmd(getFormatter func() *output.Formatter, getAuthConfig func() *auth.AuthConfig) *cobra.Command {
	var (
		port     int
		saveFile string
	)

	cmd := &cobra.Command{
		Use:   "intercept",
		Short: "Traffic interception and analysis",
		Long: `Intercept and analyze HTTP traffic for security testing.

The intercept command starts a proxy server for capturing and
analyzing web traffic between the client and target application:

  - HTTP traffic interception
  - Request/response logging
  - Traffic export to JSON file

Configure your browser or application to use this proxy for traffic capture.

Examples:
  wast intercept                       # Start proxy on default port (8080)
  wast intercept --port 9090           # Use custom port
  wast intercept --output json         # JSON output for logged traffic
  wast intercept --save traffic.json   # Save traffic to file

Note: HTTPS interception requires additional certificate setup (future feature).`,
		Run: func(cmd *cobra.Command, args []string) {
			formatter := getFormatter()

			// Show startup message
			formatter.Info(fmt.Sprintf("Starting HTTP proxy on port %d...", port))
			formatter.Info("Configure your browser/application to use this proxy")
			formatter.Info("Press Ctrl+C to stop the proxy and see results")

			// Create context that cancels on SIGINT/SIGTERM
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Setup signal handling for graceful shutdown
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				<-sigChan
				formatter.Info("Shutting down proxy...")
				cancel()
			}()

			// Create and start the proxy
			opts := []proxy.Option{
				proxy.WithPort(port),
			}

			if saveFile != "" {
				opts = append(opts, proxy.WithSaveFile(saveFile))
			}

			p := proxy.NewProxy(opts...)

			result, err := p.Start(ctx)
			if err != nil {
				formatter.Failure("intercept", fmt.Sprintf("Proxy error: %v", err), nil)
				return
			}

			formatter.Success("intercept", "Proxy session completed", result)
		},
	}

	// Add flags
	cmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on")
	cmd.Flags().StringVarP(&saveFile, "save", "s", "", "Save intercepted traffic to JSON file")

	return cmd
}
