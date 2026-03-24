package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
		port      int
		saveFile  string
		initCA    bool
		caCert    string
		caKey     string
		httpsOnly bool
	)

	cmd := &cobra.Command{
		Use:   "intercept",
		Short: "Traffic interception and analysis",
		Long: `Intercept and analyze HTTP/HTTPS traffic for security testing.

The intercept command starts a proxy server for capturing and
analyzing web traffic between the client and target application:

  - HTTP traffic interception
  - HTTPS traffic interception (with certificate generation)
  - Request/response logging
  - Traffic export to JSON file

Configure your browser or application to use this proxy for traffic capture.

Examples:
  wast intercept                       # Start proxy on default port (8080)
  wast intercept --port 9090           # Use custom port
  wast intercept --output json         # JSON output for logged traffic
  wast intercept --save traffic.json   # Save traffic to file
  wast intercept --init-ca             # Initialize CA and exit (for certificate setup)

HTTPS Interception:
  To intercept HTTPS traffic, a root CA certificate is required. On first run
  with HTTPS interception, a CA will be automatically generated and stored in
  ~/.wast/ca/. You must install this CA certificate in your browser/system:

  1. Run 'wast intercept --init-ca' to generate the CA certificate
  2. Install ~/.wast/ca/ca.crt in your browser's certificate store:
     - Chrome: Settings > Privacy > Security > Manage certificates > Authorities > Import
     - Firefox: Settings > Privacy & Security > Certificates > View Certificates > Import
     - macOS: Add to Keychain Access and trust for SSL
     - Linux: Copy to /usr/local/share/ca-certificates/ and run update-ca-certificates
  3. Run 'wast intercept' to start the proxy with HTTPS interception

  Custom CA certificates can be specified with --ca-cert and --ca-key flags.`,
		Run: func(cmd *cobra.Command, args []string) {
			formatter := getFormatter()

			// Handle --init-ca flag
			if initCA {
				handleInitCA(formatter, caCert, caKey)
				return
			}

			// Initialize CA for HTTPS interception
			var ca *proxy.CertificateAuthority
			if !httpsOnly {
				var err error
				ca, err = initializeCA(formatter, caCert, caKey)
				if err != nil {
					formatter.Info(fmt.Sprintf("HTTPS interception disabled: %v", err))
					formatter.Info("Run 'wast intercept --init-ca' to set up HTTPS interception")
				}
			}

			// Show startup message
			if ca != nil {
				formatter.Info(fmt.Sprintf("Starting HTTP/HTTPS proxy on port %d...", port))
				formatter.Info(fmt.Sprintf("CA Certificate: %s", ca.GetCertPath()))
			} else {
				formatter.Info(fmt.Sprintf("Starting HTTP proxy on port %d...", port))
				formatter.Info("(HTTPS traffic will be tunneled without interception)")
			}
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

			if ca != nil {
				opts = append(opts, proxy.WithCA(ca))
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
	cmd.Flags().BoolVar(&initCA, "init-ca", false, "Initialize the CA certificate and exit")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "Path to custom CA certificate file")
	cmd.Flags().StringVar(&caKey, "ca-key", "", "Path to custom CA private key file")
	cmd.Flags().BoolVar(&httpsOnly, "http-only", false, "Disable HTTPS interception (tunnel HTTPS without inspection)")

	return cmd
}

// handleInitCA initializes the CA certificate and exits.
func handleInitCA(formatter *output.Formatter, caCert, caKey string) {
	var config *proxy.CAConfig

	if caCert != "" && caKey != "" {
		// Use custom paths
		config = &proxy.CAConfig{
			CertPath:      caCert,
			KeyPath:       caKey,
			ValidityYears: proxy.DefaultCAValidityYears,
			KeyBits:       proxy.DefaultKeyBits,
		}
	} else if caCert != "" || caKey != "" {
		formatter.Failure("init-ca", "Both --ca-cert and --ca-key must be specified together", nil)
		return
	} else {
		// Use default config
		config = proxy.DefaultCAConfig()
	}

	ca := proxy.NewCertificateAuthority(config)

	if ca.IsInitialized() {
		formatter.Info("CA certificate already exists")
		formatter.Info(fmt.Sprintf("Certificate: %s", ca.GetCertPath()))
		formatter.Info(fmt.Sprintf("Private Key: %s", ca.GetKeyPath()))
		formatter.Info("")
		formatter.Info("To regenerate, delete the existing files first.")
		return
	}

	formatter.Info("Generating new CA certificate...")

	if err := ca.Initialize(); err != nil {
		formatter.Failure("init-ca", fmt.Sprintf("Failed to initialize CA: %v", err), nil)
		return
	}

	formatter.Success("init-ca", "CA certificate generated successfully", map[string]string{
		"certificate": ca.GetCertPath(),
		"private_key": ca.GetKeyPath(),
	})

	formatter.Info("")
	formatter.Info("Next steps:")
	formatter.Info("1. Install the CA certificate in your browser/system trust store")
	formatter.Info(fmt.Sprintf("   Certificate location: %s", ca.GetCertPath()))
	formatter.Info("2. Run 'wast intercept' to start the proxy with HTTPS interception")
}

// initializeCA initializes or loads the CA for HTTPS interception.
func initializeCA(formatter *output.Formatter, caCert, caKey string) (*proxy.CertificateAuthority, error) {
	var config *proxy.CAConfig

	if caCert != "" && caKey != "" {
		// Use custom paths - verify they exist
		if _, err := os.Stat(caCert); os.IsNotExist(err) {
			return nil, fmt.Errorf("CA certificate not found: %s", caCert)
		}
		if _, err := os.Stat(caKey); os.IsNotExist(err) {
			return nil, fmt.Errorf("CA private key not found: %s", caKey)
		}

		config = &proxy.CAConfig{
			CertPath:      caCert,
			KeyPath:       caKey,
			ValidityYears: proxy.DefaultCAValidityYears,
			KeyBits:       proxy.DefaultKeyBits,
		}
	} else if caCert != "" || caKey != "" {
		return nil, fmt.Errorf("both --ca-cert and --ca-key must be specified together")
	} else {
		// Use default config
		config = proxy.DefaultCAConfig()
	}

	ca := proxy.NewCertificateAuthority(config)

	// Check if CA exists
	if !ca.IsInitialized() {
		// Auto-initialize if using default location
		if caCert == "" && caKey == "" {
			homeDir, _ := os.UserHomeDir()
			caDir := filepath.Join(homeDir, proxy.DefaultCADir)
			formatter.Info(fmt.Sprintf("Initializing CA in %s...", caDir))

			if err := ca.Initialize(); err != nil {
				return nil, fmt.Errorf("failed to initialize CA: %w", err)
			}

			formatter.Info(fmt.Sprintf("CA certificate created: %s", ca.GetCertPath()))
			formatter.Info("Note: Install this certificate in your browser/system to intercept HTTPS traffic")
			formatter.Info("")
		} else {
			return nil, fmt.Errorf("CA certificate not found at specified paths")
		}
	} else {
		// Load existing CA
		if err := ca.Load(); err != nil {
			return nil, fmt.Errorf("failed to load CA: %w", err)
		}
	}

	return ca, nil
}
