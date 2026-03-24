package commands

import (
	"context"
	"time"

	"github.com/djannot/wast/pkg/api"
	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/output"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/spf13/cobra"
)

// APIResult represents the result of an API testing operation when no target is provided.
type APIResult struct {
	Features []string `json:"features" yaml:"features"`
	Formats  []string `json:"formats" yaml:"formats"`
	Status   string   `json:"status" yaml:"status"`
}

// NewAPICmd creates and returns the api command.
func NewAPICmd(getFormatter func() *output.Formatter, getAuthConfig func() *auth.AuthConfig, getRateLimitConfig func() ratelimit.Config) *cobra.Command {
	var specPath string
	var baseURL string
	var dryRun bool
	var timeout int
	var respectRateLimits bool

	cmd := &cobra.Command{
		Use:   "api [target]",
		Short: "API security testing",
		Long: `Test APIs for security vulnerabilities and misconfigurations.

The api command provides specialized testing for REST, GraphQL,
and other API types:

API Discovery:
  - OpenAPI/Swagger specification parsing
  - GraphQL introspection
  - Endpoint enumeration
  - Parameter discovery

Security Testing:
  - Authentication bypass attempts
  - Authorization testing (BOLA/IDOR)
  - Rate limiting validation
  - Input validation testing
  - Mass assignment vulnerabilities
  - Injection attacks (SQLi, NoSQLi, etc.)

API-Specific Checks:
  - JWT token analysis
  - OAuth/OIDC flow testing
  - API versioning issues
  - Excessive data exposure
  - Broken function level authorization

Rate Limiting:
  Use --rate-limit or --delay to throttle requests proactively.
  Use --respect-rate-limits to handle HTTP 429 responses with automatic backoff.

Examples:
  wast api https://api.example.com                # Test API
  wast api --spec openapi.yaml                    # Parse OpenAPI spec
  wast api --spec swagger.yaml --output json      # Parse Swagger spec with JSON output
  wast api --spec https://api.example.com/openapi.json  # Parse remote spec
  wast api --spec openapi.yaml --dry-run          # List endpoints without testing
  wast api --spec openapi.yaml --base-url https://staging.api.com  # Override base URL
  wast api https://example.com/graphql --graphql  # GraphQL testing
  wast api https://api.example.com --output json  # JSON output
  wast api --spec openapi.yaml --rate-limit 5     # 5 requests per second
  wast api --spec openapi.yaml --delay 200        # 200ms delay between requests`,
		Run: func(cmd *cobra.Command, args []string) {
			formatter := getFormatter()
			authConfig := getAuthConfig()
			rateLimitConfig := getRateLimitConfig()

			// If --spec is provided, parse the specification and optionally test endpoints
			if specPath != "" {
				runAPITesting(formatter, authConfig, rateLimitConfig, specPath, baseURL, dryRun, timeout, respectRateLimits)
				return
			}

			// If no target is provided, show available features
			if len(args) == 0 {
				result := APIResult{
					Features: []string{
						"endpoint_discovery",
						"auth_bypass_testing",
						"authorization_testing",
						"rate_limit_testing",
						"input_validation",
						"injection_testing",
						"jwt_analysis",
						"oauth_testing",
					},
					Formats: []string{
						"rest",
						"graphql",
						"grpc",
						"soap",
					},
					Status: "ready - provide a target URL or --spec flag to begin",
				}
				formatter.Success("api", "API command capabilities", result)
				return
			}

			// Target URL provided - perform API discovery
			target := args[0]
			runAPIDiscovery(formatter, authConfig, rateLimitConfig, target, timeout)
		},
	}

	// Add flags
	cmd.Flags().StringVar(&specPath, "spec", "", "Path or URL to OpenAPI/Swagger specification")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Override the base URL from the specification")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "List endpoints without making requests")
	cmd.Flags().IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")
	cmd.Flags().BoolVar(&respectRateLimits, "respect-rate-limits", false, "Pause when rate limited (HTTP 429) based on Retry-After header")

	return cmd
}

// runAPITesting parses an API specification and tests the endpoints.
func runAPITesting(formatter *output.Formatter, authConfig *auth.AuthConfig, rateLimitConfig ratelimit.Config, specPath, baseURL string, dryRun bool, timeout int, respectRateLimits bool) {
	// Parse the specification
	spec, err := api.ParseSpec(specPath)
	if err != nil {
		formatter.Failure("api", "Failed to parse API specification", map[string]interface{}{
			"spec_path": specPath,
			"error":     err.Error(),
		})
		return
	}

	// Build tester options
	opts := []api.TesterOption{
		api.WithTimeout(time.Duration(timeout) * time.Second),
		api.WithDryRun(dryRun),
		api.WithRespectRateLimits(respectRateLimits),
	}

	// Add base URL override if provided
	if baseURL != "" {
		opts = append(opts, api.WithBaseURL(baseURL))
	}

	// Add authentication if configured
	if !authConfig.IsEmpty() {
		opts = append(opts, api.WithAuth(authConfig))
	}

	// Add rate limiting if configured
	if rateLimitConfig.IsEnabled() {
		opts = append(opts, api.WithRateLimitConfig(rateLimitConfig))
	}

	// Create tester and run tests
	tester := api.NewTester(opts...)
	ctx := context.Background()
	result := tester.TestAll(ctx, spec)

	// Determine success message based on mode
	var message string
	if dryRun {
		message = "API endpoints discovered (dry run)"
	} else {
		message = "API endpoint testing completed"
	}

	// Output result based on whether it succeeded
	if len(result.Errors) > 0 && result.Summary.TestedEndpoints == 0 && !dryRun {
		formatter.Failure("api", "API endpoint testing failed", result)
	} else {
		formatter.Success("api", message, result)
	}
}

// runAPIDiscovery performs API endpoint discovery on the target URL.
func runAPIDiscovery(formatter *output.Formatter, authConfig *auth.AuthConfig, rateLimitConfig ratelimit.Config, target string, timeout int) {
	// Build discoverer options
	opts := []api.DiscovererOption{
		api.WithDiscovererTimeout(time.Duration(timeout) * time.Second),
	}

	// Add authentication if configured
	if !authConfig.IsEmpty() {
		opts = append(opts, api.WithDiscovererAuth(authConfig))
	}

	// Add rate limiting if configured
	if rateLimitConfig.IsEnabled() {
		opts = append(opts, api.WithDiscovererRateLimitConfig(rateLimitConfig))
	}

	// Create discoverer and run discovery
	discoverer := api.NewDiscoverer(opts...)
	ctx := context.Background()
	result := discoverer.Discover(ctx, target)

	// Determine success/failure based on results
	if len(result.Errors) > 0 && result.Summary.EndpointsFound == 0 {
		formatter.Failure("api", "API discovery failed", result)
	} else if result.Summary.EndpointsFound > 0 {
		formatter.Success("api", "API discovery completed", result)
	} else {
		formatter.Success("api", "API discovery completed - no documentation endpoints found", result)
	}
}
