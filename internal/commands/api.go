package commands

import (
	"context"
	"time"

	"github.com/djannot/wast/pkg/api"
	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/output"
	"github.com/spf13/cobra"
)

// APIResult represents the result of an API testing operation.
type APIResult struct {
	Target   string   `json:"target,omitempty" yaml:"target,omitempty"`
	Features []string `json:"features" yaml:"features"`
	Formats  []string `json:"formats" yaml:"formats"`
	Status   string   `json:"status" yaml:"status"`
}

// NewAPICmd creates and returns the api command.
func NewAPICmd(getFormatter func() *output.Formatter, getAuthConfig func() *auth.AuthConfig) *cobra.Command {
	var specPath string
	var baseURL string
	var dryRun bool
	var timeout int

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

Examples:
  wast api https://api.example.com                # Test API
  wast api --spec openapi.yaml                    # Parse OpenAPI spec
  wast api --spec swagger.yaml --output json      # Parse Swagger spec with JSON output
  wast api --spec https://api.example.com/openapi.json  # Parse remote spec
  wast api --spec openapi.yaml --dry-run          # List endpoints without testing
  wast api --spec openapi.yaml --base-url https://staging.api.com  # Override base URL
  wast api https://example.com/graphql --graphql  # GraphQL testing
  wast api https://api.example.com --output json  # JSON output`,
		Run: func(cmd *cobra.Command, args []string) {
			formatter := getFormatter()
			authConfig := getAuthConfig()

			// If --spec is provided, parse the specification and optionally test endpoints
			if specPath != "" {
				runAPITesting(formatter, authConfig, specPath, baseURL, dryRun, timeout)
				return
			}

			target := ""
			if len(args) > 0 {
				target = args[0]
			}

			result := APIResult{
				Target: target,
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
				Status: "placeholder - not yet implemented",
			}

			formatter.Success("api", "API command (placeholder)", result)
		},
	}

	// Add flags
	cmd.Flags().StringVar(&specPath, "spec", "", "Path or URL to OpenAPI/Swagger specification")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Override the base URL from the specification")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "List endpoints without making requests")
	cmd.Flags().IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")

	return cmd
}

// runAPITesting parses an API specification and tests the endpoints.
func runAPITesting(formatter *output.Formatter, authConfig *auth.AuthConfig, specPath, baseURL string, dryRun bool, timeout int) {
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
	}

	// Add base URL override if provided
	if baseURL != "" {
		opts = append(opts, api.WithBaseURL(baseURL))
	}

	// Add authentication if configured
	if !authConfig.IsEmpty() {
		opts = append(opts, api.WithAuth(authConfig))
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
