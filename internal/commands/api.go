package commands

import (
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
// Note: getAuthConfig is accepted for future use when API testing is implemented.
func NewAPICmd(getFormatter func() *output.Formatter, getAuthConfig func() *auth.AuthConfig) *cobra.Command {
	var specPath string

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
  wast api https://example.com/graphql --graphql  # GraphQL testing
  wast api https://api.example.com --output json  # JSON output`,
		Run: func(cmd *cobra.Command, args []string) {
			formatter := getFormatter()

			// If --spec is provided, parse the specification
			if specPath != "" {
				runSpecParsing(formatter, specPath)
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

	// Add the --spec flag for OpenAPI/Swagger specification parsing
	cmd.Flags().StringVar(&specPath, "spec", "", "Path or URL to OpenAPI/Swagger specification")

	return cmd
}

// runSpecParsing parses an API specification and outputs the result.
func runSpecParsing(formatter *output.Formatter, specPath string) {
	spec, err := api.ParseSpec(specPath)
	if err != nil {
		formatter.Failure("api", "Failed to parse API specification", map[string]interface{}{
			"spec_path": specPath,
			"error":     err.Error(),
		})
		return
	}

	formatter.Success("api", "API specification parsed successfully", spec)
}
