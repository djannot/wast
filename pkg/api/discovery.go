// Package api provides OpenAPI/Swagger specification parsing and API endpoint testing.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
)

// DiscoveryResult represents the result of API endpoint discovery.
type DiscoveryResult struct {
	Target              string                      `json:"target" yaml:"target"`
	BaseURL             string                      `json:"base_url" yaml:"base_url"`
	DiscoveredEndpoints []DiscoveredEndpoint        `json:"discovered_endpoints" yaml:"discovered_endpoints"`
	APITypes            []string                    `json:"api_types" yaml:"api_types"`
	GraphQLFindings     []*GraphQLSecurityResult    `json:"graphql_findings,omitempty" yaml:"graphql_findings,omitempty"`
	Summary             DiscoverySummary            `json:"summary" yaml:"summary"`
	Errors              []string                    `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// DiscoveredEndpoint represents a discovered API documentation or endpoint.
type DiscoveredEndpoint struct {
	URL         string `json:"url" yaml:"url"`
	Type        string `json:"type" yaml:"type"` // openapi, swagger, graphql, api-docs
	StatusCode  int    `json:"status_code" yaml:"status_code"`
	ContentType string `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	SpecVersion string `json:"spec_version,omitempty" yaml:"spec_version,omitempty"`
}

// DiscoverySummary provides an overview of the discovery results.
type DiscoverySummary struct {
	EndpointsProbed    int  `json:"endpoints_probed" yaml:"endpoints_probed"`
	EndpointsFound     int  `json:"endpoints_found" yaml:"endpoints_found"`
	HasOpenAPI         bool `json:"has_openapi" yaml:"has_openapi"`
	HasSwagger         bool `json:"has_swagger" yaml:"has_swagger"`
	HasGraphQL         bool `json:"has_graphql" yaml:"has_graphql"`
	SpecificationFound bool `json:"specification_found" yaml:"specification_found"`
}

// String returns a human-readable representation of the discovery result.
func (r *DiscoveryResult) String() string {
	var sb strings.Builder

	sb.WriteString("API Discovery Results\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n")
	sb.WriteString(fmt.Sprintf("Target: %s\n", r.Target))
	sb.WriteString(fmt.Sprintf("Base URL: %s\n", r.BaseURL))

	if len(r.APITypes) > 0 {
		sb.WriteString(fmt.Sprintf("\nAPI Types Detected: %s\n", strings.Join(r.APITypes, ", ")))
	}

	if len(r.DiscoveredEndpoints) > 0 {
		sb.WriteString(fmt.Sprintf("\nDiscovered Endpoints (%d):\n", len(r.DiscoveredEndpoints)))
		for _, ep := range r.DiscoveredEndpoints {
			sb.WriteString(fmt.Sprintf("  [%d] %s (%s)", ep.StatusCode, ep.URL, ep.Type))
			if ep.SpecVersion != "" {
				sb.WriteString(fmt.Sprintf(" - %s", ep.SpecVersion))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("\nNo API documentation endpoints discovered.\n")
	}

	sb.WriteString(fmt.Sprintf("\nSummary:\n"))
	sb.WriteString(fmt.Sprintf("  Endpoints Probed: %d\n", r.Summary.EndpointsProbed))
	sb.WriteString(fmt.Sprintf("  Endpoints Found: %d\n", r.Summary.EndpointsFound))
	sb.WriteString(fmt.Sprintf("  Specification Found: %v\n", r.Summary.SpecificationFound))

	if len(r.GraphQLFindings) > 0 {
		sb.WriteString("\nGraphQL Security Findings:\n")
		for _, gqlResult := range r.GraphQLFindings {
			sb.WriteString(fmt.Sprintf("  Endpoint: %s\n", gqlResult.URL))
			sb.WriteString(fmt.Sprintf("  Introspection Enabled: %v\n", gqlResult.IntrospectionEnabled))
			if gqlResult.SchemaInfo != nil {
				sb.WriteString(fmt.Sprintf("  Schema Types: %d\n", gqlResult.SchemaInfo.TypeCount))
			}
			if len(gqlResult.Findings) > 0 {
				for _, finding := range gqlResult.Findings {
					sb.WriteString(fmt.Sprintf("    [%s] %s\n", strings.ToUpper(finding.Severity), finding.Description))
				}
			}
		}
	}

	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, err := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	return sb.String()
}

// Discoverer performs API endpoint discovery.
type Discoverer struct {
	client      HTTPClient
	userAgent   string
	timeout     time.Duration
	authConfig  *auth.AuthConfig
	rateLimiter ratelimit.Limiter
}

// DiscovererOption is a function that configures a Discoverer.
type DiscovererOption func(*Discoverer)

// WithDiscovererHTTPClient sets a custom HTTP client for the discoverer.
func WithDiscovererHTTPClient(c HTTPClient) DiscovererOption {
	return func(d *Discoverer) {
		d.client = c
	}
}

// WithDiscovererUserAgent sets the user agent string for the discoverer.
func WithDiscovererUserAgent(ua string) DiscovererOption {
	return func(d *Discoverer) {
		d.userAgent = ua
	}
}

// WithDiscovererTimeout sets the timeout for HTTP requests.
func WithDiscovererTimeout(timeout time.Duration) DiscovererOption {
	return func(d *Discoverer) {
		d.timeout = timeout
	}
}

// WithDiscovererAuth sets the authentication configuration for the discoverer.
func WithDiscovererAuth(config *auth.AuthConfig) DiscovererOption {
	return func(d *Discoverer) {
		d.authConfig = config
	}
}

// WithDiscovererRateLimiter sets a rate limiter for the discoverer.
func WithDiscovererRateLimiter(limiter ratelimit.Limiter) DiscovererOption {
	return func(d *Discoverer) {
		d.rateLimiter = limiter
	}
}

// WithDiscovererRateLimitConfig sets rate limiting from a configuration.
func WithDiscovererRateLimitConfig(cfg ratelimit.Config) DiscovererOption {
	return func(d *Discoverer) {
		d.rateLimiter = ratelimit.NewLimiterFromConfig(cfg)
	}
}

// NewDiscoverer creates a new Discoverer with the given options.
func NewDiscoverer(opts ...DiscovererOption) *Discoverer {
	d := &Discoverer{
		userAgent: "WAST/1.0 (Web Application Security Testing)",
		timeout:   30 * time.Second,
	}

	for _, opt := range opts {
		opt(d)
	}

	// Create default HTTP client if not set
	if d.client == nil {
		d.client = NewDefaultHTTPClient(d.timeout)
	}

	return d
}

// commonEndpoints returns the list of common API documentation endpoint paths to probe.
func commonEndpoints() []endpointProbe {
	return []endpointProbe{
		// OpenAPI 3.x endpoints
		{path: "/openapi.json", endpointType: "openapi", description: "OpenAPI 3.x specification (JSON)"},
		{path: "/openapi.yaml", endpointType: "openapi", description: "OpenAPI 3.x specification (YAML)"},
		{path: "/openapi.yml", endpointType: "openapi", description: "OpenAPI 3.x specification (YAML)"},
		{path: "/.well-known/openapi.json", endpointType: "openapi", description: "Well-known OpenAPI specification"},
		{path: "/.well-known/openapi.yaml", endpointType: "openapi", description: "Well-known OpenAPI specification"},

		// Versioned OpenAPI endpoints
		{path: "/v1/openapi.json", endpointType: "openapi", description: "OpenAPI v1 specification"},
		{path: "/v2/openapi.json", endpointType: "openapi", description: "OpenAPI v2 specification"},
		{path: "/v3/openapi.json", endpointType: "openapi", description: "OpenAPI v3 specification"},
		{path: "/api/v1/openapi.json", endpointType: "openapi", description: "API v1 OpenAPI specification"},
		{path: "/api/v2/openapi.json", endpointType: "openapi", description: "API v2 OpenAPI specification"},
		{path: "/api/openapi.json", endpointType: "openapi", description: "API OpenAPI specification"},

		// Swagger 2.0 endpoints
		{path: "/swagger.json", endpointType: "swagger", description: "Swagger 2.0 specification (JSON)"},
		{path: "/swagger.yaml", endpointType: "swagger", description: "Swagger 2.0 specification (YAML)"},
		{path: "/swagger.yml", endpointType: "swagger", description: "Swagger 2.0 specification (YAML)"},
		{path: "/api/swagger.json", endpointType: "swagger", description: "API Swagger specification"},
		{path: "/v1/swagger.json", endpointType: "swagger", description: "Swagger v1 specification"},
		{path: "/v2/swagger.json", endpointType: "swagger", description: "Swagger v2 specification"},

		// API documentation endpoints
		{path: "/api-docs", endpointType: "api-docs", description: "API documentation"},
		{path: "/api-docs/", endpointType: "api-docs", description: "API documentation"},
		{path: "/api-docs/swagger.json", endpointType: "swagger", description: "API docs Swagger specification"},
		{path: "/api-docs/swagger.yaml", endpointType: "swagger", description: "API docs Swagger specification"},
		{path: "/docs", endpointType: "api-docs", description: "API documentation"},
		{path: "/docs/", endpointType: "api-docs", description: "API documentation"},
		{path: "/docs/api", endpointType: "api-docs", description: "API documentation"},
		{path: "/swagger-ui/", endpointType: "swagger-ui", description: "Swagger UI"},
		{path: "/swagger-ui.html", endpointType: "swagger-ui", description: "Swagger UI HTML"},
		{path: "/redoc", endpointType: "api-docs", description: "ReDoc API documentation"},

		// GraphQL endpoints
		{path: "/graphql", endpointType: "graphql", description: "GraphQL endpoint"},
		{path: "/graphiql", endpointType: "graphql", description: "GraphiQL interface"},
		{path: "/api/graphql", endpointType: "graphql", description: "API GraphQL endpoint"},
		{path: "/v1/graphql", endpointType: "graphql", description: "GraphQL v1 endpoint"},
	}
}

// endpointProbe represents an endpoint to probe during discovery.
type endpointProbe struct {
	path         string
	endpointType string
	description  string
}

// Discover performs API endpoint discovery on the target URL.
func (d *Discoverer) Discover(ctx context.Context, target string) *DiscoveryResult {
	result := &DiscoveryResult{
		Target:              target,
		DiscoveredEndpoints: make([]DiscoveredEndpoint, 0),
		APITypes:            make([]string, 0),
		GraphQLFindings:     make([]*GraphQLSecurityResult, 0),
		Errors:              make([]string, 0),
	}

	// Parse and normalize the base URL
	baseURL, err := d.normalizeBaseURL(target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid target URL: %s", err.Error()))
		return result
	}
	result.BaseURL = baseURL

	// Probe common endpoints
	endpoints := commonEndpoints()
	apiTypeMap := make(map[string]bool)

	for _, ep := range endpoints {
		// Check context cancellation
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, "Discovery cancelled: "+ctx.Err().Error())
			d.updateDiscoverySummary(result, len(endpoints), apiTypeMap)
			return result
		default:
		}

		// Apply rate limiting
		if d.rateLimiter != nil {
			if err := d.rateLimiter.Wait(ctx); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
				continue
			}
		}

		result.Summary.EndpointsProbed++

		// Probe the endpoint
		discovered := d.probeEndpoint(ctx, baseURL, ep, result)
		if discovered != nil {
			result.DiscoveredEndpoints = append(result.DiscoveredEndpoints, *discovered)
			result.Summary.EndpointsFound++
			apiTypeMap[discovered.Type] = true
		}
	}

	d.updateDiscoverySummary(result, len(endpoints), apiTypeMap)
	return result
}

// normalizeBaseURL parses and normalizes the target URL to extract the base URL.
func (d *Discoverer) normalizeBaseURL(target string) (string, error) {
	// Add scheme if missing
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", err
	}

	// Build base URL from scheme, host, and port
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	return baseURL, nil
}

// probeEndpoint probes a specific endpoint and returns discovery info if found.
func (d *Discoverer) probeEndpoint(ctx context.Context, baseURL string, ep endpointProbe, result *DiscoveryResult) *DiscoveredEndpoint {
	fullURL := baseURL + ep.path

	// For GraphQL endpoints, use POST with introspection query
	if ep.endpointType == "graphql" {
		return d.probeGraphQLEndpoint(ctx, fullURL, ep, result)
	}

	// For other endpoints, use GET
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil
	}

	// Set headers
	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept", "application/json, application/yaml, application/x-yaml, text/yaml, text/html, */*")

	// Apply authentication if configured
	if d.authConfig != nil {
		d.authConfig.ApplyToRequest(req)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Only consider 2xx responses as successful discovery
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	contentType := resp.Header.Get("Content-Type")

	// Read body for spec version detection
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		body = nil
	}

	discovered := &DiscoveredEndpoint{
		URL:         fullURL,
		Type:        ep.endpointType,
		StatusCode:  resp.StatusCode,
		ContentType: contentType,
		Description: ep.description,
	}

	// Try to detect spec version for OpenAPI/Swagger endpoints
	if ep.endpointType == "openapi" || ep.endpointType == "swagger" {
		specVersion := d.detectSpecVersion(body)
		if specVersion != "" {
			discovered.SpecVersion = specVersion
		}
	}

	return discovered
}

// probeGraphQLEndpoint probes a GraphQL endpoint with an introspection query.
func (d *Discoverer) probeGraphQLEndpoint(ctx context.Context, fullURL string, ep endpointProbe, result *DiscoveryResult) *DiscoveredEndpoint {
	// GraphQL introspection query
	introspectionQuery := `{"query":"query { __schema { types { name } } }"}`

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewBufferString(introspectionQuery))
	if err != nil {
		return nil
	}

	// Set headers
	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Apply authentication if configured
	if d.authConfig != nil {
		d.authConfig.ApplyToRequest(req)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// Check if response looks like a valid GraphQL response
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if d.isGraphQLResponse(body) {
			// Perform GraphQL security testing
			securityResult := d.TestGraphQLSecurity(ctx, fullURL)
			if securityResult != nil {
				result.GraphQLFindings = append(result.GraphQLFindings, securityResult)
			}

			description := "GraphQL endpoint detected"
			if securityResult != nil && securityResult.IntrospectionEnabled {
				description = "GraphQL endpoint with introspection enabled"
			}

			return &DiscoveredEndpoint{
				URL:         fullURL,
				Type:        ep.endpointType,
				StatusCode:  resp.StatusCode,
				ContentType: resp.Header.Get("Content-Type"),
				Description: description,
			}
		}
	}

	// Also try GET request for GraphQL endpoints (some may respond to GET)
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept", "application/json, text/html, */*")

	if d.authConfig != nil {
		d.authConfig.ApplyToRequest(req)
	}

	resp, err = d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check for GraphQL playground or similar UI
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/html") {
			return &DiscoveredEndpoint{
				URL:         fullURL,
				Type:        ep.endpointType,
				StatusCode:  resp.StatusCode,
				ContentType: contentType,
				Description: "GraphQL endpoint (playground/UI detected)",
			}
		}
	}

	return nil
}

// isGraphQLResponse checks if the response body looks like a valid GraphQL response.
func (d *Discoverer) isGraphQLResponse(body []byte) bool {
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return false
	}

	// Valid GraphQL response should have "data" or "errors" field
	_, hasData := response["data"]
	_, hasErrors := response["errors"]
	return hasData || hasErrors
}

// detectSpecVersion attempts to detect the specification version from the response body.
func (d *Discoverer) detectSpecVersion(body []byte) string {
	if body == nil || len(body) == 0 {
		return ""
	}

	var spec map[string]interface{}
	if err := json.Unmarshal(body, &spec); err != nil {
		// Try YAML parsing as fallback
		return ""
	}

	// Check for OpenAPI 3.x
	if openapi, ok := spec["openapi"].(string); ok {
		return "OpenAPI " + openapi
	}

	// Check for Swagger 2.0
	if swagger, ok := spec["swagger"].(string); ok {
		return "Swagger " + swagger
	}

	return ""
}

// updateDiscoverySummary updates the summary fields in the discovery result.
func (d *Discoverer) updateDiscoverySummary(result *DiscoveryResult, totalProbed int, apiTypeMap map[string]bool) {
	// Set API types from discovered endpoints
	for apiType := range apiTypeMap {
		result.APITypes = append(result.APITypes, apiType)
	}

	// Update summary flags
	result.Summary.HasOpenAPI = apiTypeMap["openapi"]
	result.Summary.HasSwagger = apiTypeMap["swagger"]
	result.Summary.HasGraphQL = apiTypeMap["graphql"]
	result.Summary.SpecificationFound = result.Summary.HasOpenAPI || result.Summary.HasSwagger
}
