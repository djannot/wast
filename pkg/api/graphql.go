// Package api provides OpenAPI/Swagger specification parsing and API endpoint testing.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/djannot/wast/pkg/httputil"
)

// GraphQLSecurityResult represents the result of GraphQL security testing.
type GraphQLSecurityResult struct {
	URL                  string             `json:"url" yaml:"url"`
	IntrospectionEnabled bool               `json:"introspection_enabled" yaml:"introspection_enabled"`
	SchemaInfo           *GraphQLSchemaInfo `json:"schema_info,omitempty" yaml:"schema_info,omitempty"`
	Findings             []GraphQLFinding   `json:"findings" yaml:"findings"`
}

// GraphQLSchemaInfo contains extracted schema details from introspection.
type GraphQLSchemaInfo struct {
	TypeCount        int    `json:"type_count" yaml:"type_count"`
	QueryTypeName    string `json:"query_type_name,omitempty" yaml:"query_type_name,omitempty"`
	MutationTypeName string `json:"mutation_type_name,omitempty" yaml:"mutation_type_name,omitempty"`
	SubscriptionType string `json:"subscription_type,omitempty" yaml:"subscription_type,omitempty"`
}

// GraphQLFinding represents a security finding related to GraphQL.
type GraphQLFinding struct {
	Type        string `json:"type" yaml:"type"`
	Severity    string `json:"severity" yaml:"severity"`
	Description string `json:"description" yaml:"description"`
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

// GraphQLIntrospectionResponse represents the GraphQL introspection query response.
type GraphQLIntrospectionResponse struct {
	Data struct {
		Schema struct {
			QueryType *struct {
				Name string `json:"name"`
			} `json:"queryType"`
			MutationType *struct {
				Name string `json:"name"`
			} `json:"mutationType"`
			SubscriptionType *struct {
				Name string `json:"name"`
			} `json:"subscriptionType"`
			Types []struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// fullIntrospectionQuery returns the complete GraphQL introspection query for schema extraction.
func fullIntrospectionQuery() string {
	return `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }"}`
}

// TestGraphQLSecurity performs security testing on a GraphQL endpoint.
func (d *Discoverer) TestGraphQLSecurity(ctx context.Context, url string) *GraphQLSecurityResult {
	result := &GraphQLSecurityResult{
		URL:      url,
		Findings: make([]GraphQLFinding, 0),
	}

	// Test for introspection
	introspectionEnabled, schemaInfo := d.testGraphQLIntrospection(ctx, url)
	result.IntrospectionEnabled = introspectionEnabled
	result.SchemaInfo = schemaInfo

	// Add finding if introspection is enabled
	if introspectionEnabled {
		finding := GraphQLFinding{
			Type:        "graphql_introspection_enabled",
			Severity:    "medium",
			Description: "GraphQL introspection is enabled, potentially exposing the entire API schema to unauthorized users",
			Remediation: "Disable introspection in production environments. Most GraphQL servers provide a configuration option to disable introspection queries.",
		}
		result.Findings = append(result.Findings, finding)
	}

	return result
}

// testGraphQLIntrospection tests if GraphQL introspection is enabled and extracts schema info.
func (d *Discoverer) testGraphQLIntrospection(ctx context.Context, url string) (bool, *GraphQLSchemaInfo) {
	// Create introspection query request
	introspectionQuery := fullIntrospectionQuery()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(introspectionQuery))
	if err != nil {
		return false, nil
	}

	// Set headers
	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Apply authentication if configured
	if d.authConfig != nil {
		d.authConfig.ApplyToRequest(req)
	}

	// Make the request
	resp, err := d.client.Do(req)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()

	// Read response body
	body, err := httputil.ReadResponseBody(resp.Body)
	if err != nil {
		return false, nil
	}

	// Check if it's a valid GraphQL response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, nil
	}

	// Parse the introspection response
	var introspectionResp GraphQLIntrospectionResponse
	if err := json.Unmarshal(body, &introspectionResp); err != nil {
		return false, nil
	}

	// Check if introspection was successful (has data and no errors, or has data with schema)
	if introspectionResp.Data.Schema.Types == nil || len(introspectionResp.Data.Schema.Types) == 0 {
		return false, nil
	}

	// Introspection is enabled, extract schema info
	schemaInfo := &GraphQLSchemaInfo{
		TypeCount: len(introspectionResp.Data.Schema.Types),
	}

	// Extract query type name
	if introspectionResp.Data.Schema.QueryType != nil {
		schemaInfo.QueryTypeName = introspectionResp.Data.Schema.QueryType.Name
	}

	// Extract mutation type name
	if introspectionResp.Data.Schema.MutationType != nil {
		schemaInfo.MutationTypeName = introspectionResp.Data.Schema.MutationType.Name
	}

	// Extract subscription type name
	if introspectionResp.Data.Schema.SubscriptionType != nil {
		schemaInfo.SubscriptionType = introspectionResp.Data.Schema.SubscriptionType.Name
	}

	return true, schemaInfo
}

// String returns a human-readable representation of the GraphQL security result.
func (r *GraphQLSecurityResult) String() string {
	var result string
	result += fmt.Sprintf("GraphQL Security Test for: %s\n", r.URL)
	result += fmt.Sprintf("Introspection Enabled: %v\n", r.IntrospectionEnabled)

	if r.SchemaInfo != nil {
		result += fmt.Sprintf("\nSchema Information:\n")
		result += fmt.Sprintf("  Total Types: %d\n", r.SchemaInfo.TypeCount)
		if r.SchemaInfo.QueryTypeName != "" {
			result += fmt.Sprintf("  Query Type: %s\n", r.SchemaInfo.QueryTypeName)
		}
		if r.SchemaInfo.MutationTypeName != "" {
			result += fmt.Sprintf("  Mutation Type: %s\n", r.SchemaInfo.MutationTypeName)
		}
		if r.SchemaInfo.SubscriptionType != "" {
			result += fmt.Sprintf("  Subscription Type: %s\n", r.SchemaInfo.SubscriptionType)
		}
	}

	if len(r.Findings) > 0 {
		result += fmt.Sprintf("\nFindings:\n")
		for _, finding := range r.Findings {
			result += fmt.Sprintf("  [%s] %s\n", finding.Severity, finding.Type)
			result += fmt.Sprintf("    %s\n", finding.Description)
			if finding.Remediation != "" {
				result += fmt.Sprintf("    Remediation: %s\n", finding.Remediation)
			}
		}
	}

	return result
}
