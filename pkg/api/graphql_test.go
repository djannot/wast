package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTestGraphQLSecurity_IntrospectionEnabled(t *testing.T) {
	// Create a mock GraphQL server with introspection enabled
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Full introspection response with schema details
			w.Write([]byte(`{
				"data": {
					"__schema": {
						"queryType": {"name": "Query"},
						"mutationType": {"name": "Mutation"},
						"subscriptionType": {"name": "Subscription"},
						"types": [
							{"name": "Query", "kind": "OBJECT"},
							{"name": "Mutation", "kind": "OBJECT"},
							{"name": "Subscription", "kind": "OBJECT"},
							{"name": "User", "kind": "OBJECT"},
							{"name": "String", "kind": "SCALAR"}
						]
					}
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := NewDiscoverer(WithDiscovererTimeout(5 * time.Second))
	ctx := context.Background()
	result := d.TestGraphQLSecurity(ctx, server.URL)

	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	if !result.IntrospectionEnabled {
		t.Error("Expected introspection to be enabled")
	}

	if result.SchemaInfo == nil {
		t.Fatal("Expected schema info to be present")
	}

	if result.SchemaInfo.TypeCount != 5 {
		t.Errorf("Expected 5 types, got %d", result.SchemaInfo.TypeCount)
	}

	if result.SchemaInfo.QueryTypeName != "Query" {
		t.Errorf("Expected query type name to be 'Query', got '%s'", result.SchemaInfo.QueryTypeName)
	}

	if result.SchemaInfo.MutationTypeName != "Mutation" {
		t.Errorf("Expected mutation type name to be 'Mutation', got '%s'", result.SchemaInfo.MutationTypeName)
	}

	if result.SchemaInfo.SubscriptionType != "Subscription" {
		t.Errorf("Expected subscription type to be 'Subscription', got '%s'", result.SchemaInfo.SubscriptionType)
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}

	// Check for the introspection enabled finding
	foundIntrospectionFinding := false
	for _, finding := range result.Findings {
		if finding.Type == "graphql_introspection_enabled" {
			foundIntrospectionFinding = true
			if finding.Severity != "medium" {
				t.Errorf("Expected severity 'medium', got '%s'", finding.Severity)
			}
			if finding.Description == "" {
				t.Error("Expected description to be non-empty")
			}
			if finding.Remediation == "" {
				t.Error("Expected remediation to be non-empty")
			}
		}
	}

	if !foundIntrospectionFinding {
		t.Error("Expected to find 'graphql_introspection_enabled' finding")
	}
}

func TestTestGraphQLSecurity_IntrospectionDisabled(t *testing.T) {
	// Create a mock GraphQL server with introspection disabled
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Response with errors indicating introspection is disabled
			w.Write([]byte(`{
				"errors": [
					{"message": "GraphQL introspection is not allowed"}
				]
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := NewDiscoverer(WithDiscovererTimeout(5 * time.Second))
	ctx := context.Background()
	result := d.TestGraphQLSecurity(ctx, server.URL)

	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	if result.IntrospectionEnabled {
		t.Error("Expected introspection to be disabled")
	}

	if result.SchemaInfo != nil {
		t.Error("Expected schema info to be nil when introspection is disabled")
	}

	// When introspection is disabled, there should be no findings
	foundIntrospectionFinding := false
	for _, finding := range result.Findings {
		if finding.Type == "graphql_introspection_enabled" {
			foundIntrospectionFinding = true
		}
	}

	if foundIntrospectionFinding {
		t.Error("Should not have introspection enabled finding when introspection is disabled")
	}
}

func TestTestGraphQLSecurity_InvalidResponse(t *testing.T) {
	// Create a mock server that returns invalid response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	d := NewDiscoverer(WithDiscovererTimeout(5 * time.Second))
	ctx := context.Background()
	result := d.TestGraphQLSecurity(ctx, server.URL)

	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	if result.IntrospectionEnabled {
		t.Error("Expected introspection to be disabled for invalid response")
	}

	if result.SchemaInfo != nil {
		t.Error("Expected schema info to be nil for invalid response")
	}
}

func TestGraphQLSecurityResult_String(t *testing.T) {
	result := &GraphQLSecurityResult{
		URL:                  "https://api.example.com/graphql",
		IntrospectionEnabled: true,
		SchemaInfo: &GraphQLSchemaInfo{
			TypeCount:         10,
			QueryCount:        5,
			MutationCount:     3,
			SubscriptionCount: 2,
			QueryTypeName:     "Query",
			MutationTypeName:  "Mutation",
			SubscriptionType:  "Subscription",
		},
		Findings: []GraphQLFinding{
			{
				Type:        "graphql_introspection_enabled",
				Severity:    "medium",
				Description: "GraphQL introspection is enabled",
				Remediation: "Disable introspection in production",
			},
		},
	}

	str := result.String()

	if !strings.Contains(str, "https://api.example.com/graphql") {
		t.Error("Expected string to contain URL")
	}

	if !strings.Contains(str, "Introspection Enabled: true") {
		t.Error("Expected string to contain introspection status")
	}

	if !strings.Contains(str, "Total Types: 10") {
		t.Error("Expected string to contain type count")
	}

	if !strings.Contains(str, "Query Type: Query") {
		t.Error("Expected string to contain query type")
	}

	if !strings.Contains(str, "Mutation Type: Mutation") {
		t.Error("Expected string to contain mutation type")
	}

	if !strings.Contains(str, "Subscription Type: Subscription") {
		t.Error("Expected string to contain subscription type")
	}

	if !strings.Contains(str, "medium") {
		t.Error("Expected string to contain severity")
	}

	if !strings.Contains(str, "graphql_introspection_enabled") {
		t.Error("Expected string to contain finding type")
	}
}

func TestFullIntrospectionQuery(t *testing.T) {
	query := fullIntrospectionQuery()

	if query == "" {
		t.Error("Expected introspection query to be non-empty")
	}

	if !strings.Contains(query, "__schema") {
		t.Error("Expected introspection query to contain __schema")
	}

	if !strings.Contains(query, "queryType") {
		t.Error("Expected introspection query to contain queryType")
	}

	if !strings.Contains(query, "mutationType") {
		t.Error("Expected introspection query to contain mutationType")
	}

	if !strings.Contains(query, "subscriptionType") {
		t.Error("Expected introspection query to contain subscriptionType")
	}

	if !strings.Contains(query, "types") {
		t.Error("Expected introspection query to contain types")
	}
}

func TestDiscoverer_Discover_GraphQLWithSecurityTesting(t *testing.T) {
	// Create a mock GraphQL server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Return introspection response
			w.Write([]byte(`{
				"data": {
					"__schema": {
						"queryType": {"name": "Query"},
						"mutationType": {"name": "Mutation"},
						"types": [
							{"name": "Query", "kind": "OBJECT"},
							{"name": "Mutation", "kind": "OBJECT"},
							{"name": "User", "kind": "OBJECT"}
						]
					}
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := NewDiscoverer(WithDiscovererTimeout(5 * time.Second))
	ctx := context.Background()
	result := d.Discover(ctx, server.URL)

	if result.Summary.EndpointsFound < 1 {
		t.Error("Expected at least one endpoint to be found")
	}

	if !result.Summary.HasGraphQL {
		t.Error("Expected HasGraphQL to be true")
	}

	// Check that GraphQL was discovered
	foundGraphQL := false
	for _, ep := range result.DiscoveredEndpoints {
		if strings.Contains(ep.URL, "/graphql") && ep.Type == "graphql" {
			foundGraphQL = true
			if !strings.Contains(ep.Description, "introspection") {
				t.Error("Expected description to mention introspection")
			}
		}
	}

	if !foundGraphQL {
		t.Error("Expected to find GraphQL endpoint")
	}

	// Check that GraphQL security findings were added
	if len(result.GraphQLFindings) == 0 {
		t.Error("Expected GraphQL security findings to be present")
	}

	// Verify the security finding details
	for _, gqlResult := range result.GraphQLFindings {
		if !gqlResult.IntrospectionEnabled {
			t.Error("Expected introspection to be enabled")
		}

		if gqlResult.SchemaInfo == nil {
			t.Error("Expected schema info to be present")
		}

		if len(gqlResult.Findings) == 0 {
			t.Error("Expected at least one security finding")
		}

		// Check for the introspection finding
		foundFinding := false
		for _, finding := range gqlResult.Findings {
			if finding.Type == "graphql_introspection_enabled" && finding.Severity == "medium" {
				foundFinding = true
			}
		}

		if !foundFinding {
			t.Error("Expected to find introspection enabled security finding")
		}
	}
}

func TestDiscoverer_Discover_GraphQLInString(t *testing.T) {
	// Create a mock GraphQL server with introspection enabled
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"__schema": {
						"queryType": {"name": "Query"},
						"types": [{"name": "Query", "kind": "OBJECT"}]
					}
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := NewDiscoverer(WithDiscovererTimeout(5 * time.Second))
	ctx := context.Background()
	result := d.Discover(ctx, server.URL)

	str := result.String()

	if !strings.Contains(str, "GraphQL Security Findings") {
		t.Error("Expected string representation to contain GraphQL Security Findings section")
	}

	if !strings.Contains(str, "Introspection Enabled: true") {
		t.Error("Expected string to contain introspection status")
	}

	if !strings.Contains(str, "Schema Types:") {
		t.Error("Expected string to contain schema types count")
	}
}
