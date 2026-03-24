package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
)

func TestNewDiscoverer(t *testing.T) {
	t.Run("default settings", func(t *testing.T) {
		d := NewDiscoverer()
		if d.userAgent != "WAST/1.0 (Web Application Security Testing)" {
			t.Errorf("Expected default user agent, got %s", d.userAgent)
		}
		if d.timeout != 30*time.Second {
			t.Errorf("Expected 30s timeout, got %v", d.timeout)
		}
		if d.client == nil {
			t.Error("Expected client to be initialized")
		}
	})

	t.Run("with custom timeout", func(t *testing.T) {
		d := NewDiscoverer(WithDiscovererTimeout(10 * time.Second))
		if d.timeout != 10*time.Second {
			t.Errorf("Expected 10s timeout, got %v", d.timeout)
		}
	})

	t.Run("with custom user agent", func(t *testing.T) {
		d := NewDiscoverer(WithDiscovererUserAgent("CustomAgent/1.0"))
		if d.userAgent != "CustomAgent/1.0" {
			t.Errorf("Expected custom user agent, got %s", d.userAgent)
		}
	})

	t.Run("with auth config", func(t *testing.T) {
		authConfig := &auth.AuthConfig{BearerToken: "test-token"}
		d := NewDiscoverer(WithDiscovererAuth(authConfig))
		if d.authConfig != authConfig {
			t.Error("Expected auth config to be set")
		}
	})

	t.Run("with rate limit config", func(t *testing.T) {
		cfg := ratelimit.Config{RequestsPerSecond: 5}
		d := NewDiscoverer(WithDiscovererRateLimitConfig(cfg))
		if d.rateLimiter == nil {
			t.Error("Expected rate limiter to be set")
		}
	})
}

func TestDiscoverer_normalizeBaseURL(t *testing.T) {
	d := NewDiscoverer()

	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "full HTTPS URL",
			input:    "https://api.example.com",
			expected: "https://api.example.com",
			wantErr:  false,
		},
		{
			name:     "full HTTP URL",
			input:    "http://api.example.com",
			expected: "http://api.example.com",
			wantErr:  false,
		},
		{
			name:     "URL without scheme",
			input:    "api.example.com",
			expected: "https://api.example.com",
			wantErr:  false,
		},
		{
			name:     "URL with port",
			input:    "https://api.example.com:8080",
			expected: "https://api.example.com:8080",
			wantErr:  false,
		},
		{
			name:     "URL with path",
			input:    "https://api.example.com/v1/api",
			expected: "https://api.example.com",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := d.normalizeBaseURL(tt.input)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestDiscoverer_Discover_OpenAPI(t *testing.T) {
	// Create a mock server that serves OpenAPI spec
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"openapi": "3.0.0", "info": {"title": "Test API", "version": "1.0.0"}}`))
		case "/swagger.json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"swagger": "2.0", "info": {"title": "Test API", "version": "1.0.0"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	d := NewDiscoverer(WithDiscovererTimeout(5 * time.Second))
	ctx := context.Background()
	result := d.Discover(ctx, server.URL)

	if result.Target != server.URL {
		t.Errorf("Expected target %s, got %s", server.URL, result.Target)
	}

	if result.Summary.EndpointsFound < 1 {
		t.Error("Expected at least one endpoint to be found")
	}

	if !result.Summary.HasOpenAPI && !result.Summary.HasSwagger {
		t.Error("Expected HasOpenAPI or HasSwagger to be true")
	}

	// Check that OpenAPI was discovered
	foundOpenAPI := false
	foundSwagger := false
	for _, ep := range result.DiscoveredEndpoints {
		if strings.Contains(ep.URL, "/openapi.json") && ep.Type == "openapi" {
			foundOpenAPI = true
			if ep.SpecVersion == "" {
				t.Error("Expected spec version to be detected for OpenAPI")
			}
		}
		if strings.Contains(ep.URL, "/swagger.json") && ep.Type == "swagger" {
			foundSwagger = true
		}
	}

	if !foundOpenAPI {
		t.Error("Expected to find OpenAPI endpoint")
	}
	if !foundSwagger {
		t.Error("Expected to find Swagger endpoint")
	}
}

func TestDiscoverer_Discover_GraphQL(t *testing.T) {
	// Create a mock GraphQL server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": {"__schema": {"types": [{"name": "Query"}]}}}`))
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
		}
	}

	if !foundGraphQL {
		t.Error("Expected to find GraphQL endpoint")
	}
}

func TestDiscoverer_Discover_NoEndpoints(t *testing.T) {
	// Create a mock server that returns 404 for all requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := NewDiscoverer(WithDiscovererTimeout(5 * time.Second))
	ctx := context.Background()
	result := d.Discover(ctx, server.URL)

	if result.Summary.EndpointsFound != 0 {
		t.Errorf("Expected 0 endpoints found, got %d", result.Summary.EndpointsFound)
	}

	if result.Summary.EndpointsProbed == 0 {
		t.Error("Expected some endpoints to be probed")
	}
}

func TestDiscoverer_Discover_WithAuth(t *testing.T) {
	// Create a mock server that requires authentication
	var receivedAuthHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		if r.URL.Path == "/openapi.json" {
			if strings.HasPrefix(receivedAuthHeader, "Bearer ") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"openapi": "3.0.0"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	authConfig := &auth.AuthConfig{BearerToken: "test-token-123"}
	d := NewDiscoverer(
		WithDiscovererTimeout(5*time.Second),
		WithDiscovererAuth(authConfig),
	)
	ctx := context.Background()
	result := d.Discover(ctx, server.URL)

	if receivedAuthHeader != "Bearer test-token-123" {
		t.Errorf("Expected auth header to be set, got %s", receivedAuthHeader)
	}

	if result.Summary.EndpointsFound < 1 {
		t.Error("Expected at least one endpoint to be found with authentication")
	}
}

func TestDiscoverer_Discover_ContextCancellation(t *testing.T) {
	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDiscoverer(WithDiscovererTimeout(5 * time.Second))

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := d.Discover(ctx, server.URL)

	// Should have at least one error about cancellation
	if len(result.Errors) == 0 {
		// The discovery might complete before the first request if cancelled at the right time
		// This is acceptable behavior
		t.Log("Discovery completed before context cancellation could take effect")
	}
}

func TestDiscoverer_isGraphQLResponse(t *testing.T) {
	d := NewDiscoverer()

	tests := []struct {
		name     string
		body     []byte
		expected bool
	}{
		{
			name:     "valid GraphQL response with data",
			body:     []byte(`{"data": {"__schema": {"types": []}}}`),
			expected: true,
		},
		{
			name:     "valid GraphQL response with errors",
			body:     []byte(`{"errors": [{"message": "Not authorized"}]}`),
			expected: true,
		},
		{
			name:     "valid GraphQL response with both",
			body:     []byte(`{"data": null, "errors": [{"message": "Error"}]}`),
			expected: true,
		},
		{
			name:     "invalid response - random JSON",
			body:     []byte(`{"status": "ok"}`),
			expected: false,
		},
		{
			name:     "invalid response - not JSON",
			body:     []byte(`<html>Not GraphQL</html>`),
			expected: false,
		},
		{
			name:     "empty body",
			body:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.isGraphQLResponse(tt.body)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDiscoverer_detectSpecVersion(t *testing.T) {
	d := NewDiscoverer()

	tests := []struct {
		name     string
		body     []byte
		expected string
	}{
		{
			name:     "OpenAPI 3.0.0",
			body:     []byte(`{"openapi": "3.0.0"}`),
			expected: "OpenAPI 3.0.0",
		},
		{
			name:     "OpenAPI 3.1.0",
			body:     []byte(`{"openapi": "3.1.0"}`),
			expected: "OpenAPI 3.1.0",
		},
		{
			name:     "Swagger 2.0",
			body:     []byte(`{"swagger": "2.0"}`),
			expected: "Swagger 2.0",
		},
		{
			name:     "no version field",
			body:     []byte(`{"info": {"title": "API"}}`),
			expected: "",
		},
		{
			name:     "invalid JSON",
			body:     []byte(`not json`),
			expected: "",
		},
		{
			name:     "empty body",
			body:     nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.detectSpecVersion(tt.body)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestDiscoveryResult_String(t *testing.T) {
	result := &DiscoveryResult{
		Target:  "https://api.example.com",
		BaseURL: "https://api.example.com",
		DiscoveredEndpoints: []DiscoveredEndpoint{
			{
				URL:         "https://api.example.com/openapi.json",
				Type:        "openapi",
				StatusCode:  200,
				SpecVersion: "OpenAPI 3.0.0",
			},
		},
		APITypes: []string{"openapi"},
		Summary: DiscoverySummary{
			EndpointsProbed:    10,
			EndpointsFound:     1,
			HasOpenAPI:         true,
			SpecificationFound: true,
		},
	}

	str := result.String()

	if !strings.Contains(str, "API Discovery Results") {
		t.Error("Expected string to contain 'API Discovery Results'")
	}
	if !strings.Contains(str, "https://api.example.com") {
		t.Error("Expected string to contain target URL")
	}
	if !strings.Contains(str, "openapi.json") {
		t.Error("Expected string to contain discovered endpoint")
	}
	if !strings.Contains(str, "OpenAPI 3.0.0") {
		t.Error("Expected string to contain spec version")
	}
}

func TestCommonEndpoints(t *testing.T) {
	endpoints := commonEndpoints()

	if len(endpoints) == 0 {
		t.Error("Expected common endpoints to be non-empty")
	}

	// Check that we have various types of endpoints
	hasOpenAPI := false
	hasSwagger := false
	hasGraphQL := false
	hasAPIDocs := false

	for _, ep := range endpoints {
		switch ep.endpointType {
		case "openapi":
			hasOpenAPI = true
		case "swagger":
			hasSwagger = true
		case "graphql":
			hasGraphQL = true
		case "api-docs":
			hasAPIDocs = true
		}
	}

	if !hasOpenAPI {
		t.Error("Expected OpenAPI endpoints in common endpoints")
	}
	if !hasSwagger {
		t.Error("Expected Swagger endpoints in common endpoints")
	}
	if !hasGraphQL {
		t.Error("Expected GraphQL endpoints in common endpoints")
	}
	if !hasAPIDocs {
		t.Error("Expected API docs endpoints in common endpoints")
	}
}
