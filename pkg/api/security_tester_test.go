package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewSecurityTester(t *testing.T) {
	tester := NewSecurityTester()

	if tester == nil {
		t.Fatal("Expected security tester to be created")
	}

	if tester.sqliScanner == nil {
		t.Error("Expected SQLi scanner to be initialized")
	}

	if tester.xssScanner == nil {
		t.Error("Expected XSS scanner to be initialized")
	}
}

func TestBOLADetection(t *testing.T) {
	// Create a test server that simulates BOLA vulnerability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any request without auth returns 200 (vulnerable)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": 1, "data": "sensitive"}`))
	}))
	defer server.Close()

	tester := NewSecurityTester()
	ctx := context.Background()

	endpoint := EndpointInfo{
		Path:   "/users/{id}",
		Method: "GET",
		Parameters: []ParameterInfo{
			{
				Name:     "id",
				In:       "path",
				Required: true,
			},
		},
		Security: []string{"bearerAuth"},
	}

	result := tester.TestEndpointSecurity(ctx, server.URL, endpoint)

	if result == nil {
		t.Fatal("Expected security test result")
	}

	// Check if BOLA vulnerability was detected
	foundBOLA := false
	for _, vuln := range result.Vulnerabilities {
		if vuln.Type == "bola" {
			foundBOLA = true
			if vuln.Severity != "high" {
				t.Errorf("Expected high severity for BOLA, got %s", vuln.Severity)
			}
			break
		}
	}

	if !foundBOLA {
		t.Error("Expected BOLA vulnerability to be detected")
	}
}

func TestAuthBypassDetection(t *testing.T) {
	// Create a test server that simulates auth bypass
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for Authorization header
		if r.Header.Get("Authorization") == "" {
			// Should return 401, but returns 200 (vulnerable)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message": "success"}`))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message": "authenticated"}`))
		}
	}))
	defer server.Close()

	tester := NewSecurityTester()
	ctx := context.Background()

	endpoint := EndpointInfo{
		Path:     "/api/protected",
		Method:   "GET",
		Security: []string{"bearerAuth"},
	}

	result := tester.TestEndpointSecurity(ctx, server.URL, endpoint)

	if result == nil {
		t.Fatal("Expected security test result")
	}

	// Check if auth bypass was detected
	foundBypass := false
	for _, authTest := range result.AuthTests {
		if authTest.TestType == "bypass" && authTest.Success {
			foundBypass = true
			if authTest.StatusCode != http.StatusOK {
				t.Errorf("Expected status code 200, got %d", authTest.StatusCode)
			}
			break
		}
	}

	if !foundBypass {
		t.Error("Expected auth bypass to be detected")
	}
}

func TestGenerateBOLATestURLs(t *testing.T) {
	tester := NewSecurityTester()

	tests := []struct {
		name      string
		url       string
		paramName string
		expectMin int
	}{
		{
			name:      "Template syntax with braces",
			url:       "http://api.example.com/users/{id}",
			paramName: "id",
			expectMin: 1,
		},
		{
			name:      "Numeric ID in URL",
			url:       "http://api.example.com/users/123",
			paramName: "id",
			expectMin: 1,
		},
		{
			name:      "UUID in URL",
			url:       "http://api.example.com/users/550e8400-e29b-41d4-a716-446655440000",
			paramName: "id",
			expectMin: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls := tester.generateBOLATestURLs(tt.url, tt.paramName)

			if len(urls) < tt.expectMin {
				t.Errorf("Expected at least %d test URLs, got %d", tt.expectMin, len(urls))
			}
		})
	}
}

func TestHasPathParameters(t *testing.T) {
	tester := NewSecurityTester()

	tests := []struct {
		name     string
		endpoint EndpointInfo
		expect   bool
	}{
		{
			name: "Has path parameter",
			endpoint: EndpointInfo{
				Parameters: []ParameterInfo{
					{Name: "id", In: "path"},
				},
			},
			expect: true,
		},
		{
			name: "Only query parameters",
			endpoint: EndpointInfo{
				Parameters: []ParameterInfo{
					{Name: "search", In: "query"},
				},
			},
			expect: false,
		},
		{
			name: "No parameters",
			endpoint: EndpointInfo{
				Parameters: []ParameterInfo{},
			},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tester.hasPathParameters(tt.endpoint)

			if result != tt.expect {
				t.Errorf("Expected %v, got %v", tt.expect, result)
			}
		})
	}
}

func TestMassAssignmentDetection(t *testing.T) {
	// Create a test server that simulates mass assignment vulnerability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back the request body to simulate accepting extra fields
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name": "test", "role": "malicious_value", "admin": "malicious_value"}`))
	}))
	defer server.Close()

	tester := NewSecurityTester()
	ctx := context.Background()

	endpoint := EndpointInfo{
		Path:   "/api/users",
		Method: "POST",
		RequestBody: &SchemaInfo{
			Type: "object",
			Properties: map[string]string{
				"name": "string",
			},
		},
	}

	result := tester.TestEndpointSecurity(ctx, server.URL, endpoint)

	if result == nil {
		t.Fatal("Expected security test result")
	}

	// Check if mass assignment vulnerability was detected
	foundMassAssignment := false
	for _, vuln := range result.Vulnerabilities {
		if vuln.Type == "mass_assignment" {
			foundMassAssignment = true
			if vuln.Severity != "high" {
				t.Errorf("Expected high severity for mass assignment, got %s", vuln.Severity)
			}
			break
		}
	}

	if !foundMassAssignment {
		t.Error("Expected mass assignment vulnerability to be detected")
	}
}
