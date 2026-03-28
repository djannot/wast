package api

import (
	"strings"
	"testing"
	"time"
)

func TestAnalyzeJWT(t *testing.T) {
	tests := []struct {
		name               string
		token              string
		expectError        bool
		expectAlgorithm    string
		expectVulnCount    int
		expectWarningCount int
	}{
		{
			name:            "Valid JWT with HS256",
			token:           "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expectError:     false,
			expectAlgorithm: "HS256",
		},
		{
			name:            "JWT with 'none' algorithm",
			token:           "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
			expectError:     false,
			expectAlgorithm: "none",
			expectVulnCount: 2, // Should detect 'none' algorithm and missing signature
		},
		{
			name:        "Invalid JWT - only 2 parts",
			token:       "invalid.token",
			expectError: true,
		},
		{
			name:        "Invalid JWT - only 1 part",
			token:       "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := AnalyzeJWT(tt.token)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if analysis == nil {
				t.Fatal("Analysis is nil")
			}

			if analysis.Algorithm != tt.expectAlgorithm {
				t.Errorf("Expected algorithm %s, got %s", tt.expectAlgorithm, analysis.Algorithm)
			}

			if tt.expectVulnCount > 0 && len(analysis.Vulnerabilities) != tt.expectVulnCount {
				t.Errorf("Expected %d vulnerabilities, got %d", tt.expectVulnCount, len(analysis.Vulnerabilities))
			}
		})
	}
}

func TestExtractJWTFromHeaders(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		expectCount int
	}{
		{
			name: "Authorization Bearer token",
			headers: map[string]string{
				"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			},
			expectCount: 1,
		},
		{
			name: "X-Auth-Token header",
			headers: map[string]string{
				"X-Auth-Token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			},
			expectCount: 1,
		},
		{
			name: "No JWT in headers",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			expectCount: 0,
		},
		{
			name: "Invalid token format",
			headers: map[string]string{
				"Authorization": "Bearer invalid-token",
			},
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := ExtractJWTFromHeaders(tt.headers)

			if len(tokens) != tt.expectCount {
				t.Errorf("Expected %d tokens, got %d", tt.expectCount, len(tokens))
			}
		})
	}
}

func TestJWTExpiration(t *testing.T) {
	// Create a JWT with expired timestamp
	expiredTime := time.Now().Add(-1 * time.Hour).Unix()
	// Header: {"alg":"HS256","typ":"JWT"}
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	// Payload with expired exp claim (needs to be dynamically created)
	// For testing purposes, we'll use a known expired token

	// This is a valid JWT structure with exp set to a past timestamp
	expiredToken := header + ".eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTE2MjM5MDIyfQ.4Adcj0vWHb3Kf6Y5qs7fZhP3LlHkCjQKwQkk5p7RXoU"

	analysis, err := AnalyzeJWT(expiredToken)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !analysis.IsExpired {
		t.Error("Expected token to be marked as expired")
	}

	hasExpiryWarning := false
	for _, warning := range analysis.Warnings {
		if strings.Contains(warning, "expired") {
			hasExpiryWarning = true
			break
		}
	}

	if !hasExpiryWarning {
		t.Error("Expected expiration warning in warnings")
	}

	_ = expiredTime // Use the variable to avoid unused variable error
}

func TestLooksLikeJWT(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{
			name:   "Valid JWT format",
			input:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			expect: true,
		},
		{
			name:   "Two parts only",
			input:  "header.payload",
			expect: false,
		},
		{
			name:   "Four parts",
			input:  "a.b.c.d",
			expect: false, // Has 4 parts, not 3
		},
		{
			name:   "Empty string",
			input:  "",
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := looksLikeJWT(tt.input)
			if result != tt.expect {
				t.Errorf("Expected %v, got %v", tt.expect, result)
			}
		})
	}
}
