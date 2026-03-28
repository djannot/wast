// Package api provides JWT analysis utilities for API security testing.
package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// JWTAnalysis represents the result of JWT token analysis.
type JWTAnalysis struct {
	Token           string                 `json:"token" yaml:"token"`
	Header          map[string]interface{} `json:"header" yaml:"header"`
	Payload         map[string]interface{} `json:"payload" yaml:"payload"`
	Algorithm       string                 `json:"algorithm" yaml:"algorithm"`
	IsExpired       bool                   `json:"is_expired" yaml:"is_expired"`
	ExpiresAt       string                 `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	IssuedAt        string                 `json:"issued_at,omitempty" yaml:"issued_at,omitempty"`
	NotBefore       string                 `json:"not_before,omitempty" yaml:"not_before,omitempty"`
	Vulnerabilities []string               `json:"vulnerabilities,omitempty" yaml:"vulnerabilities,omitempty"`
	Warnings        []string               `json:"warnings,omitempty" yaml:"warnings,omitempty"`
	Valid           bool                   `json:"valid" yaml:"valid"`
}

// AnalyzeJWT analyzes a JWT token without verifying the signature.
func AnalyzeJWT(token string) (*JWTAnalysis, error) {
	analysis := &JWTAnalysis{
		Token:           token,
		Vulnerabilities: make([]string, 0),
		Warnings:        make([]string, 0),
		Valid:           true,
	}

	// Split JWT into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	header, err := decodeJWTPart(parts[0])
	if err != nil {
		analysis.Valid = false
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, fmt.Sprintf("Failed to decode header: %s", err.Error()))
		return analysis, nil
	}
	analysis.Header = header

	// Extract algorithm
	if alg, ok := header["alg"].(string); ok {
		analysis.Algorithm = alg

		// Check for weak algorithms
		if alg == "none" {
			analysis.Vulnerabilities = append(analysis.Vulnerabilities, "CRITICAL: Algorithm is 'none' - signature verification disabled")
		} else if strings.HasPrefix(alg, "HS") {
			analysis.Warnings = append(analysis.Warnings, "Algorithm uses HMAC - vulnerable to key brute-forcing if secret is weak")
		}
	} else {
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "Missing or invalid 'alg' field in header")
	}

	// Decode payload
	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		analysis.Valid = false
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, fmt.Sprintf("Failed to decode payload: %s", err.Error()))
		return analysis, nil
	}
	analysis.Payload = payload

	// Check expiration
	if exp, ok := payload["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		analysis.ExpiresAt = expTime.Format(time.RFC3339)
		analysis.IsExpired = time.Now().After(expTime)

		if analysis.IsExpired {
			analysis.Warnings = append(analysis.Warnings, "Token has expired")
		}
	} else {
		analysis.Warnings = append(analysis.Warnings, "No expiration claim (exp) - token never expires")
	}

	// Check issued at
	if iat, ok := payload["iat"].(float64); ok {
		issuedTime := time.Unix(int64(iat), 0)
		analysis.IssuedAt = issuedTime.Format(time.RFC3339)
	}

	// Check not before
	if nbf, ok := payload["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		analysis.NotBefore = nbfTime.Format(time.RFC3339)

		if time.Now().Before(nbfTime) {
			analysis.Warnings = append(analysis.Warnings, "Token is not yet valid (nbf claim)")
		}
	}

	// Check for sensitive data in payload
	sensitiveFields := []string{"password", "secret", "api_key", "apikey", "private_key"}
	for _, field := range sensitiveFields {
		if _, exists := payload[field]; exists {
			analysis.Vulnerabilities = append(analysis.Vulnerabilities,
				fmt.Sprintf("CRITICAL: Sensitive field '%s' found in payload - JWT payload is not encrypted", field))
		}
	}

	// Check signature presence
	if parts[2] == "" {
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "CRITICAL: Missing signature")
	}

	return analysis, nil
}

// decodeJWTPart decodes a base64-encoded JWT part.
func decodeJWTPart(part string) (map[string]interface{}, error) {
	// JWT uses base64url encoding without padding
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		// Try with standard base64 as fallback
		decoded, err = base64.URLEncoding.DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("base64 decode error: %w", err)
		}
	}

	var result map[string]interface{}
	if err := json.Unmarshal(decoded, &result); err != nil {
		return nil, fmt.Errorf("JSON unmarshal error: %w", err)
	}

	return result, nil
}

// ExtractJWTFromHeaders extracts JWT tokens from common HTTP headers.
// Header matching is case-insensitive per RFC 7230.
func ExtractJWTFromHeaders(headers map[string]string) []string {
	tokens := make([]string, 0)

	// Normalize header keys to canonical form for case-insensitive matching
	normalizedHeaders := make(map[string]string)
	for k, v := range headers {
		normalizedHeaders[http.CanonicalHeaderKey(k)] = v
	}

	// Check Authorization header
	if auth, ok := normalizedHeaders["Authorization"]; ok {
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			if looksLikeJWT(token) {
				tokens = append(tokens, token)
			}
		}
	}

	// Check common JWT header names
	jwtHeaders := []string{"X-Auth-Token", "X-Jwt-Token", "X-Access-Token"}
	for _, headerName := range jwtHeaders {
		if token, ok := normalizedHeaders[headerName]; ok && looksLikeJWT(token) {
			tokens = append(tokens, token)
		}
	}

	return tokens
}

// looksLikeJWT performs a quick check if a string looks like a JWT.
func looksLikeJWT(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 3 && len(parts[0]) > 0
}
