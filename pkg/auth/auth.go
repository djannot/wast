// Package auth provides authentication configuration for HTTP requests.
// This enables authenticated testing of web applications and APIs.
package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// AuthConfig holds authentication configuration for HTTP requests.
// It supports multiple authentication methods: custom headers, bearer tokens,
// basic auth, and cookies. Multiple methods can be combined.
type AuthConfig struct {
	// AuthHeader is a raw authentication header (e.g., "Authorization: Bearer <token>")
	AuthHeader string `json:"auth_header,omitempty" yaml:"auth_header,omitempty"`

	// BearerToken is a bearer token (shorthand for "Authorization: Bearer <token>")
	BearerToken string `json:"bearer_token,omitempty" yaml:"bearer_token,omitempty"`

	// BasicAuth is basic auth credentials in the format "user:pass"
	BasicAuth string `json:"basic_auth,omitempty" yaml:"basic_auth,omitempty"`

	// Cookies is a list of cookies to include in requests (format: "name=value")
	Cookies []string `json:"cookies,omitempty" yaml:"cookies,omitempty"`
}

// IsEmpty returns true if no authentication is configured.
func (c *AuthConfig) IsEmpty() bool {
	if c == nil {
		return true
	}
	return c.AuthHeader == "" && c.BearerToken == "" && c.BasicAuth == "" && len(c.Cookies) == 0
}

// ApplyToRequest adds authentication headers and cookies to an HTTP request.
// When multiple auth methods are configured, they are applied in this priority order
// (later methods override earlier ones for the same header):
// 1. Basic auth (lowest priority for Authorization header)
// 2. Custom auth header
// 3. Bearer token (highest priority for Authorization header)
// 4. Cookies (always added, don't conflict with headers)
func (c *AuthConfig) ApplyToRequest(req *http.Request) {
	if c == nil {
		return
	}

	// Apply basic auth first (lowest priority for Authorization header)
	if c.BasicAuth != "" {
		parts := strings.SplitN(c.BasicAuth, ":", 2)
		if len(parts) == 2 {
			username := parts[0]
			password := parts[1]
			auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			req.Header.Set("Authorization", "Basic "+auth)
		}
	}

	// Apply custom auth header (can override basic auth if it sets Authorization)
	if c.AuthHeader != "" {
		parts := strings.SplitN(c.AuthHeader, ":", 2)
		if len(parts) == 2 {
			headerName := strings.TrimSpace(parts[0])
			headerValue := strings.TrimSpace(parts[1])
			req.Header.Set(headerName, headerValue)
		}
	}

	// Apply bearer token last (highest priority for Authorization header)
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}

	// Apply cookies (don't conflict with headers)
	for _, cookie := range c.Cookies {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 {
			req.AddCookie(&http.Cookie{
				Name:  strings.TrimSpace(parts[0]),
				Value: strings.TrimSpace(parts[1]),
			})
		}
	}
}

// Summary returns a human-readable summary of the auth configuration.
// Sensitive values are masked for security.
func (c *AuthConfig) Summary() string {
	if c.IsEmpty() {
		return "none"
	}

	var parts []string

	if c.AuthHeader != "" {
		// Extract header name only, mask the value
		headerParts := strings.SplitN(c.AuthHeader, ":", 2)
		if len(headerParts) == 2 {
			parts = append(parts, fmt.Sprintf("header:%s", strings.TrimSpace(headerParts[0])))
		} else {
			parts = append(parts, "header:custom")
		}
	}

	if c.BearerToken != "" {
		parts = append(parts, "bearer:***")
	}

	if c.BasicAuth != "" {
		// Extract username only, mask the password
		authParts := strings.SplitN(c.BasicAuth, ":", 2)
		if len(authParts) == 2 {
			parts = append(parts, fmt.Sprintf("basic:%s:***", authParts[0]))
		} else {
			parts = append(parts, "basic:***")
		}
	}

	if len(c.Cookies) > 0 {
		var cookieNames []string
		for _, cookie := range c.Cookies {
			cookieParts := strings.SplitN(cookie, "=", 2)
			if len(cookieParts) >= 1 {
				cookieNames = append(cookieNames, strings.TrimSpace(cookieParts[0]))
			}
		}
		parts = append(parts, fmt.Sprintf("cookies:[%s]", strings.Join(cookieNames, ",")))
	}

	return strings.Join(parts, ", ")
}

// String returns a string representation of the auth config for debugging.
func (c *AuthConfig) String() string {
	return c.Summary()
}
