// Package auth provides authentication configuration for HTTP requests.
// This enables authenticated testing of web applications and APIs.
package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// LoginConfig holds configuration for automated login flow.
// It enables WAST to authenticate by submitting credentials to a login endpoint
// and automatically capturing session cookies for subsequent requests.
type LoginConfig struct {
	// LoginURL is the URL endpoint to submit credentials to
	LoginURL string `json:"login_url,omitempty" yaml:"login_url,omitempty"`

	// Username is the username/email to authenticate with
	Username string `json:"username,omitempty" yaml:"username,omitempty"`

	// Password is the password to authenticate with
	Password string `json:"password,omitempty" yaml:"password,omitempty"`

	// UsernameField is the form field name for username (default: "username")
	UsernameField string `json:"username_field,omitempty" yaml:"username_field,omitempty"`

	// PasswordField is the form field name for password (default: "password")
	PasswordField string `json:"password_field,omitempty" yaml:"password_field,omitempty"`

	// AdditionalFields contains any additional fields to submit with the login request
	AdditionalFields map[string]string `json:"additional_fields,omitempty" yaml:"additional_fields,omitempty"`

	// ContentType specifies the request content type: "form" (default) or "json"
	ContentType string `json:"content_type,omitempty" yaml:"content_type,omitempty"`
}

// AuthConfig holds authentication configuration for HTTP requests.
// It supports multiple authentication methods: custom headers, bearer tokens,
// basic auth, cookies, and automated login flows. Multiple methods can be combined.
type AuthConfig struct {
	// AuthHeader is a raw authentication header (e.g., "Authorization: Bearer <token>")
	AuthHeader string `json:"auth_header,omitempty" yaml:"auth_header,omitempty"`

	// BearerToken is a bearer token (shorthand for "Authorization: Bearer <token>")
	BearerToken string `json:"bearer_token,omitempty" yaml:"bearer_token,omitempty"`

	// BasicAuth is basic auth credentials in the format "user:pass"
	BasicAuth string `json:"basic_auth,omitempty" yaml:"basic_auth,omitempty"`

	// Cookies is a list of cookies to include in requests (format: "name=value")
	Cookies []string `json:"cookies,omitempty" yaml:"cookies,omitempty"`

	// Login holds configuration for automated login flow
	Login *LoginConfig `json:"login,omitempty" yaml:"login,omitempty"`
}

// IsEmpty returns true if no authentication is configured.
func (c *AuthConfig) IsEmpty() bool {
	if c == nil {
		return true
	}
	hasLogin := c.Login != nil && c.Login.LoginURL != ""
	return c.AuthHeader == "" && c.BearerToken == "" && c.BasicAuth == "" && len(c.Cookies) == 0 && !hasLogin
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

	if c.Login != nil && c.Login.LoginURL != "" {
		parts = append(parts, fmt.Sprintf("login:%s:***", c.Login.Username))
	}

	return strings.Join(parts, ", ")
}

// String returns a string representation of the auth config for debugging.
func (c *AuthConfig) String() string {
	return c.Summary()
}

// PerformLogin executes the automated login flow and captures session cookies.
// It submits credentials to the login endpoint and populates the Cookies field
// with any session cookies returned by the server.
// Returns an error if the login fails or if the response indicates an error.
func (c *AuthConfig) PerformLogin(ctx context.Context) error {
	if c == nil || c.Login == nil || c.Login.LoginURL == "" {
		return fmt.Errorf("login configuration is not set")
	}

	if c.Login.Username == "" || c.Login.Password == "" {
		return fmt.Errorf("username and password are required for login")
	}

	// Validate login URL
	if _, err := url.Parse(c.Login.LoginURL); err != nil {
		return fmt.Errorf("invalid login URL: %w", err)
	}

	// Set default field names if not provided
	usernameField := c.Login.UsernameField
	if usernameField == "" {
		usernameField = "username"
	}
	passwordField := c.Login.PasswordField
	if passwordField == "" {
		passwordField = "password"
	}

	// Set default content type if not provided
	contentType := c.Login.ContentType
	if contentType == "" {
		contentType = "form"
	}

	// Create HTTP client with cookie jar to capture cookies
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to create cookie jar: %w", err)
	}

	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second, // Add reasonable timeout to prevent hanging
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects (handles 302/303 redirects after login)
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Prepare request body based on content type
	var reqBody io.Reader
	var reqContentType string

	if contentType == "json" {
		// Build JSON request body
		payload := map[string]string{
			usernameField: c.Login.Username,
			passwordField: c.Login.Password,
		}
		// Add any additional fields
		for key, value := range c.Login.AdditionalFields {
			payload[key] = value
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON payload: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
		reqContentType = "application/json"
	} else {
		// Build form-encoded request body
		formData := url.Values{}
		formData.Set(usernameField, c.Login.Username)
		formData.Set(passwordField, c.Login.Password)
		// Add any additional fields
		for key, value := range c.Login.AdditionalFields {
			formData.Set(key, value)
		}
		reqBody = strings.NewReader(formData.Encode())
		reqContentType = "application/x-www-form-urlencoded"
	}

	// Create login request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Login.LoginURL, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", reqContentType)
	req.Header.Set("User-Agent", "WAST/1.0 (Web Application Security Testing)")

	// Execute login request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for error detection with size limit to prevent memory exhaustion
	const maxBodySize = 1024 * 1024 // 1MB limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return fmt.Errorf("failed to read login response: %w", err)
	}

	// Check for login success
	// Accept 2xx and 3xx status codes (successful login may redirect)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("login failed with status %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	// Check for common error indicators in response body
	bodyLower := strings.ToLower(string(body))
	errorIndicators := []string{"invalid credentials", "login failed", "authentication failed", "incorrect username", "incorrect password", "wrong password"}
	for _, indicator := range errorIndicators {
		if strings.Contains(bodyLower, indicator) {
			return fmt.Errorf("login failed: response contains error message (%s)", indicator)
		}
	}

	// Extract cookies from cookie jar
	loginURL, err := url.Parse(c.Login.LoginURL)
	if err != nil {
		return fmt.Errorf("failed to parse login URL: %w", err)
	}

	cookies := jar.Cookies(loginURL)
	if len(cookies) == 0 {
		// Check if we might have received cookies on a redirect URL
		// Try to get cookies from the base URL (scheme + host)
		baseURL := &url.URL{
			Scheme: loginURL.Scheme,
			Host:   loginURL.Host,
		}
		cookies = jar.Cookies(baseURL)
	}

	if len(cookies) == 0 {
		return fmt.Errorf("login succeeded but no cookies were received (check if login was actually successful)")
	}

	// Populate the Cookies field with captured cookies
	c.Cookies = make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		c.Cookies = append(c.Cookies, fmt.Sprintf("%s=%s", cookie.Name, cookie.Value))
	}

	return nil
}
