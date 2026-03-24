// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/crawler"
	"github.com/djannot/wast/pkg/ratelimit"
	"golang.org/x/net/html"
)

// CSRFScanner performs CSRF vulnerability detection.
type CSRFScanner struct {
	client      HTTPClient
	userAgent   string
	timeout     time.Duration
	authConfig  *auth.AuthConfig
	rateLimiter ratelimit.Limiter
}

// CSRFScanResult represents the result of a CSRF vulnerability scan.
type CSRFScanResult struct {
	Target   string        `json:"target" yaml:"target"`
	Findings []CSRFFinding `json:"findings" yaml:"findings"`
	Summary  CSRFSummary   `json:"summary" yaml:"summary"`
	Errors   []string      `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// CSRFFinding represents a single CSRF vulnerability finding.
type CSRFFinding struct {
	FormAction  string `json:"form_action" yaml:"form_action"`
	FormMethod  string `json:"form_method" yaml:"form_method"`
	FormPage    string `json:"form_page,omitempty" yaml:"form_page,omitempty"`
	Type        string `json:"type" yaml:"type"` // "missing_token", "missing_samesite", "missing_custom_header"
	Severity    string `json:"severity" yaml:"severity"`
	Description string `json:"description" yaml:"description"`
	Remediation string `json:"remediation" yaml:"remediation"`
}

// CSRFSummary provides an overview of the CSRF scan results.
type CSRFSummary struct {
	TotalFormsTested int `json:"total_forms_tested" yaml:"total_forms_tested"`
	VulnerableForms  int `json:"vulnerable_forms" yaml:"vulnerable_forms"`
	CookiesChecked   int `json:"cookies_checked" yaml:"cookies_checked"`
	InsecureCookies  int `json:"insecure_cookies" yaml:"insecure_cookies"`
}

// Known CSRF token field names used by various frameworks.
var csrfTokenFieldNames = []string{
	"csrf_token",
	"_csrf",
	"_token",
	"authenticity_token",        // Rails
	"csrfmiddlewaretoken",       // Django
	"__requestverificationtoken", // .NET (case-insensitive)
	"_csrf_token",
	"csrf",
	"token",
	"xsrf_token",
	"_xsrf",
}

// Custom headers that can provide CSRF protection.
var csrfCustomHeaders = []string{
	"X-CSRF-Token",
	"X-Requested-With",
	"X-XSRF-TOKEN",
	"X-CSRF-Header",
}

// CSRFOption is a function that configures a CSRFScanner.
type CSRFOption func(*CSRFScanner)

// WithCSRFHTTPClient sets a custom HTTP client for the CSRF scanner.
func WithCSRFHTTPClient(c HTTPClient) CSRFOption {
	return func(s *CSRFScanner) {
		s.client = c
	}
}

// WithCSRFUserAgent sets the user agent string for the CSRF scanner.
func WithCSRFUserAgent(ua string) CSRFOption {
	return func(s *CSRFScanner) {
		s.userAgent = ua
	}
}

// WithCSRFTimeout sets the timeout for HTTP requests.
func WithCSRFTimeout(d time.Duration) CSRFOption {
	return func(s *CSRFScanner) {
		s.timeout = d
	}
}

// WithCSRFAuth sets the authentication configuration for the CSRF scanner.
func WithCSRFAuth(config *auth.AuthConfig) CSRFOption {
	return func(s *CSRFScanner) {
		s.authConfig = config
	}
}

// WithCSRFRateLimiter sets a rate limiter for the CSRF scanner.
func WithCSRFRateLimiter(limiter ratelimit.Limiter) CSRFOption {
	return func(s *CSRFScanner) {
		s.rateLimiter = limiter
	}
}

// WithCSRFRateLimitConfig sets rate limiting from a configuration.
func WithCSRFRateLimitConfig(cfg ratelimit.Config) CSRFOption {
	return func(s *CSRFScanner) {
		s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg)
	}
}

// NewCSRFScanner creates a new CSRFScanner with the given options.
func NewCSRFScanner(opts ...CSRFOption) *CSRFScanner {
	s := &CSRFScanner{
		userAgent: "WAST/1.0 (Web Application Security Testing)",
		timeout:   30 * time.Second,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Create default HTTP client if not set
	if s.client == nil {
		s.client = NewDefaultHTTPClient(s.timeout)
	}

	return s
}

// Scan performs a CSRF vulnerability scan on the given target URL.
func (s *CSRFScanner) Scan(ctx context.Context, targetURL string) *CSRFScanResult {
	result := &CSRFScanResult{
		Target:   targetURL,
		Findings: make([]CSRFFinding, 0),
		Errors:   make([]string, 0),
	}

	// Parse the target URL for validation
	_, err := url.Parse(targetURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid URL: %s", err.Error()))
		return result
	}

	// Apply rate limiting before making the request
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
			return result
		}
	}

	// Fetch the target page
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to create request: %s", err.Error()))
		return result
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	// Apply authentication configuration
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to fetch URL: %s", err.Error()))
		return result
	}
	defer resp.Body.Close()

	// Handle rate limiting (HTTP 429)
	if resp.StatusCode == http.StatusTooManyRequests {
		result.Errors = append(result.Errors, "Rate limited by server (HTTP 429)")
		return result
	}

	// Only process successful responses
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		result.Errors = append(result.Errors, fmt.Sprintf("HTTP error: %d", resp.StatusCode))
		return result
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read response: %s", err.Error()))
		return result
	}

	// Parse HTML and extract forms
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse HTML: %s", err.Error()))
		return result
	}

	// Extract forms from the page
	forms := s.extractForms(doc, targetURL)
	result.Summary.TotalFormsTested = len(forms)

	// Analyze each form for CSRF vulnerabilities
	for _, form := range forms {
		// Only check state-changing methods (POST, PUT, DELETE, PATCH)
		method := strings.ToUpper(form.Method)
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			continue
		}

		// Check for CSRF token in form fields
		hasCSRFToken := s.hasCSRFToken(form.Fields)
		if !hasCSRFToken {
			finding := CSRFFinding{
				FormAction:  form.Action,
				FormMethod:  form.Method,
				FormPage:    form.Page,
				Type:        "missing_token",
				Severity:    SeverityHigh,
				Description: "Form lacks CSRF token protection - vulnerable to Cross-Site Request Forgery attacks",
				Remediation: "Add a CSRF token hidden field (e.g., csrf_token, _token, authenticity_token) and validate it server-side. Ensure the token is unique per session and unpredictable.",
			}
			result.Findings = append(result.Findings, finding)
			result.Summary.VulnerableForms++
		}
	}

	// Check cookies for SameSite attribute
	cookies := resp.Cookies()
	result.Summary.CookiesChecked = len(cookies)
	for _, cookie := range cookies {
		// Check if cookie lacks SameSite protection
		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == 0 {
			finding := CSRFFinding{
				FormAction:  fmt.Sprintf("Cookie: %s", cookie.Name),
				FormMethod:  "N/A",
				Type:        "missing_samesite",
				Severity:    SeverityMedium,
				Description: fmt.Sprintf("Cookie '%s' lacks SameSite attribute - may be vulnerable to CSRF attacks", cookie.Name),
				Remediation: "Set the SameSite attribute to 'Strict' or 'Lax' on all cookies to prevent them from being sent in cross-site requests. Example: Set-Cookie: sessionid=...; SameSite=Strict; Secure; HttpOnly",
			}
			result.Findings = append(result.Findings, finding)
			result.Summary.InsecureCookies++
		}
	}

	return result
}

// extractForms extracts all forms from the HTML document.
func (s *CSRFScanner) extractForms(n *html.Node, baseURL string) []crawler.FormInfo {
	forms := make([]crawler.FormInfo, 0)
	var extract func(*html.Node)
	extract = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "form" {
			form := s.extractForm(node)
			form.Page = baseURL
			forms = append(forms, form)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			extract(child)
		}
	}
	extract(n)
	return forms
}

// extractForm extracts form information from a <form> tag.
func (s *CSRFScanner) extractForm(n *html.Node) crawler.FormInfo {
	form := crawler.FormInfo{
		Method: "GET", // Default method
		Fields: make([]crawler.FormFieldInfo, 0),
	}

	for _, attr := range n.Attr {
		switch attr.Key {
		case "action":
			form.Action = attr.Val
		case "method":
			form.Method = strings.ToUpper(attr.Val)
		}
	}

	// Extract form fields
	var extractFields func(*html.Node)
	extractFields = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "input", "textarea", "select":
				field := s.extractFormField(node)
				form.Fields = append(form.Fields, field)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			extractFields(child)
		}
	}
	extractFields(n)

	return form
}

// extractFormField extracts form field information.
func (s *CSRFScanner) extractFormField(n *html.Node) crawler.FormFieldInfo {
	field := crawler.FormFieldInfo{
		Type: "text", // Default type for input
	}

	if n.Data == "textarea" {
		field.Type = "textarea"
	} else if n.Data == "select" {
		field.Type = "select"
	}

	for _, attr := range n.Attr {
		switch attr.Key {
		case "name":
			field.Name = attr.Val
		case "type":
			field.Type = attr.Val
		case "value":
			field.Value = attr.Val
		}
	}

	return field
}

// hasCSRFToken checks if any form field contains a CSRF token.
func (s *CSRFScanner) hasCSRFToken(fields []crawler.FormFieldInfo) bool {
	for _, field := range fields {
		// Check if field is a hidden input (common for CSRF tokens)
		if field.Type != "hidden" && field.Type != "text" {
			continue
		}

		// Check if field name matches known CSRF token patterns
		fieldNameLower := strings.ToLower(field.Name)
		for _, tokenName := range csrfTokenFieldNames {
			if fieldNameLower == strings.ToLower(tokenName) {
				return true
			}
		}
	}
	return false
}

// String returns a human-readable representation of the scan result.
func (r *CSRFScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("CSRF Vulnerability Scan for: %s\n", r.Target))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	// Summary
	sb.WriteString("\nSummary:\n")
	sb.WriteString(fmt.Sprintf("  Total Forms Tested: %d\n", r.Summary.TotalFormsTested))
	sb.WriteString(fmt.Sprintf("  Vulnerable Forms: %d\n", r.Summary.VulnerableForms))
	sb.WriteString(fmt.Sprintf("  Cookies Checked: %d\n", r.Summary.CookiesChecked))
	sb.WriteString(fmt.Sprintf("  Insecure Cookies: %d\n", r.Summary.InsecureCookies))

	// Findings
	if len(r.Findings) > 0 {
		sb.WriteString("\nVulnerabilities:\n")
		for i, f := range r.Findings {
			sb.WriteString(fmt.Sprintf("\n  %d. [%s] %s\n", i+1, strings.ToUpper(f.Severity), f.Type))
			if f.FormAction != "" {
				sb.WriteString(fmt.Sprintf("     Form/Resource: %s\n", f.FormAction))
			}
			if f.FormMethod != "" && f.FormMethod != "N/A" {
				sb.WriteString(fmt.Sprintf("     Method: %s\n", f.FormMethod))
			}
			sb.WriteString(fmt.Sprintf("     Description: %s\n", f.Description))
			sb.WriteString(fmt.Sprintf("     Remediation: %s\n", f.Remediation))
		}
	} else {
		sb.WriteString("\nNo CSRF vulnerabilities detected.\n")
	}

	// Errors
	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, e := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}

	return sb.String()
}

// HasResults returns true if the scan produced any meaningful results.
func (r *CSRFScanResult) HasResults() bool {
	return len(r.Findings) > 0 || r.Summary.TotalFormsTested > 0
}
