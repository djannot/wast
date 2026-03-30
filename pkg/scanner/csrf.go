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
	"github.com/djannot/wast/pkg/telemetry"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/html"
)

// CSRFScanner performs CSRF vulnerability detection.
type CSRFScanner struct {
	BaseScanner
	activeMode bool // when true, verify tokens server-side
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
	FormAction           string `json:"form_action" yaml:"form_action"`
	FormMethod           string `json:"form_method" yaml:"form_method"`
	FormPage             string `json:"form_page,omitempty" yaml:"form_page,omitempty"`
	Type                 string `json:"type" yaml:"type"` // "missing_token", "missing_samesite", "missing_custom_header"
	Severity             string `json:"severity" yaml:"severity"`
	Description          string `json:"description" yaml:"description"`
	Remediation          string `json:"remediation" yaml:"remediation"`
	Verified             bool   `json:"verified" yaml:"verified"`
	VerificationAttempts int    `json:"verification_attempts,omitempty" yaml:"verification_attempts,omitempty"`
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
	"authenticity_token",         // Rails
	"csrfmiddlewaretoken",        // Django
	"__requestverificationtoken", // .NET (case-insensitive)
	"_csrf_token",
	"csrf",
	"token",
	"xsrf_token",
	"_xsrf",
	"user_token", // DVWA
}

// Keywords in server responses that indicate a rejected submission.
var tokenRejectionKeywords = []string{
	"csrf token is incorrect",
	"invalid token",
	"token expired",
	"token mismatch",
	"forbidden",
	"access denied",
	"session expired",
	"security token",
	"invalid csrf",
	"csrf verification failed",
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
	return func(s *CSRFScanner) { s.client = c }
}

// WithCSRFUserAgent sets the user agent string for the CSRF scanner.
func WithCSRFUserAgent(ua string) CSRFOption {
	return func(s *CSRFScanner) { s.userAgent = ua }
}

// WithCSRFTimeout sets the timeout for HTTP requests.
func WithCSRFTimeout(d time.Duration) CSRFOption {
	return func(s *CSRFScanner) { s.timeout = d }
}

// WithCSRFAuth sets the authentication configuration for the CSRF scanner.
func WithCSRFAuth(config *auth.AuthConfig) CSRFOption {
	return func(s *CSRFScanner) { s.authConfig = config }
}

// WithCSRFRateLimiter sets a rate limiter for the CSRF scanner.
func WithCSRFRateLimiter(limiter ratelimit.Limiter) CSRFOption {
	return func(s *CSRFScanner) { s.rateLimiter = limiter }
}

// WithCSRFRateLimitConfig sets rate limiting from a configuration.
func WithCSRFRateLimitConfig(cfg ratelimit.Config) CSRFOption {
	return func(s *CSRFScanner) { s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg) }
}

// WithCSRFTracer sets the OpenTelemetry tracer for the CSRF scanner.
func WithCSRFTracer(tracer trace.Tracer) CSRFOption {
	return func(s *CSRFScanner) { s.tracer = tracer }
}

// WithCSRFActiveMode enables active server-side token verification.
func WithCSRFActiveMode(active bool) CSRFOption {
	return func(s *CSRFScanner) { s.activeMode = active }
}

// NewCSRFScanner creates a new CSRFScanner with the given options.
func NewCSRFScanner(opts ...CSRFOption) *CSRFScanner {
	s := &CSRFScanner{BaseScanner: DefaultBaseScanner()}
	for _, opt := range opts {
		opt(s)
	}
	s.InitDefaultClient()
	return s
}

// NewCSRFScannerFromBase creates a new CSRFScanner from pre-built BaseOptions
// plus any scanner-specific options.
func NewCSRFScannerFromBase(baseOpts []BaseOption, extraOpts ...CSRFOption) *CSRFScanner {
	s := &CSRFScanner{BaseScanner: DefaultBaseScanner()}
	ApplyBaseOptions(&s.BaseScanner, baseOpts)
	for _, opt := range extraOpts {
		opt(s)
	}
	s.InitDefaultClient()
	return s
}

// Scan performs a CSRF vulnerability scan on the given target URL.
func (s *CSRFScanner) Scan(ctx context.Context, targetURL string) *CSRFScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanCSRF)
		defer span.End()
	}

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
		// Skip non-form request methods
		method := strings.ToUpper(form.Method)
		if method == "HEAD" || method == "OPTIONS" {
			continue
		}

		// Check for CSRF token in form fields
		hasToken := s.hasCSRFToken(form.Fields)
		if !hasToken {
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
		} else if s.activeMode {
			// Token field is present — verify it is actually enforced server-side.
			enforced := s.isTokenEnforced(ctx, form, targetURL)
			if !enforced {
				finding := CSRFFinding{
					FormAction:  form.Action,
					FormMethod:  form.Method,
					FormPage:    form.Page,
					Type:        "unenforced_token",
					Severity:    SeverityHigh,
					Description: "Form contains a CSRF token field but the server does not enforce it - the form is accepted without the token, making it vulnerable to Cross-Site Request Forgery attacks",
					Remediation: "Validate the CSRF token server-side on every state-changing request. Reject requests that omit or supply an invalid token.",
				}
				result.Findings = append(result.Findings, finding)
				result.Summary.VulnerableForms++
			}
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

// isTokenEnforced submits the form WITHOUT the CSRF token field and checks
// whether the server still accepts it.  If the server responds with a 2xx
// status and no rejection keywords, the token is considered unenforced.
// This method is only called when active mode is enabled.
func (s *CSRFScanner) isTokenEnforced(ctx context.Context, form crawler.FormInfo, pageURL string) bool {
	// Apply rate limiting
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			return true // assume enforced on error (conservative)
		}
	}

	// Build form data excluding CSRF token fields
	formData := url.Values{}
	for _, field := range form.Fields {
		if s.isCSRFTokenField(field) {
			continue // omit the token
		}
		if field.Name != "" {
			formData.Set(field.Name, field.Value)
		}
	}

	// Resolve the form action URL
	actionURL := form.Action
	if actionURL == "" || actionURL == "#" {
		actionURL = pageURL
	} else if !strings.HasPrefix(actionURL, "http") {
		base, err := url.Parse(pageURL)
		if err != nil {
			return true
		}
		ref, err := url.Parse(actionURL)
		if err != nil {
			return true
		}
		actionURL = base.ResolveReference(ref).String()
	}

	method := strings.ToUpper(form.Method)
	if method == "" {
		method = "GET"
	}

	var req *http.Request
	var err error

	if method == "GET" {
		u, parseErr := url.Parse(actionURL)
		if parseErr != nil {
			return true
		}
		q := u.Query()
		for k, vals := range formData {
			for _, v := range vals {
				q.Set(k, v)
			}
		}
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, actionURL, strings.NewReader(formData.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return true
	}

	req.Header.Set("User-Agent", s.userAgent)
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return true
	}
	defer resp.Body.Close()

	// If the server returns 403, 401, or a redirect to login — token is enforced
	if resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusUnauthorized {
		return true
	}

	// Read response body to look for rejection messages
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return true
	}
	bodyLower := strings.ToLower(string(body))

	for _, keyword := range tokenRejectionKeywords {
		if strings.Contains(bodyLower, keyword) {
			return true
		}
	}

	// If the server returned a 2xx with no rejection signals, the token is NOT enforced
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false
	}

	// For 3xx redirects, check if it redirects to a login page (enforced)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		locationLower := strings.ToLower(location)
		if strings.Contains(locationLower, "login") || strings.Contains(locationLower, "signin") || strings.Contains(locationLower, "auth") {
			return true
		}
		// Non-login redirect with no rejection keywords — likely unenforced
		return false
	}

	// Conservative default: assume enforced
	return true
}

// isCSRFTokenField checks if a form field is a CSRF token field.
func (s *CSRFScanner) isCSRFTokenField(field crawler.FormFieldInfo) bool {
	if field.Type != "hidden" && field.Type != "text" {
		return false
	}
	fieldNameLower := strings.ToLower(field.Name)
	for _, tokenName := range csrfTokenFieldNames {
		if fieldNameLower == strings.ToLower(tokenName) {
			return true
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

// VerifyFinding re-tests a CSRF finding by attempting to submit the form and checking protection mechanisms.
func (s *CSRFScanner) VerifyFinding(ctx context.Context, finding *CSRFFinding, config VerificationConfig) (*VerificationResult, error) {
	if finding == nil {
		return nil, fmt.Errorf("finding is nil")
	}

	// For cookie-based findings (missing_samesite), verification is straightforward
	if finding.Type == "missing_samesite" {
		return &VerificationResult{
			Verified:    true,
			Attempts:    1,
			Confidence:  0.9,
			Explanation: "Cookie SameSite attribute absence verified through header inspection",
		}, nil
	}

	// For missing_token findings, we verify by checking if the form can be submitted without a token
	if finding.Type == "missing_token" {
		return s.verifyMissingTokenFinding(ctx, finding, config)
	}

	// For unenforced_token findings, the token was already verified server-side during active scan
	if finding.Type == "unenforced_token" {
		return &VerificationResult{
			Verified:    true,
			Attempts:    1,
			Confidence:  0.95,
			Explanation: "CSRF token field is present but server does not enforce it - verified by submitting without token",
		}, nil
	}

	// For other types, return a conservative verification
	return &VerificationResult{
		Verified:    true,
		Attempts:    1,
		Confidence:  0.7,
		Explanation: fmt.Sprintf("CSRF finding type '%s' verified through initial scan", finding.Type),
	}, nil
}

// verifyMissingTokenFinding verifies that a form lacks CSRF protection by re-fetching and analyzing it.
func (s *CSRFScanner) verifyMissingTokenFinding(ctx context.Context, finding *CSRFFinding, config VerificationConfig) (*VerificationResult, error) {
	if finding.FormPage == "" {
		return &VerificationResult{
			Verified:    true,
			Attempts:    1,
			Confidence:  0.6,
			Explanation: "Form page not available for re-verification, trusting initial scan",
		}, nil
	}

	successCount := 0
	totalAttempts := 0
	maxAttempts := config.MaxRetries
	if maxAttempts <= 0 {
		maxAttempts = 2
	}

	// Re-fetch the page multiple times to confirm the finding
	for i := 0; i < maxAttempts; i++ {
		// Apply rate limiting before making the request
		if s.rateLimiter != nil {
			if err := s.rateLimiter.Wait(ctx); err != nil {
				return nil, fmt.Errorf("rate limiting error: %w", err)
			}
		}

		// Apply delay between attempts if configured
		if i > 0 && config.Delay > 0 {
			time.Sleep(config.Delay)
		}

		totalAttempts++

		// Fetch the form page
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, finding.FormPage, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", s.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		if s.authConfig != nil {
			s.authConfig.ApplyToRequest(req)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Parse HTML and check for CSRF tokens
		doc, err := html.Parse(strings.NewReader(string(body)))
		if err != nil {
			continue
		}

		forms := s.extractForms(doc, finding.FormPage)
		for _, form := range forms {
			// Match the form by action and method
			if form.Action == finding.FormAction && strings.ToUpper(form.Method) == strings.ToUpper(finding.FormMethod) {
				// Check if form still lacks CSRF token
				if !s.hasCSRFToken(form.Fields) {
					successCount++
				}
				break
			}
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	// Calculate verification result
	confidence := float64(successCount) / float64(totalAttempts)
	verified := confidence >= 0.5 // At least 50% of attempts must confirm

	explanation := fmt.Sprintf("Verified %d out of %d attempts confirmed the form lacks CSRF protection",
		successCount, totalAttempts)

	if !verified {
		explanation = fmt.Sprintf("Only %d out of %d attempts confirmed missing CSRF token - protection may have been added",
			successCount, totalAttempts)
	}

	return &VerificationResult{
		Verified:    verified,
		Attempts:    totalAttempts,
		Confidence:  confidence,
		Explanation: explanation,
	}, nil
}
