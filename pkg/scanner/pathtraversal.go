// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// PathTraversalScanner performs active Path Traversal/LFI vulnerability detection.
type PathTraversalScanner struct {
	client      HTTPClient
	userAgent   string
	timeout     time.Duration
	authConfig  *auth.AuthConfig
	rateLimiter ratelimit.Limiter
	tracer      trace.Tracer
}

// PathTraversalScanResult represents the result of a Path Traversal vulnerability scan.
type PathTraversalScanResult struct {
	Target   string                 `json:"target" yaml:"target"`
	Findings []PathTraversalFinding `json:"findings" yaml:"findings"`
	Summary  PathTraversalSummary   `json:"summary" yaml:"summary"`
	Errors   []string               `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// PathTraversalFinding represents a single Path Traversal vulnerability finding.
type PathTraversalFinding struct {
	URL                  string `json:"url" yaml:"url"`
	Parameter            string `json:"parameter" yaml:"parameter"`
	Payload              string `json:"payload" yaml:"payload"`
	Evidence             string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Severity             string `json:"severity" yaml:"severity"`
	Type                 string `json:"type" yaml:"type"` // "unix", "windows", "encoded"
	Description          string `json:"description" yaml:"description"`
	Remediation          string `json:"remediation" yaml:"remediation"`
	Confidence           string `json:"confidence" yaml:"confidence"`
	Verified             bool   `json:"verified" yaml:"verified"`
	VerificationAttempts int    `json:"verification_attempts,omitempty" yaml:"verification_attempts,omitempty"`
}

// PathTraversalSummary provides an overview of the Path Traversal scan results.
type PathTraversalSummary struct {
	TotalTests           int `json:"total_tests" yaml:"total_tests"`
	VulnerabilitiesFound int `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	HighSeverityCount    int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount  int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount     int `json:"low_severity_count" yaml:"low_severity_count"`
}

// pathTraversalPayload represents a test payload for Path Traversal detection.
type pathTraversalPayload struct {
	Payload     string
	Type        string // "unix", "windows", "encoded"
	Severity    string
	Description string
}

// pathTraversalPayloads is the list of detection payloads to test for Path Traversal.
var pathTraversalPayloads = []pathTraversalPayload{
	// Unix-style path traversal - /etc/passwd
	{
		Payload:     "../../../etc/passwd",
		Type:        "unix",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application allows access to /etc/passwd via directory traversal",
	},
	{
		Payload:     "../../../../etc/passwd",
		Type:        "unix",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application allows access to /etc/passwd via directory traversal",
	},
	{
		Payload:     "../../../../../etc/passwd",
		Type:        "unix",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application allows access to /etc/passwd via directory traversal",
	},
	{
		Payload:     "../../../../../../etc/passwd",
		Type:        "unix",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application allows access to /etc/passwd via directory traversal",
	},
	{
		Payload:     "../../../etc/shadow",
		Type:        "unix",
		Severity:    SeverityHigh,
		Description: "Critical Path Traversal vulnerability - application allows access to /etc/shadow containing password hashes",
	},
	// Absolute path injection
	{
		Payload:     "/etc/passwd",
		Type:        "unix",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application allows absolute path access to /etc/passwd",
	},
	// Windows-style path traversal
	{
		Payload:     "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		Type:        "windows",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application allows access to Windows hosts file",
	},
	{
		Payload:     "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		Type:        "windows",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application allows access to Windows hosts file",
	},
	{
		Payload:     "..\\..\\..\\windows\\win.ini",
		Type:        "windows",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application allows access to Windows configuration files",
	},
	{
		Payload:     "C:\\windows\\system32\\drivers\\etc\\hosts",
		Type:        "windows",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application allows absolute path access to Windows hosts file",
	},
	// URL-encoded payloads (single encoding)
	{
		Payload:     "..%2F..%2F..%2Fetc%2Fpasswd",
		Type:        "encoded",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application vulnerable to URL-encoded directory traversal",
	},
	{
		Payload:     "..%5C..%5C..%5Cwindows%5Cwin.ini",
		Type:        "encoded",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application vulnerable to URL-encoded directory traversal (Windows)",
	},
	// Double URL-encoded payloads
	{
		Payload:     "..%252F..%252F..%252Fetc%252Fpasswd",
		Type:        "encoded",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application vulnerable to double URL-encoded directory traversal",
	},
	{
		Payload:     "..%255C..%255C..%255Cwindows%255Cwin.ini",
		Type:        "encoded",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application vulnerable to double URL-encoded directory traversal (Windows)",
	},
	// Null byte injection
	{
		Payload:     "../../../etc/passwd%00",
		Type:        "unix",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application vulnerable to null byte injection",
	},
	{
		Payload:     "../../../etc/passwd%00.jpg",
		Type:        "unix",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application vulnerable to null byte injection with extension bypass",
	},
	// Mixed encoding and path separators
	{
		Payload:     "....//....//....//etc/passwd",
		Type:        "unix",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application vulnerable to double dot bypass",
	},
	{
		Payload:     "..;/..;/..;/etc/passwd",
		Type:        "unix",
		Severity:    SeverityHigh,
		Description: "Path Traversal vulnerability detected - application vulnerable to semicolon path separator bypass",
	},
}

// PathTraversalOption is a function that configures a PathTraversalScanner.
type PathTraversalOption func(*PathTraversalScanner)

// WithPathTraversalHTTPClient sets a custom HTTP client for the Path Traversal scanner.
func WithPathTraversalHTTPClient(c HTTPClient) PathTraversalOption {
	return func(s *PathTraversalScanner) {
		s.client = c
	}
}

// WithPathTraversalUserAgent sets the user agent string for the Path Traversal scanner.
func WithPathTraversalUserAgent(ua string) PathTraversalOption {
	return func(s *PathTraversalScanner) {
		s.userAgent = ua
	}
}

// WithPathTraversalTimeout sets the timeout for HTTP requests.
func WithPathTraversalTimeout(d time.Duration) PathTraversalOption {
	return func(s *PathTraversalScanner) {
		s.timeout = d
	}
}

// WithPathTraversalAuth sets the authentication configuration for the Path Traversal scanner.
func WithPathTraversalAuth(config *auth.AuthConfig) PathTraversalOption {
	return func(s *PathTraversalScanner) {
		s.authConfig = config
	}
}

// WithPathTraversalRateLimiter sets a rate limiter for the Path Traversal scanner.
func WithPathTraversalRateLimiter(limiter ratelimit.Limiter) PathTraversalOption {
	return func(s *PathTraversalScanner) {
		s.rateLimiter = limiter
	}
}

// WithPathTraversalRateLimitConfig sets rate limiting from a configuration.
func WithPathTraversalRateLimitConfig(cfg ratelimit.Config) PathTraversalOption {
	return func(s *PathTraversalScanner) {
		s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg)
	}
}

// WithPathTraversalTracer sets the OpenTelemetry tracer for the Path Traversal scanner.
func WithPathTraversalTracer(tracer trace.Tracer) PathTraversalOption {
	return func(s *PathTraversalScanner) {
		s.tracer = tracer
	}
}

// NewPathTraversalScanner creates a new PathTraversalScanner with the given options.
func NewPathTraversalScanner(opts ...PathTraversalOption) *PathTraversalScanner {
	s := &PathTraversalScanner{
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

// Scan performs a Path Traversal vulnerability scan on the given target URL.
func (s *PathTraversalScanner) Scan(ctx context.Context, targetURL string) *PathTraversalScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanPathTraversal)
		defer span.End()
	}

	result := &PathTraversalScanResult{
		Target:   targetURL,
		Findings: make([]PathTraversalFinding, 0),
		Errors:   make([]string, 0),
	}

	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid URL: %s", err.Error()))
		return result
	}

	// Extract query parameters to test
	params := parsedURL.Query()

	// If no query parameters exist, test with common file inclusion parameter names
	if len(params) == 0 {
		params.Set("file", "")
		params.Set("path", "")
		params.Set("page", "")
		params.Set("include", "")
		params.Set("document", "")
		params.Set("folder", "")
		params.Set("template", "")
		params.Set("style", "")
	}

	// Test each parameter with each payload
	for paramName := range params {
		for _, payload := range pathTraversalPayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			finding := s.testParameter(ctx, parsedURL, paramName, payload)
			result.Summary.TotalTests++

			if finding != nil {
				result.Findings = append(result.Findings, *finding)
				result.Summary.VulnerabilitiesFound++
			}

			// Check context cancellation
			select {
			case <-ctx.Done():
				result.Errors = append(result.Errors, "Scan cancelled")
				s.calculateSummary(result)
				return result
			default:
			}
		}
	}

	// Calculate final summary
	s.calculateSummary(result)

	return result
}

// ScanPOST performs Path Traversal scanning with POST method using form-encoded parameters.
func (s *PathTraversalScanner) ScanPOST(ctx context.Context, targetURL string, parameters map[string]string) *PathTraversalScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanPathTraversal)
		defer span.End()
	}

	result := &PathTraversalScanResult{
		Target:   targetURL,
		Findings: make([]PathTraversalFinding, 0),
		Errors:   make([]string, 0),
	}

	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid URL: %s", err.Error()))
		return result
	}

	// Use provided parameters or fallback to common file inclusion parameter names
	params := parameters
	if len(params) == 0 {
		params = map[string]string{
			"file":     "",
			"path":     "",
			"page":     "",
			"include":  "",
			"document": "",
			"folder":   "",
			"template": "",
			"style":    "",
		}
	}

	// Test each parameter with each payload
	for paramName := range params {
		for _, payload := range pathTraversalPayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			finding := s.testParameterPOST(ctx, parsedURL, paramName, payload, params)
			result.Summary.TotalTests++

			if finding != nil {
				result.Findings = append(result.Findings, *finding)
				result.Summary.VulnerabilitiesFound++
			}

			// Check context cancellation
			select {
			case <-ctx.Done():
				result.Errors = append(result.Errors, "Scan cancelled")
				s.calculateSummary(result)
				return result
			default:
			}
		}
	}

	// Calculate final summary
	s.calculateSummary(result)

	return result
}

// buildPathTraversalFormBody constructs a URL-encoded form body while preserving
// literal path separators (/ and \) in the payload value. Standard url.Values.Encode()
// encodes / as %2F, which breaks path traversal payloads against targets like PHP's
// include() that require literal ../ sequences.
func buildPathTraversalFormBody(params map[string]string, payloadParam, payloadValue string) string {
	// Sort keys for deterministic body construction.
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(params))
	for _, k := range keys {
		v := params[k]
		if k == payloadParam {
			v = payloadValue
		}
		// Encode key normally; encode value but preserve / and \ for traversal payloads.
		encodedKey := url.QueryEscape(k)
		encodedValue := v
		encodedValue = strings.ReplaceAll(encodedValue, " ", "+")
		encodedValue = strings.ReplaceAll(encodedValue, "&", "%26")
		encodedValue = strings.ReplaceAll(encodedValue, "=", "%3D")
		encodedValue = strings.ReplaceAll(encodedValue, "#", "%23")
		parts = append(parts, encodedKey+"="+encodedValue)
	}
	return strings.Join(parts, "&")
}

// testParameterPOST tests a single parameter with a specific Path Traversal payload using POST method.
func (s *PathTraversalScanner) testParameterPOST(ctx context.Context, baseURL *url.URL, paramName string, payload pathTraversalPayload, allParameters map[string]string) *PathTraversalFinding {
	// Build the form body manually to preserve path separators (/ and \).
	// url.Values.Encode() would encode / as %2F, breaking path traversal payloads
	// against PHP's include() and similar functions that need literal ../ sequences.
	formBody := buildPathTraversalFormBody(allParameters, paramName, payload.Payload)

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formBody))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Apply authentication configuration
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	// Send the request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Handle rate limiting (HTTP 429)
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Analyze the response for Path Traversal indicators
	confidence, evidence := s.analyzePathTraversalResponse(resp, bodyStr, payload)

	// Only report if there's medium or high confidence
	if confidence != "low" && confidence != "" {
		finding := &PathTraversalFinding{
			URL:         baseURL.String(),
			Parameter:   paramName,
			Payload:     payload.Payload,
			Evidence:    evidence,
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  confidence,
		}
		return finding
	}

	return nil
}

// testParameter tests a single parameter with a specific Path Traversal payload.
func (s *PathTraversalScanner) testParameter(ctx context.Context, baseURL *url.URL, paramName string, payload pathTraversalPayload) *PathTraversalFinding {
	// Get the original parameter value if it exists
	originalValue := baseURL.Query().Get(paramName)

	// Test 1: Direct payload replacement (no encoding for path separators)
	finding := s.testPayloadVariant(ctx, baseURL, paramName, payload, payload.Payload, false)
	if finding != nil {
		return finding
	}

	// Test 2: If original value exists and looks like a filename, try prepending the payload
	// This handles DVWA's case where page=include.php can be exploited with include.php/../../../etc/passwd
	if originalValue != "" && !strings.HasPrefix(payload.Payload, "/") {
		// For relative path payloads, try prepending to existing value
		wrapperPayload := originalValue + "/" + payload.Payload
		finding = s.testPayloadVariant(ctx, baseURL, paramName, payload, wrapperPayload, false)
		if finding != nil {
			finding.Payload = wrapperPayload
			return finding
		}
	}

	// Test 3: Try URL-encoded version for servers that decode before processing
	// Only test encoded version if it's not already an encoded payload
	if !strings.Contains(payload.Payload, "%2F") && !strings.Contains(payload.Payload, "%5C") {
		finding = s.testPayloadVariant(ctx, baseURL, paramName, payload, payload.Payload, true)
		if finding != nil {
			return finding
		}
	}

	return nil
}

// testPayloadVariant tests a single payload variant with optional URL encoding
func (s *PathTraversalScanner) testPayloadVariant(ctx context.Context, baseURL *url.URL, paramName string, payload pathTraversalPayload, payloadValue string, urlEncode bool) *PathTraversalFinding {
	// Create a copy of the URL with the test payload
	testURL := *baseURL
	q := testURL.Query()

	// Set the payload value
	q.Set(paramName, payloadValue)

	// Choose encoding strategy based on the urlEncode flag
	if urlEncode {
		// Use standard URL encoding
		testURL.RawQuery = q.Encode()
	} else {
		// Construct RawQuery manually to avoid encoding path separators.
		// This is critical for LFI detection where PHP's include() needs literal ../
		// Sort keys for deterministic query string construction (map iteration is
		// non-deterministic in Go, which can cause subtle issues with multi-param URLs).
		keys := make([]string, 0, len(q))
		for key := range q {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		params := []string{}
		for _, key := range keys {
			for _, value := range q[key] {
				// Only encode special URL characters, not path separators.
				// For path traversal payloads, we want to preserve / and \ characters
				// but still encode other special characters like spaces, &, =, etc.
				encodedKey := url.QueryEscape(key)
				encodedValue := value
				encodedValue = strings.ReplaceAll(encodedValue, " ", "+")
				encodedValue = strings.ReplaceAll(encodedValue, "&", "%26")
				encodedValue = strings.ReplaceAll(encodedValue, "=", "%3D")
				encodedValue = strings.ReplaceAll(encodedValue, "#", "%23")

				params = append(params, encodedKey+"="+encodedValue)
			}
		}
		testURL.RawQuery = strings.Join(params, "&")
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	// Apply authentication configuration
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	// Send the request
	resp, err := s.client.Do(req)

	// Handle request errors
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Handle rate limiting (HTTP 429)
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Analyze the response for Path Traversal indicators
	confidence, evidence := s.analyzePathTraversalResponse(resp, bodyStr, payload)

	// Only report if there's medium or high confidence
	if confidence != "low" && confidence != "" {
		finding := &PathTraversalFinding{
			URL:         testURL.String(),
			Parameter:   paramName,
			Payload:     payloadValue,
			Evidence:    evidence,
			Severity:    payload.Severity,
			Type:        payload.Type,
			Description: payload.Description,
			Remediation: s.getRemediation(),
			Confidence:  confidence,
		}
		return finding
	}

	return nil
}

// analyzePathTraversalResponse analyzes the HTTP response to determine if Path Traversal is possible.
func (s *PathTraversalScanner) analyzePathTraversalResponse(resp *http.Response, body string, payload pathTraversalPayload) (confidence string, evidence string) {
	// Check for status codes that indicate successful file access
	if resp.StatusCode == http.StatusOK {
		// Look for Unix /etc/passwd file signatures
		if payload.Type == "unix" && strings.Contains(payload.Payload, "passwd") {
			if containsPasswdSignature(body) {
				return "high", "Response contains /etc/passwd file contents (root:x:0:0 pattern detected)"
			}
		}

		// Look for Unix /etc/shadow file signatures
		if payload.Type == "unix" && strings.Contains(payload.Payload, "shadow") {
			if containsShadowSignature(body) {
				return "high", "Response contains /etc/shadow file contents (password hash patterns detected)"
			}
		}

		// Look for Windows hosts file signatures
		if payload.Type == "windows" && strings.Contains(strings.ToLower(payload.Payload), "hosts") {
			if containsWindowsHostsSignature(body) {
				return "high", "Response contains Windows hosts file contents"
			}
		}

		// Look for Windows win.ini file signatures
		if payload.Type == "windows" && strings.Contains(strings.ToLower(payload.Payload), "win.ini") {
			if containsWinIniSignature(body) {
				return "high", "Response contains Windows win.ini file contents"
			}
		}

		// Check for generic file access patterns
		if containsFileAccessPatterns(body) {
			return "medium", fmt.Sprintf("Response contains file system content indicators (status: %d, size: %d bytes)", resp.StatusCode, len(body))
		}
	}

	// Check for error messages that reveal path traversal attempts
	if containsPathTraversalErrorPatterns(body) {
		return "medium", "Response contains path traversal error messages"
	}

	return "", ""
}

// containsPasswdSignature checks if response contains Unix passwd file signatures.
func containsPasswdSignature(body string) bool {
	// Unescape HTML entities in case the response is HTML-encoded
	// This handles cases where DVWA or other apps HTML-escape the file contents
	unescapedBody := html.UnescapeString(body)

	// First check for highly specific passwd signatures (root, daemon, etc.)
	// These are strong indicators even with a single match
	specificSignatures := []*regexp.Regexp{
		regexp.MustCompile(`root:x:0:0:`),   // Root user (UID 0)
		regexp.MustCompile(`daemon:x:1:1:`), // Daemon user (UID 1)
		regexp.MustCompile(`bin:x:2:2:`),    // Bin user (UID 2)
		regexp.MustCompile(`sys:x:3:3:`),    // Sys user (UID 3)
		regexp.MustCompile(`nobody:x:`),     // Nobody user
		regexp.MustCompile(`www-data:x:`),   // Web server user (common on Debian/Ubuntu)
		regexp.MustCompile(`apache:x:`),     // Web server user (common on RedHat)
		regexp.MustCompile(`nginx:x:`),      // Web server user
	}

	for _, pattern := range specificSignatures {
		if pattern.MatchString(unescapedBody) {
			return true
		}
	}

	// Fall back to counting generic passwd-style entries
	// Look for typical /etc/passwd patterns - count unique lines
	// Split by newlines and check each line (using unescaped body)
	lines := strings.Split(unescapedBody, "\n")
	matchedLines := 0

	// Pattern to match passwd file entries (username:x:uid:gid:...)
	// Don't anchor to start of line (^) to handle HTML-wrapped responses
	passwdPattern := regexp.MustCompile(`[a-z_][a-z0-9_-]*:x:[0-9]+:[0-9]+:`)

	for _, line := range lines {
		if passwdPattern.MatchString(line) {
			matchedLines++
		}
	}

	// Lower threshold to 1 to catch partial file reads (e.g., DVWA LFI)
	// The specific signatures above provide better confidence for single-line matches
	return matchedLines >= 1
}

// containsShadowSignature checks if response contains Unix shadow file signatures.
func containsShadowSignature(body string) bool {
	// Look for typical /etc/shadow patterns (encrypted password hashes)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`root:\$[0-9]\$`),                                  // Shadow password hash
		regexp.MustCompile(`[a-z]+:\$[0-9]\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+:`), // Full shadow entry
		regexp.MustCompile(`[a-z]+:!:`),                                       // Locked account
		regexp.MustCompile(`[a-z]+:\*:`),                                      // Disabled password
	}

	for _, pattern := range patterns {
		if pattern.MatchString(body) {
			return true
		}
	}

	return false
}

// containsWindowsHostsSignature checks if response contains Windows hosts file signatures.
func containsWindowsHostsSignature(body string) bool {
	bodyLower := strings.ToLower(body)
	signatures := []string{
		"127.0.0.1       localhost",
		"::1             localhost",
		"# copyright (c) 1993-2009 microsoft corp",
		"# this is a sample hosts file",
	}

	matchCount := 0
	for _, sig := range signatures {
		if strings.Contains(bodyLower, sig) {
			matchCount++
		}
	}

	return matchCount >= 1
}

// containsWinIniSignature checks if response contains Windows win.ini file signatures.
func containsWinIniSignature(body string) bool {
	bodyLower := strings.ToLower(body)
	signatures := []string{
		"[fonts]",
		"[extensions]",
		"[mci extensions]",
		"[files]",
		"[mail]",
	}

	matchCount := 0
	for _, sig := range signatures {
		if strings.Contains(bodyLower, sig) {
			matchCount++
		}
	}

	// If we find multiple ini-style sections, it's likely win.ini
	return matchCount >= 2
}

// containsFileAccessPatterns checks for generic file system content indicators.
func containsFileAccessPatterns(body string) bool {
	// Look for common file system patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`/bin/bash`),
		regexp.MustCompile(`/bin/sh`),
		regexp.MustCompile(`/usr/bin`),
		regexp.MustCompile(`/usr/local`),
		regexp.MustCompile(`C:\\Windows`),
		regexp.MustCompile(`C:\\Program Files`),
		regexp.MustCompile(`\[boot loader\]`),
	}

	for _, pattern := range patterns {
		if pattern.MatchString(body) {
			return true
		}
	}

	return false
}

// containsPathTraversalErrorPatterns checks for error messages revealing path traversal.
func containsPathTraversalErrorPatterns(body string) bool {
	bodyLower := strings.ToLower(body)
	patterns := []string{
		"no such file or directory",
		"failed to open stream",
		"permission denied",
		"file not found",
		"cannot find the file",
		"invalid path",
		"path traversal",
		"directory traversal",
		"include_path=",
		"failed opening required",
	}

	for _, pattern := range patterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	return false
}

// getRemediation returns remediation guidance for Path Traversal vulnerabilities.
func (s *PathTraversalScanner) getRemediation() string {
	return "Implement strict input validation for file path parameters. Use allowlists for permitted files/directories. " +
		"Avoid using user input directly in file system operations. Use indirect references (e.g., file IDs mapped to paths server-side). " +
		"Sanitize input by removing directory traversal sequences (../, ..\\ and encoded variants). " +
		"Use built-in security functions like realpath() to resolve canonical paths and verify they stay within allowed directories. " +
		"Implement proper file system permissions. Consider using chroot jails or containerization to isolate file access. " +
		"Never trust user-supplied file names or paths without validation."
}

// calculateSummary calculates the summary statistics for the scan.
func (s *PathTraversalScanner) calculateSummary(result *PathTraversalScanResult) {
	result.Summary.VulnerabilitiesFound = len(result.Findings)

	for _, finding := range result.Findings {
		switch finding.Severity {
		case SeverityHigh:
			result.Summary.HighSeverityCount++
		case SeverityMedium:
			result.Summary.MediumSeverityCount++
		case SeverityLow:
			result.Summary.LowSeverityCount++
		}
	}
}

// String returns a human-readable representation of the scan result.
func (r *PathTraversalScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Path Traversal Vulnerability Scan for: %s\n", r.Target))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	// Summary
	sb.WriteString("\nSummary:\n")
	sb.WriteString(fmt.Sprintf("  Total Tests: %d\n", r.Summary.TotalTests))
	sb.WriteString(fmt.Sprintf("  Vulnerabilities Found: %d\n", r.Summary.VulnerabilitiesFound))
	sb.WriteString(fmt.Sprintf("  High Severity: %d\n", r.Summary.HighSeverityCount))
	sb.WriteString(fmt.Sprintf("  Medium Severity: %d\n", r.Summary.MediumSeverityCount))
	sb.WriteString(fmt.Sprintf("  Low Severity: %d\n", r.Summary.LowSeverityCount))

	// Findings
	if len(r.Findings) > 0 {
		sb.WriteString("\nVulnerabilities:\n")
		for i, f := range r.Findings {
			sb.WriteString(fmt.Sprintf("\n  %d. [%s] %s Path Traversal\n", i+1, strings.ToUpper(f.Severity), strings.Title(f.Type)))
			sb.WriteString(fmt.Sprintf("     Parameter: %s\n", f.Parameter))
			sb.WriteString(fmt.Sprintf("     Payload: %s\n", f.Payload))
			sb.WriteString(fmt.Sprintf("     Description: %s\n", f.Description))
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("     Evidence: %s\n", f.Evidence))
			}
			sb.WriteString(fmt.Sprintf("     Confidence: %s\n", f.Confidence))
			sb.WriteString(fmt.Sprintf("     Remediation: %s\n", f.Remediation))
		}
	} else {
		sb.WriteString("\nNo Path Traversal vulnerabilities detected.\n")
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
func (r *PathTraversalScanResult) HasResults() bool {
	return len(r.Findings) > 0 || r.Summary.TotalTests > 0
}

// VerifyFinding re-tests a Path Traversal finding with payload variants to confirm it's reproducible.
func (s *PathTraversalScanner) VerifyFinding(ctx context.Context, finding *PathTraversalFinding, config VerificationConfig) (*VerificationResult, error) {
	if finding == nil {
		return nil, fmt.Errorf("finding is nil")
	}

	// Parse the original URL to extract parameters
	parsedURL, err := url.Parse(finding.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL in finding: %w", err)
	}

	// Generate payload variants for verification
	variants := s.generatePathTraversalPayloadVariants(finding.Payload, finding.Type)

	successCount := 0
	totalAttempts := 0
	maxAttempts := config.MaxRetries
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	// Test each variant
	for i, variant := range variants {
		if i >= maxAttempts {
			break
		}

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

		// Test with the variant payload
		testURL := *parsedURL
		q := testURL.Query()
		q.Set(finding.Parameter, variant)
		testURL.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
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
			// Network errors don't count as failed verification
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// Check if variant produces similar Path Traversal indicators
		confidence, _ := s.analyzePathTraversalResponse(resp, bodyStr, pathTraversalPayload{Type: finding.Type, Payload: variant})
		if confidence == "high" || confidence == "medium" {
			successCount++
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	// Calculate verification result
	confidenceScore := float64(successCount) / float64(totalAttempts)
	verified := confidenceScore >= 0.5 // At least 50% of variants must succeed

	explanation := fmt.Sprintf("Verified %d out of %d payload variants successfully reproduced the vulnerability",
		successCount, totalAttempts)

	if !verified {
		explanation = fmt.Sprintf("Only %d out of %d payload variants reproduced the vulnerability - likely a false positive or WAF protection",
			successCount, totalAttempts)
	}

	return &VerificationResult{
		Verified:    verified,
		Attempts:    totalAttempts,
		Confidence:  confidenceScore,
		Explanation: explanation,
	}, nil
}

// generatePathTraversalPayloadVariants creates different variations of the Path Traversal payload.
func (s *PathTraversalScanner) generatePathTraversalPayloadVariants(originalPayload string, payloadType string) []string {
	variants := make([]string, 0)

	// Add the original payload
	variants = append(variants, originalPayload)

	// Add deeper traversal variants
	if strings.Contains(originalPayload, "../") {
		variants = append(variants, "../../"+originalPayload)
		variants = append(variants, strings.Replace(originalPayload, "../", "../../../../", 1))
	}

	if strings.Contains(originalPayload, "..\\") {
		variants = append(variants, "..\\..\\"+originalPayload)
	}

	// Add URL encoding variants
	if !strings.Contains(originalPayload, "%2F") && !strings.Contains(originalPayload, "%5C") {
		// Single encoding
		encoded := strings.ReplaceAll(originalPayload, "/", "%2F")
		encoded = strings.ReplaceAll(encoded, "\\", "%5C")
		variants = append(variants, encoded)
	}

	// Add case variations for Windows paths
	if payloadType == "windows" {
		variants = append(variants, strings.ToUpper(originalPayload))
		variants = append(variants, strings.ToLower(originalPayload))
	}

	return variants
}
