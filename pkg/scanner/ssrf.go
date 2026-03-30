// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/callback"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// CallbackServer is an interface for out-of-band callback detection.
type CallbackServer interface {
	GenerateCallbackID() string
	GetHTTPCallbackURL(id string) string
	GetDNSCallbackDomain(id string) string
	WaitForCallback(ctx context.Context, id string, timeout time.Duration) (callback.CallbackEvent, bool)
}

// SSRFScanner performs active SSRF vulnerability detection.
type SSRFScanner struct {
	client             HTTPClient
	userAgent          string
	timeout            time.Duration
	authConfig         *auth.AuthConfig
	rateLimiter        ratelimit.Limiter
	tracer             trace.Tracer
	callbackServer     CallbackServer
	OnlyProvidedParams bool // If true, only test parameters that exist in the URL (don't invent parameters)
}

// ssrfBaselineResponse stores characteristics of a baseline HTTP response
// for comparison against payload responses to reduce false positives.
type ssrfBaselineResponse struct {
	StatusCode         int
	BodyLength         int
	Body               string
	Signatures         []string // signatures found in baseline
	ContentHash        string   // MD5 hash of extracted body content
	WordCount          int      // Number of words in the response
	StructuralElements int      // Count of structural HTML elements (tr, li, etc.)
}

// SSRFScanResult represents the result of an SSRF vulnerability scan.
type SSRFScanResult struct {
	Target   string        `json:"target" yaml:"target"`
	Findings []SSRFFinding `json:"findings" yaml:"findings"`
	Summary  SSRFSummary   `json:"summary" yaml:"summary"`
	Errors   []string      `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// SSRFFinding represents a single SSRF vulnerability finding.
type SSRFFinding struct {
	URL                  string `json:"url" yaml:"url"`
	Parameter            string `json:"parameter" yaml:"parameter"`
	Payload              string `json:"payload" yaml:"payload"`
	Evidence             string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Severity             string `json:"severity" yaml:"severity"`
	Type                 string `json:"type" yaml:"type"` // "blind", "callback", "time-based"
	Description          string `json:"description" yaml:"description"`
	Remediation          string `json:"remediation" yaml:"remediation"`
	Confidence           string `json:"confidence" yaml:"confidence"`
	Verified             bool   `json:"verified" yaml:"verified"`
	VerificationAttempts int    `json:"verification_attempts,omitempty" yaml:"verification_attempts,omitempty"`
}

// SSRFSummary provides an overview of the SSRF scan results.
type SSRFSummary struct {
	TotalTests           int `json:"total_tests" yaml:"total_tests"`
	VulnerabilitiesFound int `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	HighSeverityCount    int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount  int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount     int `json:"low_severity_count" yaml:"low_severity_count"`
}

// ssrfPayload represents a test payload for SSRF detection.
type ssrfPayload struct {
	Payload     string
	Type        string // "blind", "callback", "time-based"
	Severity    string
	Description string
	Target      string // What the payload tries to access
}

// ssrfPayloads is the list of safe detection payloads to test for SSRF.
var ssrfPayloads = []ssrfPayload{
	// Internal IP addresses - localhost
	{
		Payload:     "http://127.0.0.1",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "SSRF vulnerability detected - application allows requests to localhost (127.0.0.1)",
		Target:      "localhost",
	},
	{
		Payload:     "http://localhost",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "SSRF vulnerability detected - application allows requests to localhost hostname",
		Target:      "localhost",
	},
	{
		Payload:     "http://0.0.0.0",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "SSRF vulnerability detected - application allows requests to 0.0.0.0 (all interfaces)",
		Target:      "localhost",
	},
	// Cloud metadata endpoints - AWS
	{
		Payload:     "http://169.254.169.254/latest/meta-data/",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "Critical SSRF vulnerability - application allows access to AWS EC2 metadata service (169.254.169.254)",
		Target:      "aws-metadata",
	},
	{
		Payload:     "http://169.254.169.254/latest/api/token",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "Critical SSRF vulnerability - application allows access to AWS IMDSv2 token endpoint",
		Target:      "aws-metadata",
	},
	// Private network ranges - RFC 1918
	{
		Payload:     "http://192.168.1.1",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "SSRF vulnerability detected - application allows requests to private network (192.168.x.x)",
		Target:      "private-network",
	},
	{
		Payload:     "http://10.0.0.1",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "SSRF vulnerability detected - application allows requests to private network (10.x.x.x)",
		Target:      "private-network",
	},
	{
		Payload:     "http://172.16.0.1",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "SSRF vulnerability detected - application allows requests to private network (172.16-31.x.x)",
		Target:      "private-network",
	},
	// Protocol smuggling attempts
	{
		Payload:     "file:///etc/passwd",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "Critical SSRF vulnerability - application allows file:// protocol access",
		Target:      "file-protocol",
	},
	{
		Payload:     "dict://127.0.0.1:11211/stats",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "SSRF vulnerability detected - application allows dict:// protocol for service probing",
		Target:      "dict-protocol",
	},
	{
		Payload:     "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "SSRF vulnerability detected - application allows gopher:// protocol for protocol smuggling",
		Target:      "gopher-protocol",
	},
	// GCP metadata endpoint
	{
		Payload:     "http://metadata.google.internal/computeMetadata/v1/",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "Critical SSRF vulnerability - application allows access to GCP metadata service",
		Target:      "gcp-metadata",
	},
	// Azure metadata endpoint
	{
		Payload:     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "Critical SSRF vulnerability - application allows access to Azure Instance Metadata Service",
		Target:      "azure-metadata",
	},
	// Kubernetes metadata endpoints
	{
		Payload:     "http://kubernetes.default.svc/api/v1/namespaces",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "Critical SSRF vulnerability - application allows access to Kubernetes API (namespaces endpoint)",
		Target:      "k8s-metadata",
	},
	{
		Payload:     "http://kubernetes.default.svc.cluster.local/api/v1/secrets",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "Critical SSRF vulnerability - application allows access to Kubernetes API (secrets endpoint)",
		Target:      "k8s-metadata",
	},
	{
		Payload:     "https://kubernetes.default.svc/api/v1/pods",
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "Critical SSRF vulnerability - application allows access to Kubernetes API (pods endpoint)",
		Target:      "k8s-metadata",
	},
	// DNS rebinding detection patterns
	{
		Payload:     "http://127.0.0.1.nip.io",
		Type:        "blind",
		Severity:    SeverityMedium,
		Description: "Potential SSRF vulnerability - application may be vulnerable to DNS rebinding attacks",
		Target:      "dns-rebinding",
	},
}

// SSRFOption is a function that configures an SSRFScanner.
type SSRFOption func(*SSRFScanner)

// WithSSRFHTTPClient sets a custom HTTP client for the SSRF scanner.
func WithSSRFHTTPClient(c HTTPClient) SSRFOption {
	return func(s *SSRFScanner) {
		s.client = c
	}
}

// WithSSRFUserAgent sets the user agent string for the SSRF scanner.
func WithSSRFUserAgent(ua string) SSRFOption {
	return func(s *SSRFScanner) {
		s.userAgent = ua
	}
}

// WithSSRFTimeout sets the timeout for HTTP requests.
func WithSSRFTimeout(d time.Duration) SSRFOption {
	return func(s *SSRFScanner) {
		s.timeout = d
	}
}

// WithSSRFAuth sets the authentication configuration for the SSRF scanner.
func WithSSRFAuth(config *auth.AuthConfig) SSRFOption {
	return func(s *SSRFScanner) {
		s.authConfig = config
	}
}

// WithSSRFRateLimiter sets a rate limiter for the SSRF scanner.
func WithSSRFRateLimiter(limiter ratelimit.Limiter) SSRFOption {
	return func(s *SSRFScanner) {
		s.rateLimiter = limiter
	}
}

// WithSSRFRateLimitConfig sets rate limiting from a configuration.
func WithSSRFRateLimitConfig(cfg ratelimit.Config) SSRFOption {
	return func(s *SSRFScanner) {
		s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg)
	}
}

// WithSSRFTracer sets the OpenTelemetry tracer for the SSRF scanner.
func WithSSRFTracer(tracer trace.Tracer) SSRFOption {
	return func(s *SSRFScanner) {
		s.tracer = tracer
	}
}

// WithSSRFOnlyProvidedParams sets whether to only test provided parameters.
// When true, the scanner will not invent common parameter names when none exist.
// This reduces false positives when scanning URLs without query parameters.
func WithSSRFOnlyProvidedParams(only bool) SSRFOption {
	return func(s *SSRFScanner) {
		s.OnlyProvidedParams = only
	}
}

// WithSSRFCallbackServer sets the callback server for out-of-band detection.
// When set, the scanner will generate callback URLs and use them to verify SSRF vulnerabilities.
func WithSSRFCallbackServer(server CallbackServer) SSRFOption {
	return func(s *SSRFScanner) {
		s.callbackServer = server
	}
}

// NewSSRFScanner creates a new SSRFScanner with the given options.
func NewSSRFScanner(opts ...SSRFOption) *SSRFScanner {
	s := &SSRFScanner{
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

// fetchBaseline retrieves a baseline response from the target URL without any payload injection.
// This is used to compare against responses with SSRF payloads to reduce false positives.
func (s *SSRFScanner) fetchBaseline(ctx context.Context, targetURL string, method string, formData url.Values) *ssrfBaselineResponse {
	var req *http.Request
	var err error

	if method == http.MethodPost && formData != nil {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(formData.Encode()))
		if err != nil {
			return nil
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return nil
		}
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

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

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Collect signatures present in baseline
	signatures := s.collectSignatures(bodyStr)

	// Compute content characteristics for enhanced comparison
	contentHash := computeContentHash(bodyStr)
	wordCount := countWords(bodyStr)
	structuralElements := countStructuralElements(bodyStr)

	return &ssrfBaselineResponse{
		StatusCode:         resp.StatusCode,
		BodyLength:         len(body),
		Body:               bodyStr,
		Signatures:         signatures,
		ContentHash:        contentHash,
		WordCount:          wordCount,
		StructuralElements: structuralElements,
	}
}

// collectSignatures extracts all detectable signatures from a response body.
func (s *SSRFScanner) collectSignatures(body string) []string {
	signatures := make([]string, 0)
	bodyLower := strings.ToLower(body)

	// Check for AWS metadata signatures
	awsSignatures := []string{"ami-id", "instance-id", "instance-type", "local-hostname", "local-ipv4", "public-hostname", "public-ipv4", "security-groups", "iam/security-credentials"}
	for _, sig := range awsSignatures {
		if strings.Contains(bodyLower, sig) {
			signatures = append(signatures, "aws:"+sig)
		}
	}

	// Check for GCP metadata signatures
	gcpSignatures := []string{"computemetadata", "project-id", "machine-type", "service-accounts", "attributes/"}
	for _, sig := range gcpSignatures {
		if strings.Contains(bodyLower, sig) {
			signatures = append(signatures, "gcp:"+sig)
		}
	}

	// Check for Azure metadata signatures
	azureSignatures := []string{"vmid", "subscriptionid", "resourcegroupname", "ostype"}
	for _, sig := range azureSignatures {
		if strings.Contains(bodyLower, sig) {
			signatures = append(signatures, "azure:"+sig)
		}
	}

	// Check for Kubernetes signatures
	k8sSignatures := []string{"apiversion", "kind", "metadata", "namespace", "items", "serviceaccounttoken"}
	for _, sig := range k8sSignatures {
		if strings.Contains(bodyLower, sig) {
			signatures = append(signatures, "k8s:"+sig)
		}
	}

	// Check for localhost signatures
	localhostSignatures := []string{"localhost", "127.0.0.1", "::1", "[::1]"}
	for _, sig := range localhostSignatures {
		if strings.Contains(bodyLower, sig) {
			signatures = append(signatures, "localhost:"+sig)
		}
	}

	// Check for internal service signatures
	internalServiceSignatures := []string{"apache", "nginx", "tomcat", "jenkins", "grafana", "prometheus", "elasticsearch", "kibana", "rabbitmq", "redis", "memcached", "etcd", "consul"}
	for _, sig := range internalServiceSignatures {
		if strings.Contains(bodyLower, sig) {
			signatures = append(signatures, "service:"+sig)
		}
	}

	// Check for file access signatures
	fileSignatures := []string{"root:x:", "/bin/bash", "/bin/sh", "etc/passwd", "[boot loader]", "c:\\windows"}
	for _, sig := range fileSignatures {
		if strings.Contains(strings.ToLower(body), strings.ToLower(sig)) {
			signatures = append(signatures, "file:"+sig)
		}
	}

	// Check for private IP patterns
	if containsPrivateIPPatterns(body) {
		signatures = append(signatures, "private-ip")
	}

	return signatures
}

// Scan performs an SSRF vulnerability scan on the given target URL.
func (s *SSRFScanner) Scan(ctx context.Context, targetURL string) *SSRFScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanSSRF)
		defer span.End()
	}

	result := &SSRFScanResult{
		Target:   targetURL,
		Findings: make([]SSRFFinding, 0),
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

	// If no query parameters exist, test with common parameter names
	// UNLESS OnlyProvidedParams is set (to avoid false positives)
	if len(params) == 0 {
		if s.OnlyProvidedParams {
			// Don't invent parameters - just return empty result
			s.calculateSummary(result)
			return result
		}
		// Invent common SSRF parameter names for testing
		params.Set("url", "")
		params.Set("uri", "")
		params.Set("path", "")
		params.Set("dest", "")
		params.Set("redirect", "")
		params.Set("file", "")
		params.Set("callback", "")
	}

	// Test each parameter with each payload
	for paramName := range params {
		// Fetch per-parameter baseline with a benign value for this specific parameter
		// This is more accurate than a single URL baseline, especially for invented parameters
		baselineURL := *parsedURL
		q := baselineURL.Query()
		q.Set(paramName, "https://example.com") // Benign, safe URL value
		baselineURL.RawQuery = q.Encode()
		baseline := s.fetchBaseline(ctx, baselineURL.String(), http.MethodGet, nil)

		for _, payload := range ssrfPayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			finding := s.testParameter(ctx, parsedURL, paramName, payload, baseline)
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

		// Test with callback payloads if callback server is configured
		if s.callbackServer != nil {
			finding := s.testParameterWithCallback(ctx, parsedURL, paramName)
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

// ScanPOST scans a URL for SSRF vulnerabilities using POST form data.
// Unlike Scan(), which tests GET query parameters, ScanPOST sends payloads in
// the request body as application/x-www-form-urlencoded data.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - targetURL: The URL to test (should not include query parameters)
//   - parameters: Form parameters and their original values. When testing each
//     parameter, all other parameters are included with their original values
//     to ensure proper form validation. If empty, tests common parameter names
//     (url, uri, path, dest, redirect, file, callback) with empty default values.
//
// Returns:
//   - An SSRFScanResult containing all findings, summary statistics, and any errors.
//     The result is never nil, even if errors occur.
//
// This method is typically called by the discovery module when scanning POST forms.
func (s *SSRFScanner) ScanPOST(ctx context.Context, targetURL string, parameters map[string]string) *SSRFScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanSSRF)
		defer span.End()
	}

	result := &SSRFScanResult{
		Target:   targetURL,
		Findings: make([]SSRFFinding, 0),
		Errors:   make([]string, 0),
	}

	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid URL: %s", err.Error()))
		return result
	}

	// Use provided parameters or fallback to common parameter names
	params := parameters
	if len(params) == 0 {
		if s.OnlyProvidedParams {
			// Don't invent parameters - just return empty result
			s.calculateSummary(result)
			return result
		}
		// Invent common SSRF parameter names for testing
		params = map[string]string{
			"url":      "",
			"uri":      "",
			"path":     "",
			"dest":     "",
			"redirect": "",
			"file":     "",
			"callback": "",
		}
	}

	// Test each parameter with each payload
	for paramName := range params {
		// Fetch per-parameter baseline with a benign value for this specific parameter
		// This is more accurate than a single form baseline, especially for invented parameters
		baselineFormData := url.Values{}
		for k, v := range params {
			baselineFormData.Set(k, v)
		}
		// Set this parameter to a benign, safe URL value for baseline
		baselineFormData.Set(paramName, "https://example.com")
		baseline := s.fetchBaseline(ctx, parsedURL.String(), http.MethodPost, baselineFormData)

		for _, payload := range ssrfPayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			finding := s.testParameterPOST(ctx, parsedURL, paramName, payload, params, baseline)
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

		// Test with callback payloads if callback server is configured
		if s.callbackServer != nil {
			finding := s.testParameterWithCallbackPOST(ctx, parsedURL, paramName, params)
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

// testParameter tests a single parameter with a specific SSRF payload.
func (s *SSRFScanner) testParameter(ctx context.Context, baseURL *url.URL, paramName string, payload ssrfPayload, baseline *ssrfBaselineResponse) *SSRFFinding {
	// Create a copy of the URL with the test payload
	testURL := *baseURL
	q := testURL.Query()
	q.Set(paramName, payload.Payload)
	testURL.RawQuery = q.Encode()

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

	// Measure request time for timing-based detection
	startTime := time.Now()

	// Send the request
	resp, err := s.client.Do(req)

	requestDuration := time.Since(startTime)

	// Handle request errors - this might indicate SSRF attempt was blocked
	if err != nil {
		// Check if error indicates network timeout or connection refused
		// These could be signs that SSRF was attempted but blocked
		if isNetworkError(err) {
			// Don't report false positives on network errors
			return nil
		}
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

	// Analyze the response for SSRF indicators
	confidence, evidence := s.analyzeSSRFResponse(resp, bodyStr, payload, requestDuration, baseline)

	// Only report if there's medium or high confidence
	if confidence != "low" && confidence != "" {
		finding := &SSRFFinding{
			URL:         testURL.String(),
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

// testParameterPOST tests a single parameter with a specific SSRF payload using POST.
func (s *SSRFScanner) testParameterPOST(ctx context.Context, baseURL *url.URL, paramName string, payload ssrfPayload, allParameters map[string]string, baseline *ssrfBaselineResponse) *SSRFFinding {
	// Create form data with ALL parameters
	formData := url.Values{}
	for k, v := range allParameters {
		formData.Set(k, v)
	}
	// Override the parameter being tested
	formData.Set(paramName, payload.Payload)

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
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

	// Measure request time for timing-based detection
	startTime := time.Now()

	// Send the request
	resp, err := s.client.Do(req)

	requestDuration := time.Since(startTime)

	// Handle request errors - this might indicate SSRF attempt was blocked
	if err != nil {
		// Check if error indicates network timeout or connection refused
		// These could be signs that SSRF was attempted but blocked
		if isNetworkError(err) {
			// Don't report false positives on network errors
			return nil
		}
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

	// Analyze the response for SSRF indicators
	confidence, evidence := s.analyzeSSRFResponse(resp, bodyStr, payload, requestDuration, baseline)

	// Only report if there's medium or high confidence
	if confidence != "low" && confidence != "" {
		finding := &SSRFFinding{
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

// testParameterWithCallback tests a parameter using out-of-band callback detection (GET).
func (s *SSRFScanner) testParameterWithCallback(ctx context.Context, baseURL *url.URL, paramName string) *SSRFFinding {
	// Generate unique callback ID
	callbackID := s.callbackServer.GenerateCallbackID()

	// Try both HTTP and DNS callbacks
	httpURL := s.callbackServer.GetHTTPCallbackURL(callbackID)
	dnsURL := s.callbackServer.GetDNSCallbackDomain(callbackID)

	// Test HTTP callback first
	if httpURL != "" {
		finding := s.testCallbackURL(ctx, baseURL, paramName, callbackID, httpURL, "HTTP")
		if finding != nil {
			return finding
		}
	}

	// Test DNS callback
	if dnsURL != "" {
		// Use DNS URL in different formats
		dnsPayload := fmt.Sprintf("http://%s", dnsURL)
		finding := s.testCallbackURL(ctx, baseURL, paramName, callbackID, dnsPayload, "DNS")
		if finding != nil {
			return finding
		}
	}

	return nil
}

// testParameterWithCallbackPOST tests a parameter using out-of-band callback detection (POST).
func (s *SSRFScanner) testParameterWithCallbackPOST(ctx context.Context, baseURL *url.URL, paramName string, allParameters map[string]string) *SSRFFinding {
	// Generate unique callback ID
	callbackID := s.callbackServer.GenerateCallbackID()

	// Try both HTTP and DNS callbacks
	httpURL := s.callbackServer.GetHTTPCallbackURL(callbackID)
	dnsURL := s.callbackServer.GetDNSCallbackDomain(callbackID)

	// Test HTTP callback first
	if httpURL != "" {
		finding := s.testCallbackURLPOST(ctx, baseURL, paramName, allParameters, callbackID, httpURL, "HTTP")
		if finding != nil {
			return finding
		}
	}

	// Test DNS callback
	if dnsURL != "" {
		// Use DNS URL in different formats
		dnsPayload := fmt.Sprintf("http://%s", dnsURL)
		finding := s.testCallbackURLPOST(ctx, baseURL, paramName, allParameters, callbackID, dnsPayload, "DNS")
		if finding != nil {
			return finding
		}
	}

	return nil
}

// testCallbackURL sends a request with callback URL and waits for the callback.
func (s *SSRFScanner) testCallbackURL(ctx context.Context, baseURL *url.URL, paramName string, callbackID string, callbackURL string, callbackType string) *SSRFFinding {
	// Create a copy of the URL with the callback payload
	testURL := *baseURL
	q := testURL.Query()
	q.Set(paramName, callbackURL)
	testURL.RawQuery = q.Encode()

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

	// Apply rate limiting before making the request
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			return nil
		}
	}

	// Send the request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Wait for callback (5 seconds timeout)
	event, received := s.callbackServer.WaitForCallback(ctx, callbackID, 5*time.Second)

	if received {
		// We received a callback! This is definitive proof of SSRF
		evidence := fmt.Sprintf("Out-of-band %s callback received from %s at %s",
			callbackType, event.SourceIP, event.Timestamp.Format(time.RFC3339))

		if event.Method != "" {
			evidence += fmt.Sprintf(" (Method: %s, Path: %s)", event.Method, event.Path)
		}

		if event.Query != "" {
			evidence += fmt.Sprintf(" (DNS Query: %s)", event.Query)
		}

		return &SSRFFinding{
			URL:         testURL.String(),
			Parameter:   paramName,
			Payload:     callbackURL,
			Evidence:    evidence,
			Severity:    SeverityHigh,
			Type:        "callback",
			Description: fmt.Sprintf("SSRF vulnerability confirmed via out-of-band %s callback - application made a server-side request to attacker-controlled domain", callbackType),
			Remediation: s.getRemediation(),
			Confidence:  "high",
			Verified:    true,
		}
	}

	return nil
}

// testCallbackURLPOST sends a POST request with callback URL and waits for the callback.
func (s *SSRFScanner) testCallbackURLPOST(ctx context.Context, baseURL *url.URL, paramName string, allParameters map[string]string, callbackID string, callbackURL string, callbackType string) *SSRFFinding {
	// Create form data with ALL parameters
	formData := url.Values{}
	for k, v := range allParameters {
		formData.Set(k, v)
	}
	// Override the parameter being tested
	formData.Set(paramName, callbackURL)

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
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

	// Apply rate limiting before making the request
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Wait(ctx); err != nil {
			return nil
		}
	}

	// Send the request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Wait for callback (5 seconds timeout)
	event, received := s.callbackServer.WaitForCallback(ctx, callbackID, 5*time.Second)

	if received {
		// We received a callback! This is definitive proof of SSRF
		evidence := fmt.Sprintf("Out-of-band %s callback received from %s at %s",
			callbackType, event.SourceIP, event.Timestamp.Format(time.RFC3339))

		if event.Method != "" {
			evidence += fmt.Sprintf(" (Method: %s, Path: %s)", event.Method, event.Path)
		}

		if event.Query != "" {
			evidence += fmt.Sprintf(" (DNS Query: %s)", event.Query)
		}

		return &SSRFFinding{
			URL:         baseURL.String(),
			Parameter:   paramName,
			Payload:     callbackURL,
			Evidence:    evidence,
			Severity:    SeverityHigh,
			Type:        "callback",
			Description: fmt.Sprintf("SSRF vulnerability confirmed via out-of-band %s callback - application made a server-side request to attacker-controlled domain", callbackType),
			Remediation: s.getRemediation(),
			Confidence:  "high",
			Verified:    true,
		}
	}

	return nil
}

// analyzeSSRFResponse analyzes the HTTP response to determine if SSRF is possible.
// It compares the response against a baseline to reduce false positives.
func (s *SSRFScanner) analyzeSSRFResponse(resp *http.Response, body string, payload ssrfPayload, duration time.Duration, baseline *ssrfBaselineResponse) (confidence string, evidence string) {
	// If we have a baseline, perform enhanced differential analysis
	if baseline != nil {
		// Compute characteristics for current response
		currentContentHash := computeContentHash(body)
		currentWordCount := countWords(body)
		currentStructuralElements := countStructuralElements(body)

		// Check if status code changed significantly
		statusChanged := resp.StatusCode != baseline.StatusCode

		// Check if body length changed significantly (more than 10%)
		bodyLengthDiff := float64(len(body)-baseline.BodyLength) / float64(baseline.BodyLength+1)
		significantLengthChange := bodyLengthDiff > 0.1 || bodyLengthDiff < -0.1

		// Enhanced content comparison using content hash
		contentIdentical := currentContentHash == baseline.ContentHash

		// Check if word count changed significantly
		wordCountDiff := 0
		if baseline.WordCount > 0 {
			wordCountDiff = currentWordCount - baseline.WordCount
			if wordCountDiff < 0 {
				wordCountDiff = -wordCountDiff
			}
		}
		significantWordCountChange := wordCountDiff > 3 // At least 3 words difference

		// Check if structural elements changed
		structuralDiff := currentStructuralElements - baseline.StructuralElements
		if structuralDiff < 0 {
			structuralDiff = -structuralDiff
		}
		significantStructuralChange := structuralDiff > 1 // At least 1 element difference

		// If content hash matches, responses are semantically identical - definitely a false positive
		if contentIdentical {
			return "", ""
		}

		// If status code, length, word count, and structure are all similar,
		// the application is likely just ignoring the parameter
		if !statusChanged && !significantLengthChange && !significantWordCountChange && !significantStructuralChange {
			// Check if the body is exactly the same
			if body == baseline.Body {
				// Exact same response - almost certainly a false positive
				return "", ""
			}

			// Collect signatures in current response
			currentSignatures := s.collectSignatures(body)

			// Check if all signatures present were also in baseline
			allSignaturesInBaseline := true
			for _, sig := range currentSignatures {
				found := false
				for _, baseSig := range baseline.Signatures {
					if sig == baseSig {
						found = true
						break
					}
				}
				if !found {
					allSignaturesInBaseline = false
					break
				}
			}

			// If all signatures were already present in baseline, this is likely a false positive
			if allSignaturesInBaseline && len(currentSignatures) > 0 {
				return "", ""
			}

			// If none of the key metrics changed significantly and no new signatures appeared,
			// this is very likely a false positive (application ignoring the parameter)
			if len(currentSignatures) == 0 {
				return "", ""
			}
		}
	}

	// Check for status codes that indicate successful internal requests
	if resp.StatusCode == http.StatusOK {
		// Look for cloud metadata signatures
		if payload.Target == "aws-metadata" {
			// AWS metadata often returns plain text with specific patterns
			if containsAWSMetadataSignature(body) {
				// Check if these signatures were NOT in baseline
				if baseline != nil && s.signaturesInBaseline(baseline.Signatures, "aws") {
					return "", ""
				}
				return "high", "Response contains AWS metadata service signatures"
			}
		}

		if payload.Target == "gcp-metadata" {
			if containsGCPMetadataSignature(body) {
				if baseline != nil && s.signaturesInBaseline(baseline.Signatures, "gcp") {
					return "", ""
				}
				return "high", "Response contains GCP metadata service signatures"
			}
		}

		if payload.Target == "azure-metadata" {
			if containsAzureMetadataSignature(body) {
				if baseline != nil && s.signaturesInBaseline(baseline.Signatures, "azure") {
					return "", ""
				}
				return "high", "Response contains Azure metadata service signatures"
			}
		}

		if payload.Target == "k8s-metadata" {
			if containsKubernetesMetadataSignature(body) {
				if baseline != nil && s.signaturesInBaseline(baseline.Signatures, "k8s") {
					return "", ""
				}
				return "high", "Response contains Kubernetes API signatures"
			}
		}

		// Check for localhost/internal responses
		if payload.Target == "localhost" {
			// Look for common localhost service responses
			if containsLocalhostSignature(body) {
				if baseline != nil && s.signaturesInBaseline(baseline.Signatures, "localhost") {
					return "", ""
				}
				return "high", "Response contains localhost service signatures"
			}
			// Check for private network patterns
			if containsPrivateIPPatterns(body) {
				if baseline != nil && s.signaturesInBaseline(baseline.Signatures, "private-ip") {
					return "", ""
				}
				return "medium", "Response contains private IP address patterns"
			}
		}

		// Check for file protocol access
		if payload.Target == "file-protocol" {
			if containsFileAccessSignature(body) {
				if baseline != nil && s.signaturesInBaseline(baseline.Signatures, "file") {
					return "", ""
				}
				return "high", "Response contains file system access indicators"
			}
		}

		// Check for private network responses
		if payload.Target == "private-network" {
			// Only report if we detect actual private network content
			if containsPrivateIPPatterns(body) || containsInternalServiceSignatures(body) {
				// Check if these signatures were already in baseline
				if baseline != nil && (s.signaturesInBaseline(baseline.Signatures, "private-ip") || s.signaturesInBaseline(baseline.Signatures, "service")) {
					return "", ""
				}
				return "medium", fmt.Sprintf("Received response from private network address with internal content indicators (status: %d, size: %d bytes)", resp.StatusCode, len(body))
			}
		}

		// Check for protocol smuggling responses
		if strings.HasSuffix(payload.Target, "-protocol") {
			// Only report if there's evidence the protocol was actually processed
			if containsFileAccessSignature(body) || containsProtocolSmugglingSignatures(body) {
				if baseline != nil && s.signaturesInBaseline(baseline.Signatures, "file") {
					return "", ""
				}
				return "medium", fmt.Sprintf("Application may have processed %s protocol in URL parameter", strings.TrimSuffix(payload.Target, "-protocol"))
			}
		}
	}

	// Check for time-based indicators (very slow responses to internal IPs might indicate connection attempts)
	if duration > 10*time.Second && payload.Target == "private-network" {
		return "low", fmt.Sprintf("Request took %v - may indicate connection attempt to internal network", duration)
	}

	// Check for error messages that reveal internal network structure
	if containsInternalNetworkErrorPatterns(body) {
		return "medium", "Response contains internal network error messages"
	}

	return "", ""
}

// signaturesInBaseline checks if any signatures with the given prefix are present in baseline.
func (s *SSRFScanner) signaturesInBaseline(baselineSignatures []string, prefix string) bool {
	for _, sig := range baselineSignatures {
		// Handle special case for "private-ip" which doesn't have a colon
		if prefix == "private-ip" && sig == "private-ip" {
			return true
		}
		if strings.HasPrefix(sig, prefix+":") {
			return true
		}
	}
	return false
}

// containsAWSMetadataSignature checks if response contains AWS metadata signatures.
func containsAWSMetadataSignature(body string) bool {
	signatures := []string{
		"ami-id",
		"instance-id",
		"instance-type",
		"local-hostname",
		"local-ipv4",
		"public-hostname",
		"public-ipv4",
		"security-groups",
		"iam/security-credentials",
	}

	bodyLower := strings.ToLower(body)
	matchCount := 0
	for _, sig := range signatures {
		if strings.Contains(bodyLower, sig) {
			matchCount++
		}
	}

	// If we find multiple AWS-specific terms, it's likely AWS metadata
	return matchCount >= 2
}

// containsGCPMetadataSignature checks if response contains GCP metadata signatures.
func containsGCPMetadataSignature(body string) bool {
	signatures := []string{
		"computeMetadata",
		"project-id",
		"instance-id",
		"machine-type",
		"service-accounts",
		"attributes/",
	}

	bodyLower := strings.ToLower(body)
	matchCount := 0
	for _, sig := range signatures {
		if strings.Contains(bodyLower, strings.ToLower(sig)) {
			matchCount++
		}
	}

	return matchCount >= 2
}

// containsAzureMetadataSignature checks if response contains Azure metadata signatures.
func containsAzureMetadataSignature(body string) bool {
	signatures := []string{
		"compute",
		"vmId",
		"subscriptionId",
		"resourceGroupName",
		"location",
		"osType",
		"sku",
	}

	bodyLower := strings.ToLower(body)
	matchCount := 0
	for _, sig := range signatures {
		if strings.Contains(bodyLower, strings.ToLower(sig)) {
			matchCount++
		}
	}

	return matchCount >= 2
}

// containsKubernetesMetadataSignature checks if response contains Kubernetes API signatures.
func containsKubernetesMetadataSignature(body string) bool {
	signatures := []string{
		"apiVersion",
		"kind",
		"metadata",
		"namespace",
		"items",
		"serviceAccountToken",
	}

	bodyLower := strings.ToLower(body)
	matchCount := 0
	for _, sig := range signatures {
		if strings.Contains(bodyLower, strings.ToLower(sig)) {
			matchCount++
		}
	}

	// If we find multiple Kubernetes-specific terms, it's likely Kubernetes API response
	return matchCount >= 2
}

// containsLocalhostSignature checks if response contains localhost service signatures.
func containsLocalhostSignature(body string) bool {
	signatures := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"[::1]",
	}

	bodyLower := strings.ToLower(body)
	for _, sig := range signatures {
		if strings.Contains(bodyLower, sig) {
			return true
		}
	}

	return false
}

// containsPrivateIPPatterns checks if response contains private IP patterns.
func containsPrivateIPPatterns(body string) bool {
	// Match private IP ranges
	privateIPPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
		regexp.MustCompile(`\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b`),
		regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`),
	}

	for _, pattern := range privateIPPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}

	return false
}

// containsFileAccessSignature checks if response contains file access indicators.
func containsFileAccessSignature(body string) bool {
	signatures := []string{
		"root:x:",
		"/bin/bash",
		"/bin/sh",
		"etc/passwd",
		"[boot loader]",
		"C:\\Windows",
	}

	for _, sig := range signatures {
		if strings.Contains(body, sig) {
			return true
		}
	}

	return false
}

// containsInternalNetworkErrorPatterns checks for error messages revealing internal network.
func containsInternalNetworkErrorPatterns(body string) bool {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)connection refused.*10\.\d+\.\d+\.\d+`),
		regexp.MustCompile(`(?i)connection refused.*192\.168\.\d+\.\d+`),
		regexp.MustCompile(`(?i)connection refused.*172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+`),
		regexp.MustCompile(`(?i)timeout.*internal`),
		regexp.MustCompile(`(?i)unable to connect.*localhost`),
	}

	for _, pattern := range patterns {
		if pattern.MatchString(body) {
			return true
		}
	}

	return false
}

// containsInternalServiceSignatures checks if response contains signatures of internal services.
func containsInternalServiceSignatures(body string) bool {
	bodyLower := strings.ToLower(body)
	signatures := []string{
		"apache",
		"nginx",
		"tomcat",
		"jenkins",
		"grafana",
		"prometheus",
		"elasticsearch",
		"kibana",
		"rabbitmq",
		"redis",
		"memcached",
		"etcd",
		"consul",
	}

	for _, sig := range signatures {
		if strings.Contains(bodyLower, sig) {
			return true
		}
	}
	return false
}

// containsProtocolSmugglingSignatures checks if response indicates protocol smuggling.
func containsProtocolSmugglingSignatures(body string) bool {
	bodyLower := strings.ToLower(body)
	signatures := []string{
		"gopher://",
		"dict://",
		"file://",
		"ftp://",
		"tftp://",
		"ldap://",
	}

	for _, sig := range signatures {
		if strings.Contains(bodyLower, sig) {
			return true
		}
	}
	return false
}

// isNetworkError checks if an error is a network-related error.
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common network error types
	if _, ok := err.(net.Error); ok {
		return true
	}

	errStr := err.Error()
	networkErrorPatterns := []string{
		"connection refused",
		"connection reset",
		"network is unreachable",
		"no such host",
		"timeout",
		"i/o timeout",
	}

	for _, pattern := range networkErrorPatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}

	return false
}

// getRemediation returns remediation guidance for SSRF vulnerabilities.
func (s *SSRFScanner) getRemediation() string {
	return "Implement strict URL validation and sanitization. Use an allowlist of permitted domains/IPs. " +
		"Block access to private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, 169.254.x.x). " +
		"Disable support for unnecessary URL schemes (file://, dict://, gopher://, etc.). " +
		"Implement network segmentation to prevent access to internal services. " +
		"Use a separate service or proxy for making external requests with strict controls. " +
		"Validate and sanitize all user-supplied URLs on the server side."
}

// calculateSummary calculates the summary statistics for the scan.
func (s *SSRFScanner) calculateSummary(result *SSRFScanResult) {
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
func (r *SSRFScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("SSRF Vulnerability Scan for: %s\n", r.Target))
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
			sb.WriteString(fmt.Sprintf("\n  %d. [%s] %s SSRF\n", i+1, strings.ToUpper(f.Severity), titleCase(f.Type)))
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
		sb.WriteString("\nNo SSRF vulnerabilities detected.\n")
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
func (r *SSRFScanResult) HasResults() bool {
	return len(r.Findings) > 0 || r.Summary.TotalTests > 0
}

// VerifyFinding re-tests an SSRF finding with payload variants to confirm it's reproducible.
func (s *SSRFScanner) VerifyFinding(ctx context.Context, finding *SSRFFinding, config VerificationConfig) (*VerificationResult, error) {
	if finding == nil {
		return nil, fmt.Errorf("finding is nil")
	}

	// Parse the original URL to extract parameters
	parsedURL, err := url.Parse(finding.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL in finding: %w", err)
	}

	// Generate payload variants for verification
	variants := s.generateSSRFPayloadVariants(finding.Payload)

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

		startTime := time.Now()
		resp, err := s.client.Do(req)
		requestDuration := time.Since(startTime)

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

		// Check if variant produces similar SSRF indicators
		// Note: verification doesn't use baseline comparison
		confidence, _ := s.analyzeSSRFResponse(resp, bodyStr, ssrfPayload{Target: extractTargetType(finding.Payload)}, requestDuration, nil)
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

// generateSSRFPayloadVariants creates different variations of the SSRF payload.
func (s *SSRFScanner) generateSSRFPayloadVariants(originalPayload string) []string {
	variants := make([]string, 0)

	// Add the original payload
	variants = append(variants, originalPayload)

	// URL encoding variations
	if strings.Contains(originalPayload, "://") {
		// Try with URL-encoded slashes
		encoded := strings.ReplaceAll(originalPayload, "/", "%2F")
		variants = append(variants, encoded)

		// Try with double URL encoding
		doubleEncoded := strings.ReplaceAll(originalPayload, "/", "%252F")
		variants = append(variants, doubleEncoded)
	}

	// Case variations for localhost
	if strings.Contains(originalPayload, "localhost") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "localhost", "LOCALHOST"))
		variants = append(variants, strings.ReplaceAll(originalPayload, "localhost", "LocalHost"))
	}

	// IP address variations (decimal to other formats)
	if strings.Contains(originalPayload, "127.0.0.1") {
		// Octal representation
		variants = append(variants, strings.ReplaceAll(originalPayload, "127.0.0.1", "0177.0.0.1"))
		// Integer representation (127.0.0.1 = 2130706433)
		variants = append(variants, strings.ReplaceAll(originalPayload, "127.0.0.1", "2130706433"))
		// Hex representation
		variants = append(variants, strings.ReplaceAll(originalPayload, "127.0.0.1", "0x7f.0x0.0x0.0x1"))
	}

	// Protocol variations
	if strings.HasPrefix(originalPayload, "http://") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "http://", "HTTP://"))
	}

	return variants
}

// extractTargetType extracts the target type from a payload URL.
func extractTargetType(payload string) string {
	// Check protocol prefixes first (before checking host patterns)
	if strings.HasPrefix(payload, "file://") {
		return "file-protocol"
	}
	if strings.HasPrefix(payload, "dict://") {
		return "dict-protocol"
	}
	if strings.HasPrefix(payload, "gopher://") {
		return "gopher-protocol"
	}

	// Check for cloud metadata endpoints
	if strings.Contains(payload, "169.254.169.254") {
		if strings.Contains(payload, "api-version") {
			return "azure-metadata"
		}
		return "aws-metadata"
	}
	if strings.Contains(payload, "metadata.google.internal") {
		return "gcp-metadata"
	}
	if strings.Contains(payload, "kubernetes.default.svc") {
		return "k8s-metadata"
	}

	// Check for localhost and private network targets
	if strings.Contains(payload, "127.0.0.1") || strings.Contains(payload, "localhost") || strings.Contains(payload, "0.0.0.0") {
		return "localhost"
	}
	if strings.Contains(payload, "192.168.") || strings.Contains(payload, "10.") || strings.Contains(payload, "172.16.") {
		return "private-network"
	}

	return "unknown"
}
