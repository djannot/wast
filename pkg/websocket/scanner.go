// Package websocket provides WebSocket security scanning functionality.
package websocket

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/websocket"
)

// Severity levels for security findings.
const (
	SeverityInfo   = "info"
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

// SecurityScanner performs passive security checks on WebSocket endpoints.
type SecurityScanner struct {
	client      HTTPClient
	userAgent   string
	timeout     time.Duration
	authConfig  *auth.AuthConfig
	rateLimiter ratelimit.Limiter
	tracer      trace.Tracer
	activeMode  bool // Enable active testing
}

// ScannerOption is a function that configures a SecurityScanner.
type ScannerOption func(*SecurityScanner)

// WithScannerHTTPClient sets a custom HTTP client for the scanner.
func WithScannerHTTPClient(c HTTPClient) ScannerOption {
	return func(s *SecurityScanner) {
		s.client = c
	}
}

// WithScannerUserAgent sets the user agent string for the scanner.
func WithScannerUserAgent(ua string) ScannerOption {
	return func(s *SecurityScanner) {
		s.userAgent = ua
	}
}

// WithScannerTimeout sets the timeout for operations.
func WithScannerTimeout(t time.Duration) ScannerOption {
	return func(s *SecurityScanner) {
		s.timeout = t
	}
}

// WithScannerAuth sets the authentication configuration.
func WithScannerAuth(config *auth.AuthConfig) ScannerOption {
	return func(s *SecurityScanner) {
		s.authConfig = config
	}
}

// WithScannerRateLimiter sets a rate limiter for the scanner.
func WithScannerRateLimiter(limiter ratelimit.Limiter) ScannerOption {
	return func(s *SecurityScanner) {
		s.rateLimiter = limiter
	}
}

// WithScannerTracer sets the OpenTelemetry tracer.
func WithScannerTracer(tracer trace.Tracer) ScannerOption {
	return func(s *SecurityScanner) {
		s.tracer = tracer
	}
}

// WithActiveMode enables active security testing.
func WithActiveMode(active bool) ScannerOption {
	return func(s *SecurityScanner) {
		s.activeMode = active
	}
}

// NewSecurityScanner creates a new WebSocket security scanner.
func NewSecurityScanner(opts ...ScannerOption) *SecurityScanner {
	s := &SecurityScanner{
		userAgent:  "WAST/1.0 (Web Application Security Testing)",
		timeout:    30 * time.Second,
		activeMode: false,
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

// WebSocketFinding represents a security finding for a WebSocket endpoint.
type WebSocketFinding struct {
	URL                string   `json:"url" yaml:"url"`
	FindingType        string   `json:"finding_type" yaml:"finding_type"` // "insecure_protocol", "missing_origin_validation", "missing_accept"
	Severity           string   `json:"severity" yaml:"severity"`
	Description        string   `json:"description" yaml:"description"`
	Remediation        string   `json:"remediation" yaml:"remediation"`
	Evidence           string   `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Confidence         string   `json:"confidence" yaml:"confidence"` // "high", "medium", "low"
	RuleID             string   `json:"rule_id" yaml:"rule_id"`       // SARIF rule ID
	CWE                string   `json:"cwe,omitempty" yaml:"cwe,omitempty"`
	OriginHeader       string   `json:"origin_header,omitempty" yaml:"origin_header,omitempty"`
	OriginValidated    bool     `json:"origin_validated" yaml:"origin_validated"`
	AcceptHeaderPresent bool    `json:"accept_header_present" yaml:"accept_header_present"`
}

// ScanResult represents the result of a WebSocket security scan.
type ScanResult struct {
	Target   string                `json:"target" yaml:"target"`
	Findings []WebSocketFinding    `json:"findings" yaml:"findings"`
	Summary  ScanSummary           `json:"summary" yaml:"summary"`
	Errors   []string              `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// ScanSummary provides an overview of the scan results.
type ScanSummary struct {
	TotalEndpoints      int `json:"total_endpoints" yaml:"total_endpoints"`
	VulnerableEndpoints int `json:"vulnerable_endpoints" yaml:"vulnerable_endpoints"`
	HighSeverityCount   int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount    int `json:"low_severity_count" yaml:"low_severity_count"`
	InfoCount           int `json:"info_count" yaml:"info_count"`
}

// Scan performs security scanning on detected WebSocket endpoints.
func (s *SecurityScanner) Scan(ctx context.Context, detectionResult *DetectionResult) *ScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, "wast.websocket.scan")
		defer span.End()
	}

	result := &ScanResult{
		Target:   detectionResult.Target,
		Findings: make([]WebSocketFinding, 0),
		Errors:   make([]string, 0),
	}

	result.Summary.TotalEndpoints = len(detectionResult.Endpoints)

	// Track which endpoints have vulnerabilities
	vulnerableEndpoints := make(map[string]bool)

	for _, endpoint := range detectionResult.Endpoints {
		// Check for insecure WebSocket protocol (ws:// instead of wss://)
		if !endpoint.IsSecure {
			finding := WebSocketFinding{
				URL:         endpoint.URL,
				FindingType: "insecure_protocol",
				Severity:    SeverityMedium,
				Description: fmt.Sprintf("WebSocket endpoint uses insecure ws:// protocol instead of wss://, allowing traffic interception and manipulation"),
				Remediation: "Use wss:// (WebSocket Secure) instead of ws:// to encrypt WebSocket traffic over TLS",
				Evidence:    fmt.Sprintf("Detected in: %s", endpoint.SourcePage),
				Confidence:  "high",
				RuleID:      "WAST-WS-001",
				CWE:         "CWE-319",
			}
			result.Findings = append(result.Findings, finding)
			vulnerableEndpoints[endpoint.URL] = true
		}

		// Perform active tests if enabled
		if s.activeMode {
			activeFindings := s.performActiveTests(ctx, endpoint)
			for _, finding := range activeFindings {
				result.Findings = append(result.Findings, finding)
				vulnerableEndpoints[endpoint.URL] = true
			}
		} else {
			// Passive check: warn about potential missing origin validation
			finding := WebSocketFinding{
				URL:         endpoint.URL,
				FindingType: "potential_missing_origin_validation",
				Severity:    SeverityInfo,
				Description: "WebSocket endpoint detected. Origin header validation should be verified (requires active testing with --active flag)",
				Remediation: "Implement server-side Origin header validation to prevent Cross-Site WebSocket Hijacking (CSWSH) attacks",
				Evidence:    fmt.Sprintf("Detected in: %s", endpoint.SourcePage),
				Confidence:  "low",
				RuleID:      "WAST-WS-002",
				CWE:         "CWE-346",
			}
			result.Findings = append(result.Findings, finding)
		}
	}

	// Calculate summary
	result.Summary.VulnerableEndpoints = len(vulnerableEndpoints)
	for _, finding := range result.Findings {
		switch finding.Severity {
		case SeverityHigh:
			result.Summary.HighSeverityCount++
		case SeverityMedium:
			result.Summary.MediumSeverityCount++
		case SeverityLow:
			result.Summary.LowSeverityCount++
		case SeverityInfo:
			result.Summary.InfoCount++
		}
	}

	return result
}

// performActiveTests performs active security tests on a WebSocket endpoint.
func (s *SecurityScanner) performActiveTests(ctx context.Context, endpoint WebSocketEndpoint) []WebSocketFinding {
	findings := make([]WebSocketFinding, 0)

	// Apply rate limiting if configured
	if s.rateLimiter != nil {
		s.rateLimiter.Wait(ctx)
	}

	// Test 1: Check Origin header validation
	originFinding := s.testOriginValidation(ctx, endpoint)
	if originFinding != nil {
		findings = append(findings, *originFinding)
	}

	// Test 2: Check Sec-WebSocket-Accept header
	acceptFinding := s.testWebSocketAccept(ctx, endpoint)
	if acceptFinding != nil {
		findings = append(findings, *acceptFinding)
	}

	return findings
}

// testOriginValidation tests if the WebSocket endpoint validates the Origin header.
func (s *SecurityScanner) testOriginValidation(ctx context.Context, endpoint WebSocketEndpoint) *WebSocketFinding {
	// Parse the WebSocket URL
	wsURL, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil
	}

	// Configure WebSocket with malicious origin
	config := &websocket.Config{
		Location: wsURL,
		Origin: &url.URL{
			Scheme: "http",
			Host:   "evil.com",
		},
		Version: 13,
	}

	// Use TLS config for wss://
	if endpoint.IsSecure {
		config.TlsConfig = &tls.Config{
			InsecureSkipVerify: true, // For testing purposes only
		}
	}

	// Set timeout context
	testCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Attempt connection with malicious origin
	ws, err := s.dialWebSocket(testCtx, config)
	if err == nil {
		// Connection succeeded with malicious origin - vulnerability!
		ws.Close()

		return &WebSocketFinding{
			URL:             endpoint.URL,
			FindingType:     "missing_origin_validation",
			Severity:        SeverityHigh,
			Description:     "WebSocket endpoint does not validate Origin header, allowing Cross-Site WebSocket Hijacking (CSWSH) attacks",
			Remediation:     "Implement server-side Origin header validation to only allow connections from trusted origins",
			Evidence:        "Connection succeeded with Origin: http://evil.com",
			Confidence:      "high",
			RuleID:          "WAST-WS-002",
			CWE:             "CWE-346",
			OriginHeader:    "http://evil.com",
			OriginValidated: false,
		}
	}

	// Connection failed - origin may be validated (or other error)
	// Try with legitimate origin to confirm
	legitimateOrigin := &url.URL{
		Scheme: "https",
		Host:   wsURL.Host,
	}
	config.Origin = legitimateOrigin

	testCtx2, cancel2 := context.WithTimeout(ctx, s.timeout)
	defer cancel2()

	ws2, err2 := s.dialWebSocket(testCtx2, config)
	if err2 == nil {
		ws2.Close()
		// Legitimate origin works, malicious doesn't - good!
		return &WebSocketFinding{
			URL:             endpoint.URL,
			FindingType:     "origin_validation_present",
			Severity:        SeverityInfo,
			Description:     "WebSocket endpoint appears to validate Origin header correctly",
			Remediation:     "Continue monitoring and ensure all origin validation logic is secure",
			Evidence:        fmt.Sprintf("Rejected Origin: http://evil.com, Accepted Origin: %s", legitimateOrigin.String()),
			Confidence:      "medium",
			RuleID:          "WAST-WS-003",
			OriginHeader:    legitimateOrigin.String(),
			OriginValidated: true,
		}
	}

	// Both failed - endpoint may be down or have other issues
	return nil
}

// testWebSocketAccept tests if the endpoint properly handles WebSocket handshake.
func (s *SecurityScanner) testWebSocketAccept(ctx context.Context, endpoint WebSocketEndpoint) *WebSocketFinding {
	// Parse the WebSocket URL and convert to HTTP(S) for handshake test
	wsURL, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil
	}

	// Convert ws:// to http:// and wss:// to https://
	httpScheme := "http"
	if endpoint.IsSecure {
		httpScheme = "https"
	}
	httpURL := fmt.Sprintf("%s://%s%s", httpScheme, wsURL.Host, wsURL.Path)

	// Create HTTP request for WebSocket upgrade
	req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
	if err != nil {
		return nil
	}

	// Set WebSocket upgrade headers
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	// Apply authentication if configured
	if s.authConfig != nil && !s.authConfig.IsEmpty() {
		s.authConfig.ApplyToRequest(req)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check if Sec-WebSocket-Accept is present in response
	acceptHeader := resp.Header.Get("Sec-WebSocket-Accept")
	if resp.StatusCode == http.StatusSwitchingProtocols && acceptHeader == "" {
		return &WebSocketFinding{
			URL:                 endpoint.URL,
			FindingType:         "missing_accept_header",
			Severity:            SeverityLow,
			Description:         "WebSocket endpoint responds to upgrade but missing Sec-WebSocket-Accept header",
			Remediation:         "Ensure proper WebSocket handshake implementation with Sec-WebSocket-Accept header",
			Evidence:            fmt.Sprintf("Status: %d, Sec-WebSocket-Accept header: %s", resp.StatusCode, acceptHeader),
			Confidence:          "high",
			RuleID:              "WAST-WS-004",
			AcceptHeaderPresent: false,
		}
	}

	return nil
}

// dialWebSocket attempts to establish a WebSocket connection with the given config.
func (s *SecurityScanner) dialWebSocket(ctx context.Context, config *websocket.Config) (*websocket.Conn, error) {
	// Create a channel to receive the connection or error
	type result struct {
		conn *websocket.Conn
		err  error
	}
	resultCh := make(chan result, 1)

	go func() {
		conn, err := websocket.DialConfig(config)
		resultCh <- result{conn: conn, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultCh:
		return res.conn, res.err
	}
}

// String returns a human-readable representation of the scan result.
func (r *ScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("WebSocket Security Scan for: %s\n", r.Target))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	// Summary
	sb.WriteString("\nSummary:\n")
	sb.WriteString(fmt.Sprintf("  Total Endpoints: %d\n", r.Summary.TotalEndpoints))
	sb.WriteString(fmt.Sprintf("  Vulnerable Endpoints: %d\n", r.Summary.VulnerableEndpoints))
	sb.WriteString(fmt.Sprintf("  High Severity: %d\n", r.Summary.HighSeverityCount))
	sb.WriteString(fmt.Sprintf("  Medium Severity: %d\n", r.Summary.MediumSeverityCount))
	sb.WriteString(fmt.Sprintf("  Low Severity: %d\n", r.Summary.LowSeverityCount))
	sb.WriteString(fmt.Sprintf("  Info: %d\n", r.Summary.InfoCount))

	// Findings
	if len(r.Findings) > 0 {
		sb.WriteString("\nFindings:\n")
		for i, finding := range r.Findings {
			sb.WriteString(fmt.Sprintf("\n%d. [%s] %s\n", i+1, strings.ToUpper(finding.Severity), finding.FindingType))
			sb.WriteString(fmt.Sprintf("   URL: %s\n", finding.URL))
			sb.WriteString(fmt.Sprintf("   Rule ID: %s\n", finding.RuleID))
			if finding.CWE != "" {
				sb.WriteString(fmt.Sprintf("   CWE: %s\n", finding.CWE))
			}
			sb.WriteString(fmt.Sprintf("   Description: %s\n", finding.Description))
			if finding.Evidence != "" {
				sb.WriteString(fmt.Sprintf("   Evidence: %s\n", finding.Evidence))
			}
			sb.WriteString(fmt.Sprintf("   Confidence: %s\n", finding.Confidence))
			sb.WriteString(fmt.Sprintf("   Remediation: %s\n", finding.Remediation))
		}
	}

	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors encountered:\n")
		for _, err := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	return sb.String()
}
