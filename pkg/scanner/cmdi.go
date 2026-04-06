// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"crypto/md5"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// CMDiScanner performs active command injection vulnerability detection.
type CMDiScanner struct {
	BaseScanner
	timeBasedDelay time.Duration // Default 5 seconds
	verbose        bool          // Enable verbose debug logging
}

// CMDiScanResult represents the result of a command injection vulnerability scan.
type CMDiScanResult struct {
	Target   string        `json:"target" yaml:"target"`
	Findings []CMDiFinding `json:"findings" yaml:"findings"`
	Summary  CMDiSummary   `json:"summary" yaml:"summary"`
	Errors   []string      `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// CMDiFinding represents a single command injection vulnerability finding.
type CMDiFinding struct {
	URL                  string `json:"url" yaml:"url"`
	Parameter            string `json:"parameter" yaml:"parameter"`
	Payload              string `json:"payload" yaml:"payload"`
	Evidence             string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Severity             string `json:"severity" yaml:"severity"`
	Type                 string `json:"type" yaml:"type"`       // "time-based", "error-based", "output-based"
	OSType               string `json:"os_type" yaml:"os_type"` // "unix", "windows", "unknown"
	Description          string `json:"description" yaml:"description"`
	Remediation          string `json:"remediation" yaml:"remediation"`
	Confidence           string `json:"confidence" yaml:"confidence"` // "high", "medium", "low"
	Verified             bool   `json:"verified" yaml:"verified"`
	VerificationAttempts int    `json:"verification_attempts,omitempty" yaml:"verification_attempts,omitempty"`
}

// CMDiSummary provides an overview of the command injection scan results.
type CMDiSummary struct {
	TotalTests           int `json:"total_tests" yaml:"total_tests"`
	VulnerabilitiesFound int `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	HighSeverityCount    int `json:"high_severity_count" yaml:"high_severity_count"`
	MediumSeverityCount  int `json:"medium_severity_count" yaml:"medium_severity_count"`
	LowSeverityCount     int `json:"low_severity_count" yaml:"low_severity_count"`
}

// cmdiPayload represents a test payload for command injection detection.
type cmdiPayload struct {
	Payload       string
	Type          string // "time-based", "error-based", "output-based"
	OSType        string // "unix", "windows", "both"
	Severity      string
	Description   string
	ErrorPattern  *regexp.Regexp // Pattern to match in response for error-based detection
	ExpectedDelay time.Duration  // Expected delay for time-based payloads
}

// Common shell error patterns from various operating systems.
var cmdErrorPatterns = []*regexp.Regexp{
	// Unix/Linux shell errors
	regexp.MustCompile(`(?i)/bin/(ba)?sh:`),
	regexp.MustCompile(`(?i)command not found`),
	regexp.MustCompile(`(?i)sh: \d+: .*: not found`),
	regexp.MustCompile(`(?i)bash: .*: command not found`),
	regexp.MustCompile(`(?i)cannot execute`),
	regexp.MustCompile(`(?i)permission denied`),
	regexp.MustCompile(`(?i)/bin/sh: .*: not found`),
	regexp.MustCompile(`(?i)sh: .*: No such file or directory`),

	// Windows command errors
	regexp.MustCompile(`(?i)not recognized as an internal or external command`),
	regexp.MustCompile(`(?i)'.*' is not recognized`),
	regexp.MustCompile(`(?i)The system cannot find the path specified`),
	regexp.MustCompile(`(?i)cmd\.exe`),
	regexp.MustCompile(`(?i)The filename, directory name, or volume label syntax is incorrect`),

	// Generic execution errors
	regexp.MustCompile(`(?i)syntax error near unexpected token`),
	regexp.MustCompile(`(?i)unexpected EOF while looking for matching`),
	regexp.MustCompile(`(?i)command failed`),
	regexp.MustCompile(`(?i)exec format error`),
}

// Common command output patterns that indicate successful command execution.
var cmdOutputPatterns = []*regexp.Regexp{
	// Unix command output indicators
	regexp.MustCompile(`(?i)uid=[0-9]+`),
	regexp.MustCompile(`(?i)gid=[0-9]+`),
	regexp.MustCompile(`(?i)groups=[0-9]+`),
	regexp.MustCompile(`root:[x*]:[0-9]+`),
	regexp.MustCompile(`/bin/(ba)?sh`),
	regexp.MustCompile(`(?i)/home/[a-z0-9_-]+`),
	regexp.MustCompile(`(?i)/usr/bin`),
	regexp.MustCompile(`(?i)/etc/passwd`),

	// Common Unix/Linux usernames from whoami command
	// Pattern matches typical service account usernames at line boundaries
	// This avoids false positives from usernames in HTML/page structure by requiring
	// the username to be on its own line (as whoami output would be)
	regexp.MustCompile(`(?m)^(root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|backup|list|irc|gnats|nobody|systemd-network|systemd-resolve|systemd-timesync|messagebus|syslog|_apt|tss|uuidd|tcpdump|sshd|landscape|pollinate|fwupd-refresh|systemd-coredump|lxd|usbmux|avahi|hplip|pulse|gnome-initial-setup|colord|geoclue|speech-dispatcher|dnsmasq|lightdm|nm-openconnect|nm-openvpn|saned|cups-browsed|kernoops|whoopsie|gdm|rtkit|cups-pk-helper|apache|apache2|httpd|nginx|www-data|www|http|_www|wwwrun)$`),

	// Windows command output indicators
	regexp.MustCompile(`(?i)NT AUTHORITY`),
	regexp.MustCompile(`(?i)BUILTIN\\`),
	regexp.MustCompile(`(?i)\\Users\\`),
	regexp.MustCompile(`(?i)C:\\Windows`),
	regexp.MustCompile(`(?i)C:\\Program Files`),
}

// cmdiPayloads is the list of safe detection payloads to test for command injection.
//
// SECURITY WARNING: This list contains ONLY non-destructive payloads for responsible
// vulnerability detection. DO NOT add destructive commands (rm, del, wget, curl to external
// hosts, etc.) as this scanner is designed for ethical security testing only. All payloads
// use safe commands: sleep/timeout (time delays), id/whoami (read-only info), dir/type
// (directory listing). Adding destructive payloads would violate responsible disclosure
// practices and could cause harm to target systems.
var cmdiPayloads = []cmdiPayload{
	// Time-based Unix/Linux payloads
	{
		Payload:       ";sleep 5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (semicolon separator)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "|sleep 5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (pipe separator)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "&&sleep 5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (AND separator)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "||sleep 5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (OR separator)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "`sleep 5`",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (backtick substitution)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "$(sleep 5)",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Unix sleep (command substitution)",
		ExpectedDelay: 5 * time.Second,
	},

	// Additional separator variants for URL context
	// Note: These will be automatically URL-encoded by the HTTP client
	{
		Payload:       "; sleep 5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using semicolon with space",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "| sleep 5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using pipe with space",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "&& sleep 5",
		Type:          "time-based",
		OSType:        "unix",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using AND with space",
		ExpectedDelay: 5 * time.Second,
	},

	// Time-based Windows payloads
	{
		Payload:       "&timeout 5",
		Type:          "time-based",
		OSType:        "windows",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Windows timeout",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "|timeout 5",
		Type:          "time-based",
		OSType:        "windows",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Windows timeout (pipe)",
		ExpectedDelay: 5 * time.Second,
	},
	{
		Payload:       "&&timeout 5",
		Type:          "time-based",
		OSType:        "windows",
		Severity:      SeverityHigh,
		Description:   "Time-based blind command injection detected using Windows timeout (AND)",
		ExpectedDelay: 5 * time.Second,
	},

	// Error-based Unix/Linux payloads
	{
		Payload:      ";id",
		Type:         "error-based",
		OSType:       "unix",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Unix id command separator (semicolon)",
		ErrorPattern: nil, // Will check against all patterns
	},
	{
		Payload:      "|whoami",
		Type:         "error-based",
		OSType:       "unix",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Unix whoami command (pipe)",
		ErrorPattern: nil,
	},
	{
		Payload:      "&&id",
		Type:         "error-based",
		OSType:       "unix",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Unix id command (AND)",
		ErrorPattern: nil,
	},
	{
		Payload:      "`id`",
		Type:         "error-based",
		OSType:       "unix",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Unix id command (backtick)",
		ErrorPattern: nil,
	},
	{
		Payload:      "$(whoami)",
		Type:         "error-based",
		OSType:       "unix",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Unix whoami command (command substitution)",
		ErrorPattern: nil,
	},

	// Error-based Windows payloads
	{
		Payload:      "& dir",
		Type:         "error-based",
		OSType:       "windows",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Windows dir command",
		ErrorPattern: nil,
	},
	{
		Payload:      "| type",
		Type:         "error-based",
		OSType:       "windows",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Windows type command (pipe)",
		ErrorPattern: nil,
	},
	{
		Payload:      "&& whoami",
		Type:         "error-based",
		OSType:       "windows",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Windows whoami command",
		ErrorPattern: nil,
	},
	{
		Payload:      "|| whoami",
		Type:         "error-based",
		OSType:       "windows",
		Severity:     SeverityHigh,
		Description:  "Command injection detected - Windows whoami command (OR)",
		ErrorPattern: nil,
	},

	// Output-based Unix/Linux payloads - append commands to valid input
	{
		Payload:     "127.0.0.1; id",
		Type:        "output-based",
		OSType:      "unix",
		Severity:    SeverityHigh,
		Description: "Command injection detected - Unix id command output in response (semicolon separator)",
	},
	{
		Payload:     "127.0.0.1 && whoami",
		Type:        "output-based",
		OSType:      "unix",
		Severity:    SeverityHigh,
		Description: "Command injection detected - Unix whoami command output in response (AND separator)",
	},
	{
		Payload:     "127.0.0.1 | id",
		Type:        "output-based",
		OSType:      "unix",
		Severity:    SeverityHigh,
		Description: "Command injection detected - Unix id command output in response (pipe separator)",
	},
	{
		Payload:     "test; whoami",
		Type:        "output-based",
		OSType:      "unix",
		Severity:    SeverityHigh,
		Description: "Command injection detected - Unix whoami command output in response (semicolon)",
	},
	{
		Payload:     "test && id",
		Type:        "output-based",
		OSType:      "unix",
		Severity:    SeverityHigh,
		Description: "Command injection detected - Unix id command output in response (AND)",
	},
	{
		Payload:     "test | whoami",
		Type:        "output-based",
		OSType:      "unix",
		Severity:    SeverityHigh,
		Description: "Command injection detected - Unix whoami command output in response (pipe)",
	},
	{
		Payload:     "localhost; cat /etc/passwd",
		Type:        "output-based",
		OSType:      "unix",
		Severity:    SeverityHigh,
		Description: "Command injection detected - Unix cat /etc/passwd output in response",
	},

	// Output-based Windows payloads
	{
		Payload:     "127.0.0.1 & whoami",
		Type:        "output-based",
		OSType:      "windows",
		Severity:    SeverityHigh,
		Description: "Command injection detected - Windows whoami command output in response",
	},
	{
		Payload:     "127.0.0.1 | whoami",
		Type:        "output-based",
		OSType:      "windows",
		Severity:    SeverityHigh,
		Description: "Command injection detected - Windows whoami command output in response (pipe)",
	},
	{
		Payload:     "test & whoami",
		Type:        "output-based",
		OSType:      "windows",
		Severity:    SeverityHigh,
		Description: "Command injection detected - Windows whoami command output in response",
	},
	{
		Payload:     "test && whoami",
		Type:        "output-based",
		OSType:      "windows",
		Severity:    SeverityHigh,
		Description: "Command injection detected - Windows whoami command output in response (AND)",
	},
}

// Common vulnerable parameter names to test.
var cmdiVulnerableParams = []string{
	"cmd", "exec", "command", "ping", "query", "jump", "code", "reg",
	"do", "func", "arg", "option", "process", "step", "daemon", "dir",
	"download", "log", "ip", "cli", "shell", "sys", "run", "execute",
}

// CMDiOption is a function that configures a CMDiScanner.
type CMDiOption func(*CMDiScanner)

// WithCMDiHTTPClient sets a custom HTTP client for the command injection scanner.
func WithCMDiHTTPClient(c HTTPClient) CMDiOption {
	return func(s *CMDiScanner) { s.client = c }
}

// WithCMDiUserAgent sets the user agent string for the command injection scanner.
func WithCMDiUserAgent(ua string) CMDiOption {
	return func(s *CMDiScanner) { s.userAgent = ua }
}

// WithCMDiTimeout sets the timeout for HTTP requests.
func WithCMDiTimeout(d time.Duration) CMDiOption {
	return func(s *CMDiScanner) { s.timeout = d }
}

// WithCMDiAuth sets the authentication configuration for the command injection scanner.
func WithCMDiAuth(config *auth.AuthConfig) CMDiOption {
	return func(s *CMDiScanner) { s.authConfig = config }
}

// WithCMDiRateLimiter sets a rate limiter for the command injection scanner.
func WithCMDiRateLimiter(limiter ratelimit.Limiter) CMDiOption {
	return func(s *CMDiScanner) { s.rateLimiter = limiter }
}

// WithCMDiRateLimitConfig sets rate limiting from a configuration.
func WithCMDiRateLimitConfig(cfg ratelimit.Config) CMDiOption {
	return func(s *CMDiScanner) { s.rateLimiter = ratelimit.NewLimiterFromConfig(cfg) }
}

// WithCMDiTracer sets the OpenTelemetry tracer for the command injection scanner.
func WithCMDiTracer(tracer trace.Tracer) CMDiOption {
	return func(s *CMDiScanner) { s.tracer = tracer }
}

// WithCMDiTimeBasedDelay sets the expected delay duration for time-based command injection detection.
func WithCMDiTimeBasedDelay(d time.Duration) CMDiOption {
	return func(s *CMDiScanner) { s.timeBasedDelay = d }
}

// WithCMDiVerbose enables verbose debug logging for the command injection scanner.
func WithCMDiVerbose() CMDiOption {
	return func(s *CMDiScanner) { s.verbose = true }
}

// submitButtonExactPatterns lists parameter names that are submit-button indicators when
// matched exactly (case-insensitive). These patterns are also common data-field prefixes
// (e.g. "search_query", "action_type"), so prefix/suffix expansion is intentionally avoided
// to prevent false negatives in a security scanner.
var submitButtonExactPatterns = map[string]bool{
	"submit": true,
	"go":     true,
	"search": true,
	"action": true,
	"send":   true,
}

// submitButtonPrefixPatterns lists patterns that are safe for prefix/suffix expansion because
// they are unambiguously submit-button names (e.g. "btn_primary", "my_button").
var submitButtonPrefixPatterns = []string{"btn", "button"}

// isSubmitButton reports whether the given parameter name matches a common submit button pattern.
// This helps the scanner skip non-data form fields to avoid wasted effort and false positives.
// Exact matching is used for patterns like "search" and "action" that also appear as data-field
// prefixes, to avoid false negatives on legitimate injection targets such as "search_query".
func isSubmitButton(paramName string) bool {
	lower := strings.ToLower(paramName)
	// Exact-match only for ambiguous patterns (also common data-field names)
	if submitButtonExactPatterns[lower] {
		return true
	}
	// Prefix/suffix expansion only for unambiguously submit-button names
	for _, pattern := range submitButtonPrefixPatterns {
		if lower == pattern || strings.HasPrefix(lower, pattern+"_") || strings.HasSuffix(lower, "_"+pattern) {
			return true
		}
	}
	return false
}

// NewCMDiScanner creates a new CMDiScanner with the given options.
func NewCMDiScanner(opts ...CMDiOption) *CMDiScanner {
	s := &CMDiScanner{
		BaseScanner:    DefaultBaseScanner(),
		timeBasedDelay: 5 * time.Second,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.InitDefaultClient()
	return s
}

// NewCMDiScannerFromBase creates a new CMDiScanner from pre-built BaseOptions
// plus any scanner-specific options.
func NewCMDiScannerFromBase(baseOpts []BaseOption, extraOpts ...CMDiOption) *CMDiScanner {
	s := &CMDiScanner{
		BaseScanner:    DefaultBaseScanner(),
		timeBasedDelay: 5 * time.Second,
	}
	ApplyBaseOptions(&s.BaseScanner, baseOpts)
	for _, opt := range extraOpts {
		opt(s)
	}
	s.InitDefaultClient()
	return s
}

// Scan performs a command injection vulnerability scan on the given target URL.
func (s *CMDiScanner) Scan(ctx context.Context, targetURL string) *CMDiScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanCMDi)
		defer span.End()
	}

	result := &CMDiScanResult{
		Target:   targetURL,
		Findings: make([]CMDiFinding, 0),
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

	// If no query parameters exist, test with common vulnerable parameter names
	if len(params) == 0 {
		for _, paramName := range cmdiVulnerableParams {
			params.Set(paramName, "test")
		}
	}

	// Get baseline responses and timing for detection
	baselineResponses := make(map[string]*baselineResponse)
	baselineTiming := make(map[string]time.Duration)
	for paramName := range params {
		baseline, duration := s.getBaselineWithTiming(ctx, parsedURL, paramName)
		if baseline != nil {
			baselineResponses[paramName] = baseline
			baselineTiming[paramName] = duration
		}
	}

	// Test each parameter with each payload
	for paramName := range params {
		for _, payload := range cmdiPayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			var finding *CMDiFinding
			if payload.Type == "time-based" {
				// Time-based detection
				baseline := baselineTiming[paramName]
				finding = s.testTimeBased(ctx, parsedURL, paramName, payload, baseline)
			} else if payload.Type == "error-based" {
				// Error-based detection
				finding = s.testErrorBased(ctx, parsedURL, paramName, payload)
			} else if payload.Type == "output-based" {
				// Output-based detection
				baseline := baselineResponses[paramName]
				finding = s.testOutputBased(ctx, parsedURL, paramName, payload, baseline)
			}

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

// ScanPOST scans a URL for command injection vulnerabilities using POST form data.
// Unlike Scan(), which tests GET query parameters, ScanPOST sends payloads in
// the request body as application/x-www-form-urlencoded data.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - targetURL: The URL to test (should not include query parameters)
//   - parameters: Form parameters and their original values. When testing each
//     parameter, all other parameters are included with their original values
//     to ensure proper form validation. If empty, tests common vulnerable
//     parameter names with default values.
//
// Returns:
//   - A CMDiScanResult containing all findings, summary statistics, and any errors.
//     The result is never nil, even if errors occur.
//
// This method is typically called by the discovery module when scanning POST forms.
func (s *CMDiScanner) ScanPOST(ctx context.Context, targetURL string, parameters map[string]string) *CMDiScanResult {
	// Create tracing span if tracer is available
	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, telemetry.SpanNameScanCMDi)
		defer span.End()
	}

	result := &CMDiScanResult{
		Target:   targetURL,
		Findings: make([]CMDiFinding, 0),
		Errors:   make([]string, 0),
	}

	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid URL: %s", err.Error()))
		return result
	}

	// Use provided parameters or fallback to common vulnerable parameter names
	params := parameters
	if len(params) == 0 {
		params = make(map[string]string)
		for _, paramName := range cmdiVulnerableParams {
			params[paramName] = "test"
		}
	}

	// Get baseline responses and timing for detection
	baselineResponses := make(map[string]*baselineResponse)
	baselineTiming := make(map[string]time.Duration)
	for paramName := range params {
		// Skip submit button parameters — they carry no injectable data
		if isSubmitButton(paramName) {
			if s.verbose {
				log.Printf("[CMDi] ScanPOST: skipping submit-button parameter %q", paramName)
			}
			continue
		}
		baseline, duration := s.getBaselineWithTimingPOST(ctx, parsedURL, paramName, params)
		if baseline != nil {
			baselineResponses[paramName] = baseline
			baselineTiming[paramName] = duration
		}
	}

	// Test each parameter with each payload
	for paramName := range params {
		// Skip submit button parameters — they carry no injectable data
		if isSubmitButton(paramName) {
			continue
		}
		for _, payload := range cmdiPayloads {
			// Apply rate limiting before making the request
			if s.rateLimiter != nil {
				if err := s.rateLimiter.Wait(ctx); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Rate limiting error: %s", err.Error()))
					return result
				}
			}

			var finding *CMDiFinding
			if payload.Type == "time-based" {
				// Time-based detection
				baseline := baselineTiming[paramName]
				finding = s.testTimeBasedPOST(ctx, parsedURL, paramName, payload, baseline, params)
			} else if payload.Type == "error-based" {
				// Error-based detection
				finding = s.testErrorBasedPOST(ctx, parsedURL, paramName, payload, params)
			} else if payload.Type == "output-based" {
				// Output-based detection
				baseline := baselineResponses[paramName]
				finding = s.testOutputBasedPOST(ctx, parsedURL, paramName, payload, params, baseline)
			}

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

// getBaselineWithTiming makes a request with the original parameter value to establish a baseline
// and measures the request duration for time-based detection.
func (s *CMDiScanner) getBaselineWithTiming(ctx context.Context, baseURL *url.URL, paramName string) (*baselineResponse, time.Duration) {
	// Create a copy of the URL with the original parameter value
	testURL := *baseURL
	q := testURL.Query()

	// Use original value if it exists, otherwise use a safe default
	originalValue := q.Get(paramName)
	if originalValue == "" {
		originalValue = "test"
		q.Set(paramName, originalValue)
	}
	testURL.RawQuery = q.Encode()

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return nil, 0
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	// Apply authentication configuration
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	// Measure request time
	startTime := time.Now()
	resp, err := s.client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()

	// Read response body
	body, err := readResponseBody(resp.Body)
	if err != nil {
		return nil, 0
	}

	baseline := &baselineResponse{
		StatusCode:  resp.StatusCode,
		BodyLength:  len(body),
		BodyHash:    fmt.Sprintf("%x", len(body)), // Simple hash for comparison
		ContainsKey: string(body),
	}

	return baseline, duration
}

// getBaselineWithTimingPOST makes a POST request with the original parameter value to establish a baseline
// and measures the request duration for time-based detection.
func (s *CMDiScanner) getBaselineWithTimingPOST(ctx context.Context, baseURL *url.URL, paramName string, allParameters map[string]string) (*baselineResponse, time.Duration) {
	// Create form data with ALL parameters
	formData := url.Values{}
	for k, v := range allParameters {
		if k == paramName && v == "" {
			// Use a benign placeholder when the target parameter has no default value.
			// An empty string may cause the server to produce no output, making differential
			// analysis unreliable (baseline body differs from injected body for structural
			// reasons unrelated to the injection).
			v = "test"
		}
		formData.Set(k, v)
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, 0
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Apply authentication configuration
	if s.authConfig != nil {
		s.authConfig.ApplyToRequest(req)
	}

	// Measure request time
	startTime := time.Now()
	resp, err := s.client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()

	// Read response body
	body, err := readResponseBody(resp.Body)
	if err != nil {
		return nil, 0
	}

	// Calculate proper hash of response body
	hash := md5.Sum(body)

	baseline := &baselineResponse{
		StatusCode:  resp.StatusCode,
		BodyLength:  len(body),
		BodyHash:    fmt.Sprintf("%x", hash),
		ContainsKey: string(body),
	}

	return baseline, duration
}

// buildPrependedPayloads returns payload variants to try for a given parameter.
// It always includes the original payload as a direct replacement. If originalValue
// is non-empty, it also prepends originalValue to the payload so that apps requiring
// a valid prefix (e.g. a ping page that needs an IP before a shell separator) still
// process the request. If originalValue is empty, it prepends common benign defaults
// ("127.0.0.1" for IP-like parameters and "test" as a generic fallback).
func buildPrependedPayloads(originalValue, payloadStr string) []string {
	variants := []string{payloadStr}
	if originalValue != "" {
		prepended := originalValue + payloadStr
		if prepended != payloadStr {
			variants = append(variants, prepended)
		}
	} else {
		// Empty original value: try benign prefixes so the app processes the form.
		// Many real-world apps (e.g. DVWA /vulnerabilities/exec/) require a valid
		// prefix before a command separator to actually invoke the shell command.
		variants = append(variants, "127.0.0.1"+payloadStr, "test"+payloadStr)
	}
	return variants
}

// testErrorBased tests a single parameter with an error-based command injection payload.
// It tries the payload directly and also prepended with the original parameter value (or
// a benign default when empty) to handle apps that require a valid prefix.
func (s *CMDiScanner) testErrorBased(ctx context.Context, baseURL *url.URL, paramName string, payload cmdiPayload) *CMDiFinding {
	originalValue := baseURL.Query().Get(paramName)
	payloadVariants := buildPrependedPayloads(originalValue, payload.Payload)

	for _, payloadValue := range payloadVariants {
		// Create a copy of the URL with the test payload variant
		testURL := *baseURL
		q := testURL.Query()
		q.Set(paramName, payloadValue)
		testURL.RawQuery = q.Encode()

		// Create the request
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
		if err != nil {
			continue
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
			continue
		}

		// Handle rate limiting (HTTP 429)
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			continue
		}

		// Read response body
		body, err := readResponseBody(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// Check for shell error patterns in the response
		for _, pattern := range cmdErrorPatterns {
			if pattern.MatchString(bodyStr) {
				// Command error detected!
				match := pattern.FindString(bodyStr)
				finding := &CMDiFinding{
					URL:         testURL.String(),
					Parameter:   paramName,
					Payload:     payloadValue,
					Evidence:    s.extractEvidence(bodyStr, match),
					Severity:    payload.Severity,
					Type:        payload.Type,
					OSType:      payload.OSType,
					Description: payload.Description,
					Remediation: s.getRemediation(),
					Confidence:  "high", // Error-based detection with shell errors is high confidence
				}
				return finding
			}
		}
	}

	return nil
}

// testOutputBased tests a single parameter with an output-based command injection payload.
// It performs differential analysis by comparing the response with payload against the baseline response.
// It tries the payload directly and also prepended with the original parameter value (or a benign
// default when empty) to handle apps that require a valid prefix before the shell separator.
func (s *CMDiScanner) testOutputBased(ctx context.Context, baseURL *url.URL, paramName string, payload cmdiPayload, baseline *baselineResponse) *CMDiFinding {
	// Check if baseline is available for differential analysis
	if baseline == nil {
		return nil
	}

	originalValue := baseURL.Query().Get(paramName)
	payloadVariants := buildPrependedPayloads(originalValue, payload.Payload)

	for _, payloadValue := range payloadVariants {
		// Create a copy of the URL with the test payload variant
		testURL := *baseURL
		q := testURL.Query()
		q.Set(paramName, payloadValue)
		testURL.RawQuery = q.Encode()

		// Create the request
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
		if err != nil {
			continue
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
			continue
		}

		// Handle rate limiting (HTTP 429)
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			continue
		}

		// Read response body
		body, err := readResponseBody(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// Strip the injected payload (and HTML/URL-encoded variants) from the
		// response body before running pattern matching.  This prevents reflected
		// input (e.g., an XSS parameter echoing "localhost; cat /etc/passwd")
		// from triggering output-based CMDi patterns like `/etc/passwd` or
		// `root:x:0`.  Genuine command output that appears independently of the
		// reflected payload is preserved.
		strippedBody := stripCMDiPayloadFromBody(bodyStr, payloadValue)

		// Perform differential analysis: check if command output patterns appear in the
		// injected response but NOT in the baseline response (to avoid false positives)
		for _, pattern := range cmdOutputPatterns {
			if pattern.MatchString(strippedBody) {
				// Pattern found in injected response - now check if it was also in baseline
				if !pattern.MatchString(baseline.ContainsKey) {
					// Pattern is NEW - this indicates command output from our injection!
					match := pattern.FindString(strippedBody)
					finding := &CMDiFinding{
						URL:         testURL.String(),
						Parameter:   paramName,
						Payload:     payloadValue,
						Evidence:    s.extractEvidence(bodyStr, match),
						Severity:    payload.Severity,
						Type:        payload.Type,
						OSType:      payload.OSType,
						Description: payload.Description,
						Remediation: s.getRemediation(),
						Confidence:  "high", // Output-based detection with differential analysis is high confidence
					}
					return finding
				}
			}
		}
	}

	return nil
}

// testTimeBased tests a single parameter with a time-based command injection payload.
// It measures request duration and compares with baseline and expected delay.
// It tries the payload directly and also prepended with the original parameter value (or a benign
// default when empty) to handle apps that require a valid prefix before the shell separator.
func (s *CMDiScanner) testTimeBased(ctx context.Context, baseURL *url.URL, paramName string, payload cmdiPayload, baselineDuration time.Duration) *CMDiFinding {
	originalValue := baseURL.Query().Get(paramName)
	payloadVariants := buildPrependedPayloads(originalValue, payload.Payload)

	// Determine the expected delay (use payload's expected delay or scanner's default)
	expectedDelay := payload.ExpectedDelay
	if expectedDelay == 0 {
		expectedDelay = s.timeBasedDelay
	}

	// Calculate threshold: baseline + expected delay - tolerance
	// We use a percentage-based tolerance (20% of expected delay) to account for network jitter
	// This prevents false positives on slow networks while still detecting actual delays
	tolerance := time.Duration(float64(expectedDelay) * 0.2)
	if tolerance < 500*time.Millisecond {
		tolerance = 500 * time.Millisecond // Minimum 500ms tolerance
	}
	minExpectedDuration := baselineDuration + expectedDelay - tolerance

	for _, payloadValue := range payloadVariants {
		// Create a copy of the URL with the test payload variant
		testURL := *baseURL
		q := testURL.Query()
		q.Set(paramName, payloadValue)
		testURL.RawQuery = q.Encode()

		// Create the request
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", s.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		// Apply authentication configuration
		if s.authConfig != nil {
			s.authConfig.ApplyToRequest(req)
		}

		// Measure request time
		startTime := time.Now()
		resp, err := s.client.Do(req)
		requestDuration := time.Since(startTime)

		if err != nil {
			continue
		}

		// Handle rate limiting (HTTP 429)
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			continue
		}

		// Read response body to check for shell errors (which would indicate even higher confidence)
		body, err := readResponseBody(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// First check if there are shell errors - this would be even stronger evidence
		shellErrorFound := false
		var errorMatch string
		for _, pattern := range cmdErrorPatterns {
			if pattern.MatchString(bodyStr) {
				shellErrorFound = true
				errorMatch = pattern.FindString(bodyStr)
				break
			}
		}

		// Check if the request took significantly longer than expected
		if requestDuration >= minExpectedDuration {
			confidence := "high"
			evidenceMsg := fmt.Sprintf("Request took %v (baseline: %v, expected delay: %v) - indicates time-based command injection",
				requestDuration, baselineDuration, expectedDelay)

			// If shell error is also present, mention it in evidence
			if shellErrorFound {
				evidenceMsg += fmt.Sprintf("; Shell error also detected: %s", s.extractEvidence(bodyStr, errorMatch))
				confidence = "high" // Both timing and error confirms vulnerability
			}

			return &CMDiFinding{
				URL:         testURL.String(),
				Parameter:   paramName,
				Payload:     payloadValue,
				Evidence:    evidenceMsg,
				Severity:    payload.Severity,
				Type:        payload.Type,
				OSType:      payload.OSType,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  confidence,
			}
		}
	}

	return nil
}

// testErrorBasedPOST tests a single parameter with an error-based command injection payload using POST.
// It tries the payload directly and also prepended with the original parameter value (or a benign
// default when empty) to handle apps that require a valid prefix before the shell separator.
func (s *CMDiScanner) testErrorBasedPOST(ctx context.Context, baseURL *url.URL, paramName string, payload cmdiPayload, allParameters map[string]string) *CMDiFinding {
	originalValue := allParameters[paramName]
	payloadVariants := buildPrependedPayloads(originalValue, payload.Payload)

	for _, payloadValue := range payloadVariants {
		// Create form data with ALL parameters
		formData := url.Values{}
		for k, v := range allParameters {
			formData.Set(k, v)
		}
		// Override the parameter being tested with this variant
		formData.Set(paramName, payloadValue)

		// Create the request
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
		if err != nil {
			continue
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
			continue
		}

		// Handle rate limiting (HTTP 429)
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			continue
		}

		// Read response body
		body, err := readResponseBody(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// Check for shell error patterns in the response
		for _, pattern := range cmdErrorPatterns {
			if pattern.MatchString(bodyStr) {
				// Command error detected!
				match := pattern.FindString(bodyStr)
				finding := &CMDiFinding{
					URL:         baseURL.String(),
					Parameter:   paramName,
					Payload:     payloadValue,
					Evidence:    s.extractEvidence(bodyStr, match),
					Severity:    payload.Severity,
					Type:        payload.Type,
					OSType:      payload.OSType,
					Description: payload.Description,
					Remediation: s.getRemediation(),
					Confidence:  "high", // Error-based detection with shell errors is high confidence
				}
				return finding
			}
		}
	}

	return nil
}

// testOutputBasedPOST tests a single parameter with an output-based command injection payload using POST.
// It performs differential analysis by comparing the response with payload against the baseline response.
// It tries the payload directly and also prepended with the original parameter value (or a benign
// default when empty) to handle apps that require a valid prefix before the shell separator.
func (s *CMDiScanner) testOutputBasedPOST(ctx context.Context, baseURL *url.URL, paramName string, payload cmdiPayload, allParameters map[string]string, baseline *baselineResponse) *CMDiFinding {
	// Check if baseline is available for differential analysis
	if baseline == nil {
		return nil
	}

	originalValue := allParameters[paramName]
	payloadVariants := buildPrependedPayloads(originalValue, payload.Payload)

	for _, payloadValue := range payloadVariants {
		// Create form data with ALL parameters
		formData := url.Values{}
		for k, v := range allParameters {
			formData.Set(k, v)
		}
		// Override the parameter being tested with this variant
		formData.Set(paramName, payloadValue)

		// Create the request
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
		if err != nil {
			continue
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
			continue
		}

		// Handle rate limiting (HTTP 429)
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			continue
		}

		// Read response body
		body, err := readResponseBody(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// Strip the injected payload (and HTML/URL-encoded variants) from the
		// response body before running pattern matching.  This prevents reflected
		// input (e.g., an XSS parameter echoing "localhost; cat /etc/passwd")
		// from triggering output-based CMDi patterns like `/etc/passwd` or
		// `root:x:0`.  Genuine command output that appears independently of the
		// reflected payload is preserved.
		strippedBody := stripCMDiPayloadFromBody(bodyStr, payloadValue)

		// Perform differential analysis: check if command output patterns appear in the
		// injected response but NOT in the baseline response (to avoid false positives)
		if s.verbose {
			log.Printf("[CMDi] testOutputBasedPOST: param=%q payload=%q injected_body_len=%d baseline_body_len=%d stripped_body_len=%d",
				paramName, payloadValue, len(bodyStr), len(baseline.ContainsKey), len(strippedBody))
		}
		for _, pattern := range cmdOutputPatterns {
			inInjected := pattern.MatchString(strippedBody)
			inBaseline := pattern.MatchString(baseline.ContainsKey)
			if s.verbose {
				log.Printf("[CMDi] testOutputBasedPOST: pattern=%q inInjected=%v inBaseline=%v",
					pattern.String(), inInjected, inBaseline)
			}
			if inInjected {
				// Pattern found in injected response - now check if it was also in baseline
				if !inBaseline {
					// Pattern is NEW - this indicates command output from our injection!
					match := pattern.FindString(strippedBody)
					finding := &CMDiFinding{
						URL:         baseURL.String(),
						Parameter:   paramName,
						Payload:     payloadValue,
						Evidence:    s.extractEvidence(bodyStr, match),
						Severity:    payload.Severity,
						Type:        payload.Type,
						OSType:      payload.OSType,
						Description: payload.Description,
						Remediation: s.getRemediation(),
						Confidence:  "high", // Output-based detection with differential analysis is high confidence
					}
					return finding
				}
			}
		}
	}

	return nil
}

// testTimeBasedPOST tests a single parameter with a time-based command injection payload using POST.
// It tries the payload directly and also prepended with the original parameter value (or a benign
// default when empty) to handle apps that require a valid prefix before the shell separator.
func (s *CMDiScanner) testTimeBasedPOST(ctx context.Context, baseURL *url.URL, paramName string, payload cmdiPayload, baselineDuration time.Duration, allParameters map[string]string) *CMDiFinding {
	originalValue := allParameters[paramName]
	payloadVariants := buildPrependedPayloads(originalValue, payload.Payload)

	// Determine the expected delay
	expectedDelay := payload.ExpectedDelay
	if expectedDelay == 0 {
		expectedDelay = s.timeBasedDelay
	}

	// Calculate threshold
	tolerance := 1 * time.Second
	minExpectedDuration := baselineDuration + expectedDelay - tolerance

	for _, payloadValue := range payloadVariants {
		// Create form data with ALL parameters
		formData := url.Values{}
		for k, v := range allParameters {
			formData.Set(k, v)
		}
		// Override the parameter being tested with this variant
		formData.Set(paramName, payloadValue)

		// Create the request
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", s.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Apply authentication configuration
		if s.authConfig != nil {
			s.authConfig.ApplyToRequest(req)
		}

		// Measure request time
		startTime := time.Now()
		resp, err := s.client.Do(req)
		requestDuration := time.Since(startTime)

		if err != nil {
			continue
		}

		// Handle rate limiting (HTTP 429)
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			continue
		}

		// Read response body to check for shell errors
		body, err := readResponseBody(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// Check if there are shell errors
		shellErrorFound := false
		var errorMatch string
		for _, pattern := range cmdErrorPatterns {
			if pattern.MatchString(bodyStr) {
				shellErrorFound = true
				errorMatch = pattern.FindString(bodyStr)
				break
			}
		}

		// Check if the request took significantly longer than expected
		if requestDuration >= minExpectedDuration {
			confidence := "high"
			evidenceMsg := fmt.Sprintf("Request took %v (baseline: %v, expected delay: %v) - indicates time-based command injection",
				requestDuration, baselineDuration, expectedDelay)

			// If shell error is also present, mention it in evidence
			if shellErrorFound {
				evidenceMsg += fmt.Sprintf("; Shell error also detected: %s", s.extractEvidence(bodyStr, errorMatch))
				confidence = "high"
			}

			return &CMDiFinding{
				URL:         baseURL.String(),
				Parameter:   paramName,
				Payload:     payloadValue,
				Evidence:    evidenceMsg,
				Severity:    payload.Severity,
				Type:        payload.Type,
				OSType:      payload.OSType,
				Description: payload.Description,
				Remediation: s.getRemediation(),
				Confidence:  confidence,
			}
		}
	}

	return nil
}

// extractEvidence extracts a snippet of the response containing the shell error.
func (s *CMDiScanner) extractEvidence(body, errorMatch string) string {
	if errorMatch == "" {
		return "Shell error detected in response"
	}

	idx := strings.Index(body, errorMatch)
	if idx == -1 {
		return errorMatch
	}

	// Extract context around the error (up to 200 characters)
	start := idx - 30
	if start < 0 {
		start = 0
	}
	end := idx + len(errorMatch) + 30
	if end > len(body) {
		end = len(body)
	}

	snippet := body[start:end]
	// Clean up the snippet
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	snippet = strings.ReplaceAll(snippet, "\t", " ")
	snippet = strings.TrimSpace(snippet)

	return fmt.Sprintf("...%s...", snippet)
}

// getRemediation returns remediation guidance for command injection vulnerabilities.
func (s *CMDiScanner) getRemediation() string {
	return "Use parameterized system calls or avoid passing user input to system commands. " +
		"Implement strict input validation with allowlists. " +
		"Consider using language-specific APIs instead of shell commands. " +
		"If system commands are necessary, use built-in escaping functions and run with minimal privileges. " +
		"Implement proper error handling that doesn't expose system details to users."
}

// calculateSummary calculates the summary statistics for the scan.
func (s *CMDiScanner) calculateSummary(result *CMDiScanResult) {
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
func (r *CMDiScanResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Command Injection Vulnerability Scan for: %s\n", r.Target))
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
			sb.WriteString(fmt.Sprintf("\n  %d. [%s] %s Command Injection (%s)\n", i+1, strings.ToUpper(f.Severity), titleCase(f.Type), f.OSType))
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
		sb.WriteString("\nNo command injection vulnerabilities detected.\n")
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
func (r *CMDiScanResult) HasResults() bool {
	return len(r.Findings) > 0 || r.Summary.TotalTests > 0
}

// VerifyFinding re-tests a command injection finding with payload variants.
func (s *CMDiScanner) VerifyFinding(ctx context.Context, finding *CMDiFinding, config VerificationConfig) (*VerificationResult, error) {
	if finding == nil {
		return nil, fmt.Errorf("finding is nil")
	}

	// Parse the original URL to extract parameters
	parsedURL, err := url.Parse(finding.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL in finding: %w", err)
	}

	// Get baseline for comparison
	baseline, baselineDuration := s.getBaselineWithTiming(ctx, parsedURL, finding.Parameter)
	if baseline == nil {
		return &VerificationResult{
			Verified:    false,
			Attempts:    1,
			Confidence:  0.0,
			Explanation: "Failed to obtain baseline response for verification",
		}, nil
	}

	// Generate payload variants for verification
	variants := s.generateCMDiPayloadVariants(finding.Payload, finding.Type)

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

		// For time-based command injection, measure request duration
		if finding.Type == "time-based" {
			// Create test URL with variant
			testURL := *parsedURL
			q := testURL.Query()
			q.Set(finding.Parameter, variant)
			testURL.RawQuery = q.Encode()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", s.userAgent)
			if s.authConfig != nil {
				s.authConfig.ApplyToRequest(req)
			}

			// Measure request time
			startTime := time.Now()
			resp, err := s.client.Do(req)
			requestDuration := time.Since(startTime)

			if err != nil {
				continue
			}
			resp.Body.Close()

			// Check if request took significantly longer (expected delay is typically 5 seconds)
			expectedDelay := s.timeBasedDelay
			// Use percentage-based tolerance (20% of expected delay) to account for network jitter
			tolerance := time.Duration(float64(expectedDelay) * 0.2)
			if tolerance < 500*time.Millisecond {
				tolerance = 500 * time.Millisecond // Minimum 500ms tolerance
			}
			minExpectedDuration := baselineDuration + expectedDelay - tolerance

			if requestDuration >= minExpectedDuration {
				successCount++
			}
		} else {
			// Test the variant for error-based
			testURL := *parsedURL
			q := testURL.Query()
			q.Set(finding.Parameter, variant)
			testURL.RawQuery = q.Encode()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", s.userAgent)
			if s.authConfig != nil {
				s.authConfig.ApplyToRequest(req)
			}

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}

			body, err := readResponseBody(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			// For error-based command injection, check for shell error patterns
			foundError := false
			for _, pattern := range cmdErrorPatterns {
				if pattern.MatchString(string(body)) {
					foundError = true
					break
				}
			}
			if foundError {
				successCount++
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
	verified := confidence >= 0.5 // At least 50% of variants must succeed

	explanation := fmt.Sprintf("Verified %d out of %d payload variants successfully reproduced the vulnerability",
		successCount, totalAttempts)

	if !verified {
		explanation = fmt.Sprintf("Only %d out of %d payload variants reproduced the vulnerability - likely a false positive or WAF interference",
			successCount, totalAttempts)
	}

	return &VerificationResult{
		Verified:    verified,
		Attempts:    totalAttempts,
		Confidence:  confidence,
		Explanation: explanation,
	}, nil
}

// generateCMDiPayloadVariants creates different encodings and variations of the command injection payload.
func (s *CMDiScanner) generateCMDiPayloadVariants(originalPayload, findingType string) []string {
	variants := make([]string, 0)

	// Add the original payload
	variants = append(variants, originalPayload)

	// Case variations for commands
	if strings.Contains(originalPayload, "sleep") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "sleep", "SLEEP"))
	}
	if strings.Contains(originalPayload, "timeout") {
		variants = append(variants, strings.ReplaceAll(originalPayload, "timeout", "TIMEOUT"))
	}

	// Separator variations
	if strings.HasPrefix(originalPayload, ";") {
		variants = append(variants, strings.Replace(originalPayload, ";", "&&", 1))
		variants = append(variants, strings.Replace(originalPayload, ";", "|", 1))
	}
	if strings.HasPrefix(originalPayload, "&") && !strings.HasPrefix(originalPayload, "&&") {
		variants = append(variants, strings.Replace(originalPayload, "&", ";", 1))
		variants = append(variants, strings.Replace(originalPayload, "&", "|", 1))
	}

	// Different time delays for time-based payloads
	if findingType == "time-based" {
		if strings.Contains(originalPayload, "5") {
			variants = append(variants, strings.ReplaceAll(originalPayload, "5", "6"))
			variants = append(variants, strings.ReplaceAll(originalPayload, "5", "4"))
		}
	}

	// URL encoding variations
	if !strings.Contains(originalPayload, "%") {
		// Add URL-encoded version
		urlEncoded := originalPayload
		urlEncoded = strings.ReplaceAll(urlEncoded, ";", "%3B")
		urlEncoded = strings.ReplaceAll(urlEncoded, "|", "%7C")
		urlEncoded = strings.ReplaceAll(urlEncoded, "&", "%26")
		urlEncoded = strings.ReplaceAll(urlEncoded, " ", "+")
		if urlEncoded != originalPayload {
			variants = append(variants, urlEncoded)
		}
	}

	return variants
}

// stripCMDiPayloadFromBody removes occurrences of the injected CMDi payload
// (and common HTML-encoded / URL-encoded variants) from the response body.
// This prevents reflected input (e.g., an XSS-vulnerable parameter that echoes
// "localhost; cat /etc/passwd" back into the page) from triggering output-based
// CMDi patterns like `root:x:0` or `/etc/passwd`.
//
// Only the payload string itself is stripped — genuine command output that appears
// independently of the reflected payload is preserved so true positives are still
// detected.
func stripCMDiPayloadFromBody(body string, payload string) string {
	if payload == "" {
		return body
	}

	result := body

	// Build a list of strings to strip: the raw payload plus common variants
	toStrip := []string{payload}

	// Add HTML-escaped variant (e.g., &lt; for < , &amp; for &, &#39; for ')
	htmlEscaped := html.EscapeString(payload)
	if htmlEscaped != payload {
		toStrip = append(toStrip, htmlEscaped)
	}

	// Add URL-decoded variant (handles %3A%2F%2F, %20, etc.)
	if decoded, err := url.QueryUnescape(payload); err == nil && decoded != payload {
		toStrip = append(toStrip, decoded)
	}

	// Add URL-encoded variant
	encoded := url.QueryEscape(payload)
	if encoded != payload {
		toStrip = append(toStrip, encoded)
	}

	// Remove all variants (case-insensitive)
	for _, s := range toStrip {
		if s == "" {
			continue
		}
		sLower := strings.ToLower(s)
		idx := 0
		for {
			pos := strings.Index(strings.ToLower(result[idx:]), sLower)
			if pos == -1 {
				break
			}
			result = result[:idx+pos] + result[idx+pos+len(s):]
			// don't advance idx — the replacement may have brought new content to this position
		}
	}

	return result
}
