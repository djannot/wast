// Package output provides formatters for CLI output in JSON, YAML, and text formats.
package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/djannot/wast/pkg/scanner"
)

// SARIF 2.1.0 Schema Implementation
// Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

// SARIFReport represents the root of a SARIF document.
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of the analysis tool.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFToolComponent `json:"driver"`
}

// SARIFToolComponent describes the tool component.
type SARIFToolComponent struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a rule that was evaluated during the analysis.
type SARIFRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription SARIFMessage           `json:"shortDescription,omitempty"`
	FullDescription  SARIFMessage           `json:"fullDescription,omitempty"`
	Help             SARIFMessage           `json:"help,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

// SARIFResult represents a single result from the analysis.
type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex,omitempty"`
	Level      string                 `json:"level"`
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFMessage represents a message string with optional markdown.
type SARIFMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFLocation represents a location where a result was detected.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
}

// SARIFPhysicalLocation represents a physical location in an artifact.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation represents a location in a file or URI.
type SARIFArtifactLocation struct {
	URI   string `json:"uri"`
	Index int    `json:"index,omitempty"`
}

// SARIFRegion represents a region within an artifact.
type SARIFRegion struct {
	StartLine   int                   `json:"startLine,omitempty"`
	StartColumn int                   `json:"startColumn,omitempty"`
	EndLine     int                   `json:"endLine,omitempty"`
	EndColumn   int                   `json:"endColumn,omitempty"`
	Snippet     *SARIFArtifactContent `json:"snippet,omitempty"`
}

// SARIFArtifactContent represents content from an artifact.
type SARIFArtifactContent struct {
	Text string `json:"text,omitempty"`
}

// SARIFInvocation describes a single invocation of the tool.
type SARIFInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

// Rule ID constants for WAST scanners
const (
	RuleIDXSS          = "WAST-XSS-001"
	RuleIDSQLi         = "WAST-SQLI-001"
	RuleIDCMDi         = "WAST-CMDI-001"
	RuleIDCSRF         = "WAST-CSRF-001"
	RuleIDSSRF         = "WAST-SSRF-001"
	RuleIDRedirect     = "WAST-REDIRECT-001"
	RuleIDHeaderHSTS   = "WAST-HDR-001"
	RuleIDHeaderCSP    = "WAST-HDR-002"
	RuleIDHeaderXFrame = "WAST-HDR-003"
	RuleIDHeaderCT     = "WAST-HDR-004"
	RuleIDCookie       = "WAST-COOKIE-001"
	RuleIDCORS         = "WAST-CORS-001"
)

// CWE references for common vulnerabilities
const (
	CWEXSS      = "CWE-79"
	CWESQLi     = "CWE-89"
	CWECMDi     = "CWE-78"
	CWECSRF     = "CWE-352"
	CWESSRF     = "CWE-918"
	CWERedirect = "CWE-601"
	CWEHeaders  = "CWE-693"
	CWECookie   = "CWE-614"
	CWECORS     = "CWE-942"
)

// outputSARIF outputs data as SARIF 2.1.0 format.
func (f *Formatter) outputSARIF(data interface{}) error {
	sarifReport, err := convertToSARIF(data)
	if err != nil {
		return fmt.Errorf("failed to convert to SARIF: %w", err)
	}

	encoder := json.NewEncoder(f.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarifReport)
}

// convertToSARIF converts various scan result types to SARIF format.
func convertToSARIF(data interface{}) (*SARIFReport, error) {
	report := &SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    make([]SARIFRun, 0),
	}

	// Try to convert based on type
	switch v := data.(type) {
	case CommandResult:
		// Extract the actual scan data
		if v.Data != nil {
			return convertToSARIF(v.Data)
		}
		return report, nil

	case map[string]interface{}:
		// Handle generic map (from JSON unmarshaling)
		return convertMapToSARIF(v, report)

	default:
		// Try to convert as CompleteScanResult by re-marshaling
		// This handles the case where we get the actual struct types
		return convertStructToSARIF(data, report)
	}
}

// convertMapToSARIF handles conversion from generic map structures.
func convertMapToSARIF(data map[string]interface{}, report *SARIFReport) (*SARIFReport, error) {
	run := SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFToolComponent{
				Name:            "WAST",
				Version:         "1.0.0",
				SemanticVersion: "1.0.0",
				InformationURI:  "https://github.com/djannot/wast",
				Rules:           buildAllRules(),
			},
		},
		Results: make([]SARIFResult, 0),
		Invocations: []SARIFInvocation{
			{ExecutionSuccessful: true},
		},
	}

	// Process headers if present
	if headers, ok := data["headers"].(map[string]interface{}); ok {
		processHeadersMap(headers, &run)
	}

	// Process XSS if present
	if xss, ok := data["xss"].(map[string]interface{}); ok {
		processXSSMap(xss, &run)
	}

	// Process SQLi if present
	if sqli, ok := data["sqli"].(map[string]interface{}); ok {
		processSQLiMap(sqli, &run)
	}

	// Process CSRF if present
	if csrf, ok := data["csrf"].(map[string]interface{}); ok {
		processCSRFMap(csrf, &run)
	}

	// Process SSRF if present
	if ssrf, ok := data["ssrf"].(map[string]interface{}); ok {
		processSSRFMap(ssrf, &run)
	}

	// Process Redirect if present
	if redirect, ok := data["redirect"].(map[string]interface{}); ok {
		processRedirectMap(redirect, &run)
	}

	// Process CMDi if present
	if cmdi, ok := data["cmdi"].(map[string]interface{}); ok {
		processCMDiMap(cmdi, &run)
	}

	report.Runs = append(report.Runs, run)
	return report, nil
}

// convertStructToSARIF handles conversion from actual struct types.
func convertStructToSARIF(data interface{}, report *SARIFReport) (*SARIFReport, error) {
	// Marshal and unmarshal to convert to map
	jsonData, err := json.Marshal(data)
	if err != nil {
		return report, err
	}

	var dataMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &dataMap); err != nil {
		return report, err
	}

	return convertMapToSARIF(dataMap, report)
}

// buildAllRules creates the complete set of SARIF rules for WAST.
func buildAllRules() []SARIFRule {
	return []SARIFRule{
		{
			ID:   RuleIDXSS,
			Name: "CrossSiteScripting",
			ShortDescription: SARIFMessage{
				Text: "Cross-Site Scripting (XSS) vulnerability detected",
			},
			FullDescription: SARIFMessage{
				Text: "The application reflects user input in the response without proper encoding or validation, allowing arbitrary JavaScript execution.",
			},
			Help: SARIFMessage{
				Text:     "Implement proper output encoding/escaping for all user input. Use context-aware encoding (HTML, JavaScript, URL, CSS). Consider implementing Content Security Policy (CSP) headers.",
				Markdown: "**Remediation:** Implement proper output encoding/escaping for all user input. Use context-aware encoding (HTML, JavaScript, URL, CSS). Consider implementing Content Security Policy (CSP) headers.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEXSS, "security", "xss"},
			},
		},
		{
			ID:   RuleIDSQLi,
			Name: "SQLInjection",
			ShortDescription: SARIFMessage{
				Text: "SQL Injection vulnerability detected",
			},
			FullDescription: SARIFMessage{
				Text: "The application constructs SQL queries using unsanitized user input, allowing attackers to manipulate database queries.",
			},
			Help: SARIFMessage{
				Text:     "Use parameterized queries or prepared statements. Implement input validation and sanitization. Apply the principle of least privilege for database accounts.",
				Markdown: "**Remediation:** Use parameterized queries or prepared statements. Implement input validation and sanitization. Apply the principle of least privilege for database accounts.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWESQLi, "security", "sqli", "injection"},
			},
		},
		{
			ID:   RuleIDCMDi,
			Name: "CommandInjection",
			ShortDescription: SARIFMessage{
				Text: "Command Injection vulnerability detected",
			},
			FullDescription: SARIFMessage{
				Text: "The application executes OS commands using unsanitized user input, allowing attackers to execute arbitrary commands on the server.",
			},
			Help: SARIFMessage{
				Text:     "Use parameterized system calls or avoid passing user input to system commands. Implement strict input validation with allowlists. Consider using language-specific APIs instead of shell commands.",
				Markdown: "**Remediation:** Use parameterized system calls or avoid passing user input to system commands. Implement strict input validation with allowlists. Consider using language-specific APIs instead of shell commands. If system commands are necessary, use built-in escaping functions and run with minimal privileges.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWECMDi, "security", "cmdi", "injection", "os-command"},
			},
		},
		{
			ID:   RuleIDCSRF,
			Name: "CrossSiteRequestForgery",
			ShortDescription: SARIFMessage{
				Text: "Cross-Site Request Forgery (CSRF) vulnerability detected",
			},
			FullDescription: SARIFMessage{
				Text: "The application does not properly validate the origin of requests, allowing attackers to forge requests from authenticated users.",
			},
			Help: SARIFMessage{
				Text:     "Implement anti-CSRF tokens for all state-changing operations. Use SameSite cookie attribute. Validate Origin and Referer headers.",
				Markdown: "**Remediation:** Implement anti-CSRF tokens for all state-changing operations. Use SameSite cookie attribute. Validate Origin and Referer headers.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWECSRF, "security", "csrf"},
			},
		},
		{
			ID:   RuleIDSSRF,
			Name: "ServerSideRequestForgery",
			ShortDescription: SARIFMessage{
				Text: "Server-Side Request Forgery (SSRF) vulnerability detected",
			},
			FullDescription: SARIFMessage{
				Text: "The application allows user-controlled input to specify URLs for server-side requests, potentially enabling access to internal resources, cloud metadata endpoints (AWS, GCP, Azure, Kubernetes), or local files.",
			},
			Help: SARIFMessage{
				Text:     "Implement strict URL validation and sanitization. Use an allowlist of permitted domains/IPs. Block access to private IP ranges and Kubernetes service endpoints. Disable support for dangerous URL schemes.",
				Markdown: "**Remediation:** Implement strict URL validation and sanitization. Use an allowlist of permitted domains/IPs. Block access to private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, 169.254.x.x). Block access to Kubernetes API endpoints (kubernetes.default.svc, kubernetes.default.svc.cluster.local). Disable support for unnecessary URL schemes (file://, dict://, gopher://, etc.). Implement network segmentation to prevent access to internal services.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWESSRF, "security", "ssrf", "injection"},
			},
		},
		{
			ID:   RuleIDRedirect,
			Name: "OpenRedirect",
			ShortDescription: SARIFMessage{
				Text: "Open Redirect vulnerability detected",
			},
			FullDescription: SARIFMessage{
				Text: "The application redirects users to URLs specified in user-controlled parameters without proper validation, enabling phishing attacks and authentication bypass via protocol-relative URLs, @ symbol bypass, encoded payloads, or subdomain confusion.",
			},
			Help: SARIFMessage{
				Text:     "Implement strict URL validation before redirecting. Use an allowlist of permitted redirect destinations. Validate that redirect URLs are relative paths or belong to trusted domains. Avoid using user input directly in redirect operations.",
				Markdown: "**Remediation:** Implement strict URL validation before redirecting. Use an allowlist of permitted redirect destinations. Validate that redirect URLs are relative paths (not absolute URLs) or belong to trusted domains. If absolute URLs are required, validate the protocol (http/https only), domain (against allowlist), and path. Use indirect reference maps (e.g., redirect to /page?id=123 where 123 maps to a safe URL server-side). Implement CSRF tokens for any redirect functionality. Consider using the Referrer-Policy header to control referrer information leakage.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWERedirect, "security", "redirect", "phishing"},
			},
		},
		{
			ID:   RuleIDHeaderHSTS,
			Name: "MissingHSTSHeader",
			ShortDescription: SARIFMessage{
				Text: "Missing Strict-Transport-Security header",
			},
			FullDescription: SARIFMessage{
				Text: "The Strict-Transport-Security header is not set, allowing potential downgrade attacks and man-in-the-middle attacks.",
			},
			Help: SARIFMessage{
				Text:     "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
				Markdown: "**Remediation:** Add header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEHeaders, "security", "headers", "hsts"},
			},
		},
		{
			ID:   RuleIDHeaderCSP,
			Name: "MissingCSPHeader",
			ShortDescription: SARIFMessage{
				Text: "Missing Content-Security-Policy header",
			},
			FullDescription: SARIFMessage{
				Text: "The Content-Security-Policy header is not set, which could allow XSS attacks and other content injection vulnerabilities.",
			},
			Help: SARIFMessage{
				Text:     "Add a Content-Security-Policy header with appropriate directives",
				Markdown: "**Remediation:** Add a Content-Security-Policy header with appropriate directives for your application's needs.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEHeaders, "security", "headers", "csp"},
			},
		},
		{
			ID:   RuleIDHeaderXFrame,
			Name: "MissingXFrameOptionsHeader",
			ShortDescription: SARIFMessage{
				Text: "Missing X-Frame-Options header",
			},
			FullDescription: SARIFMessage{
				Text: "The X-Frame-Options header is not set, potentially allowing clickjacking attacks through iframe embedding.",
			},
			Help: SARIFMessage{
				Text:     "Add header: X-Frame-Options: DENY or SAMEORIGIN",
				Markdown: "**Remediation:** Add header: `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEHeaders, "security", "headers", "clickjacking"},
			},
		},
		{
			ID:   RuleIDHeaderCT,
			Name: "MissingContentTypeOptionsHeader",
			ShortDescription: SARIFMessage{
				Text: "Missing X-Content-Type-Options header",
			},
			FullDescription: SARIFMessage{
				Text: "The X-Content-Type-Options header is not set, allowing MIME type sniffing which can lead to security vulnerabilities.",
			},
			Help: SARIFMessage{
				Text:     "Add header: X-Content-Type-Options: nosniff",
				Markdown: "**Remediation:** Add header: `X-Content-Type-Options: nosniff`",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEHeaders, "security", "headers"},
			},
		},
		{
			ID:   RuleIDCookie,
			Name: "InsecureCookie",
			ShortDescription: SARIFMessage{
				Text: "Cookie missing security attributes",
			},
			FullDescription: SARIFMessage{
				Text: "One or more cookies are missing security attributes (HttpOnly, Secure, SameSite), making them vulnerable to various attacks.",
			},
			Help: SARIFMessage{
				Text:     "Set all security attributes: HttpOnly, Secure, and SameSite=Strict or Lax",
				Markdown: "**Remediation:** Set all security attributes: `HttpOnly`, `Secure`, and `SameSite=Strict` or `SameSite=Lax`",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWECookie, "security", "cookie"},
			},
		},
		{
			ID:   RuleIDCORS,
			Name: "InsecureCORSPolicy",
			ShortDescription: SARIFMessage{
				Text: "Insecure CORS policy detected",
			},
			FullDescription: SARIFMessage{
				Text: "The CORS policy is overly permissive, potentially allowing unauthorized cross-origin requests.",
			},
			Help: SARIFMessage{
				Text:     "Restrict CORS to specific trusted origins. Validate Origin header. Avoid using wildcard with credentials.",
				Markdown: "**Remediation:** Restrict CORS to specific trusted origins. Validate Origin header. Avoid using wildcard (*) with credentials.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWECORS, "security", "cors"},
			},
		},
	}
}

// Helper functions to process different scan result types

func processHeadersMap(headers map[string]interface{}, run *SARIFRun) {
	target := getStringValue(headers, "target")

	// Process header findings
	if headersList, ok := headers["headers"].([]interface{}); ok {
		for _, h := range headersList {
			if header, ok := h.(map[string]interface{}); ok {
				if !getBoolValue(header, "present") {
					result := createHeaderResult(header, target)
					if result != nil {
						run.Results = append(run.Results, *result)
					}
				}
			}
		}
	}

	// Process cookie findings
	if cookiesList, ok := headers["cookies"].([]interface{}); ok {
		for _, c := range cookiesList {
			if cookie, ok := c.(map[string]interface{}); ok {
				issues := getStringArrayValue(cookie, "issues")
				if len(issues) > 0 {
					result := createCookieResult(cookie, target)
					if result != nil {
						run.Results = append(run.Results, *result)
					}
				}
			}
		}
	}

	// Process CORS findings
	if corsList, ok := headers["cors"].([]interface{}); ok {
		for _, c := range corsList {
			if cors, ok := c.(map[string]interface{}); ok {
				issues := getStringArrayValue(cors, "issues")
				if len(issues) > 0 {
					result := createCORSResult(cors, target)
					if result != nil {
						run.Results = append(run.Results, *result)
					}
				}
			}
		}
	}
}

func processXSSMap(xss map[string]interface{}, run *SARIFRun) {
	target := getStringValue(xss, "target")

	if findings, ok := xss["findings"].([]interface{}); ok {
		for _, f := range findings {
			if finding, ok := f.(map[string]interface{}); ok {
				result := createXSSResult(finding, target)
				if result != nil {
					run.Results = append(run.Results, *result)
				}
			}
		}
	}
}

func processSQLiMap(sqli map[string]interface{}, run *SARIFRun) {
	target := getStringValue(sqli, "target")

	if findings, ok := sqli["findings"].([]interface{}); ok {
		for _, f := range findings {
			if finding, ok := f.(map[string]interface{}); ok {
				result := createSQLiResult(finding, target)
				if result != nil {
					run.Results = append(run.Results, *result)
				}
			}
		}
	}
}

func processCSRFMap(csrf map[string]interface{}, run *SARIFRun) {
	if findings, ok := csrf["findings"].([]interface{}); ok {
		for _, f := range findings {
			if finding, ok := f.(map[string]interface{}); ok {
				result := createCSRFResult(finding)
				if result != nil {
					run.Results = append(run.Results, *result)
				}
			}
		}
	}
}

func processSSRFMap(ssrf map[string]interface{}, run *SARIFRun) {
	if findings, ok := ssrf["findings"].([]interface{}); ok {
		for _, f := range findings {
			if finding, ok := f.(map[string]interface{}); ok {
				result := createSSRFResult(finding)
				if result != nil {
					run.Results = append(run.Results, *result)
				}
			}
		}
	}
}

func processRedirectMap(redirect map[string]interface{}, run *SARIFRun) {
	if findings, ok := redirect["findings"].([]interface{}); ok {
		for _, f := range findings {
			if finding, ok := f.(map[string]interface{}); ok {
				result := createRedirectResult(finding)
				if result != nil {
					run.Results = append(run.Results, *result)
				}
			}
		}
	}
}

func processCMDiMap(cmdi map[string]interface{}, run *SARIFRun) {
	if findings, ok := cmdi["findings"].([]interface{}); ok {
		for _, f := range findings {
			if finding, ok := f.(map[string]interface{}); ok {
				result := createCMDiResult(finding)
				if result != nil {
					run.Results = append(run.Results, *result)
				}
			}
		}
	}
}

// Result creation functions

func createHeaderResult(header map[string]interface{}, target string) *SARIFResult {
	name := getStringValue(header, "name")
	severity := getStringValue(header, "severity")
	description := getStringValue(header, "description")
	remediation := getStringValue(header, "remediation")

	ruleID := getRuleIDForHeader(name)

	return &SARIFResult{
		RuleID:    ruleID,
		RuleIndex: getRuleIndex(ruleID),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("Missing security header: %s - %s", name, description),
			Markdown: fmt.Sprintf("**Missing security header:** `%s`\n\n%s\n\n%s", name, description, remediation),
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: target,
					},
				},
			},
		},
		Properties: map[string]interface{}{
			"header": name,
		},
	}
}

func createCookieResult(cookie map[string]interface{}, target string) *SARIFResult {
	name := getStringValue(cookie, "name")
	severity := getStringValue(cookie, "severity")
	issues := getStringArrayValue(cookie, "issues")
	remediation := getStringValue(cookie, "remediation")

	issuesText := ""
	for i, issue := range issues {
		if i > 0 {
			issuesText += "; "
		}
		issuesText += issue
	}

	return &SARIFResult{
		RuleID:    RuleIDCookie,
		RuleIndex: getRuleIndex(RuleIDCookie),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("Insecure cookie: %s - %s", name, issuesText),
			Markdown: fmt.Sprintf("**Insecure cookie:** `%s`\n\nIssues:\n- %s\n\n%s", name, strings.Join(issues, "\n- "), remediation),
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: target,
					},
				},
			},
		},
		Properties: map[string]interface{}{
			"cookie":   name,
			"httpOnly": getBoolValue(cookie, "http_only"),
			"secure":   getBoolValue(cookie, "secure"),
			"sameSite": getStringValue(cookie, "same_site"),
		},
	}
}

func createCORSResult(cors map[string]interface{}, target string) *SARIFResult {
	header := getStringValue(cors, "header")
	value := getStringValue(cors, "value")
	severity := getStringValue(cors, "severity")
	description := getStringValue(cors, "description")
	issues := getStringArrayValue(cors, "issues")
	remediation := getStringValue(cors, "remediation")

	issuesText := ""
	for i, issue := range issues {
		if i > 0 {
			issuesText += "; "
		}
		issuesText += issue
	}

	messageText := fmt.Sprintf("Insecure CORS policy: %s - %s", header, issuesText)
	if value != "" {
		messageText = fmt.Sprintf("Insecure CORS policy: %s=%s - %s", header, value, issuesText)
	}

	return &SARIFResult{
		RuleID:    RuleIDCORS,
		RuleIndex: getRuleIndex(RuleIDCORS),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     messageText,
			Markdown: fmt.Sprintf("**Insecure CORS policy:** `%s`\n\n%s\n\nIssues:\n- %s\n\n%s", header, description, strings.Join(issues, "\n- "), remediation),
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: target,
					},
				},
			},
		},
		Properties: map[string]interface{}{
			"header": header,
			"value":  value,
		},
	}
}

func createXSSResult(finding map[string]interface{}, target string) *SARIFResult {
	url := getStringValue(finding, "url")
	parameter := getStringValue(finding, "parameter")
	payload := getStringValue(finding, "payload")
	evidence := getStringValue(finding, "evidence")
	severity := getStringValue(finding, "severity")
	xssType := getStringValue(finding, "type")
	description := getStringValue(finding, "description")
	remediation := getStringValue(finding, "remediation")
	confidence := getStringValue(finding, "confidence")

	return &SARIFResult{
		RuleID:    RuleIDXSS,
		RuleIndex: getRuleIndex(RuleIDXSS),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("XSS vulnerability in parameter '%s': %s", parameter, description),
			Markdown: fmt.Sprintf("**XSS Vulnerability (%s)**\n\nParameter: `%s`\n\n%s\n\n**Evidence:** `%s`\n\n**Remediation:** %s", xssType, parameter, description, evidence, remediation),
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: url,
					},
				},
			},
		},
		Properties: map[string]interface{}{
			"parameter":  parameter,
			"payload":    payload,
			"type":       xssType,
			"confidence": confidence,
		},
	}
}

func createSQLiResult(finding map[string]interface{}, target string) *SARIFResult {
	url := getStringValue(finding, "url")
	parameter := getStringValue(finding, "parameter")
	payload := getStringValue(finding, "payload")
	evidence := getStringValue(finding, "evidence")
	severity := getStringValue(finding, "severity")
	sqliType := getStringValue(finding, "type")
	description := getStringValue(finding, "description")
	remediation := getStringValue(finding, "remediation")
	confidence := getStringValue(finding, "confidence")

	return &SARIFResult{
		RuleID:    RuleIDSQLi,
		RuleIndex: getRuleIndex(RuleIDSQLi),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("SQL Injection vulnerability in parameter '%s': %s", parameter, description),
			Markdown: fmt.Sprintf("**SQL Injection (%s)**\n\nParameter: `%s`\n\n%s\n\n**Evidence:** `%s`\n\n**Remediation:** %s", sqliType, parameter, description, evidence, remediation),
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: url,
					},
				},
			},
		},
		Properties: map[string]interface{}{
			"parameter":  parameter,
			"payload":    payload,
			"type":       sqliType,
			"confidence": confidence,
		},
	}
}

func createCSRFResult(finding map[string]interface{}) *SARIFResult {
	formAction := getStringValue(finding, "form_action")
	formMethod := getStringValue(finding, "form_method")
	formPage := getStringValue(finding, "form_page")
	csrfType := getStringValue(finding, "type")
	severity := getStringValue(finding, "severity")
	description := getStringValue(finding, "description")
	remediation := getStringValue(finding, "remediation")

	uri := formAction
	if uri == "" {
		uri = formPage
	}

	return &SARIFResult{
		RuleID:    RuleIDCSRF,
		RuleIndex: getRuleIndex(RuleIDCSRF),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("CSRF vulnerability in form: %s - %s", formAction, description),
			Markdown: fmt.Sprintf("**CSRF Vulnerability**\n\nForm: `%s %s`\n\n%s\n\n**Remediation:** %s", formMethod, formAction, description, remediation),
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: uri,
					},
				},
			},
		},
		Properties: map[string]interface{}{
			"formAction": formAction,
			"formMethod": formMethod,
			"type":       csrfType,
		},
	}
}

func createSSRFResult(finding map[string]interface{}) *SARIFResult {
	url := getStringValue(finding, "url")
	parameter := getStringValue(finding, "parameter")
	payload := getStringValue(finding, "payload")
	ssrfType := getStringValue(finding, "type")
	severity := getStringValue(finding, "severity")
	description := getStringValue(finding, "description")
	remediation := getStringValue(finding, "remediation")
	evidence := getStringValue(finding, "evidence")
	confidence := getStringValue(finding, "confidence")

	return &SARIFResult{
		RuleID:    RuleIDSSRF,
		RuleIndex: getRuleIndex(RuleIDSSRF),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("SSRF vulnerability in parameter '%s': %s", parameter, description),
			Markdown: fmt.Sprintf("**SSRF Vulnerability**\n\nParameter: `%s`\nPayload: `%s`\n\n%s\n\nEvidence: %s\n\n**Remediation:** %s", parameter, payload, description, evidence, remediation),
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: url,
					},
				},
			},
		},
		Properties: map[string]interface{}{
			"parameter":  parameter,
			"payload":    payload,
			"type":       ssrfType,
			"confidence": confidence,
		},
	}
}

func createRedirectResult(finding map[string]interface{}) *SARIFResult {
	url := getStringValue(finding, "url")
	parameter := getStringValue(finding, "parameter")
	payload := getStringValue(finding, "payload")
	redirectType := getStringValue(finding, "type")
	severity := getStringValue(finding, "severity")
	description := getStringValue(finding, "description")
	remediation := getStringValue(finding, "remediation")
	evidence := getStringValue(finding, "evidence")
	confidence := getStringValue(finding, "confidence")

	return &SARIFResult{
		RuleID:    RuleIDRedirect,
		RuleIndex: getRuleIndex(RuleIDRedirect),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("Open Redirect vulnerability in parameter '%s': %s", parameter, description),
			Markdown: fmt.Sprintf("**Open Redirect Vulnerability (%s)**\n\nParameter: `%s`\nPayload: `%s`\n\n%s\n\nEvidence: %s\n\n**Remediation:** %s", redirectType, parameter, payload, description, evidence, remediation),
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: url,
					},
				},
			},
		},
		Properties: map[string]interface{}{
			"parameter":  parameter,
			"payload":    payload,
			"type":       redirectType,
			"confidence": confidence,
		},
	}
}

func createCMDiResult(finding map[string]interface{}) *SARIFResult {
	url := getStringValue(finding, "url")
	parameter := getStringValue(finding, "parameter")
	payload := getStringValue(finding, "payload")
	cmdiType := getStringValue(finding, "type")
	osType := getStringValue(finding, "os_type")
	severity := getStringValue(finding, "severity")
	description := getStringValue(finding, "description")
	remediation := getStringValue(finding, "remediation")
	evidence := getStringValue(finding, "evidence")
	confidence := getStringValue(finding, "confidence")

	return &SARIFResult{
		RuleID:    RuleIDCMDi,
		RuleIndex: getRuleIndex(RuleIDCMDi),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("Command Injection vulnerability in parameter '%s': %s", parameter, description),
			Markdown: fmt.Sprintf("**Command Injection (%s on %s)**\n\nParameter: `%s`\nPayload: `%s`\n\n%s\n\nEvidence: %s\n\n**Remediation:** %s", cmdiType, osType, parameter, payload, description, evidence, remediation),
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: url,
					},
				},
			},
		},
		Properties: map[string]interface{}{
			"parameter":  parameter,
			"payload":    payload,
			"type":       cmdiType,
			"osType":     osType,
			"confidence": confidence,
		},
	}
}

// Helper functions for severity mapping and rule lookups

func mapSeverityToLevel(severity string) string {
	switch severity {
	case scanner.SeverityHigh:
		return "error"
	case scanner.SeverityMedium:
		return "warning"
	case scanner.SeverityLow, scanner.SeverityInfo:
		return "note"
	default:
		return "note"
	}
}

func getRuleIDForHeader(headerName string) string {
	switch headerName {
	case "Strict-Transport-Security":
		return RuleIDHeaderHSTS
	case "Content-Security-Policy":
		return RuleIDHeaderCSP
	case "X-Frame-Options":
		return RuleIDHeaderXFrame
	case "X-Content-Type-Options":
		return RuleIDHeaderCT
	default:
		return RuleIDHeaderHSTS // Default fallback
	}
}

func getRuleIndex(ruleID string) int {
	rules := []string{
		RuleIDXSS,
		RuleIDSQLi,
		RuleIDCMDi,
		RuleIDCSRF,
		RuleIDSSRF,
		RuleIDRedirect,
		RuleIDHeaderHSTS,
		RuleIDHeaderCSP,
		RuleIDHeaderXFrame,
		RuleIDHeaderCT,
		RuleIDCookie,
		RuleIDCORS,
	}

	for i, r := range rules {
		if r == ruleID {
			return i
		}
	}
	return 0
}

// Utility functions for extracting values from maps

func getStringValue(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getBoolValue(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func getStringArrayValue(m map[string]interface{}, key string) []string {
	result := make([]string, 0)
	if v, ok := m[key]; ok {
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
		}
	}
	return result
}
