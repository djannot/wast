// Package output provides formatters for CLI output in JSON, YAML, and text formats.
package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/djannot/wast/pkg/mcpscan"
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
	RuleIDNoSQLi       = "WAST-NOSQLI-001"
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
	RuleIDLFI          = "WAST-LFI-001"
	RuleIDSSTI         = "WAST-SSTI-001"
	RuleIDXXE          = "WAST-XXE-001"
	RuleIDWSInsecure   = "WAST-WS-001"
	RuleIDWSOrigin     = "WAST-WS-002"
)

// MCP scan rule ID constants
const (
	RuleIDMCPSchema      = "WAST-MCP-SCHEMA-001"
	RuleIDMCPPrompt      = "WAST-MCP-PROMPT-001"
	RuleIDMCPPermissions = "WAST-MCP-PERMISSIONS-001"
	RuleIDMCPShadowing   = "WAST-MCP-SHADOW-001"
	RuleIDMCPInjection   = "WAST-MCP-INJECT-001"
	RuleIDMCPExposure    = "WAST-MCP-EXPOSURE-001"
	RuleIDMCPSSRF        = "WAST-MCP-SSRF-001"
	RuleIDMCPAuth        = "WAST-MCP-AUTH-001"
	RuleIDMCPDependency  = "WAST-MCP-DEP-001"
)

// CWE references for MCP scan vulnerabilities
const (
	CWEMCPPrompt      = "CWE-94"   // Code Injection (prompt injection)
	CWEMCPInjection   = "CWE-74"   // Injection
	CWEMCPExposure    = "CWE-200"  // Information Exposure
	CWEMCPSSRFVal     = "CWE-918"  // Server-Side Request Forgery
	CWEMCPAuth        = "CWE-287"  // Improper Authentication
	CWEMCPPermissions = "CWE-269"  // Improper Privilege Management
	CWEMCPShadowing   = "CWE-349"  // Acceptance of Extraneous Untrusted Data
	CWEMCPDependency  = "CWE-1104" // Use of Unmaintained Third Party Components
)

// CWE references for common vulnerabilities
const (
	CWEXSS        = "CWE-79"
	CWESQLi       = "CWE-89"
	CWENoSQLi     = "CWE-943"
	CWECMDi       = "CWE-78"
	CWECSRF       = "CWE-352"
	CWESSRF       = "CWE-918"
	CWERedirect   = "CWE-601"
	CWEHeaders    = "CWE-693"
	CWECookie     = "CWE-614"
	CWECORS       = "CWE-942"
	CWELFI        = "CWE-22"
	CWESSTI       = "CWE-94"
	CWEXXE        = "CWE-611"
	CWEWSInsecure = "CWE-319"
	CWEWSOrigin   = "CWE-346"
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

	case *mcpscan.MCPScanResult:
		return convertMCPScanResultToSARIF(v, report)

	case mcpscan.MCPScanResult:
		return convertMCPScanResultToSARIF(&v, report)

	case mcpscan.BulkScanResult:
		return convertMCPBulkScanResultToSARIF(v, report)

	case *mcpscan.BulkScanResult:
		return convertMCPBulkScanResultToSARIF(*v, report)

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

	// Process NoSQLi if present
	if nosqli, ok := data["nosqli"].(map[string]interface{}); ok {
		processNoSQLiMap(nosqli, &run)
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

	// Process PathTraversal if present
	if pathtraversal, ok := data["pathtraversal"].(map[string]interface{}); ok {
		processPathTraversalMap(pathtraversal, &run)
	}

	// Process SSTI if present
	if ssti, ok := data["ssti"].(map[string]interface{}); ok {
		processSSTIMap(ssti, &run)
	}

	// Process XXE if present
	if xxe, ok := data["xxe"].(map[string]interface{}); ok {
		processXXEMap(xxe, &run)
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
			ID:   RuleIDNoSQLi,
			Name: "NoSQLInjection",
			ShortDescription: SARIFMessage{
				Text: "NoSQL Injection vulnerability detected",
			},
			FullDescription: SARIFMessage{
				Text: "The application constructs NoSQL queries using unsanitized user input, allowing attackers to manipulate database queries via operator injection, JavaScript injection, or array parameter pollution.",
			},
			Help: SARIFMessage{
				Text:     "Validate and sanitize all user input before using it in NoSQL queries. Use parameterized queries or ODM/ORM abstractions that prevent operator injection. Disable JavaScript execution in MongoDB ($where, $function) if not required. Apply strict schema validation to reject unexpected operators.",
				Markdown: "**Remediation:** Validate and sanitize all user input before using it in NoSQL queries. Use parameterized queries or ODM/ORM abstractions that prevent operator injection. Disable JavaScript execution in MongoDB (`$where`, `$function`) if not required. Apply strict schema validation (e.g., JSON Schema) to reject unexpected operators.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWENoSQLi, "security", "nosqli", "injection", "nosql"},
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
		{
			ID:   RuleIDLFI,
			Name: "PathTraversal",
			ShortDescription: SARIFMessage{
				Text: "Path Traversal / Local File Inclusion (LFI) vulnerability detected",
			},
			FullDescription: SARIFMessage{
				Text: "The application allows user-controlled input to specify file paths without proper validation, enabling attackers to access files outside the intended directory structure. This can lead to disclosure of sensitive files like /etc/passwd, /etc/shadow, or Windows system files.",
			},
			Help: SARIFMessage{
				Text:     "Implement strict input validation for file path parameters. Use allowlists for permitted files. Avoid using user input directly in file operations. Use indirect references and realpath() to validate canonical paths.",
				Markdown: "**Remediation:** Implement strict input validation for file path parameters. Use allowlists for permitted files/directories. Avoid using user input directly in file system operations. Use indirect references (e.g., file IDs mapped to paths server-side). Sanitize input by removing directory traversal sequences (../, ..\\ and encoded variants). Use built-in security functions like realpath() to resolve canonical paths and verify they stay within allowed directories. Implement proper file system permissions.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWELFI, "security", "lfi", "path-traversal", "file-inclusion"},
			},
		},
		{
			ID:   RuleIDSSTI,
			Name: "ServerSideTemplateInjection",
			ShortDescription: SARIFMessage{
				Text: "Server-Side Template Injection (SSTI) vulnerability detected",
			},
			FullDescription: SARIFMessage{
				Text: "The application passes user-controlled input to template engines without proper sanitization, allowing attackers to inject malicious template code. This can lead to Remote Code Execution (RCE), information disclosure, and complete system compromise. Common vulnerable engines include Jinja2, Twig, Freemarker, Thymeleaf, Velocity, and ERB.",
			},
			Help: SARIFMessage{
				Text:     "Avoid passing user input directly to template engines. Use sandboxed template environments. Implement strict input validation. Consider using logic-less template engines.",
				Markdown: "**Remediation:** Avoid passing user input directly to template engines. If dynamic templating is required, use a sandboxed environment with strict controls. Implement input validation and use template engines in 'safe mode' if available. Consider using logic-less templates (e.g., Mustache) that don't allow code execution. Never allow users to control template selection or content. Use Content Security Policy (CSP) headers as defense in depth. Validate and sanitize all template-related parameters server-side.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWESSTI, "security", "ssti", "template-injection", "rce"},
			},
		},
		{
			ID:   RuleIDXXE,
			Name: "XMLExternalEntityInjection",
			ShortDescription: SARIFMessage{
				Text: "XML External Entity (XXE) vulnerability detected",
			},
			FullDescription: SARIFMessage{
				Text: "The application processes XML input without disabling external entity resolution, allowing attackers to read local files, perform SSRF attacks, cause denial of service, or execute remote code. XXE vulnerabilities are particularly dangerous in SOAP services, XML-RPC, and REST APIs that accept XML payloads.",
			},
			Help: SARIFMessage{
				Text:     "Disable XML external entity processing in your XML parser. Configure the parser to disallow DOCTYPE declarations and external entity references.",
				Markdown: "**Remediation:** Disable XML external entity and DTD processing in your XML parser. For most parsers, set features like `XMLConstants.FEATURE_SECURE_PROCESSING`, disable `DOCTYPE` declarations, and disable external general/parameter entities. Use simple data formats like JSON when possible instead of XML. If XML is required, validate against a strict XML schema (XSD). Implement allowlisting for acceptable values. Keep XML processing libraries up to date with security patches.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEXXE, "security", "xxe", "xml", "injection", "file-disclosure"},
			},
		},
		{
			ID:   RuleIDWSInsecure,
			Name: "InsecureWebSocketProtocol",
			ShortDescription: SARIFMessage{
				Text: "Insecure WebSocket Protocol (ws://) detected",
			},
			FullDescription: SARIFMessage{
				Text: "WebSocket endpoint uses insecure ws:// protocol instead of wss://, allowing traffic interception and manipulation.",
			},
			Help: SARIFMessage{
				Text:     "Use wss:// (WebSocket Secure) instead of ws:// to encrypt WebSocket traffic over TLS.",
				Markdown: "**Remediation:** Use `wss://` (WebSocket Secure) instead of `ws://` to encrypt WebSocket traffic over TLS.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEWSInsecure, "security", "websocket", "cleartext"},
			},
		},
		{
			ID:   RuleIDWSOrigin,
			Name: "MissingWebSocketOriginValidation",
			ShortDescription: SARIFMessage{
				Text: "Missing WebSocket Origin header validation",
			},
			FullDescription: SARIFMessage{
				Text: "WebSocket endpoint does not validate Origin header, allowing Cross-Site WebSocket Hijacking (CSWSH) attacks.",
			},
			Help: SARIFMessage{
				Text:     "Implement server-side Origin header validation to only allow connections from trusted origins.",
				Markdown: "**Remediation:** Implement server-side Origin header validation to only allow connections from trusted origins. Maintain an allowlist of permitted origins.",
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEWSOrigin, "security", "websocket", "origin-validation"},
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

func processNoSQLiMap(nosqli map[string]interface{}, run *SARIFRun) {
	target := getStringValue(nosqli, "target")

	if findings, ok := nosqli["findings"].([]interface{}); ok {
		for _, f := range findings {
			if finding, ok := f.(map[string]interface{}); ok {
				result := createNoSQLiResult(finding, target)
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

func processPathTraversalMap(pathtraversal map[string]interface{}, run *SARIFRun) {
	if findings, ok := pathtraversal["findings"].([]interface{}); ok {
		for _, f := range findings {
			if finding, ok := f.(map[string]interface{}); ok {
				result := createPathTraversalResult(finding)
				if result != nil {
					run.Results = append(run.Results, *result)
				}
			}
		}
	}
}

func processSSTIMap(ssti map[string]interface{}, run *SARIFRun) {
	if findings, ok := ssti["findings"].([]interface{}); ok {
		for _, f := range findings {
			if finding, ok := f.(map[string]interface{}); ok {
				result := createSSTIResult(finding)
				if result != nil {
					run.Results = append(run.Results, *result)
				}
			}
		}
	}
}

func processXXEMap(xxe map[string]interface{}, run *SARIFRun) {
	if findings, ok := xxe["findings"].([]interface{}); ok {
		for _, f := range findings {
			if finding, ok := f.(map[string]interface{}); ok {
				result := createXXEResult(finding)
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

func createNoSQLiResult(finding map[string]interface{}, target string) *SARIFResult {
	url := getStringValue(finding, "url")
	parameter := getStringValue(finding, "parameter")
	payload := getStringValue(finding, "payload")
	evidence := getStringValue(finding, "evidence")
	severity := getStringValue(finding, "severity")
	nosqliType := getStringValue(finding, "type")
	description := getStringValue(finding, "description")
	remediation := getStringValue(finding, "remediation")
	confidence := getStringValue(finding, "confidence")

	return &SARIFResult{
		RuleID:    RuleIDNoSQLi,
		RuleIndex: getRuleIndex(RuleIDNoSQLi),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("NoSQL Injection vulnerability in parameter '%s': %s", parameter, description),
			Markdown: fmt.Sprintf("**NoSQL Injection (%s)**\n\nParameter: `%s`\n\n%s\n\n**Evidence:** `%s`\n\n**Remediation:** %s", nosqliType, parameter, description, evidence, remediation),
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
			"type":       nosqliType,
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

func createPathTraversalResult(finding map[string]interface{}) *SARIFResult {
	url := getStringValue(finding, "url")
	parameter := getStringValue(finding, "parameter")
	payload := getStringValue(finding, "payload")
	lfiType := getStringValue(finding, "type")
	severity := getStringValue(finding, "severity")
	description := getStringValue(finding, "description")
	remediation := getStringValue(finding, "remediation")
	evidence := getStringValue(finding, "evidence")
	confidence := getStringValue(finding, "confidence")

	return &SARIFResult{
		RuleID:    RuleIDLFI,
		RuleIndex: getRuleIndex(RuleIDLFI),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("Path Traversal vulnerability in parameter '%s': %s", parameter, description),
			Markdown: fmt.Sprintf("**Path Traversal / LFI (%s)**\n\nParameter: `%s`\nPayload: `%s`\n\n%s\n\nEvidence: %s\n\n**Remediation:** %s", lfiType, parameter, payload, description, evidence, remediation),
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
			"type":       lfiType,
			"confidence": confidence,
		},
	}
}

func createSSTIResult(finding map[string]interface{}) *SARIFResult {
	url := getStringValue(finding, "url")
	parameter := getStringValue(finding, "parameter")
	payload := getStringValue(finding, "payload")
	templateEngine := getStringValue(finding, "template_engine")
	severity := getStringValue(finding, "severity")
	description := getStringValue(finding, "description")
	remediation := getStringValue(finding, "remediation")
	evidence := getStringValue(finding, "evidence")
	confidence := getStringValue(finding, "confidence")

	return &SARIFResult{
		RuleID:    RuleIDSSTI,
		RuleIndex: getRuleIndex(RuleIDSSTI),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("Server-Side Template Injection vulnerability in parameter '%s': %s", parameter, description),
			Markdown: fmt.Sprintf("**SSTI (%s)**\n\nParameter: `%s`\nPayload: `%s`\n\n%s\n\nEvidence: %s\n\nConfidence: %s\n\n**Remediation:** %s", templateEngine, parameter, payload, description, evidence, confidence, remediation),
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
			"parameter":       parameter,
			"payload":         payload,
			"template_engine": templateEngine,
			"confidence":      confidence,
		},
	}
}

func createXXEResult(finding map[string]interface{}) *SARIFResult {
	url := getStringValue(finding, "url")
	parameter := getStringValue(finding, "parameter")
	payload := getStringValue(finding, "payload")
	xxeType := getStringValue(finding, "type")
	severity := getStringValue(finding, "severity")
	description := getStringValue(finding, "description")
	remediation := getStringValue(finding, "remediation")
	evidence := getStringValue(finding, "evidence")
	confidence := getStringValue(finding, "confidence")

	return &SARIFResult{
		RuleID:    RuleIDXXE,
		RuleIndex: getRuleIndex(RuleIDXXE),
		Level:     mapSeverityToLevel(severity),
		Message: SARIFMessage{
			Text:     fmt.Sprintf("XML External Entity (XXE) vulnerability in parameter '%s': %s", parameter, description),
			Markdown: fmt.Sprintf("**XXE (%s)**\n\nParameter: `%s`\nPayload: `%s`\n\n%s\n\nEvidence: %s\n\nConfidence: %s\n\n**Remediation:** %s", xxeType, parameter, payload, description, evidence, confidence, remediation),
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
			"xxe_type":   xxeType,
			"confidence": confidence,
		},
	}
}

// MCP scan SARIF conversion functions

// buildMCPRules returns the full set of SARIF rules for MCP scan categories.
func buildMCPRules() []SARIFRule {
	return []SARIFRule{
		{
			ID:   RuleIDMCPSchema,
			Name: "MCPSchemaWeakness",
			ShortDescription: SARIFMessage{
				Text: "MCP tool schema weakness detected",
			},
			FullDescription: SARIFMessage{
				Text: "The MCP tool schema has weaknesses such as missing validation, undocumented parameters, or overly permissive input definitions that could allow misuse.",
			},
			Help: SARIFMessage{
				Text:     "Define strict JSON Schema constraints for all tool parameters. Mark required parameters explicitly. Use enum, pattern, minimum/maximum where applicable to constrain input.",
				Markdown: "**Remediation:** Define strict JSON Schema constraints for all tool parameters. Mark required parameters explicitly. Use `enum`, `pattern`, `minimum`/`maximum` where applicable to constrain input.",
			},
			Properties: map[string]interface{}{
				"tags": []string{"security", "mcp", "schema"},
			},
		},
		{
			ID:   RuleIDMCPPrompt,
			Name: "MCPPromptInjection",
			ShortDescription: SARIFMessage{
				Text: "MCP prompt injection risk detected",
			},
			FullDescription: SARIFMessage{
				Text: "The MCP tool description or parameter description contains AI-directed instructions, hidden Unicode characters, base64 payloads, or other content that could hijack AI agent behaviour.",
			},
			Help: SARIFMessage{
				Text:     "Remove hidden instructions, suspicious Unicode, or encoded payloads from tool and parameter descriptions. Descriptions should be concise, human-readable, and free of directives.",
				Markdown: "**Remediation:** Remove hidden instructions, suspicious Unicode, or encoded payloads from tool and parameter descriptions. Descriptions should be concise, human-readable, and free of directives.\n\n**Reference:** " + CWEMCPPrompt,
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEMCPPrompt, "security", "mcp", "prompt-injection"},
			},
		},
		{
			ID:   RuleIDMCPPermissions,
			Name: "MCPExcessivePermissions",
			ShortDescription: SARIFMessage{
				Text: "MCP server excessive permissions detected",
			},
			FullDescription: SARIFMessage{
				Text: "The MCP server exposes tools with dangerous capabilities such as shell execution, unrestricted file system access, network access, or process management without adequate safeguards.",
			},
			Help: SARIFMessage{
				Text:     "Apply the principle of least privilege. Restrict dangerous capabilities to the minimum required. Implement allowlists for file paths, commands, and network targets. Require explicit user confirmation for destructive actions.",
				Markdown: "**Remediation:** Apply the principle of least privilege. Restrict dangerous capabilities to the minimum required. Implement allowlists for file paths, commands, and network targets. Require explicit user confirmation for destructive actions.\n\n**Reference:** " + CWEMCPPermissions,
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEMCPPermissions, "security", "mcp", "permissions"},
			},
		},
		{
			ID:   RuleIDMCPShadowing,
			Name: "MCPToolShadowing",
			ShortDescription: SARIFMessage{
				Text: "MCP tool shadowing or name collision detected",
			},
			FullDescription: SARIFMessage{
				Text: "The MCP server contains tool names that collide with or closely resemble other tools, enabling typosquatting, tool substitution attacks, or AI agent confusion.",
			},
			Help: SARIFMessage{
				Text:     "Use unique, unambiguous tool names. Avoid names that resemble common utilities or other tools in the same server. Validate tool names against known registries.",
				Markdown: "**Remediation:** Use unique, unambiguous tool names. Avoid names that resemble common utilities or other tools in the same server. Validate tool names against known registries.\n\n**Reference:** " + CWEMCPShadowing,
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEMCPShadowing, "security", "mcp", "tool-shadowing"},
			},
		},
		{
			ID:   RuleIDMCPInjection,
			Name: "MCPInjection",
			ShortDescription: SARIFMessage{
				Text: "MCP tool injection vulnerability detected",
			},
			FullDescription: SARIFMessage{
				Text: "The MCP tool passes user-controlled input unsanitized to SQL queries, OS commands, file paths, or other interpreters, enabling injection attacks.",
			},
			Help: SARIFMessage{
				Text:     "Sanitize and validate all tool parameter inputs before use. Use parameterized queries, command argument arrays instead of shell strings, and strict path allowlists.",
				Markdown: "**Remediation:** Sanitize and validate all tool parameter inputs before use. Use parameterized queries, command argument arrays instead of shell strings, and strict path allowlists.\n\n**Reference:** " + CWEMCPInjection,
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEMCPInjection, "security", "mcp", "injection"},
			},
		},
		{
			ID:   RuleIDMCPExposure,
			Name: "MCPDataExposure",
			ShortDescription: SARIFMessage{
				Text: "MCP tool sensitive data exposure detected",
			},
			FullDescription: SARIFMessage{
				Text: "The MCP tool response or configuration leaks sensitive information such as API keys, credentials, internal IP addresses, database connection strings, stack traces, or environment variables.",
			},
			Help: SARIFMessage{
				Text:     "Redact sensitive values from tool responses. Never return raw environment variables, credential strings, or internal infrastructure details. Implement response filtering.",
				Markdown: "**Remediation:** Redact sensitive values from tool responses. Never return raw environment variables, credential strings, or internal infrastructure details. Implement response filtering.\n\n**Reference:** " + CWEMCPExposure,
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEMCPExposure, "security", "mcp", "data-exposure"},
			},
		},
		{
			ID:   RuleIDMCPSSRF,
			Name: "MCPSSRF",
			ShortDescription: SARIFMessage{
				Text: "MCP tool Server-Side Request Forgery (SSRF) risk detected",
			},
			FullDescription: SARIFMessage{
				Text: "The MCP tool accepts URL parameters that could be used to make server-side requests to internal resources, cloud metadata endpoints, or local files.",
			},
			Help: SARIFMessage{
				Text:     "Validate and restrict URL parameters to an allowlist of safe destinations. Block access to private IP ranges, loopback addresses, and cloud metadata endpoints.",
				Markdown: "**Remediation:** Validate and restrict URL parameters to an allowlist of safe destinations. Block access to private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, 169.254.x.x) and cloud metadata endpoints.\n\n**Reference:** " + CWEMCPSSRFVal,
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEMCPSSRFVal, "security", "mcp", "ssrf"},
			},
		},
		{
			ID:   RuleIDMCPAuth,
			Name: "MCPAuthBypass",
			ShortDescription: SARIFMessage{
				Text: "MCP server authentication bypass risk detected",
			},
			FullDescription: SARIFMessage{
				Text: "The MCP server allows unauthenticated access to sensitive tools or does not properly enforce authentication controls.",
			},
			Help: SARIFMessage{
				Text:     "Require authentication for all sensitive MCP endpoints. Implement token-based authentication, validate tokens on every request, and return 401 for unauthenticated access.",
				Markdown: "**Remediation:** Require authentication for all sensitive MCP endpoints. Implement token-based authentication, validate tokens on every request, and return 401 for unauthenticated access.\n\n**Reference:** " + CWEMCPAuth,
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEMCPAuth, "security", "mcp", "auth-bypass"},
			},
		},
		{
			ID:   RuleIDMCPDependency,
			Name: "MCPDependencyRisk",
			ShortDescription: SARIFMessage{
				Text: "MCP server dependency risk detected",
			},
			FullDescription: SARIFMessage{
				Text: "The MCP server uses outdated or unmaintained dependencies that may contain known vulnerabilities.",
			},
			Help: SARIFMessage{
				Text:     "Keep MCP server dependencies up-to-date. Regularly audit dependencies with tools like npm audit, pip-audit, or Dependabot. Remove unused dependencies.",
				Markdown: "**Remediation:** Keep MCP server dependencies up-to-date. Regularly audit dependencies with tools like `npm audit`, `pip-audit`, or Dependabot. Remove unused dependencies.\n\n**Reference:** " + CWEMCPDependency,
			},
			Properties: map[string]interface{}{
				"tags": []string{CWEMCPDependency, "security", "mcp", "dependency", "supply-chain"},
			},
		},
	}
}

// getMCPRuleIDForCategory returns the SARIF rule ID for a given MCP check category.
func getMCPRuleIDForCategory(category mcpscan.CheckCategory) string {
	switch category {
	case mcpscan.CategorySchema:
		return RuleIDMCPSchema
	case mcpscan.CategoryPrompt:
		return RuleIDMCPPrompt
	case mcpscan.CategoryPermissions:
		return RuleIDMCPPermissions
	case mcpscan.CategoryShadowing:
		return RuleIDMCPShadowing
	case mcpscan.CategoryInjection:
		return RuleIDMCPInjection
	case mcpscan.CategoryExposure:
		return RuleIDMCPExposure
	case mcpscan.CategorySSRF:
		return RuleIDMCPSSRF
	case mcpscan.CategoryAuth:
		return RuleIDMCPAuth
	case mcpscan.CategoryDependency:
		return RuleIDMCPDependency
	default:
		return RuleIDMCPSchema
	}
}

// getMCPRuleIndex returns the index position of an MCP rule in buildMCPRules().
func getMCPRuleIndex(ruleID string) int {
	rules := []string{
		RuleIDMCPSchema,
		RuleIDMCPPrompt,
		RuleIDMCPPermissions,
		RuleIDMCPShadowing,
		RuleIDMCPInjection,
		RuleIDMCPExposure,
		RuleIDMCPSSRF,
		RuleIDMCPAuth,
		RuleIDMCPDependency,
	}
	for i, r := range rules {
		if r == ruleID {
			return i
		}
	}
	return 0
}

// mapMCPSeverityToLevel maps MCP scan severity to a SARIF level string.
func mapMCPSeverityToLevel(severity mcpscan.Severity) string {
	switch severity {
	case mcpscan.SeverityCritical, mcpscan.SeverityHigh:
		return "error"
	case mcpscan.SeverityMedium:
		return "warning"
	case mcpscan.SeverityLow, mcpscan.SeverityInfo:
		return "note"
	default:
		return "note"
	}
}

// createMCPFindingResult converts a single MCPFinding into a SARIFResult.
func createMCPFindingResult(finding mcpscan.MCPFinding, serverTarget string) *SARIFResult {
	ruleID := getMCPRuleIDForCategory(finding.Category)

	// Build location: server target as artifact URI
	location := serverTarget
	if location == "" {
		location = "mcp://unknown"
	}

	// Build message text
	msgText := finding.Title
	if finding.Description != "" {
		msgText = finding.Description
	}
	if finding.Tool != "" {
		if finding.Parameter != "" {
			msgText = fmt.Sprintf("[%s.%s] %s", finding.Tool, finding.Parameter, msgText)
		} else {
			msgText = fmt.Sprintf("[%s] %s", finding.Tool, msgText)
		}
	}

	// Build markdown message
	var mdParts []string
	mdParts = append(mdParts, fmt.Sprintf("**%s** (%s)", finding.Title, strings.ToUpper(string(finding.Severity))))
	if finding.Tool != "" {
		toolRef := finding.Tool
		if finding.Parameter != "" {
			toolRef += "." + finding.Parameter
		}
		mdParts = append(mdParts, fmt.Sprintf("**Tool:** `%s`", toolRef))
	}
	if finding.Description != "" {
		mdParts = append(mdParts, finding.Description)
	}
	if finding.Evidence != "" {
		mdParts = append(mdParts, fmt.Sprintf("**Evidence:** `%s`", finding.Evidence))
	}
	if finding.Remediation != "" {
		mdParts = append(mdParts, fmt.Sprintf("**Remediation:** %s", finding.Remediation))
	}

	props := map[string]interface{}{
		"category": string(finding.Category),
		"severity": string(finding.Severity),
		"server":   serverTarget,
	}
	if finding.Tool != "" {
		props["tool"] = finding.Tool
	}
	if finding.Parameter != "" {
		props["parameter"] = finding.Parameter
	}
	if finding.Evidence != "" {
		props["evidence"] = finding.Evidence
	}

	result := &SARIFResult{
		RuleID:    ruleID,
		RuleIndex: getMCPRuleIndex(ruleID),
		Level:     mapMCPSeverityToLevel(finding.Severity),
		Message: SARIFMessage{
			Text:     msgText,
			Markdown: strings.Join(mdParts, "\n\n"),
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: location,
					},
				},
			},
		},
		Properties: props,
	}

	return result
}

// buildMCPSARIFRun constructs a SARIFRun for a single MCP server scan result.
func buildMCPSARIFRun(result *mcpscan.MCPScanResult) SARIFRun {
	serverName := result.Server.Name
	if serverName == "" {
		serverName = result.Server.Target
	}

	run := SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFToolComponent{
				Name:            "WAST",
				Version:         "1.0.0",
				SemanticVersion: "1.0.0",
				InformationURI:  "https://github.com/djannot/wast",
				Rules:           buildMCPRules(),
			},
		},
		Results: make([]SARIFResult, 0),
		Invocations: []SARIFInvocation{
			{ExecutionSuccessful: true},
		},
	}

	for _, f := range result.Findings {
		sr := createMCPFindingResult(f, result.Server.Target)
		if sr != nil {
			run.Results = append(run.Results, *sr)
		}
	}

	// Attach server metadata to the invocation properties via a custom property bag.
	// We encode it into the existing SARIFInvocation by enriching run properties.
	_ = serverName // used above for fallback
	return run
}

// convertMCPScanResultToSARIF converts a single MCPScanResult to a SARIF report
// with one run per server.
func convertMCPScanResultToSARIF(result *mcpscan.MCPScanResult, report *SARIFReport) (*SARIFReport, error) {
	if result == nil {
		return report, nil
	}
	run := buildMCPSARIFRun(result)
	report.Runs = append(report.Runs, run)
	return report, nil
}

// convertMCPBulkScanResultToSARIF converts a BulkScanResult to a SARIF report.
// Each server with findings becomes a separate SARIF run.
func convertMCPBulkScanResultToSARIF(bulk mcpscan.BulkScanResult, report *SARIFReport) (*SARIFReport, error) {
	if len(bulk.Results) == 0 {
		// Emit an empty run so the document is still valid SARIF.
		report.Runs = append(report.Runs, SARIFRun{
			Tool: SARIFTool{
				Driver: SARIFToolComponent{
					Name:           "WAST",
					Version:        "1.0.0",
					InformationURI: "https://github.com/djannot/wast",
					Rules:          buildMCPRules(),
				},
			},
			Results:     make([]SARIFResult, 0),
			Invocations: []SARIFInvocation{{ExecutionSuccessful: true}},
		})
		return report, nil
	}

	for _, result := range bulk.Results {
		if result == nil {
			continue
		}
		run := buildMCPSARIFRun(result)
		report.Runs = append(report.Runs, run)
	}
	return report, nil
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
		RuleIDNoSQLi,
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
		RuleIDLFI,
		RuleIDSSTI,
		RuleIDXXE,
		RuleIDWSInsecure,
		RuleIDWSOrigin,
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
