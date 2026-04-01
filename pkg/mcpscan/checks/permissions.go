package checks

import (
	"fmt"
	"strings"
)

// dangerousCapability represents a recognized dangerous capability pattern.
type dangerousCapability struct {
	keywords    []string
	title       string
	description string
	severity    Severity
	remediation string
}

// knownDangerousCapabilities lists capability patterns that warrant security review.
var knownDangerousCapabilities = []dangerousCapability{
	{
		keywords:    []string{"exec", "execute", "run_command", "shell", "spawn", "popen", "system", "bash", "sh "},
		title:       "Shell or command execution capability",
		severity:    SeverityCritical,
		description: "This tool appears to execute shell commands or system calls. If exploited, an attacker could achieve arbitrary code execution on the host system.",
		remediation: "Restrict command execution to a minimal allow-list. Sandbox the process. Apply principle of least privilege.",
	},
	{
		keywords:    []string{"read_file", "write_file", "list_dir", "list_files", "delete_file", "move_file", "copy_file", "file_system", "filesystem", "readdir", "readfile", "writefile"},
		title:       "File system access capability",
		severity:    SeverityHigh,
		description: "This tool provides file system access. Broad file system access can allow reading sensitive files (credentials, keys) or writing/overwriting critical files.",
		remediation: "Scope access to a specific, non-sensitive directory. Implement path validation and disallow traversal outside the permitted root.",
	},
	{
		keywords:    []string{"http_request", "fetch", "web_request", "make_request", "http_get", "http_post", "curl", "wget", "download_url", "browse"},
		title:       "Outbound network request capability",
		severity:    SeverityHigh,
		description: "This tool makes outbound network requests. It could be abused for SSRF attacks to reach internal services, metadata endpoints, or exfiltrate data.",
		remediation: "Implement an allowlist of permitted target hosts/domains. Block internal network ranges (RFC 1918, link-local).",
	},
	{
		keywords:    []string{"query", "sql", "database", "db_query", "execute_sql", "run_query", "mongo", "redis", "elasticsearch"},
		title:       "Database query capability",
		severity:    SeverityHigh,
		description: "This tool executes database queries. Unsanitized input could lead to SQL/NoSQL injection or unauthorized data access.",
		remediation: "Use parameterized queries. Restrict database user permissions. Validate and sanitize all tool inputs before executing queries.",
	},
	{
		keywords:    []string{"eval", "interpret", "run_code", "execute_code", "run_python", "run_js", "run_javascript", "sandbox_exec"},
		title:       "Code evaluation/interpretation capability",
		severity:    SeverityCritical,
		description: "This tool evaluates or interprets code at runtime. This is an extremely high-risk capability that can lead to arbitrary code execution.",
		remediation: "Avoid exposing code evaluation via MCP tools. If absolutely necessary, run in a strict sandbox with no network access or file system access.",
	},
	{
		keywords:    []string{"send_email", "send_mail", "smtp", "email", "notify_slack", "send_message", "webhook"},
		title:       "External communication capability",
		severity:    SeverityMedium,
		description: "This tool sends messages to external systems (email, Slack, webhooks, etc.). It could be abused for phishing, data exfiltration, or spamming.",
		remediation: "Restrict recipient addresses/channels to an allow-list. Rate-limit message sending. Log all outbound communications.",
	},
	{
		keywords:    []string{"list_secrets", "get_secret", "read_secret", "secret_manager", "vault", "credentials", "api_key", "token", "password"},
		title:       "Secret or credential access capability",
		severity:    SeverityCritical,
		description: "This tool appears to access secrets, credentials, or API keys. Exposing this via MCP creates a high-value target for exfiltration.",
		remediation: "Limit secret access to the minimum required. Implement strict authorization checks before returning sensitive data.",
	},
}

// PermissionsChecker audits MCP tools for dangerous capabilities.
type PermissionsChecker struct{}

// NewPermissionsChecker creates a new PermissionsChecker.
func NewPermissionsChecker() *PermissionsChecker {
	return &PermissionsChecker{}
}

// Check runs permission analysis on all tools.
func (c *PermissionsChecker) Check(tools []ToolInfo) []Finding {
	var findings []Finding
	for _, tool := range tools {
		findings = append(findings, c.checkTool(tool)...)
	}
	return findings
}

// checkTool checks a single tool for dangerous capability indicators.
func (c *PermissionsChecker) checkTool(tool ToolInfo) []Finding {
	var findings []Finding

	corpus := strings.ToLower(tool.Name + " " + tool.Description)
	for _, p := range tool.Parameters {
		corpus += " " + strings.ToLower(p.Name) + " " + strings.ToLower(p.Description)
	}

	for _, cap := range knownDangerousCapabilities {
		for _, kw := range cap.keywords {
			if strings.Contains(corpus, kw) {
				findings = append(findings, Finding{
					Tool:     tool.Name,
					Category: CategoryPermissions,
					Severity: cap.severity,
					Title:    cap.title,
					Description: fmt.Sprintf(
						"Tool %q — %s",
						tool.Name, cap.description,
					),
					Evidence:    fmt.Sprintf("Matched keyword: %q in tool name/description", kw),
					Remediation: cap.remediation,
				})
				break
			}
		}
	}

	return findings
}
