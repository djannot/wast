package checks

import (
	"fmt"
	"regexp"
	"strings"
)

// kwPattern pairs a human-readable keyword with its pre-compiled whole-word regexp.
type kwPattern struct {
	keyword string
	re      *regexp.Regexp
}

// dangerousCapability represents a recognized dangerous capability pattern.
type dangerousCapability struct {
	kwPatterns      []kwPattern      // pre-compiled whole-word patterns matched against the lower-case corpus
	contextPatterns []*regexp.Regexp // if non-empty, at least one must also match the corpus
	title           string
	description     string
	severity        Severity
	remediation     string
}

// buildWholeWordPattern compiles a whole-word case-insensitive regexp for kw.
// Using \b word boundaries prevents substring matches like "sh" firing inside
// "refresh", "push" or "publish", and "eval" firing inside "relevant".
func buildWholeWordPattern(kw string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(kw) + `\b`)
}

// buildContextPatterns compiles a slice of whole-word patterns for context words.
func buildContextPatterns(words []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(words))
	for i, w := range words {
		out[i] = buildWholeWordPattern(w)
	}
	return out
}

// knownDangerousCapabilities lists capability patterns that warrant security review.
// Patterns are pre-compiled at init time for performance.
var knownDangerousCapabilities []dangerousCapability

func init() {
	type rawCapability struct {
		keywords        []string
		contextRequired []string // if non-empty, at least one must appear as a whole word
		title           string
		description     string
		severity        Severity
		remediation     string
	}

	raws := []rawCapability{
		{
			// "sh" is listed without a trailing space — whole-word matching prevents
			// it from firing inside "refresh", "push", or "publish".
			keywords:    []string{"exec", "execute", "run_command", "shell", "spawn", "popen", "system", "bash", "sh"},
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
			// "query" as a whole word still catches DB-query tools without false-positives
			// on tools that merely mention "querying" in a generic sense.
			keywords:    []string{"query", "sql", "database", "db_query", "execute_sql", "run_query", "mongo", "redis", "elasticsearch"},
			title:       "Database query capability",
			severity:    SeverityHigh,
			description: "This tool executes database queries. Unsanitized input could lead to SQL/NoSQL injection or unauthorized data access.",
			remediation: "Use parameterized queries. Restrict database user permissions. Validate and sanitize all tool inputs before executing queries.",
		},
		{
			// "eval" as a whole word prevents matches inside "relevant", "evaluate",
			// "evaluation" used in non-code-execution contexts.
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
			// Specific credential-management keywords that are unambiguous on their own.
			keywords:    []string{"list_secrets", "get_secret", "read_secret", "secret_manager", "vault", "credentials", "api_key", "password"},
			title:       "Secret or credential access capability",
			severity:    SeverityCritical,
			description: "This tool appears to access secrets, credentials, or API keys. Exposing this via MCP creates a high-value target for exfiltration.",
			remediation: "Limit secret access to the minimum required. Implement strict authorization checks before returning sensitive data.",
		},
		{
			// "token" is kept as a separate entry with a context requirement so that
			// blockchain / crypto tool descriptions that legitimately discuss tokens
			// (e.g. "ERC-20 token transfers") do not produce false positives.
			// The keyword only fires when the corpus also contains a credential-related word.
			keywords:        []string{"token"},
			contextRequired: []string{"secret", "credential", "api_key", "password", "private_key", "auth_token", "access_token", "bearer"},
			title:           "Secret or credential access capability",
			severity:        SeverityCritical,
			description:     "This tool appears to access secrets, credentials, or API keys. Exposing this via MCP creates a high-value target for exfiltration.",
			remediation:     "Limit secret access to the minimum required. Implement strict authorization checks before returning sensitive data.",
		},
	}

	for _, r := range raws {
		var kwPatterns []kwPattern
		for _, kw := range r.keywords {
			kwPatterns = append(kwPatterns, kwPattern{
				keyword: kw,
				re:      buildWholeWordPattern(kw),
			})
		}
		knownDangerousCapabilities = append(knownDangerousCapabilities, dangerousCapability{
			kwPatterns:      kwPatterns,
			contextPatterns: buildContextPatterns(r.contextRequired),
			title:           r.title,
			description:     r.description,
			severity:        r.severity,
			remediation:     r.remediation,
		})
	}
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
		matchedKw := ""
		for _, kwp := range cap.kwPatterns {
			if kwp.re.MatchString(corpus) {
				matchedKw = kwp.keyword
				break
			}
		}
		if matchedKw == "" {
			continue
		}

		// Context-aware guard: if the capability requires co-occurring words,
		// verify at least one is present before reporting a finding.
		if len(cap.contextPatterns) > 0 {
			contextFound := false
			for _, ctxPat := range cap.contextPatterns {
				if ctxPat.MatchString(corpus) {
					contextFound = true
					break
				}
			}
			if !contextFound {
				continue
			}
		}

		findings = append(findings, Finding{
			Tool:     tool.Name,
			Category: CategoryPermissions,
			Severity: cap.severity,
			Title:    cap.title,
			Description: fmt.Sprintf(
				"Tool %q — %s",
				tool.Name, cap.description,
			),
			Evidence:    fmt.Sprintf("Matched keyword: %q in tool name/description", matchedKw),
			Remediation: cap.remediation,
		})
	}

	return findings
}
