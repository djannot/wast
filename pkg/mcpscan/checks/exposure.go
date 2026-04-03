package checks

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// queryLikeParamNames are parameter names that suggest a free-text search or filter value.
var queryLikeParamNames = []string{"query", "search", "filter", "q", "keyword", "term", "text"}

// actionParamNames are parameter names that suggest an operation type.
var actionParamNames = []string{"action", "operation", "method", "cmd", "command", "op"}

// listLikeToolKeywords are keywords in tool names/descriptions that suggest read-only list/fetch operations.
var listLikeToolKeywords = []string{"list", "get", "search", "query", "status", "config", "info", "env", "health", "read", "fetch", "show", "describe", "check"}

// enumValuePatterns match common descriptions of enumerated values.
var enumValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)one\s+of[:\s]+([a-zA-Z0-9_-]+)`),
	regexp.MustCompile(`(?i)(?:possible|valid|allowed|accepted)\s+values?[:\s]+([a-zA-Z0-9_-]+)`),
	regexp.MustCompile(`\(([a-zA-Z0-9_-]+)\|`),
	regexp.MustCompile(`(?i)(?:can\s+be|must\s+be)[:\s]+([a-zA-Z0-9_-]+)`),
}

// containsAnyWord returns true if s contains any of the given substrings.
func containsAnyWord(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// isQueryLikeParam returns true if the parameter name suggests a search/filter value.
func isQueryLikeParam(name string) bool {
	return containsAnyWord(strings.ToLower(name), queryLikeParamNames)
}

// isActionParam returns true if the parameter name suggests an operation type.
func isActionParam(name string) bool {
	return containsAnyWord(strings.ToLower(name), actionParamNames)
}

// toolMatchesKeywords returns true if a tool's name or description contains any of the given keywords.
func toolMatchesKeywords(tool ToolInfo, keywords []string) bool {
	nameLower := strings.ToLower(tool.Name)
	descLower := strings.ToLower(tool.Description)
	return containsAnyWord(nameLower, keywords) || containsAnyWord(descLower, keywords)
}

// extractEnumValue tries to extract the first enumerated value from a parameter description.
func extractEnumValue(desc string) string {
	for _, re := range enumValuePatterns {
		if m := re.FindStringSubmatch(desc); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

// semanticValueForParam returns a realistic benign value for a parameter based on its name and description.
// It prefers semantically meaningful values over generic defaults to maximise the chance that the tool
// accepts the call and returns a meaningful response.
func semanticValueForParam(p ParamInfo) interface{} {
	switch strings.ToLower(p.Type) {
	case "boolean":
		return true
	case "number", "integer":
		return 1
	case "array":
		return []interface{}{}
	case "object":
		return map[string]interface{}{}
	}

	// String: check description for enum hints first.
	if enumVal := extractEnumValue(p.Description); enumVal != "" {
		return enumVal
	}

	// Fall back to name-based heuristics.
	nameLower := strings.ToLower(p.Name)
	switch {
	case isQueryLikeParam(nameLower):
		return "test"
	case isActionParam(nameLower):
		return "list"
	case containsAnyWord(nameLower, []string{"type", "kind", "category", "format", "mode"}):
		return "default"
	case containsAnyWord(nameLower, []string{"status", "state"}):
		return "active"
	case containsAnyWord(nameLower, []string{"id", "key", "uuid", "ref", "token"}):
		return "test-id-1"
	case containsAnyWord(nameLower, []string{"name", "label", "title", "tag"}):
		return "test"
	case containsAnyWord(nameLower, []string{"url", "endpoint", "host", "addr"}):
		return "http://localhost"
	case containsAnyWord(nameLower, []string{"path", "file", "dir", "folder"}):
		return "/tmp/test"
	default:
		return "test"
	}
}

// benignArgStrategy generates up to 3 sets of benign arguments for a tool based on
// heuristics derived from the tool name, description, and parameter metadata.
// The goal is to produce semantically valid inputs that are more likely to succeed
// and return meaningful responses, which may reveal leaked secrets.
func benignArgStrategy(tool ToolInfo) []map[string]interface{} {
	const maxSets = 3

	// Set 1: required params with semantic defaults.
	set1 := map[string]interface{}{}
	for _, p := range tool.Parameters {
		if p.Required {
			set1[p.Name] = semanticValueForParam(p)
		}
	}
	argSets := []map[string]interface{}{set1}

	// Set 2: for tools with query/search/filter params, try wildcard "*".
	set2 := copyArgSet(set1)
	modified2 := false
	for _, p := range tool.Parameters {
		if p.Required && strings.EqualFold(p.Type, "string") && isQueryLikeParam(p.Name) {
			set2[p.Name] = "*"
			modified2 = true
		}
	}
	if modified2 {
		argSets = append(argSets, set2)
	}

	if len(argSets) >= maxSets {
		return argSets[:maxSets]
	}

	// Set 3: for tools with action/operation params, try "get" as an alternative.
	set3 := copyArgSet(set1)
	modified3 := false
	for _, p := range tool.Parameters {
		if p.Required && strings.EqualFold(p.Type, "string") && isActionParam(p.Name) {
			set3[p.Name] = "get"
			modified3 = true
		}
	}
	if modified3 {
		argSets = append(argSets, set3)
	}

	if len(argSets) >= maxSets {
		return argSets[:maxSets]
	}

	// Set 3 (fallback): for list-like tools with no other variant, try an empty-string
	// value for required string params (some tools accept empty to mean "all").
	if toolMatchesKeywords(tool, listLikeToolKeywords) {
		set4 := map[string]interface{}{}
		hasVariant := false
		for _, p := range tool.Parameters {
			if p.Required {
				if strings.EqualFold(p.Type, "string") {
					existing, _ := set1[p.Name].(string)
					set4[p.Name] = ""
					if existing != "" {
						hasVariant = true
					}
				} else {
					set4[p.Name] = defaultValueForType(p.Type)
				}
			}
		}
		if hasVariant {
			argSets = append(argSets, set4)
		}
	}

	if len(argSets) > maxSets {
		return argSets[:maxSets]
	}
	return argSets
}

// copyArgSet returns a shallow copy of an argument map.
func copyArgSet(src map[string]interface{}) map[string]interface{} {
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// exposurePattern is a regex with metadata for detecting leaked sensitive data.
type exposurePattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    Severity
	Description string
}

var exposurePatterns = []*exposurePattern{
	{
		Name:        "AWS access key",
		Pattern:     regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
		Severity:    SeverityCritical,
		Description: "AWS access key ID found in response",
	},
	{
		Name:        "Private key header",
		Pattern:     regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Severity:    SeverityCritical,
		Description: "Private key material found in response",
	},
	{
		Name:        "GitHub token",
		Pattern:     regexp.MustCompile(`(?i)gh[pousr]_[0-9A-Za-z]{36,}`),
		Severity:    SeverityCritical,
		Description: "GitHub personal access token found in response",
	},
	{
		Name:        "Generic API key",
		Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*["']?[0-9a-zA-Z\-_.]{20,}`),
		Severity:    SeverityHigh,
		Description: "Generic API key or access token found in response",
	},
	{
		Name:        "Password in response",
		Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{6,}`),
		Severity:    SeverityHigh,
		Description: "Password value found in response",
	},
	{
		Name:        "Environment variable dump",
		Pattern:     regexp.MustCompile(`(?i)(HOME|PATH|USER|SHELL|PWD|LOGNAME)=/`),
		Severity:    SeverityMedium,
		Description: "Environment variable dump found in response (possible information disclosure)",
	},
	{
		Name:        "Internal path disclosure",
		Pattern:     regexp.MustCompile(`(/etc/passwd|/etc/shadow|/proc/self|/var/log|C:\\Windows\\System32|/home/\w+/\.ssh)`),
		Severity:    SeverityHigh,
		Description: "Internal system path found in response",
	},
	{
		Name:        "Stack trace",
		Pattern:     regexp.MustCompile(`(?i)(goroutine \d+ \[|at [a-zA-Z0-9/_.]+\.go:\d+|Traceback \(most recent call last\)|Exception in thread|File ".+", line \d+)`),
		Severity:    SeverityMedium,
		Description: "Stack trace found in response",
	},
	{
		Name:        "IPv4 private address",
		Pattern:     regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
		Severity:    SeverityLow,
		Description: "Private IP address found in response",
	},
	{
		Name:        "PostgreSQL connection string",
		Pattern:     regexp.MustCompile(`(?i)postgres(ql)?://[^\s"']+`),
		Severity:    SeverityCritical,
		Description: "PostgreSQL connection URI found in response",
	},
	{
		Name:        "MySQL connection string",
		Pattern:     regexp.MustCompile(`(?i)mysql://[^\s"']+`),
		Severity:    SeverityCritical,
		Description: "MySQL connection URI found in response",
	},
	{
		Name:        "MongoDB connection string",
		Pattern:     regexp.MustCompile(`(?i)mongodb(\+srv)?://[^\s"']+`),
		Severity:    SeverityCritical,
		Description: "MongoDB connection URI found in response",
	},
	{
		Name:        "Redis connection string",
		Pattern:     regexp.MustCompile(`(?i)rediss?://[^\s"']+`),
		Severity:    SeverityCritical,
		Description: "Redis connection URI found in response",
	},
	{
		Name:        "JDBC connection string",
		Pattern:     regexp.MustCompile(`(?i)jdbc:[a-z]+://[^\s"']+`),
		Severity:    SeverityCritical,
		Description: "JDBC database connection string found in response",
	},
	{
		Name:        "DATABASE_URL assignment",
		Pattern:     regexp.MustCompile(`(?i)DATABASE_URL\s*[:=]\s*["']?\S{10,}`),
		Severity:    SeverityCritical,
		Description: "DATABASE_URL environment variable found in response",
	},
}

// ExposureChecker invokes tools with benign arguments and scans responses for sensitive data.
type ExposureChecker struct{}

// NewExposureChecker creates a new ExposureChecker.
func NewExposureChecker() *ExposureChecker {
	return &ExposureChecker{}
}

// Check invokes each tool with benign arguments and scans responses.
func (c *ExposureChecker) Check(ctx context.Context, tools []ToolInfo, caller ToolCaller) []Finding {
	var findings []Finding
	for _, tool := range tools {
		findings = append(findings, c.checkTool(ctx, tool, caller)...)
	}
	return findings
}

func (c *ExposureChecker) checkTool(ctx context.Context, tool ToolInfo, caller ToolCaller) []Finding {
	argSets := benignArgStrategy(tool)

	// seen tracks (tool, finding title) pairs to avoid duplicate findings across calls.
	seen := map[string]bool{}
	var findings []Finding

	for _, args := range argSets {
		resp, err := caller.CallTool(ctx, tool.Name, args)
		var candidates []Finding
		if err != nil {
			candidates = c.scanText(tool.Name, err.Error())
		} else {
			candidates = c.scanText(tool.Name, extractResponseText(resp))
		}
		for _, f := range candidates {
			key := f.Tool + "|" + f.Title
			if !seen[key] {
				seen[key] = true
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// scanText runs all exposure patterns against a response string.
func (c *ExposureChecker) scanText(toolName, text string) []Finding {
	var findings []Finding

	for _, ep := range exposurePatterns {
		match := ep.Pattern.FindString(text)
		if match == "" {
			continue
		}

		redacted := redactMatch(match)
		idx := strings.Index(text, match)
		contextStart := idx - 50
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := idx + len(match) + 50
		if contextEnd > len(text) {
			contextEnd = len(text)
		}
		snippet := text[contextStart:contextEnd]

		findings = append(findings, Finding{
			Tool:     toolName,
			Category: CategoryExposure,
			Severity: ep.Severity,
			Title:    fmt.Sprintf("Sensitive data exposure: %s", ep.Name),
			Description: fmt.Sprintf(
				"Tool %q returned a response containing %s.",
				toolName, ep.Description,
			),
			Evidence:    fmt.Sprintf("Pattern: %s | Redacted match: %s | Context: %s", ep.Name, redacted, strings.TrimSpace(snippet)),
			Remediation: "Review tool responses and ensure sensitive data is not included.",
		})
	}

	return findings
}

// redactMatch replaces most characters of a match with asterisks.
func redactMatch(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	visible := 2
	return s[:visible] + strings.Repeat("*", len(s)-visible*2) + s[len(s)-visible:]
}
