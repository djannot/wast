package checks

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

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
	args := map[string]interface{}{}
	for _, p := range tool.Parameters {
		if p.Required {
			args[p.Name] = defaultValueForType(p.Type)
		}
	}

	resp, err := caller.CallTool(ctx, tool.Name, args)
	if err != nil {
		return c.scanText(tool.Name, err.Error())
	}
	return c.scanText(tool.Name, extractResponseText(resp))
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
