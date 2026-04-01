package checks

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"
)

// PromptChecker detects prompt injection indicators in tool and parameter descriptions.
type PromptChecker struct{}

// NewPromptChecker creates a new PromptChecker.
func NewPromptChecker() *PromptChecker {
	return &PromptChecker{}
}

// promptInjectionPatterns are case-insensitive substrings that indicate prompt injection.
var promptInjectionPatterns = []string{
	"ignore previous",
	"ignore all previous",
	"ignore the above",
	"ignore prior",
	"forget everything",
	"disregard",
	"you must",
	"you should now",
	"you are now",
	"act as",
	"from now on",
	"new instructions",
	"override",
	"jailbreak",
	"do not follow",
	"bypass",
	"your new role",
	"confidential system prompt",
	"system: ",
	"<system>",
	"[system]",
	"[inst]",
	"[/inst]",
	"</s>",
	"###instruction",
	"###system",
}

// hiddenUnicodeRange is a Unicode range used to hide text.
type hiddenUnicodeRange struct {
	start, end rune
	name       string
}

var hiddenUnicodeRanges = []hiddenUnicodeRange{
	{0x200B, 0x200F, "zero-width characters"},
	{0x202A, 0x202E, "bidi override characters"},
	{0xFFF0, 0xFFFF, "specials block"},
	{0xE0000, 0xE007F, "tag characters"},
	{0x2060, 0x2064, "invisible formatting characters"},
}

// Check runs prompt injection analysis on all tools.
func (c *PromptChecker) Check(tools []ToolInfo) []Finding {
	var findings []Finding
	for _, tool := range tools {
		findings = append(findings, c.checkTool(tool)...)
	}
	return findings
}

// checkTool checks a single tool for prompt injection indicators.
func (c *PromptChecker) checkTool(tool ToolInfo) []Finding {
	var findings []Finding
	if tool.Description != "" {
		findings = append(findings, c.checkText(tool.Name, "", tool.Description)...)
	}
	for _, param := range tool.Parameters {
		if param.Description != "" {
			findings = append(findings, c.checkText(tool.Name, param.Name, param.Description)...)
		}
	}
	return findings
}

// checkText runs all prompt-injection checks on a piece of text.
func (c *PromptChecker) checkText(toolName, paramName, text string) []Finding {
	var findings []Finding
	location := toolName
	if paramName != "" {
		location = fmt.Sprintf("%s.%s", toolName, paramName)
	}
	lower := strings.ToLower(text)

	// Check 1: Known injection patterns.
	for _, pattern := range promptInjectionPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			findings = append(findings, Finding{
				Tool:      toolName,
				Parameter: paramName,
				Category:  CategoryPrompt,
				Severity:  SeverityHigh,
				Title:     "Potential prompt injection in tool description",
				Description: fmt.Sprintf(
					"The description of %q contains the pattern %q which is commonly "+
						"used in prompt injection attacks to manipulate AI agent behavior.",
					location, pattern,
				),
				Evidence:    truncate(text, 200),
				Remediation: "Review and sanitize the tool/parameter description. Remove any AI-directed instructions.",
			})
			break
		}
	}

	// Check 2: Hidden Unicode characters.
	if hiddenChars := findHiddenUnicode(text); len(hiddenChars) > 0 {
		findings = append(findings, Finding{
			Tool:      toolName,
			Parameter: paramName,
			Category:  CategoryPrompt,
			Severity:  SeverityCritical,
			Title:     "Hidden Unicode characters in description",
			Description: fmt.Sprintf(
				"The description of %q contains hidden Unicode characters (%s) "+
					"that may be used to conceal instructions from human reviewers.",
				location, strings.Join(hiddenChars, ", "),
			),
			Evidence:    fmt.Sprintf("Characters found: %v", hiddenChars),
			Remediation: "Remove all hidden Unicode characters from tool and parameter descriptions.",
		})
	}

	// Check 3: Base64-encoded payload.
	if b64 := findBase64Payload(text); b64 != "" {
		findings = append(findings, Finding{
			Tool:      toolName,
			Parameter: paramName,
			Category:  CategoryPrompt,
			Severity:  SeverityHigh,
			Title:     "Base64-encoded content in description",
			Description: fmt.Sprintf(
				"The description of %q contains a base64-encoded payload. "+
					"This may be used to hide instructions from static analysis.",
				location,
			),
			Evidence:    truncate(b64, 100),
			Remediation: "Remove or explain any base64-encoded content in descriptions.",
		})
	}

	// Check 4: Excessively long description.
	if len(text) > 2000 {
		findings = append(findings, Finding{
			Tool:      toolName,
			Parameter: paramName,
			Category:  CategoryPrompt,
			Severity:  SeverityMedium,
			Title:     "Excessively long tool description",
			Description: fmt.Sprintf(
				"The description of %q is %d characters long. "+
					"Unusually long descriptions may contain hidden instructions.",
				location, len(text),
			),
			Evidence:    fmt.Sprintf("Description length: %d characters", len(text)),
			Remediation: "Review the description for hidden content; trim to a reasonable length.",
		})
	}

	return findings
}

// findHiddenUnicode scans text for hidden Unicode codepoints.
func findHiddenUnicode(text string) []string {
	found := map[string]bool{}
	for _, r := range text {
		if r > unicode.MaxASCII {
			for _, rng := range hiddenUnicodeRanges {
				if r >= rng.start && r <= rng.end {
					found[rng.name] = true
				}
			}
		}
	}
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	return names
}

// findBase64Payload looks for a base64-encoded string of at least 32 characters.
func findBase64Payload(text string) string {
	const minLen = 32
	words := strings.Fields(text)
	for _, word := range words {
		word = strings.Trim(word, `.,;:!?"'()[]{}`)
		if len(word) < minLen {
			continue
		}
		if isBase64Like(word) {
			if decoded, err := base64.StdEncoding.DecodeString(word); err == nil && len(decoded) > 0 {
				return word
			}
			if decoded, err := base64.URLEncoding.DecodeString(word); err == nil && len(decoded) > 0 {
				return word
			}
		}
	}
	return ""
}

// isBase64Like checks if a string consists only of base64 characters.
func isBase64Like(s string) bool {
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
			c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// truncate shortens a string to at most maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
