// Package checks provides individual security checks for MCP server scanning.
// The checks package is deliberately isolated from the parent mcpscan package to
// avoid circular imports — it defines its own lightweight Finding and ToolInfo
// types that the parent package maps to its own result types.
package checks

import (
	"fmt"
	"strings"
)

// SchemaChecker performs passive schema analysis on MCP tool definitions.
// It flags missing input validation (required, enum), overly permissive string
// parameters, and undocumented parameters.
type SchemaChecker struct{}

// NewSchemaChecker creates a new SchemaChecker.
func NewSchemaChecker() *SchemaChecker {
	return &SchemaChecker{}
}

// Check runs schema analysis on all tools and returns findings.
func (c *SchemaChecker) Check(tools []ToolInfo) []Finding {
	var findings []Finding
	for _, tool := range tools {
		findings = append(findings, c.checkTool(tool)...)
	}
	return findings
}

// checkTool performs schema checks for a single tool.
func (c *SchemaChecker) checkTool(tool ToolInfo) []Finding {
	var findings []Finding

	// Check 1: Tool has no description.
	if strings.TrimSpace(tool.Description) == "" {
		findings = append(findings, Finding{
			Tool:     tool.Name,
			Category: CategorySchema,
			Severity: SeverityLow,
			Title:    "Tool missing description",
			Description: fmt.Sprintf(
				"Tool %q has no description. Undocumented tools make it harder for "+
					"AI agents to use them safely and may hide unexpected capabilities.",
				tool.Name,
			),
			Remediation: "Add a clear description to the tool that explains what it does, " +
				"what parameters it expects, and any side effects.",
		})
	}

	// Check 2: Tool has no input schema at all.
	if tool.RawSchema == nil {
		findings = append(findings, Finding{
			Tool:     tool.Name,
			Category: CategorySchema,
			Severity: SeverityLow,
			Title:    "Tool missing input schema",
			Description: fmt.Sprintf(
				"Tool %q does not define an input schema. Without a schema, "+
					"parameter types and constraints cannot be validated.",
				tool.Name,
			),
			Remediation: "Define a JSON Schema inputSchema for the tool with property types, " +
				"descriptions, and required fields.",
		})
		return findings
	}

	// Per-parameter checks.
	for _, param := range tool.Parameters {
		findings = append(findings, c.checkParameter(tool.Name, param)...)
	}

	return findings
}

// checkParameter performs schema checks for a single parameter.
func (c *SchemaChecker) checkParameter(toolName string, param ParamInfo) []Finding {
	var findings []Finding

	// Check 3: String parameter with dangerous name but no constraints.
	if strings.EqualFold(param.Type, "string") && !param.HasEnum {
		desc := strings.ToLower(param.Description)
		dangerous := []string{
			"path", "file", "command", "cmd", "query", "sql", "script",
			"url", "uri", "address", "host", "exec", "run", "eval",
		}
		for _, kw := range dangerous {
			if strings.Contains(desc, kw) || strings.Contains(strings.ToLower(param.Name), kw) {
				findings = append(findings, Finding{
					Tool:      toolName,
					Parameter: param.Name,
					Category:  CategorySchema,
					Severity:  SeverityMedium,
					Title:     "Potentially dangerous unconstrained string parameter",
					Description: fmt.Sprintf(
						"Parameter %q of tool %q appears to accept %s-related input "+
							"but has no enum constraints or pattern validation. "+
							"This may allow injection attacks.",
						param.Name, toolName, kw,
					),
					Evidence:    fmt.Sprintf("Parameter name: %s, description: %s", param.Name, param.Description),
					Remediation: "Add an enum of allowed values, a regex pattern constraint, or explicit allowlist validation.",
				})
				break
			}
		}
	}

	// Check 4: Undocumented parameter.
	if strings.TrimSpace(param.Description) == "" {
		findings = append(findings, Finding{
			Tool:      toolName,
			Parameter: param.Name,
			Category:  CategorySchema,
			Severity:  SeverityLow,
			Title:     "Undocumented parameter",
			Description: fmt.Sprintf(
				"Parameter %q of tool %q has no description. "+
					"Undocumented parameters make it difficult to understand "+
					"expected input and may hide injection vectors.",
				param.Name, toolName,
			),
			Remediation: "Add a description to the parameter explaining its purpose and expected format.",
		})
	}

	return findings
}
