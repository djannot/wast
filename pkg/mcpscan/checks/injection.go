package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// injectionPayload is a test payload with type and evidence patterns.
type injectionPayload struct {
	Value    string
	Type     string
	Evidence []string
}

var sqlInjectionPayloads = []injectionPayload{
	{Value: "' OR '1'='1", Type: "SQLi", Evidence: []string{"syntax error", "mysql", "sqlite", "postgresql", "ORA-", "SQLSTATE"}},
	{Value: `1; DROP TABLE users--`, Type: "SQLi", Evidence: []string{"syntax error", "error", "exception"}},
	{Value: `" OR "1"="1`, Type: "SQLi", Evidence: []string{"syntax error", "mysql", "sqlite", "error"}},
}

var cmdInjectionPayloads = []injectionPayload{
	{Value: "; id", Type: "CMDi", Evidence: []string{"uid=", "gid=", "root", "user="}},
	{Value: "| id", Type: "CMDi", Evidence: []string{"uid=", "gid=", "root", "user="}},
	{Value: "`id`", Type: "CMDi", Evidence: []string{"uid=", "gid=", "root"}},
	{Value: "$(id)", Type: "CMDi", Evidence: []string{"uid=", "gid=", "root"}},
}

var pathTraversalPayloads = []injectionPayload{
	{Value: "../../etc/passwd", Type: "PathTraversal", Evidence: []string{"root:", "nobody:", "daemon:", "/bin/bash"}},
	{Value: "../../../etc/passwd", Type: "PathTraversal", Evidence: []string{"root:", "nobody:", "daemon:"}},
	{Value: "..\\..\\windows\\system32\\drivers\\etc\\hosts", Type: "PathTraversal", Evidence: []string{"localhost", "127.0.0.1"}},
}

// InjectionChecker performs active injection testing against MCP tool parameters.
type InjectionChecker struct{}

// NewInjectionChecker creates a new InjectionChecker.
func NewInjectionChecker() *InjectionChecker {
	return &InjectionChecker{}
}

// Check runs injection tests against all tools with string parameters.
func (c *InjectionChecker) Check(ctx context.Context, tools []ToolInfo, caller ToolCaller) []Finding {
	var findings []Finding
	for _, tool := range tools {
		findings = append(findings, c.checkTool(ctx, tool, caller)...)
	}
	return findings
}

// checkTool tests a single tool's string parameters with injection payloads.
func (c *InjectionChecker) checkTool(ctx context.Context, tool ToolInfo, caller ToolCaller) []Finding {
	var findings []Finding
	for _, param := range tool.Parameters {
		if !strings.EqualFold(param.Type, "string") {
			continue
		}
		findings = append(findings, c.testParam(ctx, tool, param, caller)...)
	}
	return findings
}

func (c *InjectionChecker) testParam(ctx context.Context, tool ToolInfo, param ParamInfo, caller ToolCaller) []Finding {
	var findings []Finding
	allPayloads := append(append(sqlInjectionPayloads, cmdInjectionPayloads...), pathTraversalPayloads...)

	for _, payload := range allPayloads {
		args := map[string]interface{}{param.Name: payload.Value}
		for _, p := range tool.Parameters {
			if p.Name == param.Name {
				continue
			}
			if p.Required {
				args[p.Name] = defaultValueForType(p.Type)
			}
		}

		resp, err := caller.CallTool(ctx, tool.Name, args)
		if err != nil {
			errStr := strings.ToLower(err.Error())
			for _, evidence := range payload.Evidence {
				if strings.Contains(errStr, strings.ToLower(evidence)) {
					findings = append(findings, Finding{
						Tool:      tool.Name,
						Parameter: param.Name,
						Category:  CategoryInjection,
						Severity:  SeverityHigh,
						Title:     fmt.Sprintf("%s injection detected (error response)", payload.Type),
						Description: fmt.Sprintf(
							"Tool %q parameter %q returned an error containing %q when tested with payload %q.",
							tool.Name, param.Name, evidence, payload.Value,
						),
						Evidence:    fmt.Sprintf("Error: %s", truncate(err.Error(), 300)),
						Remediation: "Use parameterized queries / command allowlists. Sanitize input. Never concatenate user input directly.",
					})
					break
				}
			}
			continue
		}

		respStr := strings.ToLower(extractResponseText(resp))
		for _, evidence := range payload.Evidence {
			if strings.Contains(respStr, strings.ToLower(evidence)) {
				findings = append(findings, Finding{
					Tool:      tool.Name,
					Parameter: param.Name,
					Category:  CategoryInjection,
					Severity:  SeverityCritical,
					Title:     fmt.Sprintf("%s injection detected", payload.Type),
					Description: fmt.Sprintf(
						"Tool %q parameter %q appears vulnerable to %s injection. "+
							"The response contains %q when tested with payload %q.",
						tool.Name, param.Name, payload.Type, evidence, payload.Value,
					),
					Evidence:    truncate(extractResponseText(resp), 300),
					Remediation: "Sanitize all input parameters. Use parameterized queries, avoid shell interpolation.",
				})
				break
			}
		}
	}

	return findings
}

// defaultValueForType returns a safe default value for a parameter type.
func defaultValueForType(t string) interface{} {
	switch strings.ToLower(t) {
	case "number", "integer":
		return 1
	case "boolean":
		return false
	case "array":
		return []interface{}{}
	case "object":
		return map[string]interface{}{}
	default:
		return "test"
	}
}

// extractResponseText extracts human-readable text from a JSON-RPC tools/call result.
func extractResponseText(raw []byte) string {
	if raw == nil {
		return ""
	}
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &result); err == nil {
		var sb strings.Builder
		for _, c := range result.Content {
			sb.WriteString(c.Text)
			sb.WriteString(" ")
		}
		return sb.String()
	}
	return string(raw)
}
