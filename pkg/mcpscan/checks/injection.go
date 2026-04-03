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

// SQLi evidence: specific database error signatures, NOT generic "error".
var sqlInjectionPayloads = []injectionPayload{
	{Value: "' OR '1'='1", Type: "SQLi", Evidence: []string{"syntax error", "mysql", "sqlite", "postgresql", "ORA-", "SQLSTATE", "unterminated", "near \"'\""}},
	{Value: `1; DROP TABLE users--`, Type: "SQLi", Evidence: []string{"syntax error", "mysql", "sqlite", "postgresql", "ORA-", "SQLSTATE"}},
	{Value: `" OR "1"="1`, Type: "SQLi", Evidence: []string{"syntax error", "mysql", "sqlite", "postgresql", "ORA-", "SQLSTATE"}},
}

var cmdInjectionPayloads = []injectionPayload{
	{Value: "; id", Type: "CMDi", Evidence: []string{"uid=", "gid="}},
	{Value: "| id", Type: "CMDi", Evidence: []string{"uid=", "gid="}},
	{Value: "`id`", Type: "CMDi", Evidence: []string{"uid=", "gid="}},
	{Value: "$(id)", Type: "CMDi", Evidence: []string{"uid=", "gid="}},
}

var pathTraversalPayloads = []injectionPayload{
	{Value: "../../etc/passwd", Type: "PathTraversal", Evidence: []string{"root:x:0:0:", "daemon:x:1:1:"}},
	{Value: "../../../etc/passwd", Type: "PathTraversal", Evidence: []string{"root:x:0:0:", "daemon:x:1:1:"}},
	{Value: "..\\..\\windows\\system32\\drivers\\etc\\hosts", Type: "PathTraversal", Evidence: []string{"127.0.0.1"}},
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
	// Step 1: Get a baseline response with a normal value.
	// This tells us what the tool returns for benign input.
	baselineArgs := map[string]interface{}{param.Name: "test_baseline_value"}
	for _, p := range tool.Parameters {
		if p.Name == param.Name {
			continue
		}
		if p.Required {
			baselineArgs[p.Name] = defaultValueForType(p.Type)
		}
	}

	baselineResp, baselineErr := caller.CallTool(ctx, tool.Name, baselineArgs)
	baselineText := ""
	baselineErrText := ""
	if baselineErr != nil {
		baselineErrText = strings.ToLower(baselineErr.Error())
	} else {
		baselineText = strings.ToLower(extractResponseText(baselineResp))
	}

	// Step 2: Test each payload and compare against baseline.
	var findings []Finding
	allPayloads := make([]injectionPayload, 0, len(sqlInjectionPayloads)+len(cmdInjectionPayloads)+len(pathTraversalPayloads))
	allPayloads = append(allPayloads, sqlInjectionPayloads...)
	allPayloads = append(allPayloads, cmdInjectionPayloads...)
	allPayloads = append(allPayloads, pathTraversalPayloads...)

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
				evidenceLower := strings.ToLower(evidence)
				// Only flag if evidence appears in the error AND was NOT in the baseline error.
				if strings.Contains(errStr, evidenceLower) && !strings.Contains(baselineErrText, evidenceLower) {
					findings = append(findings, Finding{
						Tool:      tool.Name,
						Parameter: param.Name,
						Category:  CategoryInjection,
						Severity:  SeverityHigh,
						Title:     fmt.Sprintf("%s injection detected via error response (%s.%s)", payload.Type, tool.Name, param.Name),
						Description: fmt.Sprintf(
							"Tool %q parameter %q returned an error containing %q when tested with payload %q. "+
								"This pattern was NOT present in the baseline response with a normal value, "+
								"suggesting the payload reached an underlying system (database, shell, file system).",
							tool.Name, param.Name, evidence, payload.Value,
						),
						Evidence:    fmt.Sprintf("Payload error: %s\nBaseline error: %s", truncate(err.Error(), 200), truncate(baselineErrText, 200)),
						Remediation: "Use parameterized queries / command allowlists. Sanitize input. Never concatenate user input directly.",
					})
					break
				}
			}
			continue
		}

		respStr := strings.ToLower(extractResponseText(resp))
		for _, evidence := range payload.Evidence {
			evidenceLower := strings.ToLower(evidence)
			// Only flag if evidence appears in the payload response AND was NOT in the baseline response.
			if strings.Contains(respStr, evidenceLower) && !strings.Contains(baselineText, evidenceLower) {
				findings = append(findings, Finding{
					Tool:      tool.Name,
					Parameter: param.Name,
					Category:  CategoryInjection,
					Severity:  SeverityCritical,
					Title:     fmt.Sprintf("%s injection detected (%s.%s)", payload.Type, tool.Name, param.Name),
					Description: fmt.Sprintf(
						"Tool %q parameter %q appears vulnerable to %s injection. "+
							"The response contains %q when tested with payload %q, "+
							"but this pattern was NOT present in the baseline response with a normal value.",
						tool.Name, param.Name, payload.Type, evidence, payload.Value,
					),
					Evidence:    fmt.Sprintf("Payload response: %s\nBaseline response: %s", truncate(extractResponseText(resp), 200), truncate(extractResponseText(baselineResp), 200)),
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
