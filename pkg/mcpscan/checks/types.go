package checks

import "context"

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Category groups findings by type of security concern.
type Category string

const (
	CategorySchema      Category = "schema"
	CategoryPrompt      Category = "prompt_injection"
	CategoryPermissions Category = "permissions"
	CategoryShadowing   Category = "tool_shadowing"
	CategoryInjection   Category = "injection"
	CategoryExposure    Category = "data_exposure"
	CategorySSRF        Category = "ssrf"
	CategoryAuth        Category = "auth_bypass"
)

// Finding represents a single security finding from a check.
type Finding struct {
	// Tool is the name of the MCP tool associated with the finding.
	Tool string
	// Parameter is the tool parameter associated with the finding (empty if N/A).
	Parameter string
	// Category is the check category that produced the finding.
	Category Category
	// Severity is the assessed severity.
	Severity Severity
	// Title is a concise summary.
	Title string
	// Description is a human-readable explanation.
	Description string
	// Evidence is the raw evidence supporting the finding.
	Evidence string
	// Remediation suggests how to fix the issue.
	Remediation string
}

// ParamInfo describes a single parameter of an MCP tool.
type ParamInfo struct {
	Name        string
	Type        string
	Description string
	Required    bool
	HasEnum     bool
}

// ToolInfo contains metadata about a single MCP tool.
type ToolInfo struct {
	Name        string
	Description string
	Parameters  []ParamInfo
	RawSchema   map[string]interface{}
}

// ToolCaller is the interface used by active checks to invoke MCP tools.
type ToolCaller interface {
	CallTool(ctx context.Context, toolName string, arguments map[string]interface{}) ([]byte, error)
}
