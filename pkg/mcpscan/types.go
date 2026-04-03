// Package mcpscan provides security scanning functionality for MCP (Model Context Protocol) servers.
// MCP servers expose tools via JSON-RPC 2.0 over stdio/SSE/HTTP transports and represent
// a new attack surface as AI tooling proliferates.
package mcpscan

import "time"

// Severity represents the severity level of a security finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// CheckCategory groups findings by type of security concern.
type CheckCategory string

const (
	CategorySchema      CheckCategory = "schema"
	CategoryPrompt      CheckCategory = "prompt_injection"
	CategoryPermissions CheckCategory = "permissions"
	CategoryShadowing   CheckCategory = "tool_shadowing"
	CategoryInjection   CheckCategory = "injection"
	CategoryExposure    CheckCategory = "data_exposure"
	CategorySSRF        CheckCategory = "ssrf"
	CategoryAuth        CheckCategory = "auth_bypass"
	// CategoryDependency covers supply-chain / dependency hygiene findings such as
	// outdated MCP server packages detected via NPM or PyPI registry scanning.
	CategoryDependency CheckCategory = "dependency"
)

// MCPFinding represents a single security finding from an MCP server scan.
type MCPFinding struct {
	// Tool is the name of the MCP tool associated with the finding (empty for server-level).
	Tool string `json:"tool,omitempty" yaml:"tool,omitempty"`
	// Parameter is the tool parameter associated with the finding (empty if N/A).
	Parameter string `json:"parameter,omitempty" yaml:"parameter,omitempty"`
	// Category is the check category that produced the finding.
	Category CheckCategory `json:"category" yaml:"category"`
	// Severity is the assessed severity of the finding.
	Severity Severity `json:"severity" yaml:"severity"`
	// Title is a concise summary of the issue.
	Title string `json:"title" yaml:"title"`
	// Description provides a human-readable explanation.
	Description string `json:"description" yaml:"description"`
	// Evidence is the raw evidence supporting the finding (e.g., payload, response snippet).
	Evidence string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	// Remediation suggests how to fix the issue.
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

// MCPToolParameterInfo describes a single parameter of an MCP tool.
type MCPToolParameterInfo struct {
	// Name is the parameter name.
	Name string `json:"name" yaml:"name"`
	// Type is the JSON schema type (string, number, boolean, object, array).
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// Description is the parameter description from the tool schema.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Required indicates if the parameter is required.
	Required bool `json:"required" yaml:"required"`
	// HasEnum indicates if the parameter has an enumeration of valid values.
	HasEnum bool `json:"has_enum" yaml:"has_enum"`
}

// MCPToolInfo represents metadata about a single MCP tool.
type MCPToolInfo struct {
	// Name is the tool identifier.
	Name string `json:"name" yaml:"name"`
	// Description is the tool's description (a prime target for prompt injection).
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Parameters lists the tool's input parameters.
	Parameters []MCPToolParameterInfo `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	// RawSchema holds the complete inputSchema as returned by the server.
	RawSchema map[string]interface{} `json:"raw_schema,omitempty" yaml:"raw_schema,omitempty"`
}

// MCPServerInfo contains metadata about the scanned MCP server.
type MCPServerInfo struct {
	// Transport is one of "stdio", "sse", or "http".
	Transport string `json:"transport" yaml:"transport"`
	// Target is the connection target (command for stdio, URL for sse/http).
	Target string `json:"target" yaml:"target"`
	// Name is the server's self-reported name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Version is the server's self-reported version.
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	// ProtocolVersion is the MCP protocol version negotiated during initialization.
	ProtocolVersion string `json:"protocol_version,omitempty" yaml:"protocol_version,omitempty"`
	// Tools lists all tools enumerated from the server.
	Tools []MCPToolInfo `json:"tools,omitempty" yaml:"tools,omitempty"`
}

// MCPScanSummary provides aggregate statistics for a scan.
type MCPScanSummary struct {
	// TotalTools is the number of tools enumerated.
	TotalTools int `json:"total_tools" yaml:"total_tools"`
	// TotalFindings is the total number of findings across all checks.
	TotalFindings int `json:"total_findings" yaml:"total_findings"`
	// BySeverity maps severity strings to finding counts.
	BySeverity map[string]int `json:"by_severity" yaml:"by_severity"`
	// ByCategory maps check category strings to finding counts.
	ByCategory map[string]int `json:"by_category" yaml:"by_category"`
	// PassiveChecks indicates how many passive checks were executed.
	PassiveChecks int `json:"passive_checks" yaml:"passive_checks"`
	// ActiveChecks indicates how many active checks were executed (0 if --active not set).
	ActiveChecks int `json:"active_checks" yaml:"active_checks"`
	// Errors lists any non-fatal errors encountered during the scan.
	Errors []string `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// MCPScanResult is the top-level result returned by the MCP scanner.
type MCPScanResult struct {
	// Server contains metadata about the scanned server.
	Server MCPServerInfo `json:"server" yaml:"server"`
	// Findings lists all security findings discovered.
	Findings []MCPFinding `json:"findings" yaml:"findings"`
	// Summary provides aggregate statistics.
	Summary MCPScanSummary `json:"summary" yaml:"summary"`
	// ScanDuration is how long the scan took.
	ScanDuration time.Duration `json:"scan_duration_ms" yaml:"scan_duration_ms"`
	// ActiveMode indicates whether active checks were performed.
	ActiveMode bool `json:"active_mode" yaml:"active_mode"`
}

// DiscoveredServer represents an MCP server found during discovery.
type DiscoveredServer struct {
	// Name is the human-readable key from the configuration file (e.g., "my-server").
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Transport is one of "stdio", "sse", or "http".
	Transport string `json:"transport" yaml:"transport"`
	// Target is the connection target.
	Target string `json:"target" yaml:"target"`
	// Source is where the server was found (e.g., "claude_desktop_config", "network_probe").
	Source string `json:"source" yaml:"source"`
	// Args contains command-line arguments for stdio servers.
	Args []string `json:"args,omitempty" yaml:"args,omitempty"`
	// Env contains environment variables for stdio servers.
	Env map[string]string `json:"env,omitempty" yaml:"env,omitempty"`
	// AuthRequired indicates the server responded with 401 (requires authentication).
	AuthRequired bool `json:"auth_required,omitempty" yaml:"auth_required,omitempty"`
}

// DiscoveryResult is the result of MCP server discovery.
type DiscoveryResult struct {
	// Servers lists all discovered MCP servers.
	Servers []DiscoveredServer `json:"servers" yaml:"servers"`
	// Sources lists all config files and probes checked.
	Sources []string `json:"sources" yaml:"sources"`
	// Errors lists non-fatal errors during discovery.
	Errors []string `json:"errors,omitempty" yaml:"errors,omitempty"`
	// Findings lists security findings from dependency scanning (e.g. outdated packages).
	Findings []MCPFinding `json:"findings,omitempty" yaml:"findings,omitempty"`
}

// ServerScanBrief is a concise per-server entry in a BulkScanSummary.
type ServerScanBrief struct {
	// Name is the human-readable server name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Target is the connection target.
	Target string `json:"target" yaml:"target"`
	// FindingCount is the total number of findings for this server.
	FindingCount int `json:"finding_count" yaml:"finding_count"`
	// TopSeverity is the highest severity observed (empty if no findings).
	TopSeverity string `json:"top_severity,omitempty" yaml:"top_severity,omitempty"`
	// Errored is true if the scan returned an error.
	Errored bool `json:"errored,omitempty" yaml:"errored,omitempty"`
	// AuthRequired is true if the server requires authentication.
	AuthRequired bool `json:"auth_required,omitempty" yaml:"auth_required,omitempty"`
	// Unreachable is true if the server could not be reached.
	Unreachable bool `json:"unreachable,omitempty" yaml:"unreachable,omitempty"`
}

// TopFinding tracks how many servers share a finding with a given title.
type TopFinding struct {
	// Title is the finding title.
	Title string `json:"title" yaml:"title"`
	// ServerCount is the number of servers that have this finding.
	ServerCount int `json:"server_count" yaml:"server_count"`
}

// BulkScanSummary is the aggregated summary after scanning multiple MCP servers.
type BulkScanSummary struct {
	// TotalServers is the total number of servers in the target list.
	TotalServers int `json:"total_servers" yaml:"total_servers"`
	// Scanned is the number of servers actually scanned (excluding skipped).
	Scanned int `json:"scanned" yaml:"scanned"`
	// Skipped is the number of servers skipped (e.g., stdio servers).
	Skipped int `json:"skipped" yaml:"skipped"`
	// Errored is the number of servers where the scan returned an error.
	Errored int `json:"errored" yaml:"errored"`
	// AuthRequired is the number of servers that require authentication.
	AuthRequired int `json:"auth_required" yaml:"auth_required"`
	// Unreachable is the number of servers that could not be reached (network errors).
	Unreachable int `json:"unreachable" yaml:"unreachable"`
	// TotalFindings is the total number of findings across all scanned servers.
	TotalFindings int `json:"total_findings" yaml:"total_findings"`
	// BySeverity maps severity strings to total finding counts.
	BySeverity map[string]int `json:"by_severity" yaml:"by_severity"`
	// ByCategory maps category strings to total finding counts.
	ByCategory map[string]int `json:"by_category" yaml:"by_category"`
	// TopFindings lists the most common findings across servers (by finding title).
	TopFindings []TopFinding `json:"top_findings,omitempty" yaml:"top_findings,omitempty"`
	// Servers provides per-server drill-down data.
	Servers []ServerScanBrief `json:"servers,omitempty" yaml:"servers,omitempty"`
}

// BulkScanRecord is a single server entry used to build a BulkScanSummary.
type BulkScanRecord struct {
	// Name is the human-readable server name.
	Name string
	// Target is the connection target.
	Target string
	// Result is the scan result (nil if the scan failed before producing a result).
	Result *MCPScanResult
	// Skipped is true if this server was skipped (e.g., stdio transport).
	Skipped bool
	// Errored is true if the scan returned a non-nil error.
	Errored bool
	// Unreachable is true if the error appears to be a connectivity failure.
	Unreachable bool
}

// BulkScanResult is the top-level result for a bulk scan, wrapping per-server
// results alongside the aggregated summary. This is the structure emitted for
// JSON/YAML output so AI agents can parse the overview without processing every
// individual result.
type BulkScanResult struct {
	// BulkSummary is the aggregated summary across all servers.
	BulkSummary BulkScanSummary `json:"bulk_summary" yaml:"bulk_summary"`
	// Results contains each per-server scan result (nil entries omitted).
	Results []*MCPScanResult `json:"results,omitempty" yaml:"results,omitempty"`
}
