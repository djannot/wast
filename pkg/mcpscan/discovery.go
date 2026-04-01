package mcpscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Discoverer finds MCP servers from local configuration files and network probes.
type Discoverer struct {
	// HTTPTimeout is the timeout for network probe requests.
	HTTPTimeout time.Duration
	// httpClient is used for network probing (overrideable in tests).
	httpClient *http.Client
}

// NewDiscoverer creates a new Discoverer with sensible defaults.
func NewDiscoverer() *Discoverer {
	return &Discoverer{
		HTTPTimeout: 5 * time.Second,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
}

// WithHTTPTimeout sets the HTTP timeout for network probes.
func (d *Discoverer) WithHTTPTimeout(t time.Duration) *Discoverer {
	d.HTTPTimeout = t
	d.httpClient.Timeout = t
	return d
}

// Discover scans for MCP servers using all available discovery methods.
func (d *Discoverer) Discover(ctx context.Context) *DiscoveryResult {
	result := &DiscoveryResult{
		Servers: []DiscoveredServer{},
		Sources: []string{},
		Errors:  []string{},
	}

	// Discover from local config files.
	d.discoverLocalConfigs(result)

	return result
}

// DiscoverNetwork probes a target host for MCP endpoints.
func (d *Discoverer) DiscoverNetwork(ctx context.Context, baseURL string) *DiscoveryResult {
	result := &DiscoveryResult{
		Servers: []DiscoveredServer{},
		Sources: []string{},
		Errors:  []string{},
	}

	// HTTP paths to probe (excludes /sse which is probed separately as SSE).
	paths := []string{
		"/.well-known/mcp",
		"/mcp",
		"/api/mcp",
		"/v1/mcp",
	}

	for _, path := range paths {
		url := strings.TrimRight(baseURL, "/") + path
		result.Sources = append(result.Sources, url)
		if d.probeHTTPEndpoint(ctx, url) {
			result.Servers = append(result.Servers, DiscoveredServer{
				Transport: "http",
				Target:    url,
				Source:    "network_probe",
			})
		}
	}

	// Probe the /sse endpoint separately as an SSE transport.
	sseURL := strings.TrimRight(baseURL, "/") + "/sse"
	result.Sources = append(result.Sources, sseURL)
	if d.probeSSEEndpoint(ctx, sseURL) {
		result.Servers = append(result.Servers, DiscoveredServer{
			Transport: "sse",
			Target:    sseURL,
			Source:    "network_probe",
		})
	}

	return result
}

// probeHTTPEndpoint checks if an endpoint responds to MCP initialize.
func (d *Discoverer) probeHTTPEndpoint(ctx context.Context, url string) bool {
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"wast-discover","version":"1.0.0"},"capabilities":{}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	// Check for JSON-RPC 2.0 response indicators.
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

// probeSSEEndpoint checks if an endpoint responds with SSE content type.
func (d *Discoverer) probeSSEEndpoint(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "text/event-stream")
}

// discoverLocalConfigs reads known MCP configuration files.
func (d *Discoverer) discoverLocalConfigs(result *DiscoveryResult) {
	home, err := os.UserHomeDir()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("could not determine home directory: %v", err))
		return
	}

	configFiles := d.buildConfigFilePaths(home)

	for _, cf := range configFiles {
		result.Sources = append(result.Sources, cf.path)
		servers, err := d.parseConfigFile(cf.path, cf.format)
		if err != nil {
			if !os.IsNotExist(err) {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", cf.path, err))
			}
			continue
		}
		for _, s := range servers {
			s.Source = cf.path
			result.Servers = append(result.Servers, s)
		}
	}

	// Also check .mcp.json in the current directory.
	if servers, err := d.parseConfigFile(".mcp.json", "mcp_json"); err == nil {
		for _, s := range servers {
			s.Source = ".mcp.json"
			result.Servers = append(result.Servers, s)
		}
	}
}

// configFileSpec describes a known MCP config file location and format.
type configFileSpec struct {
	path   string
	format string
}

// buildConfigFilePaths returns known MCP config file paths for the current OS.
func (d *Discoverer) buildConfigFilePaths(home string) []configFileSpec {
	specs := []configFileSpec{
		// Claude Desktop (macOS)
		{path: filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), format: "claude_desktop"},
		// Claude Code
		{path: filepath.Join(home, ".claude.json"), format: "claude_code"},
		// Cursor
		{path: filepath.Join(home, ".cursor", "mcp.json"), format: "mcp_json"},
		// VS Code
		{path: filepath.Join(".vscode", "mcp.json"), format: "mcp_json"},
		// Windsurf
		{path: filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), format: "mcp_json"},
		// Cline (macOS)
		{path: filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), format: "cline"},
	}

	if runtime.GOOS == "linux" {
		// Claude Desktop (Linux)
		specs = append(specs, configFileSpec{
			path:   filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
			format: "claude_desktop",
		})
		// Cline (Linux)
		specs = append(specs, configFileSpec{
			path:   filepath.Join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
			format: "cline",
		})
	}

	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			specs = append(specs, configFileSpec{
				path:   filepath.Join(appData, "Claude", "claude_desktop_config.json"),
				format: "claude_desktop",
			})
		}
	}

	return specs
}

// parseConfigFile reads an MCP config file and extracts server definitions.
func (d *Discoverer) parseConfigFile(path, format string) ([]DiscoveredServer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	switch format {
	case "claude_desktop", "cline":
		return parseClaudeDesktopConfig(raw)
	case "claude_code":
		return parseClaudeCodeConfig(raw)
	case "mcp_json":
		return parseMCPJsonConfig(raw)
	default:
		return parseClaudeDesktopConfig(raw)
	}
}

// mcpServerDef is the common server definition format used by most config files.
type mcpServerDef struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
	Type    string            `json:"type"` // "stdio", "sse", "http"
}

// parseClaudeDesktopConfig parses the Claude Desktop / Cline config format.
// Expected structure: {"mcpServers": {"name": {"command": ..., "args": ..., "env": ...}}}
func parseClaudeDesktopConfig(raw map[string]json.RawMessage) ([]DiscoveredServer, error) {
	mcpRaw, ok := raw["mcpServers"]
	if !ok {
		return nil, nil
	}
	var servers map[string]mcpServerDef
	if err := json.Unmarshal(mcpRaw, &servers); err != nil {
		return nil, fmt.Errorf("parse mcpServers: %w", err)
	}
	return serverDefsToDiscovered(servers), nil
}

// parseClaudeCodeConfig parses the Claude Code ~/.claude.json format.
func parseClaudeCodeConfig(raw map[string]json.RawMessage) ([]DiscoveredServer, error) {
	// Claude Code may have mcpServers at top level or nested.
	if mcpRaw, ok := raw["mcpServers"]; ok {
		var servers map[string]mcpServerDef
		if err := json.Unmarshal(mcpRaw, &servers); err != nil {
			return nil, fmt.Errorf("parse mcpServers: %w", err)
		}
		return serverDefsToDiscovered(servers), nil
	}
	return nil, nil
}

// parseMCPJsonConfig parses generic mcp.json format.
func parseMCPJsonConfig(raw map[string]json.RawMessage) ([]DiscoveredServer, error) {
	// Two common shapes: {servers: {...}} or {mcpServers: {...}}
	for _, key := range []string{"servers", "mcpServers"} {
		if mcpRaw, ok := raw[key]; ok {
			var servers map[string]mcpServerDef
			if err := json.Unmarshal(mcpRaw, &servers); err != nil {
				continue
			}
			return serverDefsToDiscovered(servers), nil
		}
	}
	return nil, nil
}

// serverDefsToDiscovered converts a map of server definitions to DiscoveredServer slice.
func serverDefsToDiscovered(servers map[string]mcpServerDef) []DiscoveredServer {
	result := make([]DiscoveredServer, 0, len(servers))
	for name, def := range servers {
		transport := def.Type
		if transport == "" {
			if def.URL != "" {
				transport = "http"
			} else {
				transport = "stdio"
			}
		}

		target := def.Command
		if def.URL != "" {
			target = def.URL
		}

		envSlice := make(map[string]string)
		if def.Env != nil {
			envSlice = def.Env
		}

		result = append(result, DiscoveredServer{
			Name:      name, // human-readable key from the config file
			Transport: transport,
			Target:    target,
			Args:      def.Args,
			Env:       envSlice,
		})
	}
	return result
}
