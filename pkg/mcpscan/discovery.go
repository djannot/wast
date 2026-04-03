package mcpscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/dns"
)

// Discoverer finds MCP servers from local configuration files and network probes.
type Discoverer struct {
	// HTTPTimeout is the timeout for network probe requests.
	HTTPTimeout time.Duration
	// httpClient is used for network probing (overrideable in tests).
	httpClient *http.Client
	// ProjectDir, when set, causes Discover() to also run DiscoverDependencies
	// against the given directory and surface out-of-date MCP packages as findings.
	ProjectDir string
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
// If d.ProjectDir is set, dependency scanning is also performed and any
// out-of-date MCP packages are surfaced as MCPFinding entries.
func (d *Discoverer) Discover(ctx context.Context) *DiscoveryResult {
	result := &DiscoveryResult{
		Servers:  []DiscoveredServer{},
		Sources:  []string{},
		Errors:   []string{},
		Findings: []MCPFinding{},
	}

	// Discover from local config files.
	d.discoverLocalConfigs(result)

	// Scan project dependencies if a project directory is configured.
	if d.ProjectDir != "" {
		depResult := d.DiscoverDependencies(ctx, d.ProjectDir)
		result.Sources = append(result.Sources, depResult.Sources...)
		result.Errors = append(result.Errors, depResult.Errors...)
		result.Findings = append(result.Findings, depResult.Findings...)
	}

	return result
}

// normalizeNetworkTarget ensures the target has an https:// scheme.
// Accepts "solo.io", "https://solo.io", or "https://solo.io/path".
func normalizeNetworkTarget(target string) string {
	target = strings.TrimSpace(target)
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	return target
}

// extractDomain returns just the hostname from a URL or bare domain.
func extractDomain(target string) string {
	target = normalizeNetworkTarget(target)
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	return parsed.Hostname()
}

// DiscoverNetwork probes a target host for MCP endpoints.
// The target can be a bare domain ("solo.io") or a full URL ("https://solo.io").
func (d *Discoverer) DiscoverNetwork(ctx context.Context, baseURL string) *DiscoveryResult {
	baseURL = normalizeNetworkTarget(baseURL)

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
		if probe := d.probeHTTPEndpoint(ctx, url); probe.found {
			result.Servers = append(result.Servers, DiscoveredServer{
				Transport:    "http",
				Target:       url,
				Source:       "network_probe",
				AuthRequired: probe.authRequired,
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

// DiscoverNetworkDeep performs subdomain enumeration on the target domain, then
// probes each discovered subdomain for MCP endpoints. This combines WAST's DNS
// reconnaissance (CT logs, zone transfers) with MCP endpoint probing.
func (d *Discoverer) DiscoverNetworkDeep(ctx context.Context, target string, progressFn func(msg string)) *DiscoveryResult {
	domain := extractDomain(target)

	result := &DiscoveryResult{
		Servers: []DiscoveredServer{},
		Sources: []string{},
		Errors:  []string{},
	}

	// Step 1: Enumerate subdomains
	if progressFn != nil {
		progressFn(fmt.Sprintf("Enumerating subdomains for %s...", domain))
	}

	subDiscoverer := dns.NewSubdomainDiscoverer(dns.WithSubdomainTimeout(d.HTTPTimeout * 6))
	subdomains, subErrors := subDiscoverer.Discover(ctx, domain)
	result.Errors = append(result.Errors, subErrors...)

	// Always include the base domain itself
	hosts := []string{domain}
	seen := map[string]bool{domain: true}
	for _, sub := range subdomains {
		sub = strings.TrimSuffix(strings.TrimSpace(sub), ".")
		if sub != "" && !seen[sub] {
			seen[sub] = true
			hosts = append(hosts, sub)
		}
	}

	if progressFn != nil {
		progressFn(fmt.Sprintf("Found %d host(s) (1 base + %d subdomains). Probing for MCP endpoints...", len(hosts), len(hosts)-1))
	}

	// Step 2: Probe each host for MCP endpoints
	for i, host := range hosts {
		if progressFn != nil && len(hosts) > 5 && i%10 == 0 {
			progressFn(fmt.Sprintf("Probing host %d/%d: %s", i+1, len(hosts), host))
		}

		hostResult := d.DiscoverNetwork(ctx, "https://"+host)
		result.Servers = append(result.Servers, hostResult.Servers...)
		result.Sources = append(result.Sources, hostResult.Sources...)
		result.Errors = append(result.Errors, hostResult.Errors...)
	}

	return result
}

// --------------------------------------------------------------------------
// MCP Registry discovery
// --------------------------------------------------------------------------

// DefaultRegistryURL is the public MCP registry API base URL.
const DefaultRegistryURL = "https://registry.modelcontextprotocol.io"

// registryListResponse is the top-level response from the MCP registry list endpoint.
type registryListResponse struct {
	Servers    []registryServer `json:"servers"`
	NextCursor string           `json:"next_cursor"`
}

// registryServer represents a single server entry in the MCP registry.
type registryServer struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Connections []registryConn      `json:"connections"`
	Packages    []registryPackage   `json:"packages"`
}

// registryConn describes one transport connection option for a registry server.
type registryConn struct {
	Type    string   `json:"type"`    // "stdio", "sse", "http"
	URL     string   `json:"url"`     // for sse/http connections
	Command string   `json:"command"` // for stdio connections
	Args    []string `json:"args"`    // for stdio connections
}

// registryPackage describes an installable package entry (used to build stdio targets).
type registryPackage struct {
	RegistryName string   `json:"registry_name"` // "npm", "pypi"
	Name         string   `json:"name"`
	Command      string   `json:"command"`
	Args         []string `json:"args"`
}

// maxRegistryPages is a safety cap on the number of pages fetched from the
// registry in a single DiscoverFromRegistry call, preventing infinite loops
// if a buggy or adversarial registry always returns a non-empty next_cursor.
const maxRegistryPages = 500

// DiscoverFromRegistry fetches MCP server entries from the public MCP registry API
// and returns them as DiscoveredServer entries. If transportFilter is non-empty
// (e.g. "sse", "http", "stdio"), only servers with a matching connection type are
// returned. Pagination is handled automatically.
func (d *Discoverer) DiscoverFromRegistry(ctx context.Context, transportFilter string) *DiscoveryResult {
	registryURL := DefaultRegistryURL

	result := &DiscoveryResult{
		Servers: []DiscoveredServer{},
		Sources: []string{registryURL},
		Errors:  []string{},
	}

	cursor := ""
	for page := 0; page < maxRegistryPages; page++ {
		u, err := url.Parse(registryURL + "/v0/servers")
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("build registry URL: %v", err))
			return result
		}
		if cursor != "" {
			q := u.Query()
			q.Set("cursor", cursor)
			u.RawQuery = q.Encode()
		}
		apiURL := u.String()

		servers, nextCursor, err := d.fetchRegistryPage(ctx, apiURL)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("registry fetch %s: %v", apiURL, err))
			return result
		}

		for _, srv := range servers {
			discovered := d.registryServerToDiscovered(srv, transportFilter)
			result.Servers = append(result.Servers, discovered...)
		}

		if nextCursor == "" {
			break
		}
		cursor = nextCursor
	}

	return result
}

// maxRegistryPageSize is the maximum number of bytes read from a single
// registry page response. 4 MiB is generous for a JSON page of server entries.
const maxRegistryPageSize = 4 << 20 // 4 MiB

// fetchRegistryPage retrieves one page of servers from the registry API.
func (d *Discoverer) fetchRegistryPage(ctx context.Context, apiURL string) ([]registryServer, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unexpected status %d from registry", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryPageSize))
	if err != nil {
		return nil, "", fmt.Errorf("read response body: %w", err)
	}
	if len(body) == maxRegistryPageSize {
		return nil, "", fmt.Errorf("registry response exceeded size limit (%d bytes)", maxRegistryPageSize)
	}

	var page registryListResponse
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, "", fmt.Errorf("parse registry response: %w", err)
	}

	return page.Servers, page.NextCursor, nil
}

// registryServerToDiscovered maps a registry server entry to DiscoveredServer
// entries (one per connection type). If transportFilter is non-empty, only
// connections with a matching type are included.
func (d *Discoverer) registryServerToDiscovered(srv registryServer, transportFilter string) []DiscoveredServer {
	var results []DiscoveredServer

	for _, conn := range srv.Connections {
		transport := strings.ToLower(conn.Type)
		if transportFilter != "" && transport != strings.ToLower(transportFilter) {
			continue
		}

		ds := DiscoveredServer{
			Name:      srv.Name,
			Transport: transport,
			Source:    "mcp-registry",
		}

		switch transport {
		case "stdio":
			ds.Target = conn.Command
			ds.Args = conn.Args
		case "sse", "http":
			ds.Target = conn.URL
		default:
			ds.Target = conn.URL
			if ds.Target == "" {
				ds.Target = conn.Command
			}
		}

		// Skip entries with no usable target.
		if ds.Target == "" {
			continue
		}

		results = append(results, ds)
	}

	// If no connections but there are packages, synthesise a stdio entry.
	if len(srv.Connections) == 0 && len(srv.Packages) > 0 {
		if transportFilter == "" || strings.ToLower(transportFilter) == "stdio" {
			pkg := srv.Packages[0]
			cmd := pkg.Command
			if cmd == "" {
				cmd = pkg.Name
			}
			if cmd != "" {
				results = append(results, DiscoveredServer{
					Name:      srv.Name,
					Transport: "stdio",
					Target:    cmd,
					Args:      pkg.Args,
					Source:    "mcp-registry",
				})
			}
		}
	}

	return results
}

// probeResult holds the result of an HTTP MCP endpoint probe.
type probeResult struct {
	found        bool
	authRequired bool
}

// probeHTTPEndpoint checks if an endpoint responds to MCP initialize.
// Returns found=true for 200 (open) or 401 (auth-protected) MCP endpoints.
func (d *Discoverer) probeHTTPEndpoint(ctx context.Context, url string) probeResult {
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"wast-discover","version":"1.0.0"},"capabilities":{}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return probeResult{}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return probeResult{}
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	isJSON := strings.Contains(contentType, "application/json")

	switch resp.StatusCode {
	case http.StatusOK:
		if isJSON {
			return probeResult{found: true}
		}
	case http.StatusUnauthorized:
		// A 401 with JSON response indicates an auth-protected MCP endpoint.
		if isJSON {
			return probeResult{found: true, authRequired: true}
		}
	}

	return probeResult{}
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

// --------------------------------------------------------------------------
// Dependency / registry scanning
// --------------------------------------------------------------------------

// DiscoverDependencies reads package.json, requirements.txt, and pyproject.toml
// inside projectDir, identifies known MCP server packages, queries NPM and PyPI
// for the latest versions, and returns any out-of-date packages as MCPFinding
// entries in the result.
func (d *Discoverer) DiscoverDependencies(ctx context.Context, projectDir string) *DiscoveryResult {
	result := &DiscoveryResult{
		Servers:  []DiscoveredServer{},
		Sources:  []string{},
		Errors:   []string{},
		Findings: []MCPFinding{},
	}

	// Scan NPM dependencies from package.json.
	d.scanPackageJSON(ctx, projectDir, result)

	// Scan Python dependencies from requirements.txt.
	d.scanRequirementsTxt(ctx, projectDir, result)

	// Scan Python dependencies from pyproject.toml.
	d.scanPyprojectToml(ctx, projectDir, result)

	return result
}

// --------------------------------------------------------------------------
// NPM scanning
// --------------------------------------------------------------------------

// npmMCPPatterns reports whether an NPM package name looks like an MCP server.
func npmMCPPackage(name string) bool {
	if strings.HasPrefix(name, "@modelcontextprotocol/") {
		return true
	}
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, "-mcp-server") ||
		strings.HasPrefix(lower, "mcp-server-") ||
		strings.HasSuffix(lower, "-mcp")
}

// scanPackageJSON reads package.json from projectDir, identifies MCP packages,
// queries the NPM registry for the latest version, and appends findings.
func (d *Discoverer) scanPackageJSON(ctx context.Context, projectDir string, result *DiscoveryResult) {
	pkgPath := filepath.Join(projectDir, "package.json")
	result.Sources = append(result.Sources, pkgPath)

	data, err := os.ReadFile(pkgPath)
	if err != nil {
		if !os.IsNotExist(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", pkgPath, err))
		}
		return
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("%s: parse error: %v", pkgPath, err))
		return
	}

	allDeps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	for name, versionSpec := range allDeps {
		if !npmMCPPackage(name) {
			continue
		}
		installedVersion := cleanVersionSpec(versionSpec)
		latest, err := d.fetchNPMLatestVersion(ctx, name)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("npm registry query for %s: %v", name, err))
			continue
		}
		if isOutdated(installedVersion, latest) {
			result.Findings = append(result.Findings, buildOutdatedFinding("npm", name, installedVersion, latest))
		}
	}
}

// fetchNPMLatestVersion queries the NPM registry for the latest version of pkg.
func (d *Discoverer) fetchNPMLatestVersion(ctx context.Context, pkg string) (string, error) {
	// NPM package names with scope (e.g. @org/name) must be URL-encoded as %40org%2Fname.
	encoded := strings.ReplaceAll(pkg, "/", "%2F")
	if strings.HasPrefix(pkg, "@") {
		// The leading @ must also be encoded for scoped packages.
		encoded = "%40" + strings.TrimPrefix(encoded, "@")
	}
	url := "https://registry.npmjs.org/" + encoded

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("package not found on NPM")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("NPM registry returned HTTP %d", resp.StatusCode)
	}

	const maxNPMResponseSize = 1 << 20 // 1 MiB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxNPMResponseSize))
	if err != nil {
		return "", err
	}
	if len(body) == maxNPMResponseSize {
		return "", fmt.Errorf("NPM registry response too large (>1 MiB)")
	}

	var doc struct {
		DistTags struct {
			Latest string `json:"latest"`
		} `json:"dist-tags"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("parse NPM response: %w", err)
	}
	if doc.DistTags.Latest == "" {
		return "", fmt.Errorf("NPM registry did not return a latest version")
	}
	return doc.DistTags.Latest, nil
}

// --------------------------------------------------------------------------
// PyPI scanning
// --------------------------------------------------------------------------

// pypiMCPPackage reports whether a PyPI package name looks like an MCP server.
func pypiMCPPackage(name string) bool {
	lower := strings.ToLower(name)
	return lower == "mcp" ||
		lower == "fastmcp" ||
		strings.HasPrefix(lower, "mcp-server-") ||
		strings.HasPrefix(lower, "mcp_server_")
}

// scanRequirementsTxt reads requirements.txt from projectDir, identifies MCP
// packages, queries PyPI for the latest version, and appends findings.
func (d *Discoverer) scanRequirementsTxt(ctx context.Context, projectDir string, result *DiscoveryResult) {
	reqPath := filepath.Join(projectDir, "requirements.txt")
	result.Sources = append(result.Sources, reqPath)

	f, err := os.Open(reqPath)
	if err != nil {
		if !os.IsNotExist(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", reqPath, err))
		}
		return
	}
	defer f.Close()

	packages := parseRequirementsTxt(f)
	for name, version := range packages {
		if !pypiMCPPackage(name) {
			continue
		}
		d.checkPyPIPackage(ctx, name, version, result)
	}
}

// parseRequirementsTxt parses a requirements.txt reader and returns package→version map.
func parseRequirementsTxt(r io.Reader) map[string]string {
	result := make(map[string]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comments.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Parse "name==version", "name>=version", "name~=version", "name[extra]==version", etc.
		name, version := parseRequirementLine(line)
		if name != "" {
			result[normalizePackageName(name)] = version
		}
	}
	return result
}

// parseRequirementLine splits a requirement spec into package name and pinned version.
// It correctly handles extras notation such as "mcp[cli]==1.0.0" or
// "requests[security]>=2.28.0" by stripping the extras bracket before searching for
// the version operator, while still returning only the bare package name.
func parseRequirementLine(line string) (name, version string) {
	// Build a bracket-stripped line for operator search.
	// "mcp[cli]==1.0.0"           → stripped = "mcp==1.0.0"
	// "requests[security]>=2.28.0"→ stripped = "requests>=2.28.0"
	// "mcp==1.0.0"                → stripped = "mcp==1.0.0"  (unchanged)
	stripped := line
	if bStart := strings.Index(line, "["); bStart >= 0 {
		if bEnd := strings.Index(line, "]"); bEnd > bStart {
			stripped = line[:bStart] + line[bEnd+1:]
		}
	}

	// Find version operator in the bracket-stripped line; the name is everything
	// before the operator.
	for _, op := range []string{"==", "~=", ">=", "<=", "!=", ">", "<"} {
		if idx := strings.Index(stripped, op); idx >= 0 {
			n := strings.TrimSpace(stripped[:idx])
			v := strings.TrimSpace(stripped[idx+len(op):])
			// For ranges like ">=1.0,<2.0" take the first segment only.
			v = strings.Split(v, ",")[0]
			v = strings.TrimSpace(v)
			return n, v
		}
	}
	// No version specifier — return the bare package name (without any extras).
	if bStart := strings.Index(stripped, "["); bStart >= 0 {
		return strings.TrimSpace(stripped[:bStart]), ""
	}
	return strings.TrimSpace(stripped), ""
}

// normalizePackageName lowercases and replaces underscores/dots with hyphens per PEP 503.
func normalizePackageName(name string) string {
	lower := strings.ToLower(name)
	lower = strings.ReplaceAll(lower, "_", "-")
	lower = strings.ReplaceAll(lower, ".", "-")
	return lower
}

// scanPyprojectToml reads pyproject.toml from projectDir, extracts dependencies,
// and checks for MCP packages.
func (d *Discoverer) scanPyprojectToml(ctx context.Context, projectDir string, result *DiscoveryResult) {
	tomlPath := filepath.Join(projectDir, "pyproject.toml")
	result.Sources = append(result.Sources, tomlPath)

	data, err := os.ReadFile(tomlPath)
	if err != nil {
		if !os.IsNotExist(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", tomlPath, err))
		}
		return
	}

	packages := parsePyprojectToml(string(data))
	for name, version := range packages {
		if !pypiMCPPackage(name) {
			continue
		}
		d.checkPyPIPackage(ctx, name, version, result)
	}
}

// parsePyprojectToml extracts dependencies from a pyproject.toml file using
// simple line-by-line parsing (no external TOML library required).
// It handles both [project] dependencies (inline and multi-line arrays) and
// [tool.poetry.dependencies] (key-per-line format).
// Section headers may have trailing inline comments, e.g. "[project]  # my project".
func parsePyprojectToml(content string) map[string]string {
	result := make(map[string]string)
	inDepsSection := false
	inPoetryDeps := false
	// inDepsArray tracks whether we are inside a multi-line [project] deps array.
	inDepsArray := false

	addItem := func(raw string) {
		item := strings.Trim(strings.TrimSpace(raw), `"'`)
		if item == "" || strings.HasPrefix(item, "#") {
			return
		}
		name, version := parseRequirementLine(item)
		if name != "" {
			result[normalizePackageName(name)] = version
		}
	}

	lines := strings.Split(content, "\n")
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)

		// If we are collecting lines of a multi-line deps array, accumulate until "]".
		if inDepsArray {
			if closeIdx := strings.Index(line, "]"); closeIdx >= 0 {
				// Items may appear before the closing bracket on this line.
				for _, item := range strings.Split(line[:closeIdx], ",") {
					addItem(item)
				}
				inDepsArray = false
			} else {
				// Strip trailing comma; the item is the whole (trimmed) line.
				addItem(strings.TrimRight(line, ","))
			}
			continue
		}

		// Detect section headers. Strip trailing inline comments to handle
		// forms like "[project]  # description".
		if strings.HasPrefix(line, "[") {
			// Remove inline comment: take the part before any " #" outside the brackets.
			headerLine := line
			if ci := strings.Index(line, " #"); ci >= 0 {
				headerLine = strings.TrimSpace(line[:ci])
			}
			inDepsSection = headerLine == "[project]"
			inPoetryDeps = headerLine == "[tool.poetry.dependencies]"
			// Any new section ends a multi-line array (defensive reset).
			inDepsArray = false
			continue
		}

		// Inside [project], look for "dependencies = [...]" array.
		if inDepsSection && strings.HasPrefix(line, "dependencies") {
			if openIdx := strings.Index(line, "["); openIdx >= 0 {
				if closeIdx := strings.Index(line, "]"); closeIdx > openIdx {
					// Single-line array: dependencies = ["mcp==1.0", "fastmcp>=2.0"]
					inner := line[openIdx+1 : closeIdx]
					for _, item := range strings.Split(inner, ",") {
						addItem(item)
					}
				} else {
					// Multi-line array: opening "[" with no closing "]" on this line.
					inDepsArray = true
				}
			}
			continue
		}

		// Inside [tool.poetry.dependencies], look for key = "version" or key = {version = "..."}
		if inPoetryDeps && line != "" && !strings.HasPrefix(line, "#") {
			if idx := strings.Index(line, "="); idx >= 0 {
				name := strings.TrimSpace(line[:idx])
				valPart := strings.TrimSpace(line[idx+1:])
				if name == "python" {
					continue
				}
				// Strip quotes.
				version := strings.Trim(valPart, `"'^~>=`)
				// Handle {version = "^1.2.3"} inline tables.
				if strings.HasPrefix(valPart, "{") {
					if vi := strings.Index(valPart, "version"); vi >= 0 {
						rest := valPart[vi:]
						if ei := strings.Index(rest, "="); ei >= 0 {
							v := strings.TrimSpace(rest[ei+1:])
							v = strings.Trim(v, `"'^~>=, }`)
							version = v
						}
					}
				}
				result[normalizePackageName(name)] = cleanVersionSpec(version)
			}
		}
	}
	return result
}

// checkPyPIPackage queries PyPI for the latest version of a package and, if the
// installed version is out of date, appends a finding to result.
func (d *Discoverer) checkPyPIPackage(ctx context.Context, name, installedVersion string, result *DiscoveryResult) {
	latest, err := d.fetchPyPILatestVersion(ctx, name)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("pypi query for %s: %v", name, err))
		return
	}
	if isOutdated(installedVersion, latest) {
		result.Findings = append(result.Findings, buildOutdatedFinding("pypi", name, installedVersion, latest))
	}
}

// fetchPyPILatestVersion queries the PyPI JSON API for the latest version of pkg.
func (d *Discoverer) fetchPyPILatestVersion(ctx context.Context, pkg string) (string, error) {
	url := "https://pypi.org/pypi/" + pkg + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("package not found on PyPI")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("PyPI returned HTTP %d", resp.StatusCode)
	}

	const maxPyPIResponseSize = 1 << 20 // 1 MiB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPyPIResponseSize))
	if err != nil {
		return "", err
	}
	if len(body) == maxPyPIResponseSize {
		return "", fmt.Errorf("PyPI registry response too large (>1 MiB)")
	}

	var doc struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("parse PyPI response: %w", err)
	}
	if doc.Info.Version == "" {
		return "", fmt.Errorf("PyPI did not return a version")
	}
	return doc.Info.Version, nil
}

// --------------------------------------------------------------------------
// Version comparison helpers
// --------------------------------------------------------------------------

// cleanVersionSpec strips NPM-style range operators (^, ~, >=, >, <=, <, =)
// from the front of a version string so that a bare semver remains.
func cleanVersionSpec(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	for len(v) > 0 {
		ch := v[0]
		if ch == '^' || ch == '~' || ch == '>' || ch == '<' || ch == '=' || ch == ' ' {
			v = v[1:]
		} else {
			break
		}
	}
	if v == "" {
		return ""
	}
	// Take only the first version part for ranges like "1.0.0 || >=2.0.0".
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return ""
	}
	v = fields[0]
	v = strings.Split(v, ",")[0]
	return v
}

// parseVersion splits a dotted version string into numeric segments.
// Non-numeric suffixes (e.g. "-beta") are ignored for the purposes of comparison.
func parseVersion(v string) []int {
	// Drop pre-release suffix after first non-numeric, non-dot character run.
	for i, ch := range v {
		if ch != '.' && (ch < '0' || ch > '9') {
			v = v[:i]
			break
		}
	}
	parts := strings.Split(strings.TrimRight(v, "."), ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		nums = append(nums, n)
	}
	return nums
}

// isOutdated returns true when installed is strictly less than latest.
// If installed is empty or cannot be parsed, it is considered outdated.
func isOutdated(installed, latest string) bool {
	installed = cleanVersionSpec(installed)
	latest = cleanVersionSpec(latest)
	if installed == "" || installed == latest {
		return false
	}
	iv := parseVersion(installed)
	lv := parseVersion(latest)
	if len(iv) == 0 {
		// Cannot parse installed version — flag it.
		return true
	}
	maxLen := len(iv)
	if len(lv) > maxLen {
		maxLen = len(lv)
	}
	for i := 0; i < maxLen; i++ {
		var a, b int
		if i < len(iv) {
			a = iv[i]
		}
		if i < len(lv) {
			b = lv[i]
		}
		if a < b {
			return true
		}
		if a > b {
			return false
		}
	}
	return false
}

// buildOutdatedFinding constructs an MCPFinding for an out-of-date MCP package.
// installedVersion must be non-empty (callers gate on isOutdated which returns
// false for empty installed versions).
func buildOutdatedFinding(registry, pkg, installedVersion, latestVersion string) MCPFinding {
	return MCPFinding{
		Category: CategoryDependency,
		Severity: SeverityMedium,
		Title:    fmt.Sprintf("Outdated MCP package: %s", pkg),
		Description: fmt.Sprintf(
			"The %s package %q is pinned to version %s, but the latest available version is %s. "+
				"Running outdated MCP server packages may expose the application to known security vulnerabilities.",
			registry, pkg, installedVersion, latestVersion,
		),
		Evidence: fmt.Sprintf("installed=%s latest=%s registry=%s", installedVersion, latestVersion, registry),
		Remediation: fmt.Sprintf(
			"Upgrade %s to version %s or later to ensure you have the latest security fixes.",
			pkg, latestVersion,
		),
	}
}
