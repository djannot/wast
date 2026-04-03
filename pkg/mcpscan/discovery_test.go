package mcpscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoverer_EmptyLocalConfig(t *testing.T) {
	d := NewDiscoverer()
	// There won't be any real config files in the CI environment for these paths,
	// but the call should not panic.
	result := d.Discover(context.Background())
	if result == nil {
		t.Fatal("expected non-nil DiscoveryResult")
	}
	if result.Servers == nil {
		t.Error("Servers slice should be initialized, not nil")
	}
}

func TestDiscoverer_ParseClaudeDesktopConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"my-server": map[string]interface{}{
				"command": "npx",
				"args":    []string{"@my/mcp-server"},
			},
		},
	}
	data, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "claude_desktop_config.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	d := NewDiscoverer()
	servers, err := d.parseConfigFile(path, "claude_desktop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Target != "npx" {
		t.Errorf("expected target 'npx', got %q", servers[0].Target)
	}
	if servers[0].Transport != "stdio" {
		t.Errorf("expected transport 'stdio', got %q", servers[0].Transport)
	}
	if servers[0].Name != "my-server" {
		t.Errorf("expected name 'my-server' (from config key), got %q", servers[0].Name)
	}
}

func TestDiscoverer_ParseMCPJsonWithURL(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"servers": map[string]interface{}{
			"remote-server": map[string]interface{}{
				"url":  "https://example.com/mcp",
				"type": "http",
			},
		},
	}
	data, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	d := NewDiscoverer()
	servers, err := d.parseConfigFile(path, "mcp_json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Target != "https://example.com/mcp" {
		t.Errorf("expected target URL, got %q", servers[0].Target)
	}
	if servers[0].Transport != "http" {
		t.Errorf("expected transport 'http', got %q", servers[0].Transport)
	}
}

func TestDiscoverer_NonExistentFile(t *testing.T) {
	d := NewDiscoverer()
	servers, err := d.parseConfigFile("/nonexistent/path/config.json", "claude_desktop")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
	if servers != nil {
		t.Errorf("expected nil servers for missing file, got %v", servers)
	}
}

func TestDiscoverer_DiscoverNetwork_HTTPEndpoint(t *testing.T) {
	// Start a test server that responds like an MCP server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"test","version":"1.0"}}}`))
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	d := NewDiscoverer().WithHTTPTimeout(2 * time.Second)
	result := d.DiscoverNetwork(context.Background(), srv.URL)

	if len(result.Servers) == 0 {
		t.Error("expected at least one discovered server from network probe")
	}
}

func TestDiscoverer_DiscoverNetwork_SSENotDuplicated(t *testing.T) {
	// Verify that the /sse path appears exactly once in Sources even though
	// it is probed both as an HTTP endpoint and as an SSE endpoint.
	d := NewDiscoverer().WithHTTPTimeout(200 * time.Millisecond)
	result := d.DiscoverNetwork(context.Background(), "http://127.0.0.1:19998")
	sseCount := 0
	for _, src := range result.Sources {
		if src == "http://127.0.0.1:19998/sse" {
			sseCount++
		}
	}
	if sseCount != 1 {
		t.Errorf("expected /sse to appear exactly once in Sources, got %d times", sseCount)
	}
}

func TestDiscoverer_DiscoverNetwork_NoServer(t *testing.T) {
	// Non-existent host.
	d := NewDiscoverer().WithHTTPTimeout(500 * time.Millisecond)
	result := d.DiscoverNetwork(context.Background(), "http://127.0.0.1:19999")
	if len(result.Servers) != 0 {
		t.Errorf("expected no servers for unreachable host, got %d", len(result.Servers))
	}
}

func TestServerDefsToDiscovered_InferTransport(t *testing.T) {
	// Command-based → stdio
	defs := map[string]mcpServerDef{
		"cmd-server": {Command: "node", Args: []string{"server.js"}},
	}
	servers := serverDefsToDiscovered(defs)
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Transport != "stdio" {
		t.Errorf("expected stdio transport, got %q", servers[0].Transport)
	}
	if servers[0].Target != "node" {
		t.Errorf("expected target 'node', got %q", servers[0].Target)
	}

	// URL-based → http
	defs2 := map[string]mcpServerDef{
		"http-server": {URL: "https://api.example.com/mcp"},
	}
	servers2 := serverDefsToDiscovered(defs2)
	if len(servers2) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers2))
	}
	if servers2[0].Transport != "http" {
		t.Errorf("expected http transport, got %q", servers2[0].Transport)
	}
	if servers2[0].Target != "https://api.example.com/mcp" {
		t.Errorf("expected target URL, got %q", servers2[0].Target)
	}
	if servers2[0].Name != "http-server" {
		t.Errorf("expected name 'http-server' (from config key), got %q", servers2[0].Name)
	}
	// Also verify cmd-server name is preserved.
	if servers[0].Name != "cmd-server" {
		t.Errorf("expected name 'cmd-server', got %q", servers[0].Name)
	}
}

// --------------------------------------------------------------------------
// Dependency scanning tests
// --------------------------------------------------------------------------

// mockRegistryHandler creates an httptest.Server that serves fake NPM and PyPI
// registry responses. latestNPM maps package name → latest version; latestPyPI
// maps package name → latest version.
func mockRegistryHandler(latestNPM map[string]string, latestPyPI map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// NPM: /[%40org%2F]pkg  or  /@org/pkg
		// PyPI: /pypi/<pkg>/json
		if strings.HasPrefix(path, "/pypi/") && strings.HasSuffix(path, "/json") {
			pkg := strings.TrimSuffix(strings.TrimPrefix(path, "/pypi/"), "/json")
			if v, ok := latestPyPI[pkg]; ok {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"info": map[string]string{"version": v},
				})
				return
			}
			http.NotFound(w, r)
			return
		}

		// NPM: decode package name from path.
		npmPkg := strings.TrimPrefix(path, "/")
		// Re-decode %40 → @ and %2F → /
		npmPkg = strings.ReplaceAll(npmPkg, "%40", "@")
		npmPkg = strings.ReplaceAll(npmPkg, "%2F", "/")
		if v, ok := latestNPM[npmPkg]; ok {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"dist-tags": map[string]string{"latest": v},
			})
			return
		}
		http.NotFound(w, r)
	}))
}

// newDiscovererWithMockRegistry returns a Discoverer whose httpClient points at
// the given test server.
func newDiscovererWithMockRegistry(srv *httptest.Server) *Discoverer {
	d := NewDiscoverer()
	d.httpClient = srv.Client()
	// Override transport to redirect all requests to mock server.
	d.httpClient.Transport = &prefixRoundTripper{
		base:   srv.Client().Transport,
		prefix: srv.URL,
	}
	return d
}

// prefixRoundTripper rewrites all requests to go to a fixed base URL, preserving path+query.
type prefixRoundTripper struct {
	base   http.RoundTripper
	prefix string
}

func (p *prefixRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := p.prefix + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	newReq := req.Clone(req.Context())
	var err error
	newReq.URL, err = newReq.URL.Parse(newURL)
	if err != nil {
		return nil, err
	}
	newReq.Host = newReq.URL.Host
	if p.base != nil {
		return p.base.RoundTrip(newReq)
	}
	return http.DefaultTransport.RoundTrip(newReq)
}

// TestDiscoverDependencies_PackageJSON tests that an outdated @modelcontextprotocol
// package in package.json produces a finding.
func TestDiscoverDependencies_PackageJSON(t *testing.T) {
	srv := mockRegistryHandler(
		map[string]string{"@modelcontextprotocol/server-filesystem": "2.0.0"},
		nil,
	)
	defer srv.Close()

	dir := t.TempDir()
	pkg := map[string]interface{}{
		"dependencies": map[string]string{
			"@modelcontextprotocol/server-filesystem": "^1.0.0",
			"express": "4.18.0", // not an MCP package — should be ignored
		},
	}
	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	d := newDiscovererWithMockRegistry(srv)
	result := d.DiscoverDependencies(context.Background(), dir)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(result.Findings), result.Findings)
	}
	f := result.Findings[0]
	if !strings.Contains(f.Title, "@modelcontextprotocol/server-filesystem") {
		t.Errorf("finding title should mention package name, got %q", f.Title)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("expected medium severity, got %q", f.Severity)
	}
}

// TestDiscoverDependencies_PackageJSON_UpToDate tests that an up-to-date package
// produces no finding.
func TestDiscoverDependencies_PackageJSON_UpToDate(t *testing.T) {
	srv := mockRegistryHandler(
		map[string]string{"mcp-server-git": "1.5.0"},
		nil,
	)
	defer srv.Close()

	dir := t.TempDir()
	pkg := map[string]interface{}{
		"dependencies": map[string]string{
			"mcp-server-git": "1.5.0",
		},
	}
	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	d := newDiscovererWithMockRegistry(srv)
	result := d.DiscoverDependencies(context.Background(), dir)

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for up-to-date package, got %d", len(result.Findings))
	}
}

// TestDiscoverDependencies_RequirementsTxt tests requirements.txt parsing.
func TestDiscoverDependencies_RequirementsTxt(t *testing.T) {
	srv := mockRegistryHandler(
		nil,
		map[string]string{"mcp": "2.1.0"},
	)
	defer srv.Close()

	dir := t.TempDir()
	reqs := "mcp==1.0.0\nrequests>=2.28.0\n# comment line\nfastapi==0.100.0\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(reqs), 0644); err != nil {
		t.Fatal(err)
	}

	d := newDiscovererWithMockRegistry(srv)
	result := d.DiscoverDependencies(context.Background(), dir)

	// mcp==1.0.0 should be outdated (latest 2.1.0)
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Title, "mcp") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a finding for outdated 'mcp' package, got %+v", result.Findings)
	}
}

// TestDiscoverDependencies_RequirementsTxt_NoMCPPackages checks that non-MCP
// packages in requirements.txt produce no findings.
func TestDiscoverDependencies_RequirementsTxt_NoMCPPackages(t *testing.T) {
	srv := mockRegistryHandler(nil, nil)
	defer srv.Close()

	dir := t.TempDir()
	reqs := "django==4.2.0\nrequests==2.28.0\nnumpy==1.25.0\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(reqs), 0644); err != nil {
		t.Fatal(err)
	}

	d := newDiscovererWithMockRegistry(srv)
	result := d.DiscoverDependencies(context.Background(), dir)

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

// TestDiscoverDependencies_PyprojectToml tests pyproject.toml [project] dependencies.
func TestDiscoverDependencies_PyprojectToml(t *testing.T) {
	srv := mockRegistryHandler(
		nil,
		map[string]string{"fastmcp": "0.9.0"},
	)
	defer srv.Close()

	dir := t.TempDir()
	toml := `[project]
name = "my-project"
dependencies = ["fastmcp==0.5.0", "httpx>=0.24.0"]
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	d := newDiscovererWithMockRegistry(srv)
	result := d.DiscoverDependencies(context.Background(), dir)

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Title, "fastmcp") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a finding for outdated 'fastmcp' package, got %+v", result.Findings)
	}
}

// TestDiscoverDependencies_EmptyDir checks that an empty directory produces no
// findings and no fatal errors.
func TestDiscoverDependencies_EmptyDir(t *testing.T) {
	srv := mockRegistryHandler(nil, nil)
	defer srv.Close()

	dir := t.TempDir()
	d := newDiscovererWithMockRegistry(srv)
	result := d.DiscoverDependencies(context.Background(), dir)

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d", len(result.Findings))
	}
}

// TestDiscoverDependencies_DevDependencies checks that devDependencies MCP
// packages are also scanned.
func TestDiscoverDependencies_DevDependencies(t *testing.T) {
	srv := mockRegistryHandler(
		map[string]string{"my-mcp-server": "3.0.0"},
		nil,
	)
	defer srv.Close()

	dir := t.TempDir()
	pkg := map[string]interface{}{
		"devDependencies": map[string]string{
			"my-mcp-server": "1.0.0",
		},
	}
	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	d := newDiscovererWithMockRegistry(srv)
	result := d.DiscoverDependencies(context.Background(), dir)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for outdated devDependency, got %d", len(result.Findings))
	}
}

// --------------------------------------------------------------------------
// Unit tests for helper functions
// --------------------------------------------------------------------------

func TestNpmMCPPackage(t *testing.T) {
	cases := []struct {
		name     string
		expected bool
	}{
		{"@modelcontextprotocol/server-filesystem", true},
		{"@modelcontextprotocol/sdk", true},
		{"mcp-server-git", true},
		{"my-mcp-server", true},
		{"chat-mcp", true},
		{"express", false},
		{"react", false},
		{"mcp-helper", false}, // doesn't match any pattern
	}
	for _, tc := range cases {
		got := npmMCPPackage(tc.name)
		if got != tc.expected {
			t.Errorf("npmMCPPackage(%q) = %v, want %v", tc.name, got, tc.expected)
		}
	}
}

func TestPypiMCPPackage(t *testing.T) {
	cases := []struct {
		name     string
		expected bool
	}{
		{"mcp", true},
		{"fastmcp", true},
		{"mcp-server-git", true},
		{"mcp_server_filesystem", true},
		{"django", false},
		{"requests", false},
		{"mcp-helper", false},
	}
	for _, tc := range cases {
		got := pypiMCPPackage(tc.name)
		if got != tc.expected {
			t.Errorf("pypiMCPPackage(%q) = %v, want %v", tc.name, got, tc.expected)
		}
	}
}

// --------------------------------------------------------------------------
// MCP registry discovery tests
// --------------------------------------------------------------------------

// sampleRegistryPage returns a JSON-encoded registry page with the given servers
// and an optional next_cursor.
func sampleRegistryPage(servers []registryServer, nextCursor string) []byte {
	page := registryListResponse{
		Servers:    servers,
		NextCursor: nextCursor,
	}
	data, _ := json.Marshal(page)
	return data
}

// TestDiscoverFromRegistry_HappyPath verifies that a valid registry response
// produces the expected DiscoveredServer entries.
func TestDiscoverFromRegistry_HappyPath(t *testing.T) {
	servers := []registryServer{
		{
			ID:   "1",
			Name: "http-server",
			Connections: []registryConn{
				{Type: "http", URL: "https://example.com/mcp"},
			},
		},
		{
			ID:   "2",
			Name: "sse-server",
			Connections: []registryConn{
				{Type: "sse", URL: "https://sse.example.com/sse"},
			},
		},
		{
			ID:   "3",
			Name: "stdio-server",
			Connections: []registryConn{
				{Type: "stdio", Command: "npx", Args: []string{"-y", "@my/mcp-server"}},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sampleRegistryPage(servers, ""))
	}))
	defer srv.Close()

	d := newDiscovererWithMockRegistryURL(srv)
	result := d.DiscoverFromRegistry(context.Background(), "")

	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.Servers) != 3 {
		t.Fatalf("expected 3 servers, got %d: %+v", len(result.Servers), result.Servers)
	}

	// Check sources recorded
	if len(result.Sources) == 0 {
		t.Error("expected at least one source")
	}

	// Verify individual entries
	byName := make(map[string]DiscoveredServer)
	for _, s := range result.Servers {
		byName[s.Name] = s
	}

	httpSrv, ok := byName["http-server"]
	if !ok {
		t.Fatal("expected http-server in results")
	}
	if httpSrv.Transport != "http" {
		t.Errorf("expected transport 'http', got %q", httpSrv.Transport)
	}
	if httpSrv.Target != "https://example.com/mcp" {
		t.Errorf("expected target URL, got %q", httpSrv.Target)
	}
	if httpSrv.Source != "mcp-registry" {
		t.Errorf("expected source 'mcp-registry', got %q", httpSrv.Source)
	}

	sseSrv, ok := byName["sse-server"]
	if !ok {
		t.Fatal("expected sse-server in results")
	}
	if sseSrv.Transport != "sse" {
		t.Errorf("expected transport 'sse', got %q", sseSrv.Transport)
	}

	stdioSrv, ok := byName["stdio-server"]
	if !ok {
		t.Fatal("expected stdio-server in results")
	}
	if stdioSrv.Transport != "stdio" {
		t.Errorf("expected transport 'stdio', got %q", stdioSrv.Transport)
	}
	if stdioSrv.Target != "npx" {
		t.Errorf("expected target 'npx', got %q", stdioSrv.Target)
	}
	if len(stdioSrv.Args) != 2 {
		t.Errorf("expected 2 args, got %d", len(stdioSrv.Args))
	}
}

// TestDiscoverFromRegistry_Pagination verifies that multi-page registry responses
// are fetched and merged correctly.
func TestDiscoverFromRegistry_Pagination(t *testing.T) {
	page1Servers := []registryServer{
		{ID: "1", Name: "server-a", Connections: []registryConn{{Type: "http", URL: "https://a.example.com/mcp"}}},
	}
	page2Servers := []registryServer{
		{ID: "2", Name: "server-b", Connections: []registryConn{{Type: "http", URL: "https://b.example.com/mcp"}}},
	}

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Query().Get("cursor") == "page2" {
			_, _ = w.Write(sampleRegistryPage(page2Servers, ""))
		} else {
			_, _ = w.Write(sampleRegistryPage(page1Servers, "page2"))
		}
	}))
	defer srv.Close()

	d := newDiscovererWithMockRegistryURL(srv)
	result := d.DiscoverFromRegistry(context.Background(), "")

	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.Servers) != 2 {
		t.Fatalf("expected 2 servers (one per page), got %d", len(result.Servers))
	}
	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls for pagination, got %d", callCount)
	}
}

// TestDiscoverFromRegistry_NetworkError verifies that a network failure is
// reported as an error without panicking.
func TestDiscoverFromRegistry_NetworkError(t *testing.T) {
	// Point at a port that isn't listening.
	d := NewDiscoverer().WithHTTPTimeout(200 * time.Millisecond)
	// Override the registry URL via a custom round-tripper that always errors.
	d.httpClient = &http.Client{
		Timeout: 200 * time.Millisecond,
		Transport: &errorRoundTripper{},
	}

	result := d.DiscoverFromRegistry(context.Background(), "")

	if len(result.Errors) == 0 {
		t.Error("expected at least one error for network failure")
	}
	if len(result.Servers) != 0 {
		t.Errorf("expected 0 servers on network failure, got %d", len(result.Servers))
	}
}

// errorRoundTripper always returns an error.
type errorRoundTripper struct{}

func (e *errorRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("simulated network failure")
}

// TestDiscoverFromRegistry_MalformedJSON verifies that malformed JSON from the
// registry is reported as an error without panicking.
func TestDiscoverFromRegistry_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{ this is not valid json`))
	}))
	defer srv.Close()

	d := newDiscovererWithMockRegistryURL(srv)
	result := d.DiscoverFromRegistry(context.Background(), "")

	if len(result.Errors) == 0 {
		t.Error("expected error for malformed JSON response")
	}
}

// TestDiscoverFromRegistry_EmptyResponse verifies that an empty servers list
// returns a valid (but empty) DiscoveryResult.
func TestDiscoverFromRegistry_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"servers":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	d := newDiscovererWithMockRegistryURL(srv)
	result := d.DiscoverFromRegistry(context.Background(), "")

	if len(result.Errors) != 0 {
		t.Errorf("unexpected errors: %v", result.Errors)
	}
	if len(result.Servers) != 0 {
		t.Errorf("expected 0 servers for empty response, got %d", len(result.Servers))
	}
}

// TestDiscoverFromRegistry_TransportFilter verifies that --registry-transport
// correctly filters servers by transport type.
func TestDiscoverFromRegistry_TransportFilter(t *testing.T) {
	servers := []registryServer{
		{
			ID:   "1",
			Name: "http-only",
			Connections: []registryConn{
				{Type: "http", URL: "https://http.example.com/mcp"},
			},
		},
		{
			ID:   "2",
			Name: "sse-only",
			Connections: []registryConn{
				{Type: "sse", URL: "https://sse.example.com/sse"},
			},
		},
		{
			ID:   "3",
			Name: "multi-transport",
			Connections: []registryConn{
				{Type: "http", URL: "https://multi.example.com/mcp"},
				{Type: "sse", URL: "https://multi.example.com/sse"},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sampleRegistryPage(servers, ""))
	}))
	defer srv.Close()

	// Filter for SSE only
	d := newDiscovererWithMockRegistryURL(srv)
	result := d.DiscoverFromRegistry(context.Background(), "sse")

	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	// Expect sse-only (1) + multi-transport sse connection (1) = 2
	if len(result.Servers) != 2 {
		t.Fatalf("expected 2 SSE servers after filter, got %d: %+v", len(result.Servers), result.Servers)
	}
	for _, s := range result.Servers {
		if s.Transport != "sse" {
			t.Errorf("expected transport 'sse' after filter, got %q for %s", s.Transport, s.Name)
		}
	}
}

// TestDiscoverFromRegistry_ServerError verifies that a non-200 HTTP response
// is reported as an error.
func TestDiscoverFromRegistry_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	d := newDiscovererWithMockRegistryURL(srv)
	result := d.DiscoverFromRegistry(context.Background(), "")

	if len(result.Errors) == 0 {
		t.Error("expected error for 500 response from registry")
	}
}

// TestDiscoverFromRegistry_FallbackToPackages verifies that registry entries
// with no connections but with packages produce a stdio DiscoveredServer.
func TestDiscoverFromRegistry_FallbackToPackages(t *testing.T) {
	servers := []registryServer{
		{
			ID:   "1",
			Name: "pkg-server",
			Packages: []registryPackage{
				{RegistryName: "npm", Name: "@my/mcp-server", Command: "npx", Args: []string{"-y", "@my/mcp-server"}},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sampleRegistryPage(servers, ""))
	}))
	defer srv.Close()

	d := newDiscovererWithMockRegistryURL(srv)
	result := d.DiscoverFromRegistry(context.Background(), "")

	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.Servers) != 1 {
		t.Fatalf("expected 1 server from package fallback, got %d", len(result.Servers))
	}
	s := result.Servers[0]
	if s.Transport != "stdio" {
		t.Errorf("expected stdio transport for package fallback, got %q", s.Transport)
	}
	if s.Target != "npx" {
		t.Errorf("expected target 'npx', got %q", s.Target)
	}
	if s.Source != "mcp-registry" {
		t.Errorf("expected source 'mcp-registry', got %q", s.Source)
	}
}

// newDiscovererWithMockRegistryURL returns a Discoverer that routes all HTTP
// requests to the mock test server, preserving path and query parameters.
// Unlike newDiscovererWithMockRegistry, this helper is for registry tests where
// we want to intercept calls to DefaultRegistryURL.
func newDiscovererWithMockRegistryURL(srv *httptest.Server) *Discoverer {
	d := NewDiscoverer()
	d.httpClient = &http.Client{
		Transport: &prefixRoundTripper{
			base:   srv.Client().Transport,
			prefix: srv.URL,
		},
	}
	return d
}

func TestIsOutdated(t *testing.T) {
	cases := []struct {
		installed string
		latest    string
		outdated  bool
	}{
		{"1.0.0", "2.0.0", true},
		{"1.0.0", "1.0.0", false},
		{"2.0.0", "1.0.0", false},
		{"1.2.3", "1.2.4", true},
		{"1.2.4", "1.2.3", false},
		{"^1.0.0", "2.0.0", true},
		{"~1.2.0", "1.3.0", true},
		{"", "1.0.0", false}, // empty installed → do not flag
		{"1.0.0", "", false}, // empty latest → do not flag
		{"1.0.0", "1.0.0", false},
		{"1.0.0-beta", "1.0.0", false}, // pre-release treated same as 1.0.0
	}
	for _, tc := range cases {
		got := isOutdated(tc.installed, tc.latest)
		if got != tc.outdated {
			t.Errorf("isOutdated(%q, %q) = %v, want %v", tc.installed, tc.latest, got, tc.outdated)
		}
	}
}

func TestCleanVersionSpec(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"^1.2.3", "1.2.3"},
		{"~1.2.3", "1.2.3"},
		{">=1.2.3", "1.2.3"},
		{"1.2.3", "1.2.3"},
		{"==1.2.3", "1.2.3"},
	}
	for _, tc := range cases {
		got := cleanVersionSpec(tc.input)
		if got != tc.expected {
			t.Errorf("cleanVersionSpec(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	input := `
# This is a comment
mcp==1.0.0
fastmcp>=2.0.0
django==4.2.0
requests  # bare name
-r other-requirements.txt
`
	r := strings.NewReader(input)
	pkgs := parseRequirementsTxt(r)

	if v, ok := pkgs["mcp"]; !ok || v != "1.0.0" {
		t.Errorf("expected mcp=1.0.0, got %q (ok=%v)", v, ok)
	}
	if v, ok := pkgs["fastmcp"]; !ok || v != "2.0.0" {
		t.Errorf("expected fastmcp=2.0.0, got %q (ok=%v)", v, ok)
	}
	if v, ok := pkgs["django"]; !ok || v != "4.2.0" {
		t.Errorf("expected django=4.2.0, got %q (ok=%v)", v, ok)
	}
	if v, ok := pkgs["requests"]; !ok || v != "" {
		t.Errorf("expected requests='', got %q (ok=%v)", v, ok)
	}
	// -r line should be skipped
	if _, ok := pkgs["-r other-requirements.txt"]; ok {
		t.Error("did not expect -r line to be included")
	}
}

func TestParseVersionComparison(t *testing.T) {
	cases := []struct {
		v    string
		want []int
	}{
		{"1.2.3", []int{1, 2, 3}},
		{"10.0.1", []int{10, 0, 1}},
		{"1.0", []int{1, 0}},
		{"2", []int{2}},
		{"1.2.3-beta", []int{1, 2, 3}},
		{"", nil},
	}
	for _, tc := range cases {
		got := parseVersion(tc.v)
		if len(got) != len(tc.want) {
			t.Errorf("parseVersion(%q) = %v, want %v", tc.v, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseVersion(%q)[%d] = %d, want %d", tc.v, i, got[i], tc.want[i])
			}
		}
	}
}

// TestDiscover_WithProjectDir ensures that Discover() calls DiscoverDependencies
// when ProjectDir is set.
func TestDiscover_WithProjectDir(t *testing.T) {
	srv := mockRegistryHandler(
		map[string]string{"@modelcontextprotocol/server-filesystem": "5.0.0"},
		nil,
	)
	defer srv.Close()

	dir := t.TempDir()
	pkg := map[string]interface{}{
		"dependencies": map[string]string{
			"@modelcontextprotocol/server-filesystem": "1.0.0",
		},
	}
	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	d := newDiscovererWithMockRegistry(srv)
	d.ProjectDir = dir
	result := d.Discover(context.Background())

	if len(result.Findings) == 0 {
		t.Error("expected findings when ProjectDir is set, got none")
	}
}

// --------------------------------------------------------------------------
// New tests addressing review feedback
// --------------------------------------------------------------------------

// TestParseRequirementsTxt_WithExtras verifies that extras notation like
// "mcp[cli]==1.0.0" is parsed correctly — the package name should be "mcp"
// and the version should be "1.0.0", not empty.
func TestParseRequirementsTxt_WithExtras(t *testing.T) {
	input := `mcp[cli]==1.0.0
requests[security]>=2.28.0
fastmcp[all]~=2.0.0
`
	r := strings.NewReader(input)
	pkgs := parseRequirementsTxt(r)

	cases := []struct {
		name    string
		wantVer string
	}{
		{"mcp", "1.0.0"},
		{"requests", "2.28.0"},
		{"fastmcp", "2.0.0"},
	}
	for _, tc := range cases {
		v, ok := pkgs[tc.name]
		if !ok {
			t.Errorf("package %q missing from parsed result", tc.name)
			continue
		}
		if v != tc.wantVer {
			t.Errorf("package %q: got version %q, want %q", tc.name, v, tc.wantVer)
		}
	}
}

// TestDiscoverDependencies_RequirementsTxt_Extras verifies that an MCP package
// declared with extras notation is flagged as outdated when a newer version
// is available in the registry.
func TestDiscoverDependencies_RequirementsTxt_Extras(t *testing.T) {
	srv := mockRegistryHandler(
		nil,
		map[string]string{"mcp": "2.5.0"},
	)
	defer srv.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("mcp[cli]==1.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	d := newDiscovererWithMockRegistry(srv)
	result := d.DiscoverDependencies(context.Background(), dir)

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Title, "mcp") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a finding for outdated 'mcp[cli]==1.0.0', got %+v", result.Findings)
	}
}

// TestDiscoverDependencies_PyprojectToml_MultiLine verifies that multi-line
// [project].dependencies arrays are parsed correctly.
func TestDiscoverDependencies_PyprojectToml_MultiLine(t *testing.T) {
	srv := mockRegistryHandler(
		nil,
		map[string]string{"mcp": "2.0.0", "fastmcp": "3.0.0"},
	)
	defer srv.Close()

	dir := t.TempDir()
	toml := `[project]
name = "my-project"
dependencies = [
  "mcp==1.0.0",
  "fastmcp>=1.5.0",
  "httpx>=0.24.0",
]
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	d := newDiscovererWithMockRegistry(srv)
	result := d.DiscoverDependencies(context.Background(), dir)

	// Both mcp and fastmcp should be flagged as outdated.
	found := map[string]bool{}
	for _, f := range result.Findings {
		if strings.Contains(f.Title, "mcp") {
			found["mcp"] = true
		}
		if strings.Contains(f.Title, "fastmcp") {
			found["fastmcp"] = true
		}
	}
	if !found["mcp"] {
		t.Errorf("expected finding for outdated 'mcp', got %+v", result.Findings)
	}
	if !found["fastmcp"] {
		t.Errorf("expected finding for outdated 'fastmcp', got %+v", result.Findings)
	}
}

// TestDiscoverDependencies_PyprojectPoetry verifies that [tool.poetry.dependencies]
// packages are parsed and checked for outdated versions.
func TestDiscoverDependencies_PyprojectPoetry(t *testing.T) {
	srv := mockRegistryHandler(
		nil,
		map[string]string{"mcp": "2.0.0"},
	)
	defer srv.Close()

	dir := t.TempDir()
	toml := `[tool.poetry.dependencies]
python = "^3.10"
mcp = "^1.0.0"
httpx = "^0.24.0"
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	d := newDiscovererWithMockRegistry(srv)
	result := d.DiscoverDependencies(context.Background(), dir)

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Title, "mcp") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finding for outdated poetry 'mcp', got %+v", result.Findings)
	}
}

// TestDiscoverDependencies_PyprojectToml_SectionWithComment verifies that
// section headers with trailing inline comments are handled correctly.
func TestDiscoverDependencies_PyprojectToml_SectionWithComment(t *testing.T) {
	srv := mockRegistryHandler(
		nil,
		map[string]string{"mcp": "2.0.0"},
	)
	defer srv.Close()

	dir := t.TempDir()
	// The [project] header has a trailing comment — should still be detected.
	toml := `[project]  # my cool project
name = "my-project"
dependencies = ["mcp==1.0.0"]
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	d := newDiscovererWithMockRegistry(srv)
	result := d.DiscoverDependencies(context.Background(), dir)

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Title, "mcp") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finding for outdated 'mcp' in file with commented section header, got %+v", result.Findings)
	}
}

// TestDiscoverDependencies_RegistryError verifies that non-200/non-404 registry
// responses produce an error entry in the result rather than panicking or
// silently swallowing the failure.
func TestDiscoverDependencies_RegistryError(t *testing.T) {
	// Registry that always returns 500 Internal Server Error.
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errSrv.Close()

	// Reuse newDiscovererWithMockRegistry — it redirects all HTTP calls to errSrv.
	d := newDiscovererWithMockRegistry(errSrv)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("mcp==1.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	result := d.DiscoverDependencies(context.Background(), dir)

	// Should have an error entry, not a finding.
	if len(result.Errors) == 0 {
		t.Error("expected at least one error from 500 registry response, got none")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings on registry error, got %d", len(result.Findings))
	}
}

// TestFindingCategory verifies that dependency findings use CategoryDependency,
// not CategoryPermissions.
func TestFindingCategory(t *testing.T) {
	f := buildOutdatedFinding("npm", "mcp-server-test", "1.0.0", "2.0.0")
	if f.Category != CategoryDependency {
		t.Errorf("expected category %q, got %q", CategoryDependency, f.Category)
	}
}
