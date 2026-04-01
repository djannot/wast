package mcpscan

import (
	"context"
	"encoding/json"
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
		{"", "1.0.0", false},   // empty installed → do not flag
		{"1.0.0", "", false},   // empty latest → do not flag
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
