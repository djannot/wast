package mcpscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
}
