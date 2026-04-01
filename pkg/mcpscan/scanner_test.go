package mcpscan

import (
	"testing"
	"time"
)

func TestNewScanner_DefaultTimeout(t *testing.T) {
	cfg := ScanConfig{
		Transport: TransportHTTP,
		Target:    "http://localhost:9999",
	}
	scanner := NewScanner(cfg)
	if scanner.cfg.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", scanner.cfg.Timeout)
	}
}

func TestNewScanner_CustomTimeout(t *testing.T) {
	cfg := ScanConfig{
		Transport: TransportHTTP,
		Target:    "http://localhost:9999",
		Timeout:   10 * time.Second,
	}
	scanner := NewScanner(cfg)
	if scanner.cfg.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", scanner.cfg.Timeout)
	}
}

func TestBuildClient_UnsupportedTransport(t *testing.T) {
	cfg := ScanConfig{
		Transport: Transport("invalid"),
		Target:    "somewhere",
		Timeout:   5 * time.Second,
	}
	scanner := NewScanner(cfg)
	_, err := scanner.buildClient()
	if err == nil {
		t.Error("expected error for unsupported transport")
	}
}

func TestBuildClient_HTTP(t *testing.T) {
	cfg := ScanConfig{
		Transport: TransportHTTP,
		Target:    "http://localhost:9999",
		Timeout:   5 * time.Second,
	}
	scanner := NewScanner(cfg)
	client, err := scanner.buildClient()
	if err != nil {
		t.Errorf("unexpected error building HTTP client: %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client")
	}
	defer client.Close()
}

func TestBuildClient_SSE(t *testing.T) {
	cfg := ScanConfig{
		Transport: TransportSSE,
		Target:    "http://localhost:9999/sse",
		Timeout:   5 * time.Second,
	}
	scanner := NewScanner(cfg)
	client, err := scanner.buildClient()
	if err != nil {
		t.Errorf("unexpected error building SSE client: %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client")
	}
	defer client.Close()
}

func TestBuildClient_Stdio(t *testing.T) {
	cfg := ScanConfig{
		Transport: TransportStdio,
		Target:    "echo",
		Args:      []string{"hello"},
		Timeout:   5 * time.Second,
	}
	scanner := NewScanner(cfg)
	client, err := scanner.buildClient()
	if err != nil {
		t.Errorf("unexpected error building stdio client: %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client")
	}
	defer client.Close()
}

func TestToCheckTools(t *testing.T) {
	tools := []MCPToolInfo{
		{
			Name:        "test_tool",
			Description: "A test tool",
			Parameters: []MCPToolParameterInfo{
				{Name: "param1", Type: "string", Description: "first param", Required: true, HasEnum: false},
			},
			RawSchema: map[string]interface{}{"type": "object"},
		},
	}

	result := toCheckTools(tools)
	if len(result) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(result))
	}
	if result[0].Name != "test_tool" {
		t.Errorf("expected name 'test_tool', got %q", result[0].Name)
	}
	if len(result[0].Parameters) != 1 {
		t.Fatalf("expected 1 parameter, got %d", len(result[0].Parameters))
	}
	if result[0].Parameters[0].Name != "param1" {
		t.Errorf("expected param name 'param1', got %q", result[0].Parameters[0].Name)
	}
}
