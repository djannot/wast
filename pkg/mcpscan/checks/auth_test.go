package checks

import (
	"context"
	"fmt"
	"testing"
)

// mockMCPConnector is a test double satisfying the MCPConnector interface.
type mockMCPConnector struct {
	connectName    string
	connectVersion string
	connectErr     error
	toolNames      []string
	listToolsErr   error
	callToolOK     bool
	callToolErr    error
}

func (m *mockMCPConnector) Connect(_ context.Context) (string, string, error) {
	return m.connectName, m.connectVersion, m.connectErr
}

func (m *mockMCPConnector) ListTools(_ context.Context) ([]string, error) {
	return m.toolNames, m.listToolsErr
}

func (m *mockMCPConnector) CallTool(_ context.Context, _ string, _ map[string]interface{}) (bool, error) {
	return m.callToolOK, m.callToolErr
}

func TestAuthChecker_ThreeFindingsOnFullBypass(t *testing.T) {
	connector := &mockMCPConnector{
		connectName:    "test-server",
		connectVersion: "1.0",
		connectErr:     nil,
		toolNames:      []string{"tool1"},
		listToolsErr:   nil,
		callToolOK:     true,
		callToolErr:    nil,
	}

	tools := []ToolInfo{
		{Name: "tool1", Description: "a test tool"},
	}

	checker := &AuthChecker{Target: "http://example.com/mcp", Connector: connector}
	findings := checker.CheckUnauthenticated(context.Background(), tools)

	if len(findings) != 3 {
		t.Errorf("expected 3 findings for full auth bypass, got %d: %+v", len(findings), findings)
	}

	categories := make(map[Category]int)
	for _, f := range findings {
		categories[f.Category]++
	}
	if categories[CategoryAuth] != 3 {
		t.Errorf("expected all 3 findings to have CategoryAuth, got: %+v", categories)
	}
}

func TestAuthChecker_ConnectFailedNoFindings(t *testing.T) {
	connector := &mockMCPConnector{
		connectErr: fmt.Errorf("HTTP 401: authentication required"),
	}

	tools := []ToolInfo{
		{Name: "tool1", Description: "a test tool"},
	}

	checker := &AuthChecker{Target: "http://example.com/mcp", Connector: connector}
	findings := checker.CheckUnauthenticated(context.Background(), tools)

	if len(findings) != 0 {
		t.Errorf("expected no findings when connect fails, got %d: %+v", len(findings), findings)
	}
}

func TestAuthChecker_EmptyTargetNilConnector(t *testing.T) {
	checker := &AuthChecker{Target: "", Connector: nil}
	findings := checker.CheckUnauthenticated(context.Background(), nil)

	if len(findings) != 0 {
		t.Errorf("expected nil/empty result for empty target and nil connector, got %d findings", len(findings))
	}
}

func TestAuthChecker_ListToolsError(t *testing.T) {
	connector := &mockMCPConnector{
		connectName:    "test-server",
		connectVersion: "1.0",
		connectErr:     nil,
		toolNames:      nil,
		listToolsErr:   fmt.Errorf("unauthorized"),
	}

	// No tools to call, so only the connect finding should be produced.
	checker := &AuthChecker{Target: "http://example.com/mcp", Connector: connector}
	findings := checker.CheckUnauthenticated(context.Background(), nil)

	if len(findings) != 1 {
		t.Errorf("expected exactly 1 finding when ListTools errors, got %d: %+v", len(findings), findings)
	}

	if len(findings) > 0 && findings[0].Category != CategoryAuth {
		t.Errorf("expected finding to have CategoryAuth, got %q", findings[0].Category)
	}
}
