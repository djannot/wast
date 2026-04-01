package checks

import (
	"context"
	"fmt"
	"testing"
)

// mockCaller is a mock ToolCaller for testing active checks.
type mockCaller struct {
	// responses maps "toolName:paramValue" -> response bytes
	responses map[string][]byte
	// errors maps "toolName:paramValue" -> error
	errors map[string]error
	// defaultResp is returned when no specific entry matches
	defaultResp []byte
}

func newMockCaller() *mockCaller {
	return &mockCaller{
		responses: map[string][]byte{},
		errors:    map[string]error{},
	}
}

func (m *mockCaller) CallTool(_ context.Context, toolName string, arguments map[string]interface{}) ([]byte, error) {
	// Build a key from toolName + all argument values
	for _, v := range arguments {
		key := fmt.Sprintf("%s:%v", toolName, v)
		if err, ok := m.errors[key]; ok {
			return nil, err
		}
		if resp, ok := m.responses[key]; ok {
			return resp, nil
		}
	}
	if m.defaultResp != nil {
		return m.defaultResp, nil
	}
	return []byte(`{"content":[]}`), nil
}

func TestInjectionChecker_NoStringParams(t *testing.T) {
	tools := []ToolInfo{
		{
			Name:        "count",
			Description: "counts things",
			Parameters: []ParamInfo{
				{Name: "n", Type: "integer", Description: "the count"},
			},
		},
	}
	caller := newMockCaller()
	checker := NewInjectionChecker()
	findings := checker.Check(context.Background(), tools, caller)
	if len(findings) != 0 {
		t.Errorf("expected no findings for non-string params, got %d", len(findings))
	}
}

func TestInjectionChecker_SQLiDetected(t *testing.T) {
	tools := []ToolInfo{
		{
			Name:        "search_users",
			Description: "searches users by name",
			Parameters: []ParamInfo{
				{Name: "name", Type: "string", Description: "user name to search"},
			},
		},
	}
	caller := newMockCaller()
	// Return a response indicating SQL error for the SQLi payload
	sqliPayload := "' OR '1'='1"
	key := fmt.Sprintf("search_users:%s", sqliPayload)
	caller.responses[key] = []byte(`{"content":[{"type":"text","text":"syntax error near unexpected token"}]}`)

	checker := NewInjectionChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryInjection {
			found = true
		}
	}
	if !found {
		t.Error("expected SQLi injection finding when response contains SQL error")
	}
}

func TestInjectionChecker_NoVulnerability(t *testing.T) {
	tools := []ToolInfo{
		{
			Name:        "safe_search",
			Description: "searches safely",
			Parameters: []ParamInfo{
				{Name: "query", Type: "string", Description: "search query"},
			},
		},
	}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"no results found"}]}`)

	checker := NewInjectionChecker()
	findings := checker.Check(context.Background(), tools, caller)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe responses, got %d", len(findings))
	}
}

func TestInjectionChecker_CMDiViaError(t *testing.T) {
	tools := []ToolInfo{
		{
			Name:        "run_cmd",
			Description: "runs a command",
			Parameters: []ParamInfo{
				{Name: "cmd", Type: "string", Description: "command to run"},
			},
		},
	}
	caller := newMockCaller()
	// Make error response contain CMDi evidence
	cmdPayload := "; id"
	key := fmt.Sprintf("run_cmd:%s", cmdPayload)
	caller.errors[key] = fmt.Errorf("uid=0(root) gid=0(root) groups=0(root)")

	checker := NewInjectionChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryInjection {
			found = true
		}
	}
	if !found {
		t.Error("expected CMDi finding when error contains command output")
	}
}
