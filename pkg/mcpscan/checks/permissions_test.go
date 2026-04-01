package checks

import (
	"testing"
)

func TestPermissionsChecker_ShellExec(t *testing.T) {
	tools := []ToolInfo{
		{Name: "run_shell", Description: "Executes a shell command on the host"},
	}
	checker := NewPermissionsChecker()
	findings := checker.Check(tools)

	found := false
	for _, f := range findings {
		if f.Category == CategoryPermissions && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical permission finding for shell execution tool")
	}
}

func TestPermissionsChecker_FileSystem(t *testing.T) {
	tools := []ToolInfo{
		{Name: "read_file", Description: "Reads a file from disk"},
	}
	checker := NewPermissionsChecker()
	findings := checker.Check(tools)

	found := false
	for _, f := range findings {
		if f.Category == CategoryPermissions {
			found = true
		}
	}
	if !found {
		t.Error("expected permission finding for file system tool")
	}
}

func TestPermissionsChecker_SafeTool(t *testing.T) {
	tools := []ToolInfo{
		{Name: "get_weather", Description: "Returns current weather for a city"},
	}
	checker := NewPermissionsChecker()
	findings := checker.Check(tools)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe weather tool, got %d", len(findings))
	}
}

func TestPermissionsChecker_NoTools(t *testing.T) {
	checker := NewPermissionsChecker()
	findings := checker.Check(nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty tool list, got %d", len(findings))
	}
}
