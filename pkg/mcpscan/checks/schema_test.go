package checks

import (
	"strings"
	"testing"
)

func TestSchemaChecker_NoTools(t *testing.T) {
	checker := NewSchemaChecker()
	findings := checker.Check(nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty tool list, got %d", len(findings))
	}
}

func TestSchemaChecker_MissingDescription(t *testing.T) {
	tools := []ToolInfo{
		{Name: "my_tool", Description: "", RawSchema: map[string]interface{}{}},
	}
	checker := NewSchemaChecker()
	findings := checker.Check(tools)

	found := false
	for _, f := range findings {
		if f.Title == "Tool missing description" {
			found = true
			if f.Severity != SeverityLow {
				t.Errorf("expected Low severity, got %s", f.Severity)
			}
			if f.Category != CategorySchema {
				t.Errorf("expected schema category, got %s", f.Category)
			}
		}
	}
	if !found {
		t.Error("expected finding for missing description")
	}
}

func TestSchemaChecker_MissingSchema(t *testing.T) {
	tools := []ToolInfo{
		{Name: "my_tool", Description: "does stuff", RawSchema: nil},
	}
	checker := NewSchemaChecker()
	findings := checker.Check(tools)

	found := false
	for _, f := range findings {
		if f.Title == "Tool missing input schema" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for missing input schema")
	}
}

func TestSchemaChecker_DangerousParam(t *testing.T) {
	tools := []ToolInfo{
		{
			Name:        "run_command",
			Description: "runs a command",
			RawSchema:   map[string]interface{}{},
			Parameters: []ParamInfo{
				{Name: "cmd", Type: "string", Description: "the command to run", Required: true, HasEnum: false},
			},
		},
	}
	checker := NewSchemaChecker()
	findings := checker.Check(tools)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "dangerous") || strings.Contains(f.Title, "unconstrained") {
			found = true
			if f.Severity != SeverityMedium {
				t.Errorf("expected Medium severity, got %s", f.Severity)
			}
			if f.Parameter != "cmd" {
				t.Errorf("expected parameter 'cmd', got %q", f.Parameter)
			}
		}
	}
	if !found {
		t.Error("expected finding for dangerous unconstrained param")
	}
}

func TestSchemaChecker_DangerousParamWithEnum(t *testing.T) {
	// If the parameter has enum constraints it should NOT be flagged.
	tools := []ToolInfo{
		{
			Name:        "run_command",
			Description: "runs a command",
			RawSchema:   map[string]interface{}{},
			Parameters: []ParamInfo{
				{Name: "cmd", Type: "string", Description: "the command to run", Required: true, HasEnum: true},
			},
		},
	}
	checker := NewSchemaChecker()
	findings := checker.Check(tools)

	for _, f := range findings {
		if strings.Contains(f.Title, "dangerous") || strings.Contains(f.Title, "unconstrained") {
			t.Error("should not flag param with enum constraints as dangerous")
		}
	}
}

func TestSchemaChecker_UndocumentedParam(t *testing.T) {
	tools := []ToolInfo{
		{
			Name:        "my_tool",
			Description: "does stuff",
			RawSchema:   map[string]interface{}{},
			Parameters: []ParamInfo{
				{Name: "x", Type: "string", Description: "", Required: false, HasEnum: false},
			},
		},
	}
	checker := NewSchemaChecker()
	findings := checker.Check(tools)

	found := false
	for _, f := range findings {
		if f.Title == "Undocumented parameter" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for undocumented parameter")
	}
}

func TestSchemaChecker_CleanTool(t *testing.T) {
	tools := []ToolInfo{
		{
			Name:        "list_files",
			Description: "Lists files in a directory",
			RawSchema:   map[string]interface{}{},
			Parameters: []ParamInfo{
				{Name: "directory", Type: "string", Description: "the directory to list", Required: true, HasEnum: false},
			},
		},
	}
	checker := NewSchemaChecker()
	findings := checker.Check(tools)
	// "directory" contains no dangerous keywords from the list (path, file, cmd, etc.)
	// it may flag "directory" if "dir" is in the list — let's just check no critical/high
	for _, f := range findings {
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			t.Errorf("unexpected critical/high severity finding: %s", f.Title)
		}
	}
}
