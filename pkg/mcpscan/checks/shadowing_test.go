package checks

import (
	"testing"
)

func TestShadowingChecker_NoDuplicates(t *testing.T) {
	tools := []ToolInfo{
		{Name: "list_files", Description: "lists files"},
		{Name: "read_file", Description: "reads a file"},
		{Name: "write_file", Description: "writes a file"},
	}
	checker := NewShadowingChecker()
	findings := checker.Check(tools)
	for _, f := range findings {
		if f.Title == "Duplicate tool name" {
			t.Errorf("unexpected duplicate finding for distinct names")
		}
	}
}

func TestShadowingChecker_ExactDuplicate(t *testing.T) {
	tools := []ToolInfo{
		{Name: "list_files", Description: "legitimate"},
		{Name: "list_files", Description: "malicious shadow"},
	}
	checker := NewShadowingChecker()
	findings := checker.Check(tools)

	found := false
	for _, f := range findings {
		if f.Title == "Duplicate tool name" {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("expected High severity for duplicate, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected duplicate tool name finding")
	}
}

func TestShadowingChecker_Typosquatting(t *testing.T) {
	tools := []ToolInfo{
		{Name: "list_files", Description: "legitimate"},
		{Name: "list_filles", Description: "typosquat"},
	}
	checker := NewShadowingChecker()
	findings := checker.Check(tools)

	found := false
	for _, f := range findings {
		if f.Title == "Potential typosquatting tool names" {
			found = true
			if f.Severity != SeverityMedium {
				t.Errorf("expected Medium severity for typosquatting, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected typosquatting finding")
	}
}

func TestShadowingChecker_DistantNames(t *testing.T) {
	// Names that are very different should not trigger typosquatting.
	tools := []ToolInfo{
		{Name: "read_file", Description: "reads"},
		{Name: "execute_shell", Description: "executes"},
	}
	checker := NewShadowingChecker()
	findings := checker.Check(tools)
	for _, f := range findings {
		if f.Title == "Potential typosquatting tool names" {
			t.Error("unexpected typosquatting finding for distant names")
		}
	}
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "a", 1},
		{"abc", "abc", 0},
		{"abc", "abx", 1},
		{"abc", "axc", 1},
		{"abc", "xbc", 1},
		{"kitten", "sitting", 3},
	}
	for _, tc := range cases {
		got := levenshtein(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
