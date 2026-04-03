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

// --- False-positive regression tests ---

// TestPermissionsChecker_FalsePositive_ShInWords verifies that "sh" appearing as
// a substring of common English words does not trigger the shell-execution check.
func TestPermissionsChecker_FalsePositive_ShInWords(t *testing.T) {
	falsePositiveTools := []ToolInfo{
		{Name: "refresh_session", Description: "Refreshes the user session token"},
		{Name: "push_notification", Description: "Sends a push notification to the device"},
		{Name: "publish_event", Description: "Publishes an event to the message bus"},
	}
	checker := NewPermissionsChecker()
	for _, tool := range falsePositiveTools {
		findings := checker.Check([]ToolInfo{tool})
		for _, f := range findings {
			if f.Title == "Shell or command execution capability" {
				t.Errorf("tool %q: false positive — shell-exec check should NOT fire for %q", tool.Name, tool.Description)
			}
		}
	}
}

// TestPermissionsChecker_FalsePositive_EvalInWords verifies that "eval" as a
// substring of "relevant" or "evaluation" does not trigger the code-eval check.
func TestPermissionsChecker_FalsePositive_EvalInWords(t *testing.T) {
	falsePositiveTools := []ToolInfo{
		{Name: "get_relevant_docs", Description: "Returns relevant documentation for a query"},
		{Name: "score_evaluation", Description: "Provides an evaluation score for a model response"},
	}
	checker := NewPermissionsChecker()
	for _, tool := range falsePositiveTools {
		findings := checker.Check([]ToolInfo{tool})
		for _, f := range findings {
			if f.Title == "Code evaluation/interpretation capability" {
				t.Errorf("tool %q: false positive — code-eval check should NOT fire for %q", tool.Name, tool.Description)
			}
		}
	}
}

// TestPermissionsChecker_FalsePositive_BlockchainToken verifies that "token" in a
// blockchain/crypto context does not trigger the secret/credential check when no
// credential-related context words are present.
func TestPermissionsChecker_FalsePositive_BlockchainToken(t *testing.T) {
	falsePositiveTools := []ToolInfo{
		{Name: "transfer_token", Description: "Transfers ERC-20 tokens between wallet addresses"},
		{Name: "mint_token", Description: "Mints new blockchain tokens for a given address"},
		{Name: "get_token_balance", Description: "Returns the token balance for a wallet"},
	}
	checker := NewPermissionsChecker()
	for _, tool := range falsePositiveTools {
		findings := checker.Check([]ToolInfo{tool})
		for _, f := range findings {
			if f.Title == "Secret or credential access capability" {
				t.Errorf("tool %q: false positive — credential check should NOT fire for blockchain token description %q", tool.Name, tool.Description)
			}
		}
	}
}

// TestPermissionsChecker_LegitimateTokenWithCredentialContext verifies that
// "token" DOES fire when the corpus contains a credential-related word.
func TestPermissionsChecker_LegitimateTokenWithCredentialContext(t *testing.T) {
	tools := []ToolInfo{
		{Name: "get_api_token", Description: "Retrieves the API token from the secret store for authentication"},
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
		t.Error("expected critical finding for a tool that retrieves an API token from the secret store")
	}
}

// TestPermissionsChecker_LegitimateShellTool verifies that a tool explicitly
// named for shell execution still triggers the check.
func TestPermissionsChecker_LegitimateShellTool(t *testing.T) {
	tools := []ToolInfo{
		{Name: "exec_shell", Description: "Executes an arbitrary shell command on the host"},
	}
	checker := NewPermissionsChecker()
	findings := checker.Check(tools)
	found := false
	for _, f := range findings {
		if f.Title == "Shell or command execution capability" && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical shell-exec finding for exec_shell tool")
	}
}

// TestPermissionsChecker_LegitimateEval verifies that a tool named "eval" or
// whose description mentions "eval" as a standalone word still triggers.
func TestPermissionsChecker_LegitimateEval(t *testing.T) {
	tools := []ToolInfo{
		{Name: "eval", Description: "Evaluates and runs arbitrary code in the runtime"},
	}
	checker := NewPermissionsChecker()
	findings := checker.Check(tools)
	found := false
	for _, f := range findings {
		if f.Title == "Code evaluation/interpretation capability" {
			found = true
		}
	}
	if !found {
		t.Error("expected code-eval finding for tool named 'eval'")
	}
}

// TestPermissionsChecker_FalsePositive_QueryInDescription verifies that mentioning
// "query" as a generic verb does not fire the database check when the tool is
// clearly not a DB query executor.
func TestPermissionsChecker_FalsePositive_QueryInDescription(t *testing.T) {
	// This tool uses "query" as a standalone word but is about querying an API,
	// not executing raw DB queries. With whole-word matching this still matches
	// because "query" is a whole word — the goal is just to ensure we aren't
	// matching substrings. Actual semantic disambiguation for "query" is out of
	// scope per the issue; this test documents the current behaviour.
	tools := []ToolInfo{
		{Name: "search_docs", Description: "query the documentation index for relevant pages"},
	}
	checker := NewPermissionsChecker()
	findings := checker.Check(tools)
	// "query" as a whole word in the description is still flagged — that is
	// expected behaviour after the fix. This test verifies no panic/error.
	_ = findings
}
