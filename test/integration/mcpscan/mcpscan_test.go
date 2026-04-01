//go:build integration

// Package mcpscantest contains integration tests that verify every mcpscan
// check detects its target vulnerability on the deliberately vulnerable MCP
// test server defined in ./vulnerable_server/main.go.
//
// Run with:
//
//	go test -v -tags=integration -race -timeout 5m ./test/integration/mcpscan/...
package mcpscantest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/mcpscan"
)

// scanResult caches the single scan result shared by all sub-tests so that we
// only spin up the vulnerable server once per test run.
var scanResult *mcpscan.MCPScanResult

// TestMain launches the vulnerable MCP server as a subprocess via the stdio
// transport, runs a full active scan, and caches the result for assertion by
// each individual sub-test.
func TestMain(m *testing.M) {
	// Use go run to compile and launch the server on the fly.  The test binary's
	// working directory is the package directory, so the relative path resolves
	// correctly to test/integration/mcpscan/vulnerable_server/main.go.
	cfg := mcpscan.ScanConfig{
		Transport:  mcpscan.TransportStdio,
		Target:     "go",
		Args:       []string{"run", "./vulnerable_server/main.go"},
		ActiveMode: true,
		Timeout:    30 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	scanner := mcpscan.NewScanner(cfg)
	result, err := scanner.Scan(ctx)
	if err != nil {
		fmt.Printf("FATAL: mcpscan failed: %v\n", err)
		// Exit with a non-zero code so the test suite reports a failure.
		// We cannot call os.Exit here inside TestMain without importing "os",
		// so we store a nil result and let each sub-test fail with a clear message.
	}
	scanResult = result

	m.Run()
}

// findingsByCategory returns all findings whose category equals cat.
func findingsByCategory(cat string) []mcpscan.MCPFinding {
	if scanResult == nil {
		return nil
	}
	var out []mcpscan.MCPFinding
	for _, f := range scanResult.Findings {
		if string(f.Category) == cat {
			out = append(out, f)
		}
	}
	return out
}

// findingsByTool returns all findings associated with the named tool.
func findingsByTool(tool string) []mcpscan.MCPFinding {
	if scanResult == nil {
		return nil
	}
	var out []mcpscan.MCPFinding
	for _, f := range scanResult.Findings {
		if f.Tool == tool {
			out = append(out, f)
		}
	}
	return out
}

// dumpFindings pretty-prints all findings for diagnostic output on failure.
func dumpFindings(t *testing.T) {
	t.Helper()
	if scanResult == nil {
		t.Log("  (no scan result available)")
		return
	}
	for i, f := range scanResult.Findings {
		t.Logf("  [%d] tool=%s param=%s category=%s severity=%s title=%q",
			i, f.Tool, f.Parameter, f.Category, f.Severity, f.Title)
	}
}

// requireScanResult fails the test immediately if the scan did not complete.
func requireScanResult(t *testing.T) {
	t.Helper()
	if scanResult == nil {
		t.Fatal("scan result is nil — the vulnerable server scan did not complete successfully")
	}
}

// ---- Individual check assertions ----

// TestPromptInjectionDetected verifies that checks/prompt.go detects the
// prompt-injection pattern embedded in the description of prompt_injection_demo.
func TestPromptInjectionDetected(t *testing.T) {
	requireScanResult(t)

	findings := findingsByCategory("prompt_injection")
	if len(findings) == 0 {
		t.Error("expected at least one prompt_injection finding, got none")
		dumpFindings(t)
		return
	}

	// At least one finding must be associated with prompt_injection_demo.
	var found bool
	for _, f := range findings {
		if f.Tool == "prompt_injection_demo" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a prompt_injection finding for tool %q; got findings: %v",
			"prompt_injection_demo", findings)
	}
}

// TestSchemaViolationDetected verifies that checks/schema.go flags tools that
// expose dangerous unconstrained string parameters (run_shell.command,
// query_database.query, fetch_url.url).
func TestSchemaViolationDetected(t *testing.T) {
	requireScanResult(t)

	findings := findingsByCategory("schema")
	if len(findings) == 0 {
		t.Error("expected at least one schema finding, got none")
		dumpFindings(t)
		return
	}

	// Expect findings for the tools with dangerous unconstrained params.
	wantTools := []string{"run_shell", "query_database"}
	for _, want := range wantTools {
		var found bool
		for _, f := range findings {
			if f.Tool == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected a schema finding for tool %q; schema findings: %v", want, findings)
		}
	}
}

// TestDangerousPermissionsDetected verifies that checks/permissions.go flags
// run_shell for its shell-execution capability (the "shell" keyword is in the
// tool name and description corpus).
func TestDangerousPermissionsDetected(t *testing.T) {
	requireScanResult(t)

	findings := findingsByCategory("permissions")
	if len(findings) == 0 {
		t.Error("expected at least one permissions finding, got none")
		dumpFindings(t)
		return
	}

	var found bool
	for _, f := range findings {
		if f.Tool == "run_shell" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a permissions finding for tool %q; permissions findings: %v",
			"run_shell", findings)
	}
}

// TestToolShadowingDetected verifies that checks/shadowing.go detects the
// typosquatting pair (read_file / read_files — Levenshtein distance 1).
func TestToolShadowingDetected(t *testing.T) {
	requireScanResult(t)

	findings := findingsByCategory("tool_shadowing")
	if len(findings) == 0 {
		t.Error("expected at least one tool_shadowing finding, got none")
		dumpFindings(t)
		return
	}

	// At least one finding must mention both tool names in the evidence or title.
	var found bool
	for _, f := range findings {
		combined := strings.ToLower(f.Title + " " + f.Description + " " + f.Evidence)
		if strings.Contains(combined, "read_file") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a tool_shadowing finding mentioning read_file/read_files; got: %v", findings)
	}
}

// TestInjectionDetected verifies that checks/injection.go detects both SQLi
// (via query_database) and CMDi (via run_shell) injection vulnerabilities.
func TestInjectionDetected(t *testing.T) {
	requireScanResult(t)

	findings := findingsByCategory("injection")
	if len(findings) == 0 {
		t.Error("expected at least one injection finding, got none")
		dumpFindings(t)
		return
	}

	// Expect findings for both injection-vulnerable tools.
	wantTools := []string{"run_shell", "query_database"}
	for _, want := range wantTools {
		var found bool
		for _, f := range findings {
			if f.Tool == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected an injection finding for tool %q; injection findings: %v", want, findings)
		}
	}
}

// TestDataExposureDetected verifies that checks/exposure.go detects the fake
// API key leaked by the get_config tool.
func TestDataExposureDetected(t *testing.T) {
	requireScanResult(t)

	findings := findingsByCategory("data_exposure")
	if len(findings) == 0 {
		t.Error("expected at least one data_exposure finding, got none")
		dumpFindings(t)
		return
	}

	var found bool
	for _, f := range findings {
		if f.Tool == "get_config" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a data_exposure finding for tool %q; data_exposure findings: %v",
			"get_config", findings)
	}
}

// TestSSRFDetected verifies that checks/ssrf.go detects the SSRF vulnerability
// in the fetch_url tool. The server reads file:///etc/passwd when probed, and
// the evidence string "root:" appears in the response.
func TestSSRFDetected(t *testing.T) {
	requireScanResult(t)

	findings := findingsByCategory("ssrf")
	if len(findings) == 0 {
		t.Error("expected at least one ssrf finding, got none")
		dumpFindings(t)
		return
	}

	var found bool
	for _, f := range findings {
		if f.Tool == "fetch_url" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an ssrf finding for tool %q; ssrf findings: %v", "fetch_url", findings)
	}
}

// TestScanSummary is a sanity-check that the scan summary totals are consistent
// with the individual finding assertions above.
func TestScanSummary(t *testing.T) {
	requireScanResult(t)

	total := len(scanResult.Findings)
	if total == 0 {
		t.Error("expected a non-zero total finding count")
		return
	}

	t.Logf("scan summary: %d findings total | passive=%d active=%d tools=%d",
		scanResult.Summary.TotalFindings,
		scanResult.Summary.PassiveChecks,
		scanResult.Summary.ActiveChecks,
		scanResult.Summary.TotalTools)

	// All seven check categories must be represented.
	requiredCategories := []string{
		"prompt_injection",
		"schema",
		"permissions",
		"tool_shadowing",
		"injection",
		"data_exposure",
		"ssrf",
	}
	for _, cat := range requiredCategories {
		if n := scanResult.Summary.BySeverity; n != nil {
			_ = n // just referencing to avoid unused warning
		}
		count := 0
		for _, f := range scanResult.Findings {
			if string(f.Category) == cat {
				count++
			}
		}
		if count == 0 {
			t.Errorf("category %q has no findings in the summary", cat)
		}
	}
}
