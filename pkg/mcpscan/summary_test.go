package mcpscan

import (
	"testing"
)

// makeResult is a helper that creates a minimal MCPScanResult with the given
// findings for use in summary tests.
func makeResult(findings []MCPFinding) *MCPScanResult {
	r := &MCPScanResult{
		Findings: findings,
		Summary: MCPScanSummary{
			BySeverity: map[string]int{},
			ByCategory: map[string]int{},
		},
	}
	for _, f := range findings {
		r.Summary.TotalFindings++
		r.Summary.BySeverity[string(f.Severity)]++
		r.Summary.ByCategory[string(f.Category)]++
	}
	return r
}

func TestBuildBulkScanSummary_Empty(t *testing.T) {
	summary := BuildBulkScanSummary(nil)
	if summary.TotalServers != 0 {
		t.Errorf("expected TotalServers=0, got %d", summary.TotalServers)
	}
	if summary.Scanned != 0 {
		t.Errorf("expected Scanned=0, got %d", summary.Scanned)
	}
}

func TestBuildBulkScanSummary_BasicCounts(t *testing.T) {
	records := []BulkScanRecord{
		{Name: "s1", Target: "http://s1", Result: makeResult(nil)},
		{Name: "s2", Target: "http://s2", Skipped: true},
		{Name: "s3", Target: "http://s3", Errored: true, Unreachable: true},
		{Name: "s4", Target: "http://s4", Errored: true},
	}

	summary := BuildBulkScanSummary(records)

	if summary.TotalServers != 4 {
		t.Errorf("TotalServers: expected 4, got %d", summary.TotalServers)
	}
	if summary.Scanned != 1 {
		t.Errorf("Scanned: expected 1, got %d", summary.Scanned)
	}
	if summary.Skipped != 1 {
		t.Errorf("Skipped: expected 1, got %d", summary.Skipped)
	}
	if summary.Errored != 2 {
		t.Errorf("Errored: expected 2, got %d", summary.Errored)
	}
	if summary.Unreachable != 1 {
		t.Errorf("Unreachable: expected 1, got %d", summary.Unreachable)
	}
	// Servers slice should have entries for non-skipped records only.
	if len(summary.Servers) != 3 {
		t.Errorf("Servers: expected 3 briefs (skipped excluded), got %d", len(summary.Servers))
	}
}

func TestBuildBulkScanSummary_AuthRequired(t *testing.T) {
	authFinding := MCPFinding{
		Title:    authRequiredFindingTitle,
		Severity: SeverityInfo,
		Category: CategoryAuth,
	}
	records := []BulkScanRecord{
		{Name: "auth-server", Target: "http://auth", Result: makeResult([]MCPFinding{authFinding})},
		{Name: "open-server", Target: "http://open", Result: makeResult(nil)},
	}

	summary := BuildBulkScanSummary(records)

	if summary.AuthRequired != 1 {
		t.Errorf("AuthRequired: expected 1, got %d", summary.AuthRequired)
	}
	if summary.Scanned != 2 {
		t.Errorf("Scanned: expected 2, got %d", summary.Scanned)
	}

	// Verify the auth-required brief.
	var authBrief *ServerScanBrief
	for i := range summary.Servers {
		if summary.Servers[i].Target == "http://auth" {
			authBrief = &summary.Servers[i]
			break
		}
	}
	if authBrief == nil {
		t.Fatal("auth-server brief not found in Servers")
	}
	if !authBrief.AuthRequired {
		t.Error("expected auth-server brief to have AuthRequired=true")
	}
}

func TestBuildBulkScanSummary_FindingAggregation(t *testing.T) {
	findings1 := []MCPFinding{
		{Title: "Missing input validation", Severity: SeverityHigh, Category: CategorySchema},
		{Title: "Prompt injection in description", Severity: SeverityCritical, Category: CategoryPrompt},
	}
	findings2 := []MCPFinding{
		{Title: "Missing input validation", Severity: SeverityHigh, Category: CategorySchema},
		{Title: "Dangerous permissions detected", Severity: SeverityMedium, Category: CategoryPermissions},
	}
	records := []BulkScanRecord{
		{Name: "s1", Target: "http://s1", Result: makeResult(findings1)},
		{Name: "s2", Target: "http://s2", Result: makeResult(findings2)},
	}

	summary := BuildBulkScanSummary(records)

	if summary.TotalFindings != 4 {
		t.Errorf("TotalFindings: expected 4, got %d", summary.TotalFindings)
	}
	if summary.BySeverity["critical"] != 1 {
		t.Errorf("BySeverity[critical]: expected 1, got %d", summary.BySeverity["critical"])
	}
	if summary.BySeverity["high"] != 2 {
		t.Errorf("BySeverity[high]: expected 2, got %d", summary.BySeverity["high"])
	}
	if summary.BySeverity["medium"] != 1 {
		t.Errorf("BySeverity[medium]: expected 1, got %d", summary.BySeverity["medium"])
	}
}

func TestBuildBulkScanSummary_TopFindings(t *testing.T) {
	// "Missing input validation" appears in 3 servers, others in fewer.
	commonFinding := MCPFinding{Title: "Missing input validation", Severity: SeverityHigh, Category: CategorySchema}
	rareFinding := MCPFinding{Title: "Prompt injection in description", Severity: SeverityCritical, Category: CategoryPrompt}

	records := []BulkScanRecord{
		{Name: "s1", Target: "http://s1", Result: makeResult([]MCPFinding{commonFinding, rareFinding})},
		{Name: "s2", Target: "http://s2", Result: makeResult([]MCPFinding{commonFinding})},
		{Name: "s3", Target: "http://s3", Result: makeResult([]MCPFinding{commonFinding})},
	}

	summary := BuildBulkScanSummary(records)

	if len(summary.TopFindings) == 0 {
		t.Fatal("expected TopFindings to be non-empty")
	}
	top := summary.TopFindings[0]
	if top.Title != "Missing input validation" {
		t.Errorf("TopFindings[0].Title: expected %q, got %q", "Missing input validation", top.Title)
	}
	if top.ServerCount != 3 {
		t.Errorf("TopFindings[0].ServerCount: expected 3, got %d", top.ServerCount)
	}

	// rareFinding should appear second.
	if len(summary.TopFindings) < 2 {
		t.Fatal("expected at least 2 TopFindings")
	}
	if summary.TopFindings[1].Title != "Prompt injection in description" {
		t.Errorf("TopFindings[1].Title: expected %q, got %q", "Prompt injection in description", summary.TopFindings[1].Title)
	}
	if summary.TopFindings[1].ServerCount != 1 {
		t.Errorf("TopFindings[1].ServerCount: expected 1, got %d", summary.TopFindings[1].ServerCount)
	}
}

func TestBuildBulkScanSummary_TopFindingsDedup(t *testing.T) {
	// A single server with the same finding title twice should count as 1 server,
	// not 2, in the TopFindings list.
	dup := MCPFinding{Title: "Repeated finding", Severity: SeverityLow, Category: CategorySchema}
	records := []BulkScanRecord{
		{Name: "s1", Target: "http://s1", Result: makeResult([]MCPFinding{dup, dup})},
		{Name: "s2", Target: "http://s2", Result: makeResult([]MCPFinding{dup})},
	}

	summary := BuildBulkScanSummary(records)

	if len(summary.TopFindings) == 0 {
		t.Fatal("expected TopFindings to be non-empty")
	}
	if summary.TopFindings[0].ServerCount != 2 {
		t.Errorf("TopFindings[0].ServerCount: expected 2 (dedup per server), got %d", summary.TopFindings[0].ServerCount)
	}
	// Total findings should be 3 (dup+dup+dup), not deduplicated.
	if summary.TotalFindings != 3 {
		t.Errorf("TotalFindings: expected 3, got %d", summary.TotalFindings)
	}
}

func TestBuildBulkScanSummary_TopSeverity(t *testing.T) {
	findings := []MCPFinding{
		{Title: "Low issue", Severity: SeverityLow, Category: CategorySchema},
		{Title: "Critical issue", Severity: SeverityCritical, Category: CategoryPrompt},
	}
	records := []BulkScanRecord{
		{Name: "s1", Target: "http://s1", Result: makeResult(findings)},
	}

	summary := BuildBulkScanSummary(records)

	if len(summary.Servers) == 0 {
		t.Fatal("expected at least one server brief")
	}
	if summary.Servers[0].TopSeverity != "critical" {
		t.Errorf("TopSeverity: expected %q, got %q", "critical", summary.Servers[0].TopSeverity)
	}
}

func TestTopSeverityFromMap(t *testing.T) {
	tests := []struct {
		name       string
		bySeverity map[string]int
		want       string
	}{
		{"critical wins", map[string]int{"critical": 1, "high": 2, "low": 3}, "critical"},
		{"high wins when no critical", map[string]int{"high": 1, "medium": 2}, "high"},
		{"empty map", map[string]int{}, ""},
		{"only info", map[string]int{"info": 5}, "info"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := topSeverityFromMap(tt.bySeverity)
			if got != tt.want {
				t.Errorf("topSeverityFromMap(%v) = %q, want %q", tt.bySeverity, got, tt.want)
			}
		})
	}
}

func TestBuildTopFindings_LimitToN(t *testing.T) {
	// Build more than defaultTopFindingsN distinct titles.
	counts := map[string]int{}
	for i := range 10 {
		counts[string(rune('A'+i))] = 10 - i
	}

	result := buildTopFindings(counts, defaultTopFindingsN)
	if len(result) != defaultTopFindingsN {
		t.Errorf("expected %d top findings, got %d", defaultTopFindingsN, len(result))
	}
	// First entry should be the one with count 10.
	if result[0].ServerCount != 10 {
		t.Errorf("expected top finding count=10, got %d", result[0].ServerCount)
	}
}
