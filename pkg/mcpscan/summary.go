package mcpscan

import "sort"

// authRequiredFindingTitle is the canonical title used by the scanner when a
// server responds with 401/403. Detecting this title allows bulk-scan
// aggregation to count auth-required servers without re-inspecting error types.
const authRequiredFindingTitle = "MCP server requires authentication"

// defaultTopFindingsN is the number of top findings to surface in the summary.
const defaultTopFindingsN = 5

// BuildBulkScanSummary aggregates a slice of BulkScanRecord entries into a
// BulkScanSummary. It is safe to call with an empty slice.
func BuildBulkScanSummary(records []BulkScanRecord) BulkScanSummary {
	summary := BulkScanSummary{
		TotalServers: len(records),
		BySeverity:   map[string]int{},
		ByCategory:   map[string]int{},
	}

	// titleCounts maps finding title → number of distinct servers with that finding.
	titleCounts := map[string]int{}

	for _, rec := range records {
		if rec.Skipped {
			summary.Skipped++
			// Skipped servers don't produce scan briefs.
			continue
		}

		brief := ServerScanBrief{
			Name:        rec.Name,
			Target:      rec.Target,
			Errored:     rec.Errored,
			Unreachable: rec.Unreachable,
		}

		if rec.Errored {
			summary.Errored++
			if rec.Unreachable {
				summary.Unreachable++
			}
			summary.Servers = append(summary.Servers, brief)
			continue
		}

		summary.Scanned++

		if rec.Result == nil {
			summary.Servers = append(summary.Servers, brief)
			continue
		}

		// Detect auth-required via the canonical finding title.
		authRequired := isAuthRequiredResult(rec.Result)
		if authRequired {
			summary.AuthRequired++
			brief.AuthRequired = true
		}

		brief.FindingCount = rec.Result.Summary.TotalFindings
		brief.TopSeverity = topSeverityFromMap(rec.Result.Summary.BySeverity)

		// Accumulate cross-server finding stats.
		seenTitles := map[string]bool{}
		for _, f := range rec.Result.Findings {
			summary.TotalFindings++
			summary.BySeverity[string(f.Severity)]++
			summary.ByCategory[string(f.Category)]++
			// Count each title once per server for TopFindings.
			if !seenTitles[f.Title] {
				seenTitles[f.Title] = true
				titleCounts[f.Title]++
			}
		}

		summary.Servers = append(summary.Servers, brief)
	}

	// Build sorted top-findings list.
	summary.TopFindings = buildTopFindings(titleCounts, defaultTopFindingsN)

	return summary
}

// isAuthRequiredResult reports whether result contains the canonical
// auth-required finding emitted by the scanner.
func isAuthRequiredResult(result *MCPScanResult) bool {
	if result == nil {
		return false
	}
	for _, f := range result.Findings {
		if f.Title == authRequiredFindingTitle {
			return true
		}
	}
	return false
}

// topSeverityFromMap returns the highest severity that has a non-zero count in
// bySeverity, following the ordering critical > high > medium > low > info.
func topSeverityFromMap(bySeverity map[string]int) string {
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if bySeverity[sev] > 0 {
			return sev
		}
	}
	return ""
}

// buildTopFindings sorts titleCounts descending by count and returns up to n
// entries as a TopFinding slice.
func buildTopFindings(titleCounts map[string]int, n int) []TopFinding {
	type entry struct {
		title string
		count int
	}
	entries := make([]entry, 0, len(titleCounts))
	for title, count := range titleCounts {
		entries = append(entries, entry{title, count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].title < entries[j].title
	})

	if n > len(entries) {
		n = len(entries)
	}
	result := make([]TopFinding, n)
	for i := 0; i < n; i++ {
		result[i] = TopFinding{
			Title:       entries[i].title,
			ServerCount: entries[i].count,
		}
	}
	return result
}
