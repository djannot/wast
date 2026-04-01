package checks

import (
	"fmt"
	"strings"
)

// ShadowingChecker detects tool name collisions and typosquatting.
type ShadowingChecker struct{}

// NewShadowingChecker creates a new ShadowingChecker.
func NewShadowingChecker() *ShadowingChecker {
	return &ShadowingChecker{}
}

// Check detects shadowing and typosquatting across the provided tool list.
func (c *ShadowingChecker) Check(tools []ToolInfo) []Finding {
	var findings []Finding

	nameMap := make(map[string][]int, len(tools))
	for i, tool := range tools {
		lower := strings.ToLower(tool.Name)
		nameMap[lower] = append(nameMap[lower], i)
	}

	// Check 1: Exact duplicate names.
	for name, indices := range nameMap {
		if len(indices) > 1 {
			findings = append(findings, Finding{
				Tool:     name,
				Category: CategoryShadowing,
				Severity: SeverityHigh,
				Title:    "Duplicate tool name",
				Description: fmt.Sprintf(
					"Multiple tools share the name %q. When two tools have the same name, "+
						"an AI agent may invoke the wrong one.",
					name,
				),
				Evidence:    fmt.Sprintf("Duplicate count: %d tools named %q", len(indices), name),
				Remediation: "Ensure all tool names are unique. Use namespacing to avoid conflicts.",
			})
		}
	}

	// Check 2: Typosquatting — detect names that are one edit distance from another.
	names := make([]string, 0, len(nameMap))
	for name := range nameMap {
		names = append(names, name)
	}

	reported := make(map[string]bool)
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			a, b := names[i], names[j]
			diff := len(a) - len(b)
			if diff < 0 {
				diff = -diff
			}
			if diff > 2 {
				continue
			}
			if levenshtein(a, b) == 1 {
				key := a + "|" + b
				if reported[key] {
					continue
				}
				reported[key] = true
				findings = append(findings, Finding{
					Tool:     a,
					Category: CategoryShadowing,
					Severity: SeverityMedium,
					Title:    "Potential typosquatting tool names",
					Description: fmt.Sprintf(
						"Tool names %q and %q differ by only one character. "+
							"This could indicate typosquatting.",
						a, b,
					),
					Evidence:    fmt.Sprintf("Edit distance between %q and %q is 1", a, b),
					Remediation: "Review both tools and ensure they are intentionally distinct.",
				})
			}
		}
	}

	return findings
}

// levenshtein computes the Levenshtein edit distance between two strings.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
		dp[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			dp[i][j] = min3(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
		}
	}
	return dp[la][lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
