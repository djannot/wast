// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Confidence level constants for correlation and risk scoring
const (
	ConfidenceVerified = 0.95 // Verified findings with proof
	ConfidenceHigh     = 0.9  // High confidence (e.g., headers, confirmed XSS/SQLi)
	ConfidenceMedium   = 0.7  // Medium confidence (e.g., possible CSRF)
	ConfidenceLow      = 0.5  // Low confidence
	ConfidenceCSRF     = 0.8  // CSRF findings require verification
	ConfidenceHeader   = 0.9  // Header findings are factual
)

// UnifiedScanResult represents a comprehensive aggregation of all scan results
// with correlation and risk scoring for AI agent consumption.
type UnifiedScanResult struct {
	Target       string              `json:"target" yaml:"target"`
	PassiveOnly  bool                `json:"passive_only" yaml:"passive_only"`
	Headers      *HeaderScanResult   `json:"headers,omitempty" yaml:"headers,omitempty"`
	SQLi         *SQLiScanResult     `json:"sqli,omitempty" yaml:"sqli,omitempty"`
	XSS          *XSSScanResult      `json:"xss,omitempty" yaml:"xss,omitempty"`
	CSRF         *CSRFScanResult     `json:"csrf,omitempty" yaml:"csrf,omitempty"`
	SSRF         *SSRFScanResult     `json:"ssrf,omitempty" yaml:"ssrf,omitempty"`
	Redirect     *RedirectScanResult `json:"redirect,omitempty" yaml:"redirect,omitempty"`
	Correlations []CorrelatedFinding `json:"correlations,omitempty" yaml:"correlations,omitempty"`
	RiskScore    RiskScore           `json:"risk_score" yaml:"risk_score"`
	Summary      UnifiedSummary      `json:"summary" yaml:"summary"`
	Errors       []string            `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// CorrelatedFinding represents related vulnerabilities across different scanners
// that together form a more severe security issue.
type CorrelatedFinding struct {
	ID                string        `json:"id" yaml:"id"`
	PrimaryFinding    interface{}   `json:"primary_finding" yaml:"primary_finding"`
	RelatedFindings   []interface{} `json:"related_findings" yaml:"related_findings"`
	EffectiveSeverity string        `json:"effective_severity" yaml:"effective_severity"`
	Confidence        float64       `json:"confidence" yaml:"confidence"` // 0-1
	Explanation       string        `json:"explanation" yaml:"explanation"`
}

// RiskScore provides a 0-100 risk assessment with breakdown by category.
type RiskScore struct {
	Overall    int            `json:"overall" yaml:"overall"`       // 0-100
	Confidence float64        `json:"confidence" yaml:"confidence"` // 0-1
	Breakdown  map[string]int `json:"breakdown" yaml:"breakdown"`   // category -> score
}

// UnifiedSummary provides an executive overview of all security findings.
type UnifiedSummary struct {
	TotalFindings      int      `json:"total_findings" yaml:"total_findings"`
	HighSeverity       int      `json:"high_severity" yaml:"high_severity"`
	MediumSeverity     int      `json:"medium_severity" yaml:"medium_severity"`
	LowSeverity        int      `json:"low_severity" yaml:"low_severity"`
	CorrelatedFindings int      `json:"correlated_findings" yaml:"correlated_findings"`
	PriorityActions    []string `json:"priority_actions" yaml:"priority_actions"`
}

// NewUnifiedScanResult creates a unified scan result from individual scanner outputs
// and performs correlation analysis.
func NewUnifiedScanResult(target string, passiveOnly bool, headers *HeaderScanResult, xss *XSSScanResult, sqli *SQLiScanResult, csrf *CSRFScanResult, ssrf *SSRFScanResult, redirect *RedirectScanResult, errors []string) *UnifiedScanResult {
	result := &UnifiedScanResult{
		Target:       target,
		PassiveOnly:  passiveOnly,
		Headers:      headers,
		XSS:          xss,
		SQLi:         sqli,
		CSRF:         csrf,
		SSRF:         ssrf,
		Redirect:     redirect,
		Correlations: make([]CorrelatedFinding, 0),
		Errors:       errors,
	}

	// Perform correlation analysis
	result.correlateFindings()

	// Calculate risk score
	result.calculateRiskScore()

	// Generate summary
	result.generateSummary()

	return result
}

// correlateFindings identifies related vulnerabilities across different scanners.
func (u *UnifiedScanResult) correlateFindings() {
	correlationID := 0

	// Correlation 1: XSS + Missing CSP
	if u.XSS != nil && u.Headers != nil {
		missingCSP := u.findMissingHeader("Content-Security-Policy")
		if missingCSP != nil {
			for _, xssFinding := range u.XSS.Findings {
				// Only correlate reflected/DOM XSS with missing CSP
				if xssFinding.Type == "reflected" || xssFinding.Type == "dom" {
					correlationID++
					correlation := CorrelatedFinding{
						ID:             fmt.Sprintf("CORR-%d", correlationID),
						PrimaryFinding: xssFinding,
						RelatedFindings: []interface{}{
							missingCSP,
						},
						EffectiveSeverity: SeverityHigh,
						Confidence:        u.calculateConfidence(xssFinding.Confidence, ConfidenceHeader),
						Explanation:       fmt.Sprintf("XSS vulnerability on parameter '%s' is more exploitable due to missing Content-Security-Policy header. An attacker can inject arbitrary JavaScript without CSP restrictions.", xssFinding.Parameter),
					}
					u.Correlations = append(u.Correlations, correlation)
				}
			}
		}
	}

	// Correlation 2: SQLi + Server Error Disclosure
	if u.SQLi != nil && u.Headers != nil {
		errorDisclosure := u.findServerVersionHeaders()
		if len(errorDisclosure) > 0 {
			for _, sqliFinding := range u.SQLi.Findings {
				// Correlate error-based SQLi with server headers that leak info
				if sqliFinding.Type == "error-based" {
					correlationID++
					correlation := CorrelatedFinding{
						ID:             fmt.Sprintf("CORR-%d", correlationID),
						PrimaryFinding: sqliFinding,
						RelatedFindings: []interface{}{
							errorDisclosure,
						},
						EffectiveSeverity: SeverityHigh,
						Confidence:        u.calculateConfidence(sqliFinding.Confidence, ConfidenceCSRF),
						Explanation:       fmt.Sprintf("SQL injection on parameter '%s' combined with verbose server headers (X-Powered-By, Server) reveals technology stack, making exploitation easier.", sqliFinding.Parameter),
					}
					u.Correlations = append(u.Correlations, correlation)
				}
			}
		}
	}

	// Correlation 3: CSRF + Missing SameSite Cookie Attribute
	if u.CSRF != nil && u.Headers != nil {
		insecureCookies := u.findCookiesWithoutSameSite()
		if len(insecureCookies) > 0 {
			for _, csrfFinding := range u.CSRF.Findings {
				if csrfFinding.Type == "missing_token" || csrfFinding.Type == "missing_samesite" {
					correlationID++
					correlation := CorrelatedFinding{
						ID:             fmt.Sprintf("CORR-%d", correlationID),
						PrimaryFinding: csrfFinding,
						RelatedFindings: []interface{}{
							insecureCookies,
						},
						EffectiveSeverity: SeverityHigh,
						Confidence:        ConfidenceCSRF,
						Explanation:       fmt.Sprintf("CSRF vulnerability on form '%s' is exploitable because session cookies lack SameSite attribute. Attacker-controlled sites can send authenticated requests.", csrfFinding.FormAction),
					}
					u.Correlations = append(u.Correlations, correlation)
				}
			}
		}
	}

	// Correlation 4: Multiple Injection Points (SQLi + XSS on same parameter)
	if u.SQLi != nil && u.XSS != nil {
		// Build a map of parameters with SQLi
		sqliParams := make(map[string]SQLiFinding)
		for _, finding := range u.SQLi.Findings {
			key := fmt.Sprintf("%s:%s", finding.URL, finding.Parameter)
			sqliParams[key] = finding
		}

		// Check for XSS on same parameters
		for _, xssFinding := range u.XSS.Findings {
			key := fmt.Sprintf("%s:%s", xssFinding.URL, xssFinding.Parameter)
			if sqliFinding, found := sqliParams[key]; found {
				correlationID++
				correlation := CorrelatedFinding{
					ID:             fmt.Sprintf("CORR-%d", correlationID),
					PrimaryFinding: sqliFinding,
					RelatedFindings: []interface{}{
						xssFinding,
					},
					EffectiveSeverity: SeverityHigh,
					Confidence:        u.calculateConfidence(sqliFinding.Confidence, u.parseConfidenceString(xssFinding.Confidence)),
					Explanation:       fmt.Sprintf("Parameter '%s' is vulnerable to both SQL injection and XSS, indicating completely absent input validation. This allows for multi-stage attacks.", xssFinding.Parameter),
				}
				u.Correlations = append(u.Correlations, correlation)
			}
		}
	}
}

// calculateRiskScore computes overall risk score and breakdown by category.
func (u *UnifiedScanResult) calculateRiskScore() {
	breakdown := make(map[string]int)
	totalScore := 0
	totalConfidence := 0.0
	confidenceCount := 0

	// Score injection vulnerabilities (SQLi, XSS)
	injectionScore := 0
	if u.SQLi != nil {
		for _, finding := range u.SQLi.Findings {
			score := u.severityToScore(finding.Severity)
			injectionScore += score
			totalConfidence += u.parseConfidenceString(finding.Confidence)
			confidenceCount++
		}
	}
	if u.XSS != nil {
		for _, finding := range u.XSS.Findings {
			score := u.severityToScore(finding.Severity)
			injectionScore += score
			totalConfidence += u.parseConfidenceString(finding.Confidence)
			confidenceCount++
		}
	}
	breakdown["injection"] = min(injectionScore, 40) // Cap at 40 points

	// Score CSRF vulnerabilities
	csrfScore := 0
	if u.CSRF != nil {
		for _, finding := range u.CSRF.Findings {
			csrfScore += u.severityToScore(finding.Severity)
		}
	}
	breakdown["csrf"] = min(csrfScore, 20) // Cap at 20 points

	// Score SSRF vulnerabilities
	ssrfScore := 0
	if u.SSRF != nil {
		for _, finding := range u.SSRF.Findings {
			score := u.severityToScore(finding.Severity)
			ssrfScore += score
			totalConfidence += u.parseConfidenceString(finding.Confidence)
			confidenceCount++
		}
	}
	breakdown["ssrf"] = min(ssrfScore, 30) // Cap at 30 points

	// Score Open Redirect vulnerabilities
	redirectScore := 0
	if u.Redirect != nil {
		for _, finding := range u.Redirect.Findings {
			score := u.severityToScore(finding.Severity)
			redirectScore += score
			totalConfidence += u.parseConfidenceString(finding.Confidence)
			confidenceCount++
		}
	}
	breakdown["redirect"] = min(redirectScore, 25) // Cap at 25 points

	// Score header misconfigurations
	misconfigScore := 0
	if u.Headers != nil {
		for _, finding := range u.Headers.Headers {
			if !finding.Present {
				misconfigScore += u.severityToScore(finding.Severity)
			}
		}
		for _, finding := range u.Headers.Cookies {
			if len(finding.Issues) > 0 {
				misconfigScore += u.severityToScore(finding.Severity) / 2 // Half weight for cookies
			}
		}
		for _, finding := range u.Headers.CORS {
			if len(finding.Issues) > 0 {
				misconfigScore += u.severityToScore(finding.Severity)
			}
		}
	}
	breakdown["misconfiguration"] = min(misconfigScore, 25) // Cap at 25 points

	// Add bonus for correlations (up to 15 points)
	correlationBonus := len(u.Correlations) * 5
	breakdown["correlation_multiplier"] = min(correlationBonus, 15)

	// Calculate overall score
	for _, score := range breakdown {
		totalScore += score
	}

	// Calculate average confidence
	avgConfidence := ConfidenceMedium // Default confidence
	if confidenceCount > 0 {
		avgConfidence = totalConfidence / float64(confidenceCount)
	}

	u.RiskScore = RiskScore{
		Overall:    min(totalScore, 100),
		Confidence: avgConfidence,
		Breakdown:  breakdown,
	}
}

// generateSummary creates the unified summary of all findings.
func (u *UnifiedScanResult) generateSummary() {
	summary := UnifiedSummary{
		CorrelatedFindings: len(u.Correlations),
		PriorityActions:    make([]string, 0),
	}

	// Count findings by severity
	severityCounts := make(map[string]int)

	if u.Headers != nil {
		for _, finding := range u.Headers.Headers {
			if !finding.Present {
				summary.TotalFindings++
				severityCounts[finding.Severity]++
			}
		}
		for _, finding := range u.Headers.Cookies {
			if len(finding.Issues) > 0 {
				summary.TotalFindings++
				severityCounts[finding.Severity]++
			}
		}
		for _, finding := range u.Headers.CORS {
			if len(finding.Issues) > 0 {
				summary.TotalFindings++
				severityCounts[finding.Severity]++
			}
		}
	}

	if u.SQLi != nil {
		for _, finding := range u.SQLi.Findings {
			summary.TotalFindings++
			severityCounts[finding.Severity]++
		}
	}

	if u.XSS != nil {
		for _, finding := range u.XSS.Findings {
			summary.TotalFindings++
			severityCounts[finding.Severity]++
		}
	}

	if u.CSRF != nil {
		for _, finding := range u.CSRF.Findings {
			summary.TotalFindings++
			severityCounts[finding.Severity]++
		}
	}

	if u.SSRF != nil {
		for _, finding := range u.SSRF.Findings {
			summary.TotalFindings++
			severityCounts[finding.Severity]++
		}
	}

	if u.Redirect != nil {
		for _, finding := range u.Redirect.Findings {
			summary.TotalFindings++
			severityCounts[finding.Severity]++
		}
	}

	summary.HighSeverity = severityCounts[SeverityHigh]
	summary.MediumSeverity = severityCounts[SeverityMedium]
	summary.LowSeverity = severityCounts[SeverityLow]

	// Generate priority actions based on findings
	summary.PriorityActions = u.generatePriorityActions()

	u.Summary = summary
}

// generatePriorityActions creates a prioritized list of recommended actions.
func (u *UnifiedScanResult) generatePriorityActions() []string {
	actions := make([]string, 0)

	// Priority 1: Active injection vulnerabilities
	if u.SQLi != nil && len(u.SQLi.Findings) > 0 {
		highSeveritySQLi := 0
		for _, finding := range u.SQLi.Findings {
			if finding.Severity == SeverityHigh {
				highSeveritySQLi++
			}
		}
		if highSeveritySQLi > 0 {
			actions = append(actions, fmt.Sprintf("CRITICAL: Fix %d high-severity SQL injection vulnerabilities immediately - use parameterized queries", highSeveritySQLi))
		}
	}

	if u.XSS != nil && len(u.XSS.Findings) > 0 {
		highSeverityXSS := 0
		for _, finding := range u.XSS.Findings {
			if finding.Severity == SeverityHigh {
				highSeverityXSS++
			}
		}
		if highSeverityXSS > 0 {
			actions = append(actions, fmt.Sprintf("CRITICAL: Fix %d high-severity XSS vulnerabilities - implement output encoding and CSP", highSeverityXSS))
		}
	}

	// Priority 2: Correlated vulnerabilities
	if len(u.Correlations) > 0 {
		actions = append(actions, fmt.Sprintf("HIGH: Address %d correlated vulnerabilities that amplify attack impact", len(u.Correlations)))
	}

	// Priority 3: Missing critical security headers
	if u.Headers != nil {
		missingCSP := u.findMissingHeader("Content-Security-Policy")
		if missingCSP != nil {
			actions = append(actions, "HIGH: Implement Content-Security-Policy header to mitigate XSS attacks")
		}

		missingHSTS := u.findMissingHeader("Strict-Transport-Security")
		if missingHSTS != nil {
			actions = append(actions, "MEDIUM: Add Strict-Transport-Security header to enforce HTTPS")
		}
	}

	// Priority 4: CSRF vulnerabilities
	if u.CSRF != nil && len(u.CSRF.Findings) > 0 {
		actions = append(actions, fmt.Sprintf("MEDIUM: Implement CSRF tokens for %d vulnerable forms", len(u.CSRF.Findings)))
	}

	// Priority 4.5: Open Redirect vulnerabilities
	if u.Redirect != nil && len(u.Redirect.Findings) > 0 {
		highSeverityRedirect := 0
		for _, finding := range u.Redirect.Findings {
			if finding.Severity == SeverityHigh {
				highSeverityRedirect++
			}
		}
		if highSeverityRedirect > 0 {
			actions = append(actions, fmt.Sprintf("HIGH: Fix %d Open Redirect vulnerabilities - implement URL validation allowlist", highSeverityRedirect))
		}
	}

	// Priority 5: Cookie security issues
	if u.Headers != nil {
		insecureCookies := u.findCookiesWithoutSameSite()
		if len(insecureCookies) > 0 {
			actions = append(actions, "MEDIUM: Add SameSite attribute to session cookies to prevent CSRF")
		}
	}

	// Limit to top 5 actions
	if len(actions) > 5 {
		actions = actions[:5]
	}

	return actions
}

// GetPrioritizedFindings returns all findings sorted by effective severity.
func (u *UnifiedScanResult) GetPrioritizedFindings() []interface{} {
	type prioritizedFinding struct {
		finding         interface{}
		severity        string
		confidence      float64
		isCorrelated    bool
		correlationInfo *CorrelatedFinding
	}

	findings := make([]prioritizedFinding, 0)

	// Add correlated findings first (they have elevated severity)
	for _, corr := range u.Correlations {
		findings = append(findings, prioritizedFinding{
			finding:         corr,
			severity:        corr.EffectiveSeverity,
			confidence:      corr.Confidence,
			isCorrelated:    true,
			correlationInfo: &corr,
		})
	}

	// Add SQLi findings
	if u.SQLi != nil {
		for _, finding := range u.SQLi.Findings {
			// Skip if already in correlations
			if !u.isInCorrelations(finding) {
				findings = append(findings, prioritizedFinding{
					finding:      finding,
					severity:     finding.Severity,
					confidence:   u.parseConfidenceString(finding.Confidence),
					isCorrelated: false,
				})
			}
		}
	}

	// Add XSS findings
	if u.XSS != nil {
		for _, finding := range u.XSS.Findings {
			if !u.isInCorrelations(finding) {
				findings = append(findings, prioritizedFinding{
					finding:      finding,
					severity:     finding.Severity,
					confidence:   u.parseConfidenceString(finding.Confidence),
					isCorrelated: false,
				})
			}
		}
	}

	// Add CSRF findings
	if u.CSRF != nil {
		for _, finding := range u.CSRF.Findings {
			if !u.isInCorrelations(finding) {
				findings = append(findings, prioritizedFinding{
					finding:      finding,
					severity:     finding.Severity,
					confidence:   ConfidenceCSRF,
					isCorrelated: false,
				})
			}
		}
	}

	// Add header findings
	if u.Headers != nil {
		for _, finding := range u.Headers.Headers {
			if !finding.Present && !u.isInCorrelations(finding) {
				findings = append(findings, prioritizedFinding{
					finding:      finding,
					severity:     finding.Severity,
					confidence:   ConfidenceHeader,
					isCorrelated: false,
				})
			}
		}
	}

	// Sort by severity (high > medium > low), then by confidence
	sort.Slice(findings, func(i, j int) bool {
		severityOrder := map[string]int{
			SeverityHigh:   3,
			SeverityMedium: 2,
			SeverityLow:    1,
			SeverityInfo:   0,
		}

		iSeverity := severityOrder[findings[i].severity]
		jSeverity := severityOrder[findings[j].severity]

		if iSeverity != jSeverity {
			return iSeverity > jSeverity
		}

		return findings[i].confidence > findings[j].confidence
	})

	// Extract just the findings
	result := make([]interface{}, len(findings))
	for i, pf := range findings {
		result[i] = pf.finding
	}

	return result
}

// Helper functions

func (u *UnifiedScanResult) findMissingHeader(name string) *HeaderFinding {
	if u.Headers == nil {
		return nil
	}
	for i := range u.Headers.Headers {
		if strings.EqualFold(u.Headers.Headers[i].Name, name) && !u.Headers.Headers[i].Present {
			return &u.Headers.Headers[i]
		}
	}
	return nil
}

func (u *UnifiedScanResult) findServerVersionHeaders() []HeaderFinding {
	results := make([]HeaderFinding, 0)
	if u.Headers == nil {
		return results
	}

	versionHeaders := []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}
	for _, finding := range u.Headers.Headers {
		for _, versionHeader := range versionHeaders {
			if strings.EqualFold(finding.Name, versionHeader) && finding.Present && finding.Value != "" {
				results = append(results, finding)
			}
		}
	}
	return results
}

func (u *UnifiedScanResult) findCookiesWithoutSameSite() []CookieFinding {
	results := make([]CookieFinding, 0)
	if u.Headers == nil {
		return results
	}

	for _, cookie := range u.Headers.Cookies {
		if cookie.SameSite == "" || cookie.SameSite == "none" {
			results = append(results, cookie)
		}
	}
	return results
}

func (u *UnifiedScanResult) calculateConfidence(conf1 string, conf2 float64) float64 {
	c1 := u.parseConfidenceString(conf1)
	return (c1 + conf2) / 2.0
}

func (u *UnifiedScanResult) parseConfidenceString(conf string) float64 {
	switch strings.ToLower(conf) {
	case "high":
		return ConfidenceHigh
	case "medium":
		return ConfidenceMedium
	case "low":
		return ConfidenceLow
	default:
		return ConfidenceMedium
	}
}

func (u *UnifiedScanResult) severityToScore(severity string) int {
	switch severity {
	case SeverityHigh:
		return 10
	case SeverityMedium:
		return 5
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func (u *UnifiedScanResult) isInCorrelations(finding interface{}) bool {
	for _, corr := range u.Correlations {
		if reflect.DeepEqual(corr.PrimaryFinding, finding) {
			return true
		}
		for _, related := range corr.RelatedFindings {
			if reflect.DeepEqual(related, finding) {
				return true
			}
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
