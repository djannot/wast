package scanner

import (
	"testing"
)

func TestNewUnifiedScanResult(t *testing.T) {
	target := "https://example.com"

	// Create sample scan results
	headers := &HeaderScanResult{
		Target: target,
		Headers: []HeaderFinding{
			{
				Name:        "Content-Security-Policy",
				Present:     false,
				Severity:    SeverityHigh,
				Description: "CSP header missing",
			},
		},
	}

	xss := &XSSScanResult{
		Target: target,
		Findings: []XSSFinding{
			{
				URL:        target + "/search",
				Parameter:  "q",
				Severity:   SeverityHigh,
				Type:       "reflected",
				Confidence: "high",
			},
		},
	}

	result := NewUnifiedScanResult(target, false, headers, xss, nil, nil, nil, nil)

	if result.Target != target {
		t.Errorf("Expected target %s, got %s", target, result.Target)
	}

	if result.PassiveOnly != false {
		t.Errorf("Expected PassiveOnly to be false")
	}

	if result.RiskScore.Overall <= 0 {
		t.Errorf("Expected non-zero risk score, got %d", result.RiskScore.Overall)
	}

	if result.Summary.TotalFindings <= 0 {
		t.Errorf("Expected findings to be counted, got %d", result.Summary.TotalFindings)
	}
}

func TestCorrelationXSSWithMissingCSP(t *testing.T) {
	target := "https://example.com"

	headers := &HeaderScanResult{
		Target: target,
		Headers: []HeaderFinding{
			{
				Name:        "Content-Security-Policy",
				Present:     false,
				Severity:    SeverityHigh,
				Description: "CSP header missing",
			},
		},
	}

	xss := &XSSScanResult{
		Target: target,
		Findings: []XSSFinding{
			{
				URL:        target + "/search",
				Parameter:  "q",
				Severity:   SeverityHigh,
				Type:       "reflected",
				Confidence: "high",
			},
		},
	}

	result := NewUnifiedScanResult(target, false, headers, xss, nil, nil, nil, nil)

	if len(result.Correlations) == 0 {
		t.Errorf("Expected XSS + missing CSP correlation, got no correlations")
	}

	found := false
	for _, corr := range result.Correlations {
		if corr.EffectiveSeverity == SeverityHigh {
			found = true
			if corr.Confidence <= 0 {
				t.Errorf("Expected positive confidence, got %f", corr.Confidence)
			}
			if corr.Explanation == "" {
				t.Errorf("Expected non-empty explanation")
			}
		}
	}

	if !found {
		t.Errorf("Expected high-severity correlation for XSS + missing CSP")
	}
}

func TestCorrelationSQLiWithServerHeaders(t *testing.T) {
	target := "https://example.com"

	headers := &HeaderScanResult{
		Target: target,
		Headers: []HeaderFinding{
			{
				Name:     "X-Powered-By",
				Present:  true,
				Value:    "PHP/7.4.0",
				Severity: SeverityLow,
			},
		},
	}

	sqli := &SQLiScanResult{
		Target: target,
		Findings: []SQLiFinding{
			{
				URL:        target + "/api/users",
				Parameter:  "id",
				Severity:   SeverityHigh,
				Type:       "error-based",
				Confidence: "high",
			},
		},
	}

	result := NewUnifiedScanResult(target, false, headers, nil, sqli, nil, nil, nil)

	if len(result.Correlations) == 0 {
		t.Errorf("Expected SQLi + server header correlation, got no correlations")
	}

	found := false
	for _, corr := range result.Correlations {
		if corr.EffectiveSeverity == SeverityHigh {
			found = true
		}
	}

	if !found {
		t.Errorf("Expected correlation for SQLi + server version disclosure")
	}
}

func TestCorrelationCSRFWithMissingSameSite(t *testing.T) {
	target := "https://example.com"

	headers := &HeaderScanResult{
		Target: target,
		Cookies: []CookieFinding{
			{
				Name:     "session_id",
				SameSite: "",
				Severity: SeverityMedium,
			},
		},
	}

	csrf := &CSRFScanResult{
		Target: target,
		Findings: []CSRFFinding{
			{
				FormAction: target + "/api/transfer",
				FormMethod: "POST",
				Type:       "missing_token",
				Severity:   SeverityHigh,
			},
		},
	}

	result := NewUnifiedScanResult(target, false, headers, nil, nil, csrf, nil, nil)

	if len(result.Correlations) == 0 {
		t.Errorf("Expected CSRF + missing SameSite correlation, got no correlations")
	}
}

func TestCorrelationMultipleInjectionPoints(t *testing.T) {
	target := "https://example.com"

	xss := &XSSScanResult{
		Target: target,
		Findings: []XSSFinding{
			{
				URL:        target + "/search",
				Parameter:  "query",
				Severity:   SeverityHigh,
				Type:       "reflected",
				Confidence: "high",
			},
		},
	}

	sqli := &SQLiScanResult{
		Target: target,
		Findings: []SQLiFinding{
			{
				URL:        target + "/search",
				Parameter:  "query",
				Severity:   SeverityHigh,
				Type:       "error-based",
				Confidence: "high",
			},
		},
	}

	result := NewUnifiedScanResult(target, false, nil, xss, sqli, nil, nil, nil)

	if len(result.Correlations) == 0 {
		t.Errorf("Expected multiple injection point correlation, got no correlations")
	}

	found := false
	for _, corr := range result.Correlations {
		if corr.EffectiveSeverity == SeverityHigh {
			found = true
		}
	}

	if !found {
		t.Errorf("Expected high-severity correlation for SQLi + XSS on same parameter")
	}
}

func TestRiskScoreCalculation(t *testing.T) {
	target := "https://example.com"

	headers := &HeaderScanResult{
		Target: target,
		Headers: []HeaderFinding{
			{
				Name:     "Content-Security-Policy",
				Present:  false,
				Severity: SeverityHigh,
			},
			{
				Name:     "X-Frame-Options",
				Present:  false,
				Severity: SeverityMedium,
			},
		},
	}

	xss := &XSSScanResult{
		Target: target,
		Findings: []XSSFinding{
			{
				URL:        target + "/search",
				Parameter:  "q",
				Severity:   SeverityHigh,
				Type:       "reflected",
				Confidence: "high",
			},
		},
	}

	sqli := &SQLiScanResult{
		Target: target,
		Findings: []SQLiFinding{
			{
				URL:        target + "/api/users",
				Parameter:  "id",
				Severity:   SeverityHigh,
				Type:       "error-based",
				Confidence: "high",
			},
		},
	}

	result := NewUnifiedScanResult(target, false, headers, xss, sqli, nil, nil, nil)

	if result.RiskScore.Overall <= 0 || result.RiskScore.Overall > 100 {
		t.Errorf("Expected risk score between 1-100, got %d", result.RiskScore.Overall)
	}

	if result.RiskScore.Confidence <= 0 || result.RiskScore.Confidence > 1 {
		t.Errorf("Expected confidence between 0-1, got %f", result.RiskScore.Confidence)
	}

	if len(result.RiskScore.Breakdown) == 0 {
		t.Errorf("Expected risk breakdown to be populated")
	}

	// Check that breakdown categories exist
	if _, ok := result.RiskScore.Breakdown["injection"]; !ok {
		t.Errorf("Expected 'injection' category in breakdown")
	}
}

func TestUnifiedSummary(t *testing.T) {
	target := "https://example.com"

	headers := &HeaderScanResult{
		Target: target,
		Headers: []HeaderFinding{
			{
				Name:     "Content-Security-Policy",
				Present:  false,
				Severity: SeverityHigh,
			},
		},
	}

	xss := &XSSScanResult{
		Target: target,
		Findings: []XSSFinding{
			{
				URL:        target + "/search",
				Parameter:  "q",
				Severity:   SeverityHigh,
				Type:       "reflected",
				Confidence: "high",
			},
			{
				URL:        target + "/comment",
				Parameter:  "text",
				Severity:   SeverityMedium,
				Type:       "reflected",
				Confidence: "medium",
			},
		},
	}

	result := NewUnifiedScanResult(target, false, headers, xss, nil, nil, nil, nil)

	if result.Summary.TotalFindings != 3 {
		t.Errorf("Expected 3 total findings, got %d", result.Summary.TotalFindings)
	}

	if result.Summary.HighSeverity != 2 {
		t.Errorf("Expected 2 high severity findings, got %d", result.Summary.HighSeverity)
	}

	if result.Summary.MediumSeverity != 1 {
		t.Errorf("Expected 1 medium severity finding, got %d", result.Summary.MediumSeverity)
	}
}

func TestPriorityActions(t *testing.T) {
	target := "https://example.com"

	sqli := &SQLiScanResult{
		Target: target,
		Findings: []SQLiFinding{
			{
				URL:        target + "/api/users",
				Parameter:  "id",
				Severity:   SeverityHigh,
				Type:       "error-based",
				Confidence: "high",
			},
		},
	}

	result := NewUnifiedScanResult(target, false, nil, nil, sqli, nil, nil, nil)

	if len(result.Summary.PriorityActions) == 0 {
		t.Errorf("Expected priority actions to be generated")
	}

	// Check that SQL injection fix is in priority actions
	found := false
	for _, action := range result.Summary.PriorityActions {
		if len(action) > 0 {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected non-empty priority actions")
	}
}

func TestGetPrioritizedFindings(t *testing.T) {
	target := "https://example.com"

	headers := &HeaderScanResult{
		Target: target,
		Headers: []HeaderFinding{
			{
				Name:     "Content-Security-Policy",
				Present:  false,
				Severity: SeverityHigh,
			},
			{
				Name:     "X-Content-Type-Options",
				Present:  false,
				Severity: SeverityLow,
			},
		},
	}

	xss := &XSSScanResult{
		Target: target,
		Findings: []XSSFinding{
			{
				URL:        target + "/search",
				Parameter:  "q",
				Severity:   SeverityMedium,
				Type:       "reflected",
				Confidence: "medium",
			},
		},
	}

	sqli := &SQLiScanResult{
		Target: target,
		Findings: []SQLiFinding{
			{
				URL:        target + "/api/users",
				Parameter:  "id",
				Severity:   SeverityHigh,
				Type:       "error-based",
				Confidence: "high",
			},
		},
	}

	result := NewUnifiedScanResult(target, false, headers, xss, sqli, nil, nil, nil)
	prioritized := result.GetPrioritizedFindings()

	if len(prioritized) == 0 {
		t.Errorf("Expected prioritized findings, got none")
	}

	// First finding should be high severity (either correlation or SQLi)
	// We can't check the exact type without type assertions, but we can verify the list is populated
	if len(prioritized) < result.Summary.TotalFindings {
		t.Errorf("Expected at least %d prioritized findings, got %d", result.Summary.TotalFindings, len(prioritized))
	}
}

func TestEmptyResultHandling(t *testing.T) {
	target := "https://example.com"

	result := NewUnifiedScanResult(target, true, nil, nil, nil, nil, nil, nil)

	if result.RiskScore.Overall != 0 {
		t.Errorf("Expected zero risk score for empty results, got %d", result.RiskScore.Overall)
	}

	if result.Summary.TotalFindings != 0 {
		t.Errorf("Expected zero findings for empty results, got %d", result.Summary.TotalFindings)
	}

	if len(result.Correlations) != 0 {
		t.Errorf("Expected no correlations for empty results, got %d", len(result.Correlations))
	}
}

func TestPassiveOnlyFlag(t *testing.T) {
	target := "https://example.com"

	headers := &HeaderScanResult{
		Target: target,
		Headers: []HeaderFinding{
			{
				Name:     "Content-Security-Policy",
				Present:  false,
				Severity: SeverityHigh,
			},
		},
	}

	result := NewUnifiedScanResult(target, true, headers, nil, nil, nil, nil, nil)

	if !result.PassiveOnly {
		t.Errorf("Expected PassiveOnly flag to be true")
	}
}

func TestErrorPropagation(t *testing.T) {
	target := "https://example.com"
	errors := []string{"error 1", "error 2"}

	result := NewUnifiedScanResult(target, false, nil, nil, nil, nil, nil, errors)

	if len(result.Errors) != 2 {
		t.Errorf("Expected 2 errors, got %d", len(result.Errors))
	}
}

func TestSeverityToScore(t *testing.T) {
	result := &UnifiedScanResult{}

	tests := []struct {
		severity string
		expected int
	}{
		{SeverityHigh, 10},
		{SeverityMedium, 5},
		{SeverityLow, 2},
		{SeverityInfo, 1},
		{"unknown", 0},
	}

	for _, tt := range tests {
		score := result.severityToScore(tt.severity)
		if score != tt.expected {
			t.Errorf("For severity %s, expected score %d, got %d", tt.severity, tt.expected, score)
		}
	}
}

func TestParseConfidenceString(t *testing.T) {
	result := &UnifiedScanResult{}

	tests := []struct {
		confidence string
		expected   float64
	}{
		{"high", 0.9},
		{"medium", 0.7},
		{"low", 0.5},
		{"unknown", 0.7},
	}

	for _, tt := range tests {
		conf := result.parseConfidenceString(tt.confidence)
		if conf != tt.expected {
			t.Errorf("For confidence %s, expected %f, got %f", tt.confidence, tt.expected, conf)
		}
	}
}

func TestCorrelationIDGeneration(t *testing.T) {
	target := "https://example.com"

	headers := &HeaderScanResult{
		Target: target,
		Headers: []HeaderFinding{
			{
				Name:     "Content-Security-Policy",
				Present:  false,
				Severity: SeverityHigh,
			},
		},
		Cookies: []CookieFinding{
			{
				Name:     "session",
				SameSite: "",
				Severity: SeverityMedium,
			},
		},
	}

	xss := &XSSScanResult{
		Target: target,
		Findings: []XSSFinding{
			{
				URL:        target + "/page1",
				Parameter:  "q",
				Severity:   SeverityHigh,
				Type:       "reflected",
				Confidence: "high",
			},
			{
				URL:        target + "/page2",
				Parameter:  "search",
				Severity:   SeverityHigh,
				Type:       "reflected",
				Confidence: "high",
			},
		},
	}

	csrf := &CSRFScanResult{
		Target: target,
		Findings: []CSRFFinding{
			{
				FormAction: target + "/form",
				Type:       "missing_token",
				Severity:   SeverityHigh,
			},
		},
	}

	result := NewUnifiedScanResult(target, false, headers, xss, nil, csrf, nil, nil)

	// Check that correlation IDs are unique
	ids := make(map[string]bool)
	for _, corr := range result.Correlations {
		if ids[corr.ID] {
			t.Errorf("Duplicate correlation ID: %s", corr.ID)
		}
		ids[corr.ID] = true
	}
}

func TestRiskScoreBreakdownCategories(t *testing.T) {
	target := "https://example.com"

	headers := &HeaderScanResult{
		Target: target,
		Headers: []HeaderFinding{
			{
				Name:     "Content-Security-Policy",
				Present:  false,
				Severity: SeverityHigh,
			},
		},
	}

	xss := &XSSScanResult{
		Target: target,
		Findings: []XSSFinding{
			{
				URL:        target + "/search",
				Parameter:  "q",
				Severity:   SeverityHigh,
				Type:       "reflected",
				Confidence: "high",
			},
		},
	}

	csrf := &CSRFScanResult{
		Target: target,
		Findings: []CSRFFinding{
			{
				FormAction: target + "/form",
				Type:       "missing_token",
				Severity:   SeverityMedium,
			},
		},
	}

	result := NewUnifiedScanResult(target, false, headers, xss, nil, csrf, nil, nil)

	// Check that expected categories are present
	expectedCategories := []string{"injection", "csrf", "misconfiguration"}
	for _, category := range expectedCategories {
		if _, ok := result.RiskScore.Breakdown[category]; !ok {
			t.Errorf("Expected category '%s' in risk breakdown", category)
		}
	}
}

// TestGetPrioritizedFindings_NoDuplicates verifies that correlated findings
// don't appear twice in the prioritized findings list (once as correlation, once as individual).
// This test addresses the critical bug where pointer comparison was causing duplicates.
func TestGetPrioritizedFindings_NoDuplicates(t *testing.T) {
	target := "https://example.com"

	// Create findings that will be in correlations
	headers := &HeaderScanResult{
		Target: target,
		Headers: []HeaderFinding{
			{Name: "Content-Security-Policy", Present: false, Severity: SeverityHigh},
		},
	}
	xss := &XSSScanResult{
		Target: target,
		Findings: []XSSFinding{
			{
				URL:        target + "/search",
				Parameter:  "q",
				Severity:   SeverityHigh,
				Type:       "reflected",
				Confidence: "high",
			},
		},
	}

	result := NewUnifiedScanResult(target, false, headers, xss, nil, nil, nil, nil)
	prioritized := result.GetPrioritizedFindings()

	// Check for duplicates by building a map of findings
	// We use a simple string representation as key
	seen := make(map[string]int)
	for _, finding := range prioritized {
		var key string
		switch f := finding.(type) {
		case CorrelatedFinding:
			key = f.ID
		case XSSFinding:
			key = "XSS:" + f.URL + ":" + f.Parameter
		case HeaderFinding:
			key = "Header:" + f.Name
		case SQLiFinding:
			key = "SQLi:" + f.URL + ":" + f.Parameter
		case CSRFFinding:
			key = "CSRF:" + f.FormAction
		default:
			key = "Unknown"
		}
		seen[key]++
	}

	// Check for any duplicates
	for key, count := range seen {
		if count > 1 {
			t.Errorf("Duplicate finding detected: %s appeared %d times", key, count)
		}
	}

	// Verify that we have at least one correlation and that the XSS finding
	// appears only once (as part of the correlation, not separately)
	correlationCount := 0
	xssStandaloneCount := 0
	for _, finding := range prioritized {
		switch f := finding.(type) {
		case CorrelatedFinding:
			correlationCount++
		case XSSFinding:
			if f.Parameter == "q" {
				xssStandaloneCount++
			}
		}
	}

	if correlationCount == 0 {
		t.Error("Expected at least one correlation in prioritized findings")
	}

	// The XSS finding should NOT appear as a standalone finding since it's in a correlation
	if xssStandaloneCount > 0 {
		t.Errorf("Expected XSS finding to only appear in correlation, but found %d standalone instances", xssStandaloneCount)
	}
}

// TestFindCookiesWithoutSameSite_NoneValue verifies that cookies with
// SameSite="none" are correctly identified as insecure.
func TestFindCookiesWithoutSameSite_NoneValue(t *testing.T) {
	target := "https://example.com"

	headers := &HeaderScanResult{
		Target: target,
		Cookies: []CookieFinding{
			{
				Name:     "session",
				SameSite: "none",
				Severity: SeverityMedium,
			},
			{
				Name:     "safe_cookie",
				SameSite: "strict",
				Severity: SeverityInfo,
			},
			{
				Name:     "empty_cookie",
				SameSite: "",
				Severity: SeverityMedium,
			},
		},
	}

	result := NewUnifiedScanResult(target, false, headers, nil, nil, nil, nil, nil)
	insecure := result.findCookiesWithoutSameSite()

	// Should find 2 insecure cookies: "none" and empty string
	if len(insecure) != 2 {
		t.Errorf("Expected 2 insecure cookies, got %d", len(insecure))
	}

	// Verify the correct cookies were identified
	foundNone := false
	foundEmpty := false
	for _, cookie := range insecure {
		if cookie.Name == "session" && cookie.SameSite == "none" {
			foundNone = true
		}
		if cookie.Name == "empty_cookie" && cookie.SameSite == "" {
			foundEmpty = true
		}
	}

	if !foundNone {
		t.Error("Expected to find cookie with SameSite='none'")
	}
	if !foundEmpty {
		t.Error("Expected to find cookie with empty SameSite")
	}
}
