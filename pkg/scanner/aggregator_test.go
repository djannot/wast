package scanner

import (
	"strings"
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

	result := NewUnifiedScanResult(target, false, headers, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

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

	result := NewUnifiedScanResult(target, false, headers, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

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

	result := NewUnifiedScanResult(target, false, headers, nil, sqli,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

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

	result := NewUnifiedScanResult(target, false, headers, nil, nil,nil, csrf, nil, nil, nil, nil, nil, nil, nil, nil)

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

	result := NewUnifiedScanResult(target, false, nil, xss, sqli,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

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

	result := NewUnifiedScanResult(target, false, headers, xss, sqli,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

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

	result := NewUnifiedScanResult(target, false, headers, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

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

	result := NewUnifiedScanResult(target, false, nil, nil, sqli,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

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

	result := NewUnifiedScanResult(target, false, headers, xss, sqli,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
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

	result := NewUnifiedScanResult(target, true, nil, nil, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

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

	result := NewUnifiedScanResult(target, true, headers, nil, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	if !result.PassiveOnly {
		t.Errorf("Expected PassiveOnly flag to be true")
	}
}

func TestErrorPropagation(t *testing.T) {
	target := "https://example.com"
	errors := []string{"error 1", "error 2"}

	result := NewUnifiedScanResult(target, false, nil, nil, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, errors)

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

	result := NewUnifiedScanResult(target, false, headers, xss, nil,nil, csrf, nil, nil, nil, nil, nil, nil, nil, nil)

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

	result := NewUnifiedScanResult(target, false, headers, xss, nil,nil, csrf, nil, nil, nil, nil, nil, nil, nil, nil)

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

	result := NewUnifiedScanResult(target, false, headers, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
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

	result := NewUnifiedScanResult(target, false, headers, nil, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
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

// TestCalculateRiskScore_AllSeverityCombinations tests calculateRiskScore with different severity levels
func TestCalculateRiskScore_AllSeverityCombinations(t *testing.T) {
	tests := []struct {
		name             string
		xssFindings      []XSSFinding
		sqliFindings     []SQLiFinding
		expectedMinScore int
		expectedMaxScore int
	}{
		{
			name: "all high severity findings",
			xssFindings: []XSSFinding{
				{URL: "http://test.com", Parameter: "q", Severity: SeverityHigh, Confidence: "high"},
			},
			sqliFindings: []SQLiFinding{
				{URL: "http://test.com", Parameter: "id", Severity: SeverityHigh, Confidence: "high"},
			},
			expectedMinScore: 20,
			expectedMaxScore: 100,
		},
		{
			name: "all medium severity findings",
			xssFindings: []XSSFinding{
				{URL: "http://test.com", Parameter: "q", Severity: SeverityMedium, Confidence: "medium"},
			},
			sqliFindings: []SQLiFinding{
				{URL: "http://test.com", Parameter: "id", Severity: SeverityMedium, Confidence: "medium"},
			},
			expectedMinScore: 10,
			expectedMaxScore: 50,
		},
		{
			name: "all low severity findings",
			xssFindings: []XSSFinding{
				{URL: "http://test.com", Parameter: "q", Severity: SeverityLow, Confidence: "low"},
			},
			sqliFindings: []SQLiFinding{
				{URL: "http://test.com", Parameter: "id", Severity: SeverityLow, Confidence: "low"},
			},
			expectedMinScore: 1,
			expectedMaxScore: 20,
		},
		{
			name: "mixed severity findings",
			xssFindings: []XSSFinding{
				{URL: "http://test.com", Parameter: "q", Severity: SeverityHigh, Confidence: "high"},
				{URL: "http://test.com", Parameter: "p", Severity: SeverityLow, Confidence: "low"},
			},
			sqliFindings: []SQLiFinding{
				{URL: "http://test.com", Parameter: "id", Severity: SeverityMedium, Confidence: "medium"},
			},
			expectedMinScore: 15,
			expectedMaxScore: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xss := &XSSScanResult{Findings: tt.xssFindings}
			sqli := &SQLiScanResult{Findings: tt.sqliFindings}

			result := NewUnifiedScanResult("http://test.com", false, nil, xss, sqli,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

			if result.RiskScore.Overall < tt.expectedMinScore {
				t.Errorf("Expected risk score >= %d, got %d", tt.expectedMinScore, result.RiskScore.Overall)
			}
			if result.RiskScore.Overall > tt.expectedMaxScore {
				t.Errorf("Expected risk score <= %d, got %d", tt.expectedMaxScore, result.RiskScore.Overall)
			}
		})
	}
}

// TestCalculateRiskScore_ZeroFindings tests calculateRiskScore with no findings
func TestCalculateRiskScore_ZeroFindings(t *testing.T) {
	result := NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	if result.RiskScore.Overall != 0 {
		t.Errorf("Expected risk score 0 for empty findings, got %d", result.RiskScore.Overall)
	}

	if result.RiskScore.Confidence != ConfidenceMedium {
		t.Errorf("Expected default confidence %f, got %f", ConfidenceMedium, result.RiskScore.Confidence)
	}
}

// TestCalculateRiskScore_CategoryCaps tests that risk scores respect category caps
func TestCalculateRiskScore_CategoryCaps(t *testing.T) {
	tests := []struct {
		name             string
		setupFunc        func() *UnifiedScanResult
		category         string
		expectedMaxScore int
	}{
		{
			name: "injection cap at 40",
			setupFunc: func() *UnifiedScanResult {
				// Create 5 high-severity injection findings (5 * 10 = 50 points, should cap at 40)
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				sqli := &SQLiScanResult{
					Findings: []SQLiFinding{
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				cmdi := &CMDiScanResult{
					Findings: []CMDiFinding{
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, xss, sqli,nil, nil, nil, nil, cmdi, nil, nil, nil, nil, nil)
			},
			category:         "injection",
			expectedMaxScore: 40,
		},
		{
			name: "csrf cap at 20",
			setupFunc: func() *UnifiedScanResult {
				// Create 3 high-severity CSRF findings (3 * 10 = 30 points, should cap at 20)
				csrf := &CSRFScanResult{
					Findings: []CSRFFinding{
						{Severity: SeverityHigh},
						{Severity: SeverityHigh},
						{Severity: SeverityHigh},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, csrf, nil, nil, nil, nil, nil, nil, nil, nil)
			},
			category:         "csrf",
			expectedMaxScore: 20,
		},
		{
			name: "ssrf cap at 30",
			setupFunc: func() *UnifiedScanResult {
				// Create 4 high-severity SSRF findings (4 * 10 = 40 points, should cap at 30)
				ssrf := &SSRFScanResult{
					Findings: []SSRFFinding{
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, nil, ssrf, nil, nil, nil, nil, nil, nil, nil)
			},
			category:         "ssrf",
			expectedMaxScore: 30,
		},
		{
			name: "redirect cap at 25",
			setupFunc: func() *UnifiedScanResult {
				// Create 3 high-severity redirect findings (3 * 10 = 30 points, should cap at 25)
				redirect := &RedirectScanResult{
					Findings: []RedirectFinding{
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, nil, nil, redirect, nil, nil, nil, nil, nil, nil)
			},
			category:         "redirect",
			expectedMaxScore: 25,
		},
		{
			name: "websocket cap at 20",
			setupFunc: func() *UnifiedScanResult {
				// Create 3 high-severity websocket findings (3 * 10 = 30 points, should cap at 20)
				websocket := &WebSocketScanResult{
					Findings: []WebSocketFinding{
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, nil, nil, nil, nil, nil, nil, nil, websocket, nil)
			},
			category:         "websocket",
			expectedMaxScore: 20,
		},
		{
			name: "misconfiguration cap at 25",
			setupFunc: func() *UnifiedScanResult {
				// Create 4 high-severity header misconfigurations (4 * 10 = 40 points, should cap at 25)
				headers := &HeaderScanResult{
					Headers: []HeaderFinding{
						{Present: false, Severity: SeverityHigh},
						{Present: false, Severity: SeverityHigh},
						{Present: false, Severity: SeverityHigh},
						{Present: false, Severity: SeverityHigh},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, headers, nil, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			},
			category:         "misconfiguration",
			expectedMaxScore: 25,
		},
		{
			name: "correlation_multiplier cap at 15",
			setupFunc: func() *UnifiedScanResult {
				// Create 4 correlations (4 * 5 = 20 points, should cap at 15)
				headers := &HeaderScanResult{
					Headers: []HeaderFinding{
						{Name: "Content-Security-Policy", Present: false, Severity: SeverityHigh},
					},
					Cookies: []CookieFinding{
						{Name: "session", SameSite: "", Severity: SeverityMedium},
					},
				}
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{URL: "http://test.com/p1", Parameter: "q1", Severity: SeverityHigh, Type: "reflected", Confidence: "high"},
						{URL: "http://test.com/p2", Parameter: "q2", Severity: SeverityHigh, Type: "reflected", Confidence: "high"},
					},
				}
				sqli := &SQLiScanResult{
					Findings: []SQLiFinding{
						{URL: "http://test.com/p1", Parameter: "q1", Severity: SeverityHigh, Type: "error-based", Confidence: "high"},
						{URL: "http://test.com/p2", Parameter: "q2", Severity: SeverityHigh, Type: "error-based", Confidence: "high"},
					},
				}
				csrf := &CSRFScanResult{
					Findings: []CSRFFinding{
						{FormAction: "http://test.com/form", Type: "missing_token", Severity: SeverityHigh},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, headers, xss, sqli,nil, csrf, nil, nil, nil, nil, nil, nil, nil, nil)
			},
			category:         "correlation_multiplier",
			expectedMaxScore: 15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.setupFunc()
			categoryScore := result.RiskScore.Breakdown[tt.category]

			if categoryScore > tt.expectedMaxScore {
				t.Errorf("Expected %s category score to be capped at %d, got %d", tt.category, tt.expectedMaxScore, categoryScore)
			}
		})
	}
}

// TestCalculateRiskScore_ConfidenceCalculation tests confidence calculation with different inputs
func TestCalculateRiskScore_ConfidenceCalculation(t *testing.T) {
	tests := []struct {
		name               string
		findings           *UnifiedScanResult
		expectedConfidence float64
		tolerance          float64
	}{
		{
			name: "high confidence findings",
			findings: func() *UnifiedScanResult {
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			}(),
			expectedConfidence: ConfidenceHigh,
			tolerance:          0.01,
		},
		{
			name: "medium confidence findings",
			findings: func() *UnifiedScanResult {
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{Severity: SeverityMedium, Confidence: "medium"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			}(),
			expectedConfidence: ConfidenceMedium,
			tolerance:          0.01,
		},
		{
			name: "low confidence findings",
			findings: func() *UnifiedScanResult {
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{Severity: SeverityLow, Confidence: "low"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			}(),
			expectedConfidence: ConfidenceLow,
			tolerance:          0.01,
		},
		{
			name: "mixed confidence findings",
			findings: func() *UnifiedScanResult {
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityLow, Confidence: "low"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			}(),
			expectedConfidence: (ConfidenceHigh + ConfidenceLow) / 2.0,
			tolerance:          0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := tt.findings.RiskScore.Confidence
			if conf < tt.expectedConfidence-tt.tolerance || conf > tt.expectedConfidence+tt.tolerance {
				t.Errorf("Expected confidence ~%f (±%f), got %f", tt.expectedConfidence, tt.tolerance, conf)
			}
		})
	}
}

// TestGeneratePriorityActions_EmptyFindings tests generatePriorityActions with no findings
func TestGeneratePriorityActions_EmptyFindings(t *testing.T) {
	result := NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	if len(result.Summary.PriorityActions) != 0 {
		t.Errorf("Expected empty priority actions for empty findings, got %d actions", len(result.Summary.PriorityActions))
	}
}

// TestGeneratePriorityActions_SingleFindingType tests generatePriorityActions with single vulnerability type
func TestGeneratePriorityActions_SingleFindingType(t *testing.T) {
	tests := []struct {
		name             string
		setupFunc        func() *UnifiedScanResult
		expectedKeywords []string
	}{
		{
			name: "only SQLi findings",
			setupFunc: func() *UnifiedScanResult {
				sqli := &SQLiScanResult{
					Findings: []SQLiFinding{
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, nil, sqli,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			},
			expectedKeywords: []string{"SQL injection", "parameterized queries"},
		},
		{
			name: "only XSS findings",
			setupFunc: func() *UnifiedScanResult {
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			},
			expectedKeywords: []string{"XSS", "output encoding", "CSP"},
		},
		{
			name: "only CMDi findings",
			setupFunc: func() *UnifiedScanResult {
				cmdi := &CMDiScanResult{
					Findings: []CMDiFinding{
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, nil, nil, nil, cmdi, nil, nil, nil, nil, nil)
			},
			expectedKeywords: []string{"Command Injection", "system commands"},
		},
		{
			name: "only SSTI findings",
			setupFunc: func() *UnifiedScanResult {
				ssti := &SSTIScanResult{
					Findings: []SSTIFinding{
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, nil, nil, nil, nil, nil, ssti, nil, nil, nil)
			},
			expectedKeywords: []string{"SSTI", "template engines"},
		},
		{
			name: "only CSRF findings",
			setupFunc: func() *UnifiedScanResult {
				csrf := &CSRFScanResult{
					Findings: []CSRFFinding{
						{Severity: SeverityMedium},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, csrf, nil, nil, nil, nil, nil, nil, nil, nil)
			},
			expectedKeywords: []string{"CSRF tokens"},
		},
		{
			name: "only Open Redirect findings",
			setupFunc: func() *UnifiedScanResult {
				redirect := &RedirectScanResult{
					Findings: []RedirectFinding{
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, nil, nil, redirect, nil, nil, nil, nil, nil, nil)
			},
			expectedKeywords: []string{"Open Redirect", "URL validation"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.setupFunc()

			if len(result.Summary.PriorityActions) == 0 {
				t.Error("Expected at least one priority action")
			}

			// Check that at least one action contains one of the expected keywords
			foundKeyword := false
			for _, action := range result.Summary.PriorityActions {
				for _, keyword := range tt.expectedKeywords {
					if strings.Contains(action, keyword) {
						foundKeyword = true
						break
					}
				}
				if foundKeyword {
					break
				}
			}

			if !foundKeyword {
				t.Errorf("Expected priority actions to contain one of %v, got: %v", tt.expectedKeywords, result.Summary.PriorityActions)
			}
		})
	}
}

// TestGeneratePriorityActions_MixedSeverityFindings tests with mixed severity across types
func TestGeneratePriorityActions_MixedSeverityFindings(t *testing.T) {
	xss := &XSSScanResult{
		Findings: []XSSFinding{
			{Severity: SeverityHigh, Confidence: "high"},
			{Severity: SeverityLow, Confidence: "low"},
		},
	}
	sqli := &SQLiScanResult{
		Findings: []SQLiFinding{
			{Severity: SeverityMedium, Confidence: "medium"},
		},
	}
	csrf := &CSRFScanResult{
		Findings: []CSRFFinding{
			{Severity: SeverityMedium},
		},
	}

	result := NewUnifiedScanResult("http://test.com", false, nil, xss, sqli,nil, csrf, nil, nil, nil, nil, nil, nil, nil, nil)

	if len(result.Summary.PriorityActions) == 0 {
		t.Error("Expected multiple priority actions for mixed findings")
	}

	// Verify critical issues appear first
	if len(result.Summary.PriorityActions) > 0 {
		firstAction := result.Summary.PriorityActions[0]
		if !strings.Contains(firstAction, "CRITICAL") && !strings.Contains(firstAction, "HIGH") {
			t.Errorf("Expected first action to be CRITICAL or HIGH priority, got: %s", firstAction)
		}
	}
}

// TestGeneratePriorityActions_AllVulnerabilityTypes tests with all vulnerability types present
func TestGeneratePriorityActions_AllVulnerabilityTypes(t *testing.T) {
	headers := &HeaderScanResult{
		Headers: []HeaderFinding{
			{Name: "Content-Security-Policy", Present: false, Severity: SeverityHigh},
		},
	}
	xss := &XSSScanResult{
		Findings: []XSSFinding{
			{Severity: SeverityHigh, Type: "reflected", Confidence: "high"},
		},
	}
	sqli := &SQLiScanResult{
		Findings: []SQLiFinding{
			{Severity: SeverityHigh, Type: "error-based", Confidence: "high"},
		},
	}
	csrf := &CSRFScanResult{
		Findings: []CSRFFinding{
			{Severity: SeverityMedium, Type: "missing_token"},
		},
	}
	ssrf := &SSRFScanResult{
		Findings: []SSRFFinding{
			{Severity: SeverityHigh, Confidence: "high"},
		},
	}
	redirect := &RedirectScanResult{
		Findings: []RedirectFinding{
			{Severity: SeverityHigh, Confidence: "high"},
		},
	}
	cmdi := &CMDiScanResult{
		Findings: []CMDiFinding{
			{Severity: SeverityHigh, Confidence: "high"},
		},
	}
	ssti := &SSTIScanResult{
		Findings: []SSTIFinding{
			{Severity: SeverityHigh, Confidence: "high"},
		},
	}

	result := NewUnifiedScanResult("http://test.com", false, headers, xss, sqli,nil, csrf, ssrf, redirect, cmdi, nil, ssti, nil, nil, nil)

	if len(result.Summary.PriorityActions) == 0 {
		t.Error("Expected multiple priority actions with all vulnerability types")
	}

	// Verify actions are truncated to max 5
	if len(result.Summary.PriorityActions) > 5 {
		t.Errorf("Expected max 5 priority actions, got %d", len(result.Summary.PriorityActions))
	}
}

// TestGeneratePriorityActions_ActionListTruncation tests that action list is truncated to 5
func TestGeneratePriorityActions_ActionListTruncation(t *testing.T) {
	// Create multiple high-severity findings that would generate >5 actions
	headers := &HeaderScanResult{
		Headers: []HeaderFinding{
			{Name: "Content-Security-Policy", Present: false, Severity: SeverityHigh},
			{Name: "Strict-Transport-Security", Present: false, Severity: SeverityMedium},
		},
		Cookies: []CookieFinding{
			{Name: "session", SameSite: "", Severity: SeverityMedium},
		},
	}
	xss := &XSSScanResult{
		Findings: []XSSFinding{
			{URL: "http://test.com/p1", Parameter: "q1", Severity: SeverityHigh, Type: "reflected", Confidence: "high"},
			{URL: "http://test.com/p2", Parameter: "q2", Severity: SeverityHigh, Type: "reflected", Confidence: "high"},
		},
	}
	sqli := &SQLiScanResult{
		Findings: []SQLiFinding{
			{URL: "http://test.com/p1", Parameter: "q1", Severity: SeverityHigh, Type: "error-based", Confidence: "high"},
		},
	}
	cmdi := &CMDiScanResult{
		Findings: []CMDiFinding{
			{Severity: SeverityHigh, Confidence: "high"},
		},
	}
	ssti := &SSTIScanResult{
		Findings: []SSTIFinding{
			{Severity: SeverityHigh, Confidence: "high"},
		},
	}
	redirect := &RedirectScanResult{
		Findings: []RedirectFinding{
			{Severity: SeverityHigh, Confidence: "high"},
		},
	}
	csrf := &CSRFScanResult{
		Findings: []CSRFFinding{
			{Severity: SeverityMedium},
		},
	}

	result := NewUnifiedScanResult("http://test.com", false, headers, xss, sqli,nil, csrf, nil, redirect, cmdi, nil, ssti, nil, nil, nil)

	// Should be truncated to exactly 5 actions
	if len(result.Summary.PriorityActions) != 5 {
		t.Errorf("Expected exactly 5 priority actions (truncated), got %d", len(result.Summary.PriorityActions))
	}
}

// TestCorrelateFindings_XSSWithMissingCSP tests XSS + missing CSP correlation
func TestCorrelateFindings_XSSWithMissingCSP(t *testing.T) {
	tests := []struct {
		name            string
		xssType         string
		shouldCorrelate bool
	}{
		{
			name:            "reflected XSS should correlate",
			xssType:         "reflected",
			shouldCorrelate: true,
		},
		{
			name:            "dom XSS should correlate",
			xssType:         "dom",
			shouldCorrelate: true,
		},
		{
			name:            "stored XSS should not correlate",
			xssType:         "stored",
			shouldCorrelate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := &HeaderScanResult{
				Headers: []HeaderFinding{
					{Name: "Content-Security-Policy", Present: false, Severity: SeverityHigh},
				},
			}
			xss := &XSSScanResult{
				Findings: []XSSFinding{
					{URL: "http://test.com", Parameter: "q", Severity: SeverityHigh, Type: tt.xssType, Confidence: "high"},
				},
			}

			result := NewUnifiedScanResult("http://test.com", false, headers, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

			if tt.shouldCorrelate {
				if len(result.Correlations) == 0 {
					t.Errorf("Expected correlation for %s XSS + missing CSP", tt.xssType)
				}
			} else {
				if len(result.Correlations) > 0 {
					t.Errorf("Did not expect correlation for %s XSS + missing CSP", tt.xssType)
				}
			}
		})
	}
}

// TestCorrelateFindings_SQLiWithServerVersionHeader tests SQLi + server version correlation
func TestCorrelateFindings_SQLiWithServerVersionHeader(t *testing.T) {
	tests := []struct {
		name            string
		sqliType        string
		shouldCorrelate bool
	}{
		{
			name:            "error-based SQLi should correlate",
			sqliType:        "error-based",
			shouldCorrelate: true,
		},
		{
			name:            "boolean-based SQLi should not correlate",
			sqliType:        "boolean-based",
			shouldCorrelate: false,
		},
		{
			name:            "time-based SQLi should not correlate",
			sqliType:        "time-based",
			shouldCorrelate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := &HeaderScanResult{
				Headers: []HeaderFinding{
					{Name: "X-Powered-By", Present: true, Value: "PHP/7.4.0", Severity: SeverityLow},
				},
			}
			sqli := &SQLiScanResult{
				Findings: []SQLiFinding{
					{URL: "http://test.com", Parameter: "id", Severity: SeverityHigh, Type: tt.sqliType, Confidence: "high"},
				},
			}

			result := NewUnifiedScanResult("http://test.com", false, headers, nil, sqli,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

			if tt.shouldCorrelate {
				if len(result.Correlations) == 0 {
					t.Errorf("Expected correlation for %s SQLi + server version header", tt.sqliType)
				}
			} else {
				if len(result.Correlations) > 0 {
					t.Errorf("Did not expect correlation for %s SQLi + server version header", tt.sqliType)
				}
			}
		})
	}
}

// TestCorrelateFindings_CSRFWithMissingSameSiteCookie tests CSRF + missing SameSite correlation
func TestCorrelateFindings_CSRFWithMissingSameSiteCookie(t *testing.T) {
	tests := []struct {
		name            string
		csrfType        string
		shouldCorrelate bool
	}{
		{
			name:            "missing_token should correlate",
			csrfType:        "missing_token",
			shouldCorrelate: true,
		},
		{
			name:            "missing_samesite should correlate",
			csrfType:        "missing_samesite",
			shouldCorrelate: true,
		},
		{
			name:            "weak_token should not correlate",
			csrfType:        "weak_token",
			shouldCorrelate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := &HeaderScanResult{
				Cookies: []CookieFinding{
					{Name: "session", SameSite: "", Severity: SeverityMedium},
				},
			}
			csrf := &CSRFScanResult{
				Findings: []CSRFFinding{
					{FormAction: "http://test.com/form", Type: tt.csrfType, Severity: SeverityHigh},
				},
			}

			result := NewUnifiedScanResult("http://test.com", false, headers, nil, nil,nil, csrf, nil, nil, nil, nil, nil, nil, nil, nil)

			if tt.shouldCorrelate {
				if len(result.Correlations) == 0 {
					t.Errorf("Expected correlation for %s CSRF + missing SameSite", tt.csrfType)
				}
			} else {
				if len(result.Correlations) > 0 {
					t.Errorf("Did not expect correlation for %s CSRF + missing SameSite", tt.csrfType)
				}
			}
		})
	}
}

// TestCorrelateFindings_MultipleInjectionPoints tests SQLi + XSS on same parameter
func TestCorrelateFindings_MultipleInjectionPoints(t *testing.T) {
	xss := &XSSScanResult{
		Findings: []XSSFinding{
			{URL: "http://test.com/search", Parameter: "query", Severity: SeverityHigh, Confidence: "high"},
		},
	}
	sqli := &SQLiScanResult{
		Findings: []SQLiFinding{
			{URL: "http://test.com/search", Parameter: "query", Severity: SeverityHigh, Confidence: "high"},
		},
	}

	result := NewUnifiedScanResult("http://test.com", false, nil, xss, sqli,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	if len(result.Correlations) == 0 {
		t.Error("Expected correlation for SQLi + XSS on same parameter")
	}

	// Verify correlation explanation mentions both vulnerabilities
	found := false
	for _, corr := range result.Correlations {
		if strings.Contains(corr.Explanation, "SQL injection") && strings.Contains(corr.Explanation, "XSS") {
			found = true
			if corr.EffectiveSeverity != SeverityHigh {
				t.Errorf("Expected high severity for multiple injection correlation, got %s", corr.EffectiveSeverity)
			}
		}
	}
	if !found {
		t.Error("Expected correlation explanation to mention both SQL injection and XSS")
	}
}

// TestCorrelateFindings_CMDiWithSSRF tests CMDi + SSRF correlation
func TestCorrelateFindings_CMDiWithSSRF(t *testing.T) {
	cmdi := &CMDiScanResult{
		Findings: []CMDiFinding{
			{URL: "http://test.com/exec", Parameter: "cmd", Severity: SeverityHigh, Confidence: "high"},
		},
	}
	ssrf := &SSRFScanResult{
		Findings: []SSRFFinding{
			{URL: "http://test.com/exec", Parameter: "cmd", Severity: SeverityHigh, Confidence: "high"},
		},
	}

	result := NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, nil, ssrf, nil, cmdi, nil, nil, nil, nil, nil)

	if len(result.Correlations) == 0 {
		t.Error("Expected correlation for CMDi + SSRF on same parameter")
	}

	// Verify correlation mentions severe vulnerability
	found := false
	for _, corr := range result.Correlations {
		if strings.Contains(corr.Explanation, "Command Injection") && strings.Contains(corr.Explanation, "SSRF") {
			found = true
			if corr.EffectiveSeverity != SeverityHigh {
				t.Errorf("Expected high severity for CMDi + SSRF correlation, got %s", corr.EffectiveSeverity)
			}
		}
	}
	if !found {
		t.Error("Expected correlation explanation to mention both Command Injection and SSRF")
	}
}

// TestCorrelateFindings_CMDiWithSQLi tests CMDi + SQLi correlation
func TestCorrelateFindings_CMDiWithSQLi(t *testing.T) {
	cmdi := &CMDiScanResult{
		Findings: []CMDiFinding{
			{URL: "http://test.com/admin", Parameter: "action", Severity: SeverityHigh, Confidence: "high"},
		},
	}
	sqli := &SQLiScanResult{
		Findings: []SQLiFinding{
			{URL: "http://test.com/admin", Parameter: "action", Severity: SeverityHigh, Confidence: "high"},
		},
	}

	result := NewUnifiedScanResult("http://test.com", false, nil, nil, sqli,nil, nil, nil, nil, cmdi, nil, nil, nil, nil, nil)

	if len(result.Correlations) == 0 {
		t.Error("Expected correlation for CMDi + SQLi on same parameter")
	}

	// Verify correlation mentions both OS and database
	found := false
	for _, corr := range result.Correlations {
		if strings.Contains(corr.Explanation, "Command Injection") && strings.Contains(corr.Explanation, "SQL Injection") {
			found = true
			if corr.EffectiveSeverity != SeverityHigh {
				t.Errorf("Expected high severity for CMDi + SQLi correlation, got %s", corr.EffectiveSeverity)
			}
		}
	}
	if !found {
		t.Error("Expected correlation explanation to mention both Command Injection and SQL Injection")
	}
}

// TestCorrelateFindings_NoCorrelations tests when no correlations should be found
func TestCorrelateFindings_NoCorrelations(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() *UnifiedScanResult
	}{
		{
			name: "XSS without missing CSP",
			setupFunc: func() *UnifiedScanResult {
				headers := &HeaderScanResult{
					Headers: []HeaderFinding{
						{Name: "Content-Security-Policy", Present: true, Value: "default-src 'self'", Severity: SeverityInfo},
					},
				}
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{URL: "http://test.com", Parameter: "q", Severity: SeverityHigh, Type: "reflected", Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, headers, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			},
		},
		{
			name: "SQLi without server version headers",
			setupFunc: func() *UnifiedScanResult {
				sqli := &SQLiScanResult{
					Findings: []SQLiFinding{
						{URL: "http://test.com", Parameter: "id", Severity: SeverityHigh, Type: "error-based", Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, nil, sqli,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			},
		},
		{
			name: "CSRF with secure cookies",
			setupFunc: func() *UnifiedScanResult {
				headers := &HeaderScanResult{
					Cookies: []CookieFinding{
						{Name: "session", SameSite: "strict", Severity: SeverityInfo},
					},
				}
				csrf := &CSRFScanResult{
					Findings: []CSRFFinding{
						{FormAction: "http://test.com/form", Type: "missing_token", Severity: SeverityHigh},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, headers, nil, nil,nil, csrf, nil, nil, nil, nil, nil, nil, nil, nil)
			},
		},
		{
			name: "SQLi and XSS on different parameters",
			setupFunc: func() *UnifiedScanResult {
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{URL: "http://test.com/search", Parameter: "q", Severity: SeverityHigh, Confidence: "high"},
					},
				}
				sqli := &SQLiScanResult{
					Findings: []SQLiFinding{
						{URL: "http://test.com/user", Parameter: "id", Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, xss, sqli,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.setupFunc()

			if len(result.Correlations) != 0 {
				t.Errorf("Expected no correlations, got %d", len(result.Correlations))
			}
		})
	}
}

// TestGenerateSummary_AllScannerResultTypes tests generateSummary with all scanner types
func TestGenerateSummary_AllScannerResultTypes(t *testing.T) {
	headers := &HeaderScanResult{
		Headers: []HeaderFinding{
			{Name: "CSP", Present: false, Severity: SeverityHigh},
		},
		Cookies: []CookieFinding{
			{Name: "session", SameSite: "", Severity: SeverityMedium, Issues: []string{"missing SameSite"}},
		},
		CORS: []CORSFinding{
			{Header: "Access-Control-Allow-Origin", Value: "*", Present: true, Severity: SeverityHigh, Issues: []string{"wildcard origin"}},
		},
	}
	xss := &XSSScanResult{
		Findings: []XSSFinding{
			{Severity: SeverityHigh, Confidence: "high"},
		},
	}
	sqli := &SQLiScanResult{
		Findings: []SQLiFinding{
			{Severity: SeverityHigh, Confidence: "high"},
		},
	}
	csrf := &CSRFScanResult{
		Findings: []CSRFFinding{
			{Severity: SeverityMedium},
		},
	}
	ssrf := &SSRFScanResult{
		Findings: []SSRFFinding{
			{Severity: SeverityMedium, Confidence: "medium"},
		},
	}
	redirect := &RedirectScanResult{
		Findings: []RedirectFinding{
			{Severity: SeverityLow, Confidence: "low"},
		},
	}
	cmdi := &CMDiScanResult{
		Findings: []CMDiFinding{
			{Severity: SeverityHigh, Confidence: "high"},
		},
	}
	pathtraversal := &PathTraversalScanResult{
		Findings: []PathTraversalFinding{
			{Severity: SeverityMedium, Confidence: "medium"},
		},
	}
	ssti := &SSTIScanResult{
		Findings: []SSTIFinding{
			{Severity: SeverityHigh, Confidence: "high"},
		},
	}
	websocket := &WebSocketScanResult{
		Findings: []WebSocketFinding{
			{Severity: SeverityLow, Confidence: "low"},
		},
	}

	result := NewUnifiedScanResult("http://test.com", false, headers, xss, sqli,nil, csrf, ssrf, redirect, cmdi, pathtraversal, ssti, nil, websocket, nil)

	// Total findings: 1 header + 1 cookie + 1 cors + 1 xss + 1 sqli + 1 csrf + 1 ssrf + 1 redirect + 1 cmdi + 1 pathtraversal + 1 ssti + 1 websocket = 12
	expectedTotal := 12
	if result.Summary.TotalFindings != expectedTotal {
		t.Errorf("Expected %d total findings, got %d", expectedTotal, result.Summary.TotalFindings)
	}

	// High severity: header, xss, sqli, cmdi, ssti, cors = 6
	expectedHigh := 6
	if result.Summary.HighSeverity != expectedHigh {
		t.Errorf("Expected %d high severity findings, got %d", expectedHigh, result.Summary.HighSeverity)
	}

	// Medium severity: cookie, csrf, ssrf, pathtraversal = 4
	expectedMedium := 4
	if result.Summary.MediumSeverity != expectedMedium {
		t.Errorf("Expected %d medium severity findings, got %d", expectedMedium, result.Summary.MediumSeverity)
	}

	// Low severity: redirect, websocket = 2
	expectedLow := 2
	if result.Summary.LowSeverity != expectedLow {
		t.Errorf("Expected %d low severity findings, got %d", expectedLow, result.Summary.LowSeverity)
	}
}

// TestGenerateSummary_CorrectSeverityCountAggregation tests severity count aggregation
func TestGenerateSummary_CorrectSeverityCountAggregation(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func() *UnifiedScanResult
		expectedHigh   int
		expectedMedium int
		expectedLow    int
	}{
		{
			name: "all high severity",
			setupFunc: func() *UnifiedScanResult {
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityHigh, Confidence: "high"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			},
			expectedHigh:   2,
			expectedMedium: 0,
			expectedLow:    0,
		},
		{
			name: "all medium severity",
			setupFunc: func() *UnifiedScanResult {
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{Severity: SeverityMedium, Confidence: "medium"},
						{Severity: SeverityMedium, Confidence: "medium"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			},
			expectedHigh:   0,
			expectedMedium: 2,
			expectedLow:    0,
		},
		{
			name: "all low severity",
			setupFunc: func() *UnifiedScanResult {
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{Severity: SeverityLow, Confidence: "low"},
						{Severity: SeverityLow, Confidence: "low"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			},
			expectedHigh:   0,
			expectedMedium: 0,
			expectedLow:    2,
		},
		{
			name: "mixed severities",
			setupFunc: func() *UnifiedScanResult {
				xss := &XSSScanResult{
					Findings: []XSSFinding{
						{Severity: SeverityHigh, Confidence: "high"},
						{Severity: SeverityMedium, Confidence: "medium"},
						{Severity: SeverityLow, Confidence: "low"},
					},
				}
				return NewUnifiedScanResult("http://test.com", false, nil, xss, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			},
			expectedHigh:   1,
			expectedMedium: 1,
			expectedLow:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.setupFunc()

			if result.Summary.HighSeverity != tt.expectedHigh {
				t.Errorf("Expected %d high severity, got %d", tt.expectedHigh, result.Summary.HighSeverity)
			}
			if result.Summary.MediumSeverity != tt.expectedMedium {
				t.Errorf("Expected %d medium severity, got %d", tt.expectedMedium, result.Summary.MediumSeverity)
			}
			if result.Summary.LowSeverity != tt.expectedLow {
				t.Errorf("Expected %d low severity, got %d", tt.expectedLow, result.Summary.LowSeverity)
			}
		})
	}
}

// TestGenerateSummary_EmptyResultsHandling tests generateSummary with empty results
func TestGenerateSummary_EmptyResultsHandling(t *testing.T) {
	result := NewUnifiedScanResult("http://test.com", false, nil, nil, nil,nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	if result.Summary.TotalFindings != 0 {
		t.Errorf("Expected 0 total findings for empty results, got %d", result.Summary.TotalFindings)
	}
	if result.Summary.HighSeverity != 0 {
		t.Errorf("Expected 0 high severity for empty results, got %d", result.Summary.HighSeverity)
	}
	if result.Summary.MediumSeverity != 0 {
		t.Errorf("Expected 0 medium severity for empty results, got %d", result.Summary.MediumSeverity)
	}
	if result.Summary.LowSeverity != 0 {
		t.Errorf("Expected 0 low severity for empty results, got %d", result.Summary.LowSeverity)
	}
	if result.Summary.CorrelatedFindings != 0 {
		t.Errorf("Expected 0 correlated findings for empty results, got %d", result.Summary.CorrelatedFindings)
	}
	if len(result.Summary.PriorityActions) != 0 {
		t.Errorf("Expected 0 priority actions for empty results, got %d", len(result.Summary.PriorityActions))
	}
}
