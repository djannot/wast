package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/djannot/wast/pkg/scanner"
)

func TestOutputSARIF(t *testing.T) {
	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
		check   func(t *testing.T, output string)
	}{
		{
			name: "XSS Finding",
			data: CommandResult{
				Success: true,
				Command: "scan",
				Message: "Security scan completed",
				Data: map[string]interface{}{
					"target": "https://example.com",
					"xss": map[string]interface{}{
						"target": "https://example.com",
						"findings": []interface{}{
							map[string]interface{}{
								"url":         "https://example.com?q=test",
								"parameter":   "q",
								"payload":     "<script>alert('XSS')</script>",
								"evidence":    "...alert('XSS')...",
								"severity":    "high",
								"type":        "reflected",
								"description": "Unescaped script tag injection detected",
								"remediation": "Implement proper output encoding",
								"confidence":  "high",
							},
						},
						"summary": map[string]interface{}{
							"total_tests":           1,
							"vulnerabilities_found": 1,
							"high_severity_count":   1,
							"medium_severity_count": 0,
							"low_severity_count":    0,
						},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				var sarif SARIFReport
				if err := json.Unmarshal([]byte(output), &sarif); err != nil {
					t.Fatalf("Failed to parse SARIF output: %v", err)
				}

				if sarif.Version != "2.1.0" {
					t.Errorf("Expected version 2.1.0, got %s", sarif.Version)
				}

				if len(sarif.Runs) != 1 {
					t.Fatalf("Expected 1 run, got %d", len(sarif.Runs))
				}

				run := sarif.Runs[0]
				if run.Tool.Driver.Name != "WAST" {
					t.Errorf("Expected tool name WAST, got %s", run.Tool.Driver.Name)
				}

				if len(run.Results) != 1 {
					t.Fatalf("Expected 1 result, got %d", len(run.Results))
				}

				result := run.Results[0]
				if result.RuleID != RuleIDXSS {
					t.Errorf("Expected rule ID %s, got %s", RuleIDXSS, result.RuleID)
				}

				if result.Level != "error" {
					t.Errorf("Expected level error, got %s", result.Level)
				}

				if !strings.Contains(result.Message.Text, "XSS") {
					t.Errorf("Expected message to contain 'XSS', got %s", result.Message.Text)
				}

				if len(result.Locations) != 1 {
					t.Fatalf("Expected 1 location, got %d", len(result.Locations))
				}

				if result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "https://example.com?q=test" {
					t.Errorf("Expected URI to be test URL, got %s", result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
				}
			},
		},
		{
			name: "SQLi Finding",
			data: CommandResult{
				Success: true,
				Command: "scan",
				Data: map[string]interface{}{
					"target": "https://example.com",
					"sqli": map[string]interface{}{
						"target": "https://example.com",
						"findings": []interface{}{
							map[string]interface{}{
								"url":         "https://example.com?id=1",
								"parameter":   "id",
								"payload":     "1' OR '1'='1",
								"evidence":    "SQL syntax error",
								"severity":    "high",
								"type":        "error-based",
								"description": "SQL injection detected",
								"remediation": "Use parameterized queries",
								"confidence":  "high",
							},
						},
						"summary": map[string]interface{}{
							"total_tests":           1,
							"vulnerabilities_found": 1,
							"high_severity_count":   1,
						},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				var sarif SARIFReport
				if err := json.Unmarshal([]byte(output), &sarif); err != nil {
					t.Fatalf("Failed to parse SARIF output: %v", err)
				}

				if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
					t.Fatalf("Expected 1 result")
				}

				result := sarif.Runs[0].Results[0]
				if result.RuleID != RuleIDSQLi {
					t.Errorf("Expected rule ID %s, got %s", RuleIDSQLi, result.RuleID)
				}

				if result.Level != "error" {
					t.Errorf("Expected level error, got %s", result.Level)
				}
			},
		},
		{
			name: "Header Findings",
			data: CommandResult{
				Success: true,
				Command: "scan",
				Data: map[string]interface{}{
					"target": "https://example.com",
					"headers": map[string]interface{}{
						"target": "https://example.com",
						"headers": []interface{}{
							map[string]interface{}{
								"name":        "Strict-Transport-Security",
								"present":     false,
								"severity":    "high",
								"description": "HSTS ensures browsers only connect via HTTPS",
								"remediation": "Add header: Strict-Transport-Security: max-age=31536000",
							},
							map[string]interface{}{
								"name":        "Content-Security-Policy",
								"present":     false,
								"severity":    "high",
								"description": "CSP helps prevent XSS attacks",
								"remediation": "Add a Content-Security-Policy header",
							},
						},
						"cookies": []interface{}{},
						"cors":    []interface{}{},
						"summary": map[string]interface{}{
							"total_headers":       2,
							"missing_headers":     2,
							"high_severity_count": 2,
						},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				var sarif SARIFReport
				if err := json.Unmarshal([]byte(output), &sarif); err != nil {
					t.Fatalf("Failed to parse SARIF output: %v", err)
				}

				if len(sarif.Runs) != 1 {
					t.Fatalf("Expected 1 run, got %d", len(sarif.Runs))
				}

				run := sarif.Runs[0]
				if len(run.Results) != 2 {
					t.Fatalf("Expected 2 results, got %d", len(run.Results))
				}

				// Check HSTS finding
				hstsFound := false
				cspFound := false
				for _, result := range run.Results {
					if result.RuleID == RuleIDHeaderHSTS {
						hstsFound = true
						if result.Level != "error" {
							t.Errorf("Expected error level for HSTS, got %s", result.Level)
						}
					}
					if result.RuleID == RuleIDHeaderCSP {
						cspFound = true
						if result.Level != "error" {
							t.Errorf("Expected error level for CSP, got %s", result.Level)
						}
					}
				}

				if !hstsFound {
					t.Error("HSTS finding not found in results")
				}
				if !cspFound {
					t.Error("CSP finding not found in results")
				}
			},
		},
		{
			name: "Cookie Finding",
			data: CommandResult{
				Success: true,
				Command: "scan",
				Data: map[string]interface{}{
					"target": "https://example.com",
					"headers": map[string]interface{}{
						"target":  "https://example.com",
						"headers": []interface{}{},
						"cookies": []interface{}{
							map[string]interface{}{
								"name":      "session",
								"http_only": false,
								"secure":    false,
								"same_site": "Not Set",
								"issues": []interface{}{
									"Missing HttpOnly flag",
									"Missing Secure flag",
								},
								"severity":    "high",
								"remediation": "Set all security attributes",
							},
						},
						"cors":    []interface{}{},
						"summary": map[string]interface{}{},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				var sarif SARIFReport
				if err := json.Unmarshal([]byte(output), &sarif); err != nil {
					t.Fatalf("Failed to parse SARIF output: %v", err)
				}

				if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
					t.Fatalf("Expected 1 result")
				}

				result := sarif.Runs[0].Results[0]
				if result.RuleID != RuleIDCookie {
					t.Errorf("Expected rule ID %s, got %s", RuleIDCookie, result.RuleID)
				}

				if !strings.Contains(result.Message.Text, "session") {
					t.Errorf("Expected message to contain cookie name 'session'")
				}
			},
		},
		{
			name: "CORS Finding",
			data: CommandResult{
				Success: true,
				Command: "scan",
				Data: map[string]interface{}{
					"target": "https://example.com",
					"headers": map[string]interface{}{
						"target":  "https://example.com",
						"headers": []interface{}{},
						"cookies": []interface{}{},
						"cors": []interface{}{
							map[string]interface{}{
								"header":      "Access-Control-Allow-Origin",
								"value":       "*",
								"present":     true,
								"description": "Wildcard origin allows any domain",
								"issues": []interface{}{
									"Wildcard (*) allows any origin to access resources",
								},
								"severity":    "medium",
								"remediation": "Restrict to specific trusted origins",
							},
						},
						"summary": map[string]interface{}{},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				var sarif SARIFReport
				if err := json.Unmarshal([]byte(output), &sarif); err != nil {
					t.Fatalf("Failed to parse SARIF output: %v", err)
				}

				if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
					t.Fatalf("Expected 1 result")
				}

				result := sarif.Runs[0].Results[0]
				if result.RuleID != RuleIDCORS {
					t.Errorf("Expected rule ID %s, got %s", RuleIDCORS, result.RuleID)
				}

				if result.Level != "warning" {
					t.Errorf("Expected level warning for medium severity, got %s", result.Level)
				}
			},
		},
		{
			name: "CSRF Finding",
			data: CommandResult{
				Success: true,
				Command: "scan",
				Data: map[string]interface{}{
					"target": "https://example.com",
					"csrf": map[string]interface{}{
						"target": "https://example.com",
						"findings": []interface{}{
							map[string]interface{}{
								"form_action": "/submit",
								"form_method": "POST",
								"form_page":   "https://example.com/form",
								"type":        "missing_token",
								"severity":    "high",
								"description": "Form lacks CSRF protection",
								"remediation": "Implement anti-CSRF tokens",
							},
						},
						"summary": map[string]interface{}{},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				var sarif SARIFReport
				if err := json.Unmarshal([]byte(output), &sarif); err != nil {
					t.Fatalf("Failed to parse SARIF output: %v", err)
				}

				if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
					t.Fatalf("Expected 1 result")
				}

				result := sarif.Runs[0].Results[0]
				if result.RuleID != RuleIDCSRF {
					t.Errorf("Expected rule ID %s, got %s", RuleIDCSRF, result.RuleID)
				}
			},
		},
		{
			name: "SSRF Finding",
			data: CommandResult{
				Success: true,
				Command: "scan",
				Data: map[string]interface{}{
					"target": "https://example.com",
					"ssrf": map[string]interface{}{
						"target": "https://example.com",
						"findings": []interface{}{
							map[string]interface{}{
								"url":         "https://example.com/fetch?url=http://169.254.169.254",
								"parameter":   "url",
								"payload":     "http://169.254.169.254/latest/meta-data/",
								"type":        "cloud-metadata",
								"severity":    "high",
								"description": "SSRF allows access to cloud metadata endpoint",
								"remediation": "Implement URL allowlist validation",
								"evidence":    "Response contains AWS metadata",
								"confidence":  "high",
							},
						},
						"summary": map[string]interface{}{},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				var sarif SARIFReport
				if err := json.Unmarshal([]byte(output), &sarif); err != nil {
					t.Fatalf("Failed to parse SARIF output: %v", err)
				}

				if len(sarif.Runs) != 1 {
					t.Fatalf("Expected 1 run, got %d", len(sarif.Runs))
				}

				if len(sarif.Runs[0].Results) != 1 {
					t.Fatalf("Expected 1 result, got %d", len(sarif.Runs[0].Results))
				}

				result := sarif.Runs[0].Results[0]
				if result.RuleID != RuleIDSSRF {
					t.Errorf("Expected rule ID %s, got %s", RuleIDSSRF, result.RuleID)
				}

				if result.Level != "error" {
					t.Errorf("Expected level error for high severity, got %s", result.Level)
				}

				if !strings.Contains(result.Message.Text, "SSRF") {
					t.Errorf("Expected message to contain 'SSRF', got %s", result.Message.Text)
				}

				if !strings.Contains(result.Message.Text, "url") {
					t.Errorf("Expected message to contain parameter 'url', got %s", result.Message.Text)
				}

				if len(result.Locations) != 1 {
					t.Fatalf("Expected 1 location, got %d", len(result.Locations))
				}

				expectedURI := "https://example.com/fetch?url=http://169.254.169.254"
				if result.Locations[0].PhysicalLocation.ArtifactLocation.URI != expectedURI {
					t.Errorf("Expected URI %s, got %s", expectedURI, result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
				}

				// Check properties
				if props := result.Properties; props != nil {
					if param, ok := props["parameter"].(string); !ok || param != "url" {
						t.Errorf("Expected parameter property 'url', got %v", props["parameter"])
					}
					if confidence, ok := props["confidence"].(string); !ok || confidence != "high" {
						t.Errorf("Expected confidence property 'high', got %v", props["confidence"])
					}
					if ssrfType, ok := props["type"].(string); !ok || ssrfType != "cloud-metadata" {
						t.Errorf("Expected type property 'cloud-metadata', got %v", props["type"])
					}
				}
			},
		},
		{
			name: "Open Redirect Finding",
			data: CommandResult{
				Success: true,
				Command: "scan",
				Data: map[string]interface{}{
					"target": "https://example.com",
					"redirect": map[string]interface{}{
						"target": "https://example.com",
						"findings": []interface{}{
							map[string]interface{}{
								"url":         "https://example.com/redirect?target=https://evil.com",
								"parameter":   "target",
								"payload":     "https://evil.com",
								"type":        "header-based",
								"severity":    "medium",
								"description": "Open redirect allows arbitrary external redirects",
								"remediation": "Validate redirect URLs against allowlist",
								"evidence":    "Location header redirects to external domain",
								"confidence":  "high",
							},
						},
						"summary": map[string]interface{}{},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				var sarif SARIFReport
				if err := json.Unmarshal([]byte(output), &sarif); err != nil {
					t.Fatalf("Failed to parse SARIF output: %v", err)
				}

				if len(sarif.Runs) != 1 {
					t.Fatalf("Expected 1 run, got %d", len(sarif.Runs))
				}

				if len(sarif.Runs[0].Results) != 1 {
					t.Fatalf("Expected 1 result, got %d", len(sarif.Runs[0].Results))
				}

				result := sarif.Runs[0].Results[0]
				if result.RuleID != RuleIDRedirect {
					t.Errorf("Expected rule ID %s, got %s", RuleIDRedirect, result.RuleID)
				}

				if result.Level != "warning" {
					t.Errorf("Expected level warning for medium severity, got %s", result.Level)
				}

				if !strings.Contains(result.Message.Text, "Redirect") {
					t.Errorf("Expected message to contain 'Redirect', got %s", result.Message.Text)
				}

				if !strings.Contains(result.Message.Text, "target") {
					t.Errorf("Expected message to contain parameter 'target', got %s", result.Message.Text)
				}

				if len(result.Locations) != 1 {
					t.Fatalf("Expected 1 location, got %d", len(result.Locations))
				}

				expectedURI := "https://example.com/redirect?target=https://evil.com"
				if result.Locations[0].PhysicalLocation.ArtifactLocation.URI != expectedURI {
					t.Errorf("Expected URI %s, got %s", expectedURI, result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
				}

				// Check properties
				if props := result.Properties; props != nil {
					if param, ok := props["parameter"].(string); !ok || param != "target" {
						t.Errorf("Expected parameter property 'target', got %v", props["parameter"])
					}
					if confidence, ok := props["confidence"].(string); !ok || confidence != "high" {
						t.Errorf("Expected confidence property 'high', got %v", props["confidence"])
					}
					if redirectType, ok := props["type"].(string); !ok || redirectType != "header-based" {
						t.Errorf("Expected type property 'header-based', got %v", props["type"])
					}
				}
			},
		},
		{
			name: "Command Injection Finding",
			data: CommandResult{
				Success: true,
				Command: "scan",
				Data: map[string]interface{}{
					"target": "https://example.com",
					"cmdi": map[string]interface{}{
						"target": "https://example.com",
						"findings": []interface{}{
							map[string]interface{}{
								"url":         "https://example.com/exec?cmd=whoami",
								"parameter":   "cmd",
								"payload":     "whoami; cat /etc/passwd",
								"type":        "time-based",
								"os_type":     "linux",
								"severity":    "high",
								"description": "Command injection allows arbitrary command execution",
								"remediation": "Avoid passing user input to system commands",
								"evidence":    "Time delay indicates command execution",
								"confidence":  "high",
							},
						},
						"summary": map[string]interface{}{},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				var sarif SARIFReport
				if err := json.Unmarshal([]byte(output), &sarif); err != nil {
					t.Fatalf("Failed to parse SARIF output: %v", err)
				}

				if len(sarif.Runs) != 1 {
					t.Fatalf("Expected 1 run, got %d", len(sarif.Runs))
				}

				if len(sarif.Runs[0].Results) != 1 {
					t.Fatalf("Expected 1 result, got %d", len(sarif.Runs[0].Results))
				}

				result := sarif.Runs[0].Results[0]
				if result.RuleID != RuleIDCMDi {
					t.Errorf("Expected rule ID %s, got %s", RuleIDCMDi, result.RuleID)
				}

				if result.Level != "error" {
					t.Errorf("Expected level error for high severity, got %s", result.Level)
				}

				if !strings.Contains(result.Message.Text, "Command Injection") {
					t.Errorf("Expected message to contain 'Command Injection', got %s", result.Message.Text)
				}

				if !strings.Contains(result.Message.Text, "cmd") {
					t.Errorf("Expected message to contain parameter 'cmd', got %s", result.Message.Text)
				}

				if len(result.Locations) != 1 {
					t.Fatalf("Expected 1 location, got %d", len(result.Locations))
				}

				expectedURI := "https://example.com/exec?cmd=whoami"
				if result.Locations[0].PhysicalLocation.ArtifactLocation.URI != expectedURI {
					t.Errorf("Expected URI %s, got %s", expectedURI, result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
				}

				// Check properties
				if props := result.Properties; props != nil {
					if param, ok := props["parameter"].(string); !ok || param != "cmd" {
						t.Errorf("Expected parameter property 'cmd', got %v", props["parameter"])
					}
					if confidence, ok := props["confidence"].(string); !ok || confidence != "high" {
						t.Errorf("Expected confidence property 'high', got %v", props["confidence"])
					}
					if cmdiType, ok := props["type"].(string); !ok || cmdiType != "time-based" {
						t.Errorf("Expected type property 'time-based', got %v", props["type"])
					}
					if osType, ok := props["osType"].(string); !ok || osType != "linux" {
						t.Errorf("Expected osType property 'linux', got %v", props["osType"])
					}
				}
			},
		},
		{
			name: "Multiple Findings",
			data: CommandResult{
				Success: true,
				Command: "scan",
				Data: map[string]interface{}{
					"target": "https://example.com",
					"xss": map[string]interface{}{
						"target": "https://example.com",
						"findings": []interface{}{
							map[string]interface{}{
								"url":         "https://example.com?q=test",
								"parameter":   "q",
								"payload":     "<script>alert('XSS')</script>",
								"severity":    "high",
								"type":        "reflected",
								"description": "XSS detected",
								"remediation": "Encode output",
								"confidence":  "high",
							},
						},
					},
					"sqli": map[string]interface{}{
						"target": "https://example.com",
						"findings": []interface{}{
							map[string]interface{}{
								"url":         "https://example.com?id=1",
								"parameter":   "id",
								"payload":     "1'",
								"severity":    "high",
								"type":        "error-based",
								"description": "SQLi detected",
								"remediation": "Use prepared statements",
								"confidence":  "high",
							},
						},
					},
					"headers": map[string]interface{}{
						"target": "https://example.com",
						"headers": []interface{}{
							map[string]interface{}{
								"name":        "Strict-Transport-Security",
								"present":     false,
								"severity":    "high",
								"description": "Missing HSTS",
								"remediation": "Add HSTS header",
							},
						},
						"cookies": []interface{}{},
						"cors":    []interface{}{},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				var sarif SARIFReport
				if err := json.Unmarshal([]byte(output), &sarif); err != nil {
					t.Fatalf("Failed to parse SARIF output: %v", err)
				}

				if len(sarif.Runs) != 1 {
					t.Fatalf("Expected 1 run, got %d", len(sarif.Runs))
				}

				run := sarif.Runs[0]
				if len(run.Results) != 3 {
					t.Fatalf("Expected 3 results, got %d", len(run.Results))
				}

				// Check that we have XSS, SQLi, and header findings
				ruleIDs := make(map[string]bool)
				for _, result := range run.Results {
					ruleIDs[result.RuleID] = true
				}

				if !ruleIDs[RuleIDXSS] {
					t.Error("XSS finding not found")
				}
				if !ruleIDs[RuleIDSQLi] {
					t.Error("SQLi finding not found")
				}
				if !ruleIDs[RuleIDHeaderHSTS] {
					t.Error("HSTS finding not found")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := NewFormatter("sarif", false, false)
			formatter.SetWriter(&buf)

			err := formatter.Output(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("outputSARIF() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.check != nil {
				tt.check(t, buf.String())
			}
		})
	}
}

func TestMapSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{scanner.SeverityHigh, "error"},
		{scanner.SeverityMedium, "warning"},
		{scanner.SeverityLow, "note"},
		{scanner.SeverityInfo, "note"},
		{"unknown", "note"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := mapSeverityToLevel(tt.severity)
			if result != tt.expected {
				t.Errorf("mapSeverityToLevel(%s) = %s, want %s", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestGetRuleIDForHeader(t *testing.T) {
	tests := []struct {
		header   string
		expected string
	}{
		{"Strict-Transport-Security", RuleIDHeaderHSTS},
		{"Content-Security-Policy", RuleIDHeaderCSP},
		{"X-Frame-Options", RuleIDHeaderXFrame},
		{"X-Content-Type-Options", RuleIDHeaderCT},
		{"Unknown-Header", RuleIDHeaderHSTS}, // Default fallback
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			result := getRuleIDForHeader(tt.header)
			if result != tt.expected {
				t.Errorf("getRuleIDForHeader(%s) = %s, want %s", tt.header, result, tt.expected)
			}
		})
	}
}

func TestSARIFRulesDefinition(t *testing.T) {
	rules := buildAllRules()

	if len(rules) != 18 {
		t.Errorf("Expected 18 rules, got %d", len(rules))
	}

	// Check that all rule IDs are present
	expectedRuleIDs := []string{
		RuleIDXSS,
		RuleIDSQLi,
		RuleIDNoSQLi,
		RuleIDCMDi,
		RuleIDCSRF,
		RuleIDSSRF,
		RuleIDRedirect,
		RuleIDHeaderHSTS,
		RuleIDHeaderCSP,
		RuleIDHeaderXFrame,
		RuleIDHeaderCT,
		RuleIDCookie,
		RuleIDCORS,
		RuleIDLFI,
		RuleIDSSTI,
		RuleIDXXE,
		RuleIDWSInsecure,
		RuleIDWSOrigin,
	}

	ruleIDsFound := make(map[string]bool)
	for _, rule := range rules {
		ruleIDsFound[rule.ID] = true

		// Check that each rule has required fields
		if rule.ID == "" {
			t.Error("Rule missing ID")
		}
		if rule.ShortDescription.Text == "" {
			t.Errorf("Rule %s missing short description", rule.ID)
		}
		if rule.FullDescription.Text == "" {
			t.Errorf("Rule %s missing full description", rule.ID)
		}
		if rule.Help.Text == "" {
			t.Errorf("Rule %s missing help text", rule.ID)
		}
		if rule.Properties == nil || rule.Properties["tags"] == nil {
			t.Errorf("Rule %s missing tags property", rule.ID)
		}
	}

	for _, expectedID := range expectedRuleIDs {
		if !ruleIDsFound[expectedID] {
			t.Errorf("Expected rule ID %s not found", expectedID)
		}
	}
}

func TestSARIFSchemaCompliance(t *testing.T) {
	// Test that generated SARIF has required fields
	data := CommandResult{
		Success: true,
		Command: "scan",
		Data: map[string]interface{}{
			"target": "https://example.com",
			"xss": map[string]interface{}{
				"target": "https://example.com",
				"findings": []interface{}{
					map[string]interface{}{
						"url":         "https://example.com?q=test",
						"parameter":   "q",
						"payload":     "test",
						"severity":    "high",
						"type":        "reflected",
						"description": "XSS",
						"remediation": "Fix it",
						"confidence":  "high",
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	formatter := NewFormatter("sarif", false, false)
	formatter.SetWriter(&buf)

	if err := formatter.Output(data); err != nil {
		t.Fatalf("Failed to output SARIF: %v", err)
	}

	var sarif SARIFReport
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("Failed to parse SARIF: %v", err)
	}

	// Check required top-level fields
	if sarif.Version != "2.1.0" {
		t.Errorf("Expected version 2.1.0, got %s", sarif.Version)
	}

	if sarif.Schema != "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json" {
		t.Errorf("Expected correct schema URL")
	}

	if len(sarif.Runs) == 0 {
		t.Fatal("Expected at least one run")
	}

	run := sarif.Runs[0]

	// Check tool information
	if run.Tool.Driver.Name == "" {
		t.Error("Tool name is required")
	}

	// Check results structure
	if len(run.Results) > 0 {
		result := run.Results[0]
		if result.RuleID == "" {
			t.Error("Result ruleId is required")
		}
		if result.Level == "" {
			t.Error("Result level is required")
		}
		if result.Message.Text == "" {
			t.Error("Result message text is required")
		}
	}
}

func TestEmptyScanResults(t *testing.T) {
	// Test handling of scan results with no findings
	data := CommandResult{
		Success: true,
		Command: "scan",
		Data: map[string]interface{}{
			"target": "https://example.com",
			"xss": map[string]interface{}{
				"target":   "https://example.com",
				"findings": []interface{}{},
			},
			"sqli": map[string]interface{}{
				"target":   "https://example.com",
				"findings": []interface{}{},
			},
			"headers": map[string]interface{}{
				"target":  "https://example.com",
				"headers": []interface{}{},
				"cookies": []interface{}{},
				"cors":    []interface{}{},
			},
		},
	}

	var buf bytes.Buffer
	formatter := NewFormatter("sarif", false, false)
	formatter.SetWriter(&buf)

	if err := formatter.Output(data); err != nil {
		t.Fatalf("Failed to output SARIF: %v", err)
	}

	var sarif SARIFReport
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("Failed to parse SARIF: %v", err)
	}

	// Should still have valid structure with no results
	if len(sarif.Runs) != 1 {
		t.Errorf("Expected 1 run even with no findings")
	}

	if len(sarif.Runs[0].Results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(sarif.Runs[0].Results))
	}
}
