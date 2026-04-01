package checks

import (
	"context"
	"fmt"
	"testing"
)

func TestIsURLParameter(t *testing.T) {
	urlLikeNames := []string{"url", "webhook", "redirect", "endpoint", "src"}
	for _, name := range urlLikeNames {
		p := ParamInfo{Name: name, Type: "string"}
		if !isURLParameter(p) {
			t.Errorf("expected isURLParameter to return true for param name %q, got false", name)
		}
	}

	nonURLNames := []string{"count", "limit", "format"}
	for _, name := range nonURLNames {
		p := ParamInfo{Name: name, Type: "string"}
		if isURLParameter(p) {
			t.Errorf("expected isURLParameter to return false for param name %q, got true", name)
		}
	}

	// Non-string type with "url" in the name should return false.
	p := ParamInfo{Name: "url", Type: "integer"}
	if isURLParameter(p) {
		t.Error("expected isURLParameter to return false for non-string type even with 'url' in name")
	}
}

func TestSSRFChecker_VulnerabilityDetected(t *testing.T) {
	tools := []ToolInfo{
		{
			Name:        "fetchResource",
			Description: "fetches a remote resource",
			Parameters: []ParamInfo{
				{Name: "url", Type: "string", Description: "URL to fetch"},
			},
		},
	}

	caller := newMockCaller()
	// Set up a response for the AWS metadata probe.
	awsProbeURL := "http://169.254.169.254/latest/meta-data/"
	key := fmt.Sprintf("fetchResource:%s", awsProbeURL)
	caller.responses[key] = []byte(`{"content":[{"type":"text","text":"ami-id: ami-12345678"}]}`)

	checker := NewSSRFChecker()
	findings := checker.Check(context.Background(), tools, caller)

	if len(findings) == 0 {
		t.Fatal("expected at least one SSRF finding, got none")
	}

	found := false
	for _, f := range findings {
		if f.Category == CategorySSRF && f.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a finding with CategorySSRF and SeverityCritical, findings: %+v", findings)
	}
}

func TestSSRFChecker_NonURLParamSkipped(t *testing.T) {
	tools := []ToolInfo{
		{
			Name:        "countItems",
			Description: "counts items",
			Parameters: []ParamInfo{
				{Name: "count", Type: "integer", Description: "how many items"},
			},
		},
	}

	caller := newMockCaller()
	checker := NewSSRFChecker()
	findings := checker.Check(context.Background(), tools, caller)

	if len(findings) != 0 {
		t.Errorf("expected no findings for non-URL integer param, got %d", len(findings))
	}
}

func TestSSRFChecker_NoEvidenceNoFinding(t *testing.T) {
	tools := []ToolInfo{
		{
			Name:        "fetchResource",
			Description: "fetches a remote resource",
			Parameters: []ParamInfo{
				{Name: "url", Type: "string", Description: "URL to fetch"},
			},
		},
	}

	caller := newMockCaller()
	// Innocuous response that contains no SSRF evidence strings.
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"hello world"}]}`)

	checker := NewSSRFChecker()
	findings := checker.Check(context.Background(), tools, caller)

	if len(findings) != 0 {
		t.Errorf("expected no findings for innocuous response, got %d", len(findings))
	}
}
