package checks

import (
	"context"
	"testing"
)

func TestExposureChecker_AWSKey(t *testing.T) {
	tools := []ToolInfo{
		{Name: "list_config", Description: "returns config"},
	}
	caller := newMockCaller()
	// AWS access key pattern: AKIA + 16 alphanumeric chars
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"Your key is AKIAIOSFODNN7EXAMPLE and secret is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("expected Critical severity for AWS key, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected exposure finding for AWS access key")
	}
}

func TestExposureChecker_NoSensitiveData(t *testing.T) {
	tools := []ToolInfo{
		{Name: "get_time", Description: "returns current time"},
	}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"2024-01-01T00:00:00Z"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)
	if len(findings) != 0 {
		t.Errorf("expected no findings for benign response, got %d", len(findings))
	}
}

func TestExposureChecker_PrivateKey(t *testing.T) {
	tools := []ToolInfo{
		{Name: "get_cert", Description: "returns certificate"},
	}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical finding for private key in response")
	}
}

func TestExposureChecker_ErrorResponse(t *testing.T) {
	tools := []ToolInfo{
		{Name: "risky_tool", Description: "can leak"},
	}
	caller := newMockCaller()
	// Error containing environment variable dump
	caller.errors["risky_tool:test"] = nil
	caller.defaultResp = nil
	// Override default to return an error with env vars
	errCaller := &errorCaller{msg: "HOME=/root PATH=/usr/bin USER=root SHELL=/bin/bash PWD=/root"}

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, errCaller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure {
			found = true
		}
	}
	if !found {
		t.Error("expected exposure finding from error response containing env vars")
	}
}

// errorCaller always returns an error with the given message.
type errorCaller struct{ msg string }

func (e *errorCaller) CallTool(_ context.Context, _ string, _ map[string]interface{}) ([]byte, error) {
	return nil, &mockError{e.msg}
}

type mockError struct{ msg string }

func (m *mockError) Error() string { return m.msg }
