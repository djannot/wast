package scanner

import (
	"context"
	"testing"
)

// mockFinding is a minimal finding type for testing newActiveScanEntry.
type mockFinding struct {
	Verified bool
	Attempts int
	Value    string
}

// mockResult is a minimal scan result used in generic helper tests.
type mockResult struct {
	Findings []mockFinding
	Errors   []string
	Count    int
}

// TestNewActiveScanEntry_Name verifies that the entry name is preserved.
func TestNewActiveScanEntry_Name(t *testing.T) {
	var result mockResult
	entry := newActiveScanEntry("TestScanner",
		func(_ context.Context, _ string) {},
		func() []mockFinding { return result.Findings },
		func(f []mockFinding) { result.Findings = f },
		func(_ context.Context, _ *mockFinding, _ VerificationConfig) (*VerificationResult, error) {
			return nil, nil
		},
		func(_ *mockFinding, _ *VerificationResult) {},
		func(f mockFinding) bool { return f.Verified },
		func(n int) { result.Count = n },
		func() []string { return result.Errors },
	)
	if entry.name != "TestScanner" {
		t.Errorf("expected name 'TestScanner', got %q", entry.name)
	}
}

// TestNewActiveScanEntry_Scan verifies that the scan closure captures the result.
func TestNewActiveScanEntry_Scan(t *testing.T) {
	var result mockResult
	called := false
	entry := newActiveScanEntry("Mock",
		func(_ context.Context, target string) {
			called = true
			result.Findings = []mockFinding{{Value: target, Verified: false}}
		},
		func() []mockFinding { return result.Findings },
		func(f []mockFinding) { result.Findings = f },
		func(_ context.Context, _ *mockFinding, _ VerificationConfig) (*VerificationResult, error) {
			return nil, nil
		},
		func(_ *mockFinding, _ *VerificationResult) {},
		func(f mockFinding) bool { return f.Verified },
		func(n int) { result.Count = n },
		func() []string { return result.Errors },
	)

	entry.scan(context.Background(), "http://example.com")
	if !called {
		t.Error("expected scan closure to be called")
	}
	if len(result.Findings) != 1 || result.Findings[0].Value != "http://example.com" {
		t.Errorf("unexpected findings after scan: %+v", result.Findings)
	}
}

// TestNewActiveScanEntry_TotalFindings verifies totalFindings returns the finding count.
func TestNewActiveScanEntry_TotalFindings(t *testing.T) {
	result := mockResult{
		Findings: []mockFinding{{Value: "a"}, {Value: "b"}, {Value: "c"}},
	}
	entry := newActiveScanEntry("Mock",
		func(_ context.Context, _ string) {},
		func() []mockFinding { return result.Findings },
		func(f []mockFinding) { result.Findings = f },
		func(_ context.Context, _ *mockFinding, _ VerificationConfig) (*VerificationResult, error) {
			return nil, nil
		},
		func(_ *mockFinding, _ *VerificationResult) {},
		func(f mockFinding) bool { return f.Verified },
		func(n int) { result.Count = n },
		func() []string { return result.Errors },
	)
	if got := entry.totalFindings(); got != 3 {
		t.Errorf("expected totalFindings() == 3, got %d", got)
	}
}

// TestNewActiveScanEntry_GetErrors verifies getErrors returns the error slice.
func TestNewActiveScanEntry_GetErrors(t *testing.T) {
	result := mockResult{
		Errors: []string{"err1", "err2"},
	}
	entry := newActiveScanEntry("Mock",
		func(_ context.Context, _ string) {},
		func() []mockFinding { return result.Findings },
		func(f []mockFinding) { result.Findings = f },
		func(_ context.Context, _ *mockFinding, _ VerificationConfig) (*VerificationResult, error) {
			return nil, nil
		},
		func(_ *mockFinding, _ *VerificationResult) {},
		func(f mockFinding) bool { return f.Verified },
		func(n int) { result.Count = n },
		func() []string { return result.Errors },
	)
	errs := entry.getErrors()
	if len(errs) != 2 || errs[0] != "err1" || errs[1] != "err2" {
		t.Errorf("unexpected errors: %v", errs)
	}
}

// TestNewActiveScanEntry_VerifyAll verifies that verifyAll applies the VerificationResult
// to each finding using the applyVR callback.
func TestNewActiveScanEntry_VerifyAll(t *testing.T) {
	result := mockResult{
		Findings: []mockFinding{
			{Value: "finding1", Verified: false},
			{Value: "finding2", Verified: false},
		},
	}
	entry := newActiveScanEntry("Mock",
		func(_ context.Context, _ string) {},
		func() []mockFinding { return result.Findings },
		func(f []mockFinding) { result.Findings = f },
		func(_ context.Context, f *mockFinding, _ VerificationConfig) (*VerificationResult, error) {
			// Mark all findings as verified.
			return &VerificationResult{Verified: true, Attempts: 1, Confidence: 0.9}, nil
		},
		func(f *mockFinding, vr *VerificationResult) {
			f.Verified = vr.Verified
			f.Attempts = vr.Attempts
		},
		func(f mockFinding) bool { return f.Verified },
		func(n int) { result.Count = n },
		func() []string { return result.Errors },
	)

	entry.verifyAll(context.Background(), VerificationConfig{Enabled: true, MaxRetries: 1})

	for i, f := range result.Findings {
		if !f.Verified {
			t.Errorf("finding[%d] expected Verified=true", i)
		}
		if f.Attempts != 1 {
			t.Errorf("finding[%d] expected Attempts=1, got %d", i, f.Attempts)
		}
	}
}

// TestNewActiveScanEntry_VerifyAll_SkipsErrorResult verifies that a nil or errored
// VerificationResult does not modify the finding.
func TestNewActiveScanEntry_VerifyAll_SkipsErrorResult(t *testing.T) {
	result := mockResult{
		Findings: []mockFinding{{Value: "x", Verified: false, Attempts: 0}},
	}
	entry := newActiveScanEntry("Mock",
		func(_ context.Context, _ string) {},
		func() []mockFinding { return result.Findings },
		func(f []mockFinding) { result.Findings = f },
		func(_ context.Context, _ *mockFinding, _ VerificationConfig) (*VerificationResult, error) {
			// Simulate an error — return nil result with no error (nil,nil is a no-op).
			return nil, nil
		},
		func(f *mockFinding, vr *VerificationResult) {
			f.Verified = vr.Verified
		},
		func(f mockFinding) bool { return f.Verified },
		func(n int) { result.Count = n },
		func() []string { return result.Errors },
	)

	entry.verifyAll(context.Background(), VerificationConfig{})
	if result.Findings[0].Verified {
		t.Error("finding should not be marked verified when VerificationResult is nil")
	}
}

// TestNewActiveScanEntry_FilterVerified verifies that filterVerified retains only
// verified findings and updates the summary count.
func TestNewActiveScanEntry_FilterVerified(t *testing.T) {
	result := mockResult{
		Findings: []mockFinding{
			{Value: "a", Verified: true},
			{Value: "b", Verified: false},
			{Value: "c", Verified: true},
			{Value: "d", Verified: false},
		},
	}
	entry := newActiveScanEntry("Mock",
		func(_ context.Context, _ string) {},
		func() []mockFinding { return result.Findings },
		func(f []mockFinding) { result.Findings = f },
		func(_ context.Context, _ *mockFinding, _ VerificationConfig) (*VerificationResult, error) {
			return nil, nil
		},
		func(_ *mockFinding, _ *VerificationResult) {},
		func(f mockFinding) bool { return f.Verified },
		func(n int) { result.Count = n },
		func() []string { return result.Errors },
	)

	entry.filterVerified()

	if len(result.Findings) != 2 {
		t.Errorf("expected 2 verified findings, got %d", len(result.Findings))
	}
	if result.Count != 2 {
		t.Errorf("expected summary count 2, got %d", result.Count)
	}
	for _, f := range result.Findings {
		if !f.Verified {
			t.Errorf("unverified finding %q survived filter", f.Value)
		}
	}
}

// TestNewActiveScanEntry_FilterVerified_AllUnverified verifies that an empty
// verified set is handled correctly (no panic, count set to 0).
func TestNewActiveScanEntry_FilterVerified_AllUnverified(t *testing.T) {
	result := mockResult{
		Findings: []mockFinding{
			{Value: "a", Verified: false},
			{Value: "b", Verified: false},
		},
		Count: 99, // pre-set to ensure it's overwritten
	}
	entry := newActiveScanEntry("Mock",
		func(_ context.Context, _ string) {},
		func() []mockFinding { return result.Findings },
		func(f []mockFinding) { result.Findings = f },
		func(_ context.Context, _ *mockFinding, _ VerificationConfig) (*VerificationResult, error) {
			return nil, nil
		},
		func(_ *mockFinding, _ *VerificationResult) {},
		func(f mockFinding) bool { return f.Verified },
		func(n int) { result.Count = n },
		func() []string { return result.Errors },
	)

	entry.filterVerified()

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings after filter, got %d", len(result.Findings))
	}
	if result.Count != 0 {
		t.Errorf("expected count 0, got %d", result.Count)
	}
}

// TestNewActiveScanEntry_FilterVerified_EmptyFindings verifies no panic when findings
// is empty.
func TestNewActiveScanEntry_FilterVerified_EmptyFindings(t *testing.T) {
	result := mockResult{}
	entry := newActiveScanEntry("Mock",
		func(_ context.Context, _ string) {},
		func() []mockFinding { return result.Findings },
		func(f []mockFinding) { result.Findings = f },
		func(_ context.Context, _ *mockFinding, _ VerificationConfig) (*VerificationResult, error) {
			return nil, nil
		},
		func(_ *mockFinding, _ *VerificationResult) {},
		func(f mockFinding) bool { return f.Verified },
		func(n int) { result.Count = n },
		func() []string { return result.Errors },
	)

	// Should not panic.
	entry.filterVerified()

	if result.Count != 0 {
		t.Errorf("expected count 0 for empty findings, got %d", result.Count)
	}
}
