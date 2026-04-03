package checks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/callback"
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

// TestSSRFChecker_OOBProbeGeneratesCallbackURL verifies that when a callback
// server is configured the checker produces a callback URL for each URL param.
func TestSSRFChecker_OOBProbeGeneratesCallbackURL(t *testing.T) {
	// Start a real callback HTTP server on a random port.
	cbSrv, baseURL := startTestCallbackServer(t)

	tools := []ToolInfo{
		{
			Name:        "fetchTool",
			Description: "fetches a URL",
			Parameters: []ParamInfo{
				{Name: "url", Type: "string", Description: "URL to fetch"},
			},
		},
	}

	// oobCaller simulates a vulnerable server that fetches the URL it receives.
	caller := newOOBSimulatingCaller(baseURL)

	checker := NewSSRFChecker(WithCallbackServer(cbSrv, 3*time.Second))
	findings := checker.Check(context.Background(), tools, caller)

	var blindFindings []Finding
	for _, f := range findings {
		if f.Category == CategorySSRF && f.Title == "Blind SSRF vulnerability — OOB callback received" {
			blindFindings = append(blindFindings, f)
		}
	}

	if len(blindFindings) == 0 {
		t.Fatalf("expected at least one blind SSRF finding, got none (all findings: %+v)", findings)
	}

	f := blindFindings[0]
	if f.Tool != "fetchTool" {
		t.Errorf("expected finding tool=fetchTool, got %q", f.Tool)
	}
	if f.Parameter != "url" {
		t.Errorf("expected finding param=url, got %q", f.Parameter)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %q", f.Severity)
	}
}

// TestSSRFChecker_OOBTimeout verifies that no blind SSRF finding is reported
// when the target server does not make a callback (timeout path).
func TestSSRFChecker_OOBTimeout(t *testing.T) {
	cbSrv, _ := startTestCallbackServer(t)

	tools := []ToolInfo{
		{
			Name:        "safeFetch",
			Description: "fetches a URL but ignores it",
			Parameters: []ParamInfo{
				{Name: "url", Type: "string", Description: "URL to fetch"},
			},
		},
	}

	// This caller does NOT make any HTTP requests — simulates a server that
	// receives the URL but doesn't actually fetch it (no blind SSRF).
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"ok"}]}`)

	// Use a very short timeout so the test completes quickly.
	checker := NewSSRFChecker(WithCallbackServer(cbSrv, 100*time.Millisecond))
	findings := checker.Check(context.Background(), tools, caller)

	for _, f := range findings {
		if f.Title == "Blind SSRF vulnerability — OOB callback received" {
			t.Errorf("unexpected blind SSRF finding for a server that made no outbound request: %+v", f)
		}
	}
}

// TestSSRFChecker_OOBDisabledByDefault verifies that without a callback server
// no OOB probe is attempted (existing behaviour is unchanged).
func TestSSRFChecker_OOBDisabledByDefault(t *testing.T) {
	tools := []ToolInfo{
		{
			Name:        "fetchTool",
			Description: "fetches a URL",
			Parameters: []ParamInfo{
				{Name: "url", Type: "string", Description: "URL to fetch"},
			},
		},
	}

	var callURLs []string
	caller := &recordingCaller{urls: &callURLs}

	checker := NewSSRFChecker() // No WithCallbackServer
	_ = checker.Check(context.Background(), tools, caller)

	for _, u := range callURLs {
		if len(u) == 32 { // 16-byte hex IDs look like OOB probe IDs
			t.Errorf("OOB probe URL unexpectedly sent without a callback server configured: %s", u)
		}
	}
}

// TestSSRFChecker_OOBNoFalsePositiveWhenCallbackNotReceived is an explicit
// no-false-positive test: the checker must not report blind SSRF when no
// callback arrives.
func TestSSRFChecker_OOBNoFalsePositiveWhenCallbackNotReceived(t *testing.T) {
	cbSrv := callback.NewServer(callback.Config{
		BaseURL: "http://127.0.0.1:19999", // port not actually bound
	})
	// Deliberately do NOT start the server — callbacks will never arrive.

	tools := []ToolInfo{
		{
			Name:        "blindFetch",
			Description: "fetches a URL",
			Parameters: []ParamInfo{
				{Name: "url", Type: "string", Description: "URL to fetch"},
			},
		},
	}

	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"done"}]}`)

	checker := NewSSRFChecker(WithCallbackServer(cbSrv, 50*time.Millisecond))
	findings := checker.Check(context.Background(), tools, caller)

	for _, f := range findings {
		if f.Title == "Blind SSRF vulnerability — OOB callback received" {
			t.Errorf("false positive: blind SSRF reported without any callback: %+v", f)
		}
	}
}

// ---- helpers ----

// startTestCallbackServer starts a real callback HTTP server on a random port
// and returns the server and its base URL. The server is stopped when the test
// completes.
func startTestCallbackServer(t *testing.T) (*callback.Server, string) {
	t.Helper()

	// Find a free port.
	addr, err := freeAddr()
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}

	baseURL := fmt.Sprintf("http://127.0.0.1%s", addr)
	cbSrv := callback.NewServer(callback.Config{
		HTTPAddr: addr,
		BaseURL:  baseURL,
	})

	ctx, cancel := context.WithCancel(context.Background())
	if err := cbSrv.Start(ctx); err != nil {
		cancel()
		t.Fatalf("failed to start callback server: %v", err)
	}

	// Give the HTTP listener a moment to be ready.
	time.Sleep(20 * time.Millisecond)

	t.Cleanup(func() {
		cancel()
		cbSrv.Stop(context.Background()) //nolint:errcheck
	})

	return cbSrv, baseURL
}

// freeAddr returns ":PORT" with an unused TCP port.
func freeAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return fmt.Sprintf(":%d", l.Addr().(*net.TCPAddr).Port), nil
}

// oobSimulatingCaller is a ToolCaller that, when it receives a URL whose prefix
// matches baseURL, makes a real HTTP GET to that URL — simulating what a
// vulnerable server would do.
type oobSimulatingCaller struct {
	baseURL string
}

func newOOBSimulatingCaller(baseURL string) *oobSimulatingCaller {
	return &oobSimulatingCaller{baseURL: baseURL}
}

func (c *oobSimulatingCaller) CallTool(_ context.Context, _ string, arguments map[string]interface{}) ([]byte, error) {
	for _, v := range arguments {
		if u, ok := v.(string); ok && len(u) > 0 {
			// If the URL points to our callback server, fetch it (simulating SSRF).
			if len(c.baseURL) > 0 && len(u) >= len(c.baseURL) && u[:len(c.baseURL)] == c.baseURL {
				go func(target string) {
					client := &http.Client{Timeout: 2 * time.Second}
					resp, err := client.Get(target) //nolint:noctx
					if err == nil {
						resp.Body.Close()
					}
				}(u)
			}
		}
	}
	return []byte(`{"content":[{"type":"text","text":"fetched"}]}`), nil
}

// recordingCaller records all URL values it receives.
type recordingCaller struct {
	urls *[]string
}

func (r *recordingCaller) CallTool(_ context.Context, _ string, arguments map[string]interface{}) ([]byte, error) {
	for _, v := range arguments {
		if u, ok := v.(string); ok {
			*r.urls = append(*r.urls, u)
		}
	}
	return []byte(`{"content":[]}`), nil
}
