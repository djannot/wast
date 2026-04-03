package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/mcpscan"
	"github.com/djannot/wast/pkg/output"
	"github.com/spf13/cobra"
)

// startMockMCPServer starts a minimal HTTP MCP server that responds to
// initialize and tools/list with empty responses. It sleeps for `delay`
// before replying so we can measure concurrency speedup.
// The returned *int64 is incremented atomically on each request.
func startMockMCPServer(t *testing.T, delay time.Duration) (url string, hits *int64) {
	t.Helper()
	var count int64

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, 1)
		if delay > 0 {
			time.Sleep(delay)
		}
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		method, _ := req["method"].(string)
		id := req["id"]

		var resp map[string]interface{}
		switch method {
		case "initialize":
			resp = map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					"serverInfo":      map[string]interface{}{"name": "mock-server", "version": "1.0.0"},
				},
			}
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
			return
		case "tools/list":
			resp = map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result":  map[string]interface{}{"tools": []interface{}{}},
			}
		default:
			resp = map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result":  map[string]interface{}{},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, &count
}

// buildTargetsFile writes a DiscoveryResult JSON file containing the given
// HTTP URLs and returns the file path.
func buildTargetsFile(t *testing.T, urls []string) string {
	t.Helper()
	servers := make([]mcpscan.DiscoveredServer, len(urls))
	for i, u := range urls {
		servers[i] = mcpscan.DiscoveredServer{
			Name:      fmt.Sprintf("mock-%d", i),
			Transport: "http",
			Target:    u,
			Source:    "test",
		}
	}
	discovery := mcpscan.DiscoveryResult{Servers: servers}
	data, err := json.Marshal(discovery)
	if err != nil {
		t.Fatalf("failed to marshal targets: %v", err)
	}

	f, err := os.CreateTemp(t.TempDir(), "targets-*.json")
	if err != nil {
		t.Fatalf("failed to create temp targets file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("failed to write targets file: %v", err)
	}
	f.Close()
	return f.Name()
}

// newTestMCPScanCmd returns a NewMCPScanCmd wired to write into buf.
func newTestMCPScanCmd(buf *bytes.Buffer) func() *output.Formatter {
	return func() *output.Formatter {
		f := output.NewFormatter("text", false, false)
		f.SetWriter(buf)
		return f
	}
}

// TestMCPScanCmd_ConcurrencyFlagRegistered verifies the flag is present with
// the correct default and documentation.
func TestMCPScanCmd_ConcurrencyFlagRegistered(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewMCPScanCmd(newTestMCPScanCmd(&buf))

	var scanSubcmd *cobra.Command
	for _, sub := range cmd.Commands() {
		if sub.Use == "scan" {
			scanSubcmd = sub
			break
		}
	}
	if scanSubcmd == nil {
		t.Fatal("scan subcommand not found")
	}

	flag := scanSubcmd.Flag("concurrency")
	if flag == nil {
		t.Fatal("Expected 'concurrency' flag to be registered on 'scan' subcommand")
	}
	if flag.DefValue != "5" {
		t.Errorf("Expected default concurrency=5, got %q", flag.DefValue)
	}
	if !strings.Contains(strings.ToLower(flag.Usage), "parallel") {
		t.Errorf("Expected concurrency flag usage to mention 'parallel', got: %s", flag.Usage)
	}
}

// TestMCPScanConcurrency_FasterThanSequential verifies that scanning N servers
// with concurrency N completes meaningfully faster than concurrency 1.
func TestMCPScanConcurrency_FasterThanSequential(t *testing.T) {
	const numServers = 4
	const serverDelay = 120 * time.Millisecond

	urls := make([]string, numServers)
	for i := range urls {
		u, _ := startMockMCPServer(t, serverDelay)
		urls[i] = u
	}
	targetsFile := buildTargetsFile(t, urls)

	runScan := func(concurrency int) time.Duration {
		var buf bytes.Buffer
		cmd := NewMCPScanCmd(newTestMCPScanCmd(&buf))
		cmd.SetArgs([]string{
			"scan",
			"--targets", targetsFile,
			"--concurrency", fmt.Sprintf("%d", concurrency),
			"--timeout", "5",
		})
		start := time.Now()
		_ = cmd.Execute() // errors from unreachable servers are acceptable
		return time.Since(start)
	}

	seqDuration := runScan(1)
	parDuration := runScan(numServers)

	t.Logf("sequential=%v  parallel(N=%d)=%v", seqDuration, numServers, parDuration)

	// Parallel should be at least 2× faster than sequential.
	if parDuration*2 > seqDuration {
		t.Errorf(
			"Parallel scan (%v) was not 2× faster than sequential (%v); expected concurrency to help",
			parDuration, seqDuration,
		)
	}
}

// TestMCPScanCmd_Concurrency1_AllServersScanned verifies that --concurrency 1
// (sequential mode) still processes every server in the targets list.
func TestMCPScanCmd_Concurrency1_AllServersScanned(t *testing.T) {
	const numServers = 3
	urls := make([]string, numServers)
	for i := range urls {
		u, _ := startMockMCPServer(t, 0)
		urls[i] = u
	}
	targetsFile := buildTargetsFile(t, urls)

	var buf bytes.Buffer
	cmd := NewMCPScanCmd(newTestMCPScanCmd(&buf))
	cmd.SetArgs([]string{
		"scan",
		"--targets", targetsFile,
		"--concurrency", "1",
		"--timeout", "5",
	})
	_ = cmd.Execute()

	got := buf.String()
	for _, url := range urls {
		if !strings.Contains(got, url) {
			t.Errorf("Expected output to reference server %s but it was absent", url)
		}
	}
}

// TestMCPScanCmd_BulkSummaryPrinted verifies that the aggregated summary block
// is always printed after a bulk scan, regardless of server count.
func TestMCPScanCmd_BulkSummaryPrinted(t *testing.T) {
	const numServers = 3
	urls := make([]string, numServers)
	for i := range urls {
		u, _ := startMockMCPServer(t, 0)
		urls[i] = u
	}
	targetsFile := buildTargetsFile(t, urls)

	var buf bytes.Buffer
	cmd := NewMCPScanCmd(newTestMCPScanCmd(&buf))
	cmd.SetArgs([]string{
		"scan",
		"--targets", targetsFile,
		"--timeout", "5",
	})
	_ = cmd.Execute()

	got := buf.String()
	if !strings.Contains(got, "Bulk Scan Summary") {
		t.Errorf("Expected 'Bulk Scan Summary' header in output, got:\n%s", got)
	}
	if !strings.Contains(got, "Servers:") {
		t.Errorf("Expected 'Servers:' line in bulk summary, got:\n%s", got)
	}
	if !strings.Contains(got, "Findings:") {
		t.Errorf("Expected 'Findings:' line in bulk summary, got:\n%s", got)
	}
}

// TestMCPScanCmd_SummaryOnlyFlag verifies that --summary-only suppresses
// per-server detail while still printing the aggregated summary.
func TestMCPScanCmd_SummaryOnlyFlag(t *testing.T) {
	const numServers = 2
	urls := make([]string, numServers)
	for i := range urls {
		u, _ := startMockMCPServer(t, 0)
		urls[i] = u
	}
	targetsFile := buildTargetsFile(t, urls)

	var fullBuf, summaryBuf bytes.Buffer

	// Full run (no --summary-only).
	fullCmd := NewMCPScanCmd(newTestMCPScanCmd(&fullBuf))
	fullCmd.SetArgs([]string{"scan", "--targets", targetsFile, "--timeout", "5"})
	_ = fullCmd.Execute()
	fullOut := fullBuf.String()

	// Summary-only run.
	sumCmd := NewMCPScanCmd(newTestMCPScanCmd(&summaryBuf))
	sumCmd.SetArgs([]string{"scan", "--targets", targetsFile, "--summary-only", "--timeout", "5"})
	_ = sumCmd.Execute()
	sumOut := summaryBuf.String()

	// Summary-only output must still contain the summary header.
	if !strings.Contains(sumOut, "Bulk Scan Summary") {
		t.Errorf("--summary-only: expected 'Bulk Scan Summary' in output, got:\n%s", sumOut)
	}

	// Summary-only output must be shorter (no per-server detail lines).
	if len(sumOut) >= len(fullOut) {
		t.Errorf("--summary-only output (%d bytes) should be shorter than full output (%d bytes)",
			len(sumOut), len(fullOut))
	}
}

// TestMCPScanCmd_SummaryOnlyFlagRegistered verifies the flag is present.
func TestMCPScanCmd_SummaryOnlyFlagRegistered(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewMCPScanCmd(newTestMCPScanCmd(&buf))

	var scanSubcmd *cobra.Command
	for _, sub := range cmd.Commands() {
		if sub.Use == "scan" {
			scanSubcmd = sub
			break
		}
	}
	if scanSubcmd == nil {
		t.Fatal("scan subcommand not found")
	}

	flag := scanSubcmd.Flag("summary-only")
	if flag == nil {
		t.Fatal("Expected 'summary-only' flag to be registered on 'scan' subcommand")
	}
	if flag.DefValue != "false" {
		t.Errorf("Expected default summary-only=false, got %q", flag.DefValue)
	}
}

// TestMCPScanCmd_BulkSummaryScannedCount verifies that the Servers count in
// the text summary matches the number of mock servers scanned.
func TestMCPScanCmd_BulkSummaryScannedCount(t *testing.T) {
	const numServers = 3
	urls := make([]string, numServers)
	for i := range urls {
		u, _ := startMockMCPServer(t, 0)
		urls[i] = u
	}
	targetsFile := buildTargetsFile(t, urls)

	var buf bytes.Buffer
	cmd := NewMCPScanCmd(newTestMCPScanCmd(&buf))
	cmd.SetArgs([]string{
		"scan",
		"--targets", targetsFile,
		"--concurrency", "1",
		"--timeout", "5",
	})
	_ = cmd.Execute()

	got := buf.String()
	// The summary line should mention "3 total".
	if !strings.Contains(got, fmt.Sprintf("%d total", numServers)) {
		t.Errorf("Expected '%d total' in summary output, got:\n%s", numServers, got)
	}
}

// buildTargetsFileWithAuth writes a DiscoveryResult JSON file where some
// servers are marked as auth-required. openURLs will have AuthRequired=false
// and authURLs will have AuthRequired=true.
func buildTargetsFileWithAuth(t *testing.T, openURLs, authURLs []string) string {
	t.Helper()
	var servers []mcpscan.DiscoveredServer
	for i, u := range openURLs {
		servers = append(servers, mcpscan.DiscoveredServer{
			Name:         fmt.Sprintf("open-%d", i),
			Transport:    "http",
			Target:       u,
			Source:       "test",
			AuthRequired: false,
		})
	}
	for i, u := range authURLs {
		servers = append(servers, mcpscan.DiscoveredServer{
			Name:         fmt.Sprintf("auth-%d", i),
			Transport:    "http",
			Target:       u,
			Source:       "test",
			AuthRequired: true,
		})
	}
	discovery := mcpscan.DiscoveryResult{Servers: servers}
	data, err := json.Marshal(discovery)
	if err != nil {
		t.Fatalf("failed to marshal targets: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "targets-auth-*.json")
	if err != nil {
		t.Fatalf("failed to create temp targets file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("failed to write targets file: %v", err)
	}
	f.Close()
	return f.Name()
}

// TestMCPScanCmd_OpenOnlyFlagRegistered verifies the flag is present with the
// correct default and documentation.
func TestMCPScanCmd_OpenOnlyFlagRegistered(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewMCPScanCmd(newTestMCPScanCmd(&buf))

	var scanSubcmd *cobra.Command
	for _, sub := range cmd.Commands() {
		if sub.Use == "scan" {
			scanSubcmd = sub
			break
		}
	}
	if scanSubcmd == nil {
		t.Fatal("scan subcommand not found")
	}

	flag := scanSubcmd.Flag("open-only")
	if flag == nil {
		t.Fatal("Expected 'open-only' flag to be registered on 'scan' subcommand")
	}
	if flag.DefValue != "false" {
		t.Errorf("Expected default open-only=false, got %q", flag.DefValue)
	}
	if !strings.Contains(strings.ToLower(flag.Usage), "auth") {
		t.Errorf("Expected open-only flag usage to mention 'auth', got: %s", flag.Usage)
	}
}

// TestMCPScanCmd_OpenOnly_FiltersAuthRequired verifies that --open-only skips
// servers where AuthRequired==true and only scans the open ones.
func TestMCPScanCmd_OpenOnly_FiltersAuthRequired(t *testing.T) {
	// Start one real mock server (open) and use a non-existent URL for auth server.
	openURL, _ := startMockMCPServer(t, 0)
	// Auth-required server — won't be contacted at all with --open-only.
	authURL := "http://127.0.0.1:1" // unreachable but doesn't matter; should be filtered

	targetsFile := buildTargetsFileWithAuth(t, []string{openURL}, []string{authURL})

	var buf bytes.Buffer
	cmd := NewMCPScanCmd(newTestMCPScanCmd(&buf))
	cmd.SetArgs([]string{
		"scan",
		"--targets", targetsFile,
		"--open-only",
		"--timeout", "5",
	})
	_ = cmd.Execute()

	got := buf.String()

	// Should mention filtering.
	if !strings.Contains(got, "Filtered out 1 auth-required") {
		t.Errorf("Expected 'Filtered out 1 auth-required' in output, got:\n%s", got)
	}

	// The auth server URL should NOT appear in output (it was filtered, not scanned).
	if strings.Contains(got, authURL) {
		t.Errorf("Auth-required server URL %q should not appear in output when --open-only is set, got:\n%s", authURL, got)
	}
}

// TestMCPScanCmd_OpenOnly_NoAuthServers verifies that when no servers are
// auth-required, --open-only has no effect on the scan.
func TestMCPScanCmd_OpenOnly_NoAuthServers(t *testing.T) {
	u1, _ := startMockMCPServer(t, 0)
	u2, _ := startMockMCPServer(t, 0)

	targetsFile := buildTargetsFileWithAuth(t, []string{u1, u2}, nil)

	var buf bytes.Buffer
	cmd := NewMCPScanCmd(newTestMCPScanCmd(&buf))
	cmd.SetArgs([]string{
		"scan",
		"--targets", targetsFile,
		"--open-only",
		"--timeout", "5",
	})
	_ = cmd.Execute()

	got := buf.String()

	// No filtering message since nothing was filtered.
	if strings.Contains(got, "Filtered out") {
		t.Errorf("Expected no filtering message when no auth-required servers present, got:\n%s", got)
	}

	// Both servers should appear in output.
	if !strings.Contains(got, u1) {
		t.Errorf("Expected open server %s to appear in output, got:\n%s", u1, got)
	}
	if !strings.Contains(got, u2) {
		t.Errorf("Expected open server %s to appear in output, got:\n%s", u2, got)
	}
}

// TestIsUnreachableError verifies heuristic error classification.
func TestIsUnreachableError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"connection refused", fmt.Errorf("dial tcp 127.0.0.1:9999: connect: connection refused"), true},
		{"no such host", fmt.Errorf("dial tcp: lookup no-such-host.invalid: no such host"), true},
		{"timeout", fmt.Errorf("context deadline exceeded"), true},
		{"application error", fmt.Errorf("JSON-RPC error -32600: invalid request"), false},
		{"parse error", fmt.Errorf("failed to parse response: unexpected EOF"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnreachableError(tt.err)
			if got != tt.want {
				t.Errorf("isUnreachableError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
