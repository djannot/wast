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
