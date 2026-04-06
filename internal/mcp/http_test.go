package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestServer creates a Server suitable for HTTP handler tests.
func newTestServer() *Server {
	return NewServer()
}

// doMCPPost sends a JSON-encoded body to the server's HTTP handler and returns
// the recorded response.
func doMCPPost(t *testing.T, s *Server, body interface{}, accept string) *httptest.ResponseRecorder {
	t.Helper()

	var reqBody []byte
	var err error
	switch v := body.(type) {
	case []byte:
		reqBody = v
	case string:
		reqBody = []byte(v)
	default:
		reqBody, err = json.Marshal(v)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
	}

	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(reqBody))
	r.Header.Set("Content-Type", "application/json")
	if accept != "" {
		r.Header.Set("Accept", accept)
	}

	w := httptest.NewRecorder()
	s.mcpHTTPHandler(w, r)
	return w
}

// parseJSONRPCResponse unmarshals the recorder body into a JSONRPCResponse.
func parseJSONRPCResponse(t *testing.T, w *httptest.ResponseRecorder) JSONRPCResponse {
	t.Helper()
	var resp JSONRPCResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON-RPC response: %v (body: %q)", err, w.Body.String())
	}
	return resp
}

// ---------------------------------------------------------------------------
// Basic transport tests
// ---------------------------------------------------------------------------

func TestHTTP_InvalidMethod(t *testing.T) {
	s := newTestServer()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest(method, "/mcp", nil)
			w := httptest.NewRecorder()
			s.mcpHTTPHandler(w, r)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405, got %d", w.Code)
			}
			if allow := w.Header().Get("Allow"); allow != http.MethodPost {
				t.Errorf("expected Allow: POST, got %q", allow)
			}
		})
	}
}

func TestHTTP_MalformedJSON(t *testing.T) {
	s := newTestServer()

	w := doMCPPost(t, s, []byte(`{this is not json`), "application/json")

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	resp := parseJSONRPCResponse(t, w)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error, got nil")
	}
	if resp.Error.Code != -32700 {
		t.Errorf("expected error code -32700 (Parse error), got %d", resp.Error.Code)
	}
}

func TestHTTP_SessionIDHeader(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize"}
	w := doMCPPost(t, s, req, "application/json")

	sessionID := w.Header().Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Error("expected Mcp-Session-Id response header to be set")
	}
}

func TestHTTP_SessionIDEchoed(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize"}
	reqBytes, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(reqBytes))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Mcp-Session-Id", "my-existing-session")

	w := httptest.NewRecorder()
	s.mcpHTTPHandler(w, r)

	if id := w.Header().Get("Mcp-Session-Id"); id != "my-existing-session" {
		t.Errorf("expected session ID to be echoed back, got %q", id)
	}
}

func TestHTTP_ContentTypeJSON(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize"}
	w := doMCPPost(t, s, req, "application/json")

	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

// ---------------------------------------------------------------------------
// JSON-RPC method tests
// ---------------------------------------------------------------------------

func TestHTTP_Initialize(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}
	w := doMCPPost(t, s, req, "application/json")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result is not a map")
	}

	if pv, ok := result["protocolVersion"].(string); !ok || pv == "" {
		t.Errorf("expected non-empty protocolVersion, got %v", result["protocolVersion"])
	}
	if si, ok := result["serverInfo"].(map[string]interface{}); !ok {
		t.Error("expected serverInfo in result")
	} else if si["name"] != "wast" {
		t.Errorf("expected serverInfo.name=wast, got %v", si["name"])
	}
	if _, ok := result["capabilities"]; !ok {
		t.Error("expected capabilities in result")
	}
}

func TestHTTP_ToolsList(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	w := doMCPPost(t, s, req, "application/json")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result is not a map")
	}

	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatal("tools is not a list")
	}
	if len(tools) == 0 {
		t.Error("expected at least one tool in tools/list response")
	}

	// Verify each tool has name, description, inputSchema
	for i, tool := range tools {
		toolMap, ok := tool.(map[string]interface{})
		if !ok {
			t.Errorf("tool[%d] is not a map", i)
			continue
		}
		if _, ok := toolMap["name"].(string); !ok {
			t.Errorf("tool[%d] missing name", i)
		}
		if _, ok := toolMap["description"].(string); !ok {
			t.Errorf("tool[%d] missing description", i)
		}
		if _, ok := toolMap["inputSchema"]; !ok {
			t.Errorf("tool[%d] missing inputSchema", i)
		}
	}
}

func TestHTTP_ToolsCall_UnknownTool(t *testing.T) {
	s := newTestServer()

	params := map[string]interface{}{
		"name":      "nonexistent_tool",
		"arguments": map[string]interface{}{},
	}
	paramsBytes, _ := json.Marshal(params)

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params:  paramsBytes,
	}
	w := doMCPPost(t, s, req, "application/json")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp := parseJSONRPCResponse(t, w)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for unknown tool, got nil")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("expected error code -32602 (Invalid params), got %d", resp.Error.Code)
	}
}

func TestHTTP_MethodNotFound(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "unknown/method",
	}
	w := doMCPPost(t, s, req, "application/json")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp := parseJSONRPCResponse(t, w)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for unknown method, got nil")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601 (Method not found), got %d", resp.Error.Code)
	}
}

func TestHTTP_Ping(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "ping",
	}
	w := doMCPPost(t, s, req, "application/json")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
}

func TestHTTP_InvalidJSONRPCVersion(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{
		JSONRPC: "1.0",
		ID:      6,
		Method:  "initialize",
	}
	w := doMCPPost(t, s, req, "application/json")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp := parseJSONRPCResponse(t, w)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for wrong version, got nil")
	}
	if resp.Error.Code != -32600 {
		t.Errorf("expected error code -32600 (Invalid Request), got %d", resp.Error.Code)
	}
}

// ---------------------------------------------------------------------------
// SSE transport tests
// ---------------------------------------------------------------------------

func TestHTTP_SSE_Initialize(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}
	w := doMCPPost(t, s, req, "text/event-stream")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("expected Content-Type text/event-stream, got %q", ct)
	}

	// SSE body should contain at least one "data: {...}" line.
	body := w.Body.String()
	if !strings.Contains(body, "data: ") {
		t.Errorf("expected SSE data lines in body, got: %q", body)
	}

	// Extract and parse the data payload.
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "data: ") {
			payload := strings.TrimPrefix(line, "data: ")
			var resp JSONRPCResponse
			if err := json.Unmarshal([]byte(payload), &resp); err != nil {
				t.Fatalf("failed to parse SSE data as JSON-RPC: %v (payload: %q)", err, payload)
			}
			if resp.Error != nil {
				t.Fatalf("unexpected error in SSE response: %+v", resp.Error)
			}
			return
		}
	}
	t.Error("no data line found in SSE body")
}

// ---------------------------------------------------------------------------
// ListenAndServe integration test (full HTTP server lifecycle)
// ---------------------------------------------------------------------------

func TestHTTP_ListenAndServe_LifecycleCancel(t *testing.T) {
	s := newTestServer()

	ctx, cancel := context.WithCancel(context.Background())

	// Use a ready channel so we know the server is up before cancelling.
	// We start the server in a goroutine and give it a brief moment to bind.
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenAndServe(ctx, "127.0.0.1:0")
	}()

	// Give the server a moment to start listening before cancelling.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ListenAndServe returned unexpected error after context cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListenAndServe did not return within 3 seconds after context cancel")
	}
}

// ---------------------------------------------------------------------------
// Input validation tests
// ---------------------------------------------------------------------------

func TestHTTP_InvalidSessionID_TooLong(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize"}
	reqBytes, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(reqBytes))
	r.Header.Set("Content-Type", "application/json")
	// 65-character session ID — exceeds the 64-char limit.
	r.Header.Set("Mcp-Session-Id", strings.Repeat("a", 65))

	w := httptest.NewRecorder()
	s.mcpHTTPHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized session ID, got %d", w.Code)
	}
}

func TestHTTP_InvalidSessionID_BadChars(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize"}
	reqBytes, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(reqBytes))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Mcp-Session-Id", "bad session\r\ninjection")

	w := httptest.NewRecorder()
	s.mcpHTTPHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid session ID chars, got %d", w.Code)
	}
}

func TestHTTP_ValidSessionID_AlphanumericHyphen(t *testing.T) {
	s := newTestServer()

	req := JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize"}
	reqBytes, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(reqBytes))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Mcp-Session-Id", "abc-123-XYZ")

	w := httptest.NewRecorder()
	s.mcpHTTPHandler(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid session ID, got %d", w.Code)
	}
	if got := w.Header().Get("Mcp-Session-Id"); got != "abc-123-XYZ" {
		t.Errorf("expected session ID to be echoed back as-is, got %q", got)
	}
}

func TestHTTP_BodySizeLimit(t *testing.T) {
	s := newTestServer()

	// Send a body that exceeds 1 MiB.
	oversized := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":"%s"}`,
		strings.Repeat("x", 1<<20+1))

	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(oversized))
	r.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	s.mcpHTTPHandler(w, r)

	// The handler should return a JSON-RPC parse error when reading fails.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with JSON-RPC error body, got %d", w.Code)
	}
	resp := parseJSONRPCResponse(t, w)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for oversized body, got nil")
	}
}

func TestHTTP_AuthToken_Missing(t *testing.T) {
	s := newTestServer()
	s.SetAuthToken("secret-token")

	req := JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize"}
	w := doMCPPost(t, s, req, "application/json")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when auth token missing, got %d", w.Code)
	}
}

func TestHTTP_AuthToken_Wrong(t *testing.T) {
	s := newTestServer()
	s.SetAuthToken("secret-token")

	req := JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize"}
	reqBytes, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(reqBytes))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer wrong-token")

	w := httptest.NewRecorder()
	s.mcpHTTPHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong auth token, got %d", w.Code)
	}
}

func TestHTTP_AuthToken_Correct(t *testing.T) {
	s := newTestServer()
	s.SetAuthToken("secret-token")

	req := JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize"}
	reqBytes, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(reqBytes))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer secret-token")

	w := httptest.NewRecorder()
	s.mcpHTTPHandler(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for correct auth token, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Non-SSE progress notification stripping test
// ---------------------------------------------------------------------------

// progressTool is a minimal Tool that emits a progress notification before
// returning a result.  It exercises the non-SSE multi-JSON body fix.
type progressTool struct {
	server *Server
}

func (pt *progressTool) Name() string        { return "test_progress" }
func (pt *progressTool) Description() string { return "emits a progress notification" }
func (pt *progressTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{"type": "object"}
}
func (pt *progressTool) Execute(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	pt.server.sendProgress(ctx, "testing", 1, 1, "step 1")
	return map[string]string{"status": "done"}, nil
}

func TestHTTP_NonSSE_ProgressNotificationsDiscarded(t *testing.T) {
	s := newTestServer()
	pt := &progressTool{server: s}
	s.tools["test_progress"] = pt

	params := map[string]interface{}{
		"name":      "test_progress",
		"arguments": map[string]interface{}{},
	}
	paramsBytes, _ := json.Marshal(params)

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      99,
		Method:  "tools/call",
		Params:  paramsBytes,
	}

	w := doMCPPost(t, s, req, "application/json")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Body must be valid JSON (a single object, not NDJSON).
	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}
	// The response should have the tool result, not a progress notification.
	if resp.ID == nil {
		t.Error("expected response ID to be set")
	}
}

// ---------------------------------------------------------------------------
// isValidSessionID unit tests
// ---------------------------------------------------------------------------

func TestIsValidSessionID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"abc-123", true},
		{"ABC-xyz-000", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false}, // too long
		{"bad session", false},           // space
		{"inject\r\nHeader: val", false}, // CRLF injection
		{"under_score", false},           // underscore not allowed
		{"", true},                       // empty is handled before validation
	}
	for _, tc := range tests {
		got := isValidSessionID(tc.id)
		if got != tc.valid {
			t.Errorf("isValidSessionID(%q) = %v, want %v", tc.id, got, tc.valid)
		}
	}
}

// ---------------------------------------------------------------------------
// generateSessionID helper test
// ---------------------------------------------------------------------------

func TestGenerateSessionID(t *testing.T) {
	id1 := generateSessionID()
	id2 := generateSessionID()

	if id1 == "" {
		t.Error("generateSessionID returned empty string")
	}
	if id1 == id2 {
		t.Error("generateSessionID returned the same ID twice (collision unlikely in real usage)")
	}
	// IDs should be valid hex strings of length 32 (16 bytes * 2).
	if len(id1) != 32 {
		t.Errorf("expected session ID length 32, got %d", len(id1))
	}
}

// ---------------------------------------------------------------------------
// Concurrent HTTP request test
// ---------------------------------------------------------------------------

// slowTool is a minimal Tool that sleeps for a configurable duration before
// returning, simulating a long-running operation like a full wast_scan.
type slowTool struct {
	sleep time.Duration
}

func (st *slowTool) Name() string        { return "test_slow" }
func (st *slowTool) Description() string { return "slow tool for concurrency testing" }
func (st *slowTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{"type": "object"}
}
func (st *slowTool) Execute(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	select {
	case <-time.After(st.sleep):
		return map[string]string{"status": "done"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestHTTP_ConcurrentRequests verifies that the HTTP transport handles multiple
// requests in parallel rather than serialising them behind a mutex.  Two
// simultaneous slow-tool calls should complete in approximately the time of
// one call, not the sum of both.
func TestHTTP_ConcurrentRequests(t *testing.T) {
	const toolSleep = 100 * time.Millisecond

	s := newTestServer()
	s.tools["test_slow"] = &slowTool{sleep: toolSleep}

	// Build a tools/call request that invokes test_slow.
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "test_slow",
		"arguments": map[string]interface{}{},
	})
	reqBody, _ := json.Marshal(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  params,
	})

	// Use a real HTTP test server so that Go's net/http stack dispatches each
	// inbound connection to a separate goroutine — giving us true concurrency.
	srv := httptest.NewServer(http.HandlerFunc(s.mcpHTTPHandler))
	defer srv.Close()

	const numRequests = 2
	var wg sync.WaitGroup
	wg.Add(numRequests)

	start := time.Now()
	for i := 0; i < numRequests; i++ {
		go func() {
			defer wg.Done()
			resp, err := http.Post(srv.URL+"/mcp", "application/json", bytes.NewReader(reqBody))
			if err != nil {
				t.Errorf("concurrent request failed: %v", err)
				return
			}
			defer resp.Body.Close()
			io.ReadAll(resp.Body) //nolint:errcheck
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	// If requests were serialised the wall-clock time would be ≥ 2×toolSleep.
	// In parallel it should be close to 1×toolSleep.  We allow generous
	// headroom (1.8×) to avoid flakiness on slow CI runners.
	maxSerial := time.Duration(float64(toolSleep) * 1.8)
	if elapsed >= maxSerial {
		t.Errorf("HTTP requests appear to be serialised: elapsed=%v, want < %v (parallel threshold)", elapsed, maxSerial)
	}
}

// ---------------------------------------------------------------------------
// Intra-request concurrent progress notification test
// ---------------------------------------------------------------------------

// concurrentProgressTool is a tool that fires multiple sendProgress calls
// concurrently from goroutines, simulating tool-internal worker pools (e.g.
// scanner discovery goroutines) calling progressCallback in parallel within a
// single request.
type concurrentProgressTool struct {
	server     *Server
	numWorkers int
}

func (ct *concurrentProgressTool) Name() string        { return "test_concurrent_progress" }
func (ct *concurrentProgressTool) Description() string { return "fires progress from concurrent goroutines" }
func (ct *concurrentProgressTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{"type": "object"}
}
func (ct *concurrentProgressTool) Execute(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	var wg sync.WaitGroup
	wg.Add(ct.numWorkers)
	// All goroutines start simultaneously to maximise the chance of concurrent
	// writes hitting the per-request writer.
	start := make(chan struct{})
	for i := 0; i < ct.numWorkers; i++ {
		go func(n int) {
			defer wg.Done()
			<-start // wait for the starting gun
			ct.server.sendProgress(ctx, "test", n, ct.numWorkers, fmt.Sprintf("worker %d done", n))
		}(i)
	}
	close(start)
	wg.Wait()
	return map[string]string{"status": "done"}, nil
}

// TestHTTP_SSE_ConcurrentProgressNotifications verifies that concurrent
// sendProgress calls from tool-internal goroutines sharing a single SSE
// connection do not cause a data race.  Run with -race to get the full benefit.
func TestHTTP_SSE_ConcurrentProgressNotifications(t *testing.T) {
	const numWorkers = 20

	s := newTestServer()
	s.tools["test_concurrent_progress"] = &concurrentProgressTool{server: s, numWorkers: numWorkers}

	params, _ := json.Marshal(map[string]interface{}{
		"name":      "test_concurrent_progress",
		"arguments": map[string]interface{}{},
	})
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  params,
	}

	// Use the SSE path so that all concurrent progress notifications are routed
	// through the per-request sseWriter, which must be concurrency-safe.
	w := doMCPPost(t, s, req, "text/event-stream")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// We expect exactly numWorkers progress events plus one final result event.
	body := w.Body.String()
	dataLines := 0
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "data: ") {
			dataLines++
		}
	}
	// numWorkers progress notifications + 1 final tools/call result = numWorkers+1
	if dataLines != numWorkers+1 {
		t.Errorf("expected %d SSE data lines, got %d\nbody:\n%s", numWorkers+1, dataLines, body)
	}
}
