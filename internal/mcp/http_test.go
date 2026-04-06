package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
// ServeHTTP integration test (full HTTP server lifecycle)
// ---------------------------------------------------------------------------

func TestHTTP_ServeHTTP_LifecycleCancel(t *testing.T) {
	s := newTestServer()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ServeHTTP(ctx, "127.0.0.1:0")
	}()

	// Cancel the context immediately; the server should shut down cleanly.
	cancel()

	if err := <-errCh; err != nil {
		t.Errorf("ServeHTTP returned unexpected error after context cancel: %v", err)
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
