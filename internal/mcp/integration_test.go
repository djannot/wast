// +build integration

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMCPServerIntegration_ReconTool tests end-to-end recon tool execution
func TestMCPServerIntegration_ReconTool(t *testing.T) {
	// Create MCP server with buffer I/O
	input := bytes.NewBuffer(nil)
	output := &bytes.Buffer{}

	server := NewServer()
	server.reader = input
	server.writer = output

	// Construct tools/call request for wast_recon
	args := map[string]interface{}{
		"target":  "example.com",
		"timeout": "5s",
	}
	argsJSON, _ := json.Marshal(args)

	params := map[string]interface{}{
		"name":      "wast_recon",
		"arguments": json.RawMessage(argsJSON),
	}
	paramsJSON, _ := json.Marshal(params)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  paramsJSON,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Execute the request
	server.handleRequest(ctx, &request)

	// Parse output - may contain multiple JSON objects (notifications + response)
	outputStr := output.String()
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")
	if len(lines) == 0 {
		t.Fatal("No output received from server")
	}

	// Find the response (last line should be the response, earlier lines are notifications)
	var response JSONRPCResponse
	var foundResponse bool
	for i := len(lines) - 1; i >= 0; i-- {
		if err := json.Unmarshal([]byte(lines[i]), &response); err == nil {
			if response.ID != nil {
				// Found the response (not a notification)
				foundResponse = true
				break
			}
		}
	}

	if !foundResponse {
		t.Fatalf("No valid response found in output: %s", outputStr)
	}

	// Verify response structure
	if response.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc 2.0, got %s", response.JSONRPC)
	}

	if response.Error != nil {
		t.Errorf("Unexpected error in response: %v", response.Error)
	}

	if response.Result == nil {
		t.Fatal("Response result should not be nil")
	}

	// Verify result has content field
	resultMap, ok := response.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Result should be a map")
	}

	content, ok := resultMap["content"].([]interface{})
	if !ok {
		t.Fatal("Result should have content field as array")
	}

	if len(content) == 0 {
		t.Fatal("Content array should not be empty")
	}

	// Verify content structure
	firstContent := content[0].(map[string]interface{})
	if firstContent["type"] != "text" {
		t.Errorf("Expected content type 'text', got %v", firstContent["type"])
	}

	textContent, ok := firstContent["text"].(string)
	if !ok || textContent == "" {
		t.Error("Content text should be a non-empty string")
	}

	// Parse the JSON text content to verify it's valid recon result
	var reconResult ReconResult
	if err := json.Unmarshal([]byte(textContent), &reconResult); err != nil {
		t.Errorf("Content text should be valid JSON: %v", err)
	}

	if reconResult.Target != "example.com" {
		t.Errorf("Expected target example.com, got %s", reconResult.Target)
	}

	// Verify DNS and TLS results are present
	if reconResult.DNS == nil {
		t.Error("DNS result should not be nil")
	}

	if reconResult.TLS == nil {
		t.Error("TLS result should not be nil")
	}

	// Verify progress notifications were sent
	var foundProgressNotification bool
	for _, line := range lines[:len(lines)-1] { // Check all lines except the response
		var notif JSONRPCNotification
		if err := json.Unmarshal([]byte(line), &notif); err == nil {
			if notif.Method == "notifications/progress" {
				foundProgressNotification = true
				break
			}
		}
	}

	if !foundProgressNotification {
		t.Error("Expected progress notifications during recon operation")
	}
}

// TestMCPServerIntegration_ScanTool tests end-to-end scan tool execution with mock backend
func TestMCPServerIntegration_ScanTool(t *testing.T) {
	// Create mock HTTP backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Test Page</body></html>"))
	}))
	defer backend.Close()

	// Create MCP server with buffer I/O
	input := bytes.NewBuffer(nil)
	output := &bytes.Buffer{}

	server := NewServer()
	server.reader = input
	server.writer = output

	// Construct tools/call request for wast_scan (safe mode)
	args := map[string]interface{}{
		"target":  backend.URL,
		"timeout": 30,
		"active":  false, // Safe mode
	}
	argsJSON, _ := json.Marshal(args)

	params := map[string]interface{}{
		"name":      "wast_scan",
		"arguments": json.RawMessage(argsJSON),
	}
	paramsJSON, _ := json.Marshal(params)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  paramsJSON,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Execute the request
	server.handleRequest(ctx, &request)

	// Parse output
	outputStr := output.String()
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")

	// Find the response
	var response JSONRPCResponse
	var foundResponse bool
	for i := len(lines) - 1; i >= 0; i-- {
		if err := json.Unmarshal([]byte(lines[i]), &response); err == nil {
			if response.ID != nil {
				foundResponse = true
				break
			}
		}
	}

	if !foundResponse {
		t.Fatalf("No valid response found in output")
	}

	// Verify response structure
	if response.Error != nil {
		t.Errorf("Unexpected error in response: %v", response.Error)
	}

	if response.Result == nil {
		t.Fatal("Response result should not be nil")
	}

	// Verify result format
	resultMap := response.Result.(map[string]interface{})
	content := resultMap["content"].([]interface{})
	firstContent := content[0].(map[string]interface{})
	textContent := firstContent["text"].(string)

	// Verify scan result structure
	var scanResult map[string]interface{}
	if err := json.Unmarshal([]byte(textContent), &scanResult); err != nil {
		t.Errorf("Content should be valid JSON scan result: %v", err)
	}

	// Verify target matches
	if target, ok := scanResult["target"].(string); !ok || target != backend.URL {
		t.Errorf("Expected target %s, got %v", backend.URL, scanResult["target"])
	}

	// Verify passive_only flag is true (safe mode)
	if passiveOnly, ok := scanResult["passive_only"].(bool); !ok || !passiveOnly {
		t.Error("Expected passive_only to be true in safe mode")
	}

	// Verify headers scan result is present
	if _, ok := scanResult["headers"]; !ok {
		t.Error("Expected headers scan result to be present")
	}
}

// TestMCPServerIntegration_ScanToolWithAuth tests scan tool with authentication parameters
func TestMCPServerIntegration_ScanToolWithAuth(t *testing.T) {
	// Create mock HTTP backend that checks for auth headers
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Bearer token is present
		authHeader := r.Header.Get("Authorization")
		if !strings.Contains(authHeader, "Bearer test-token") {
			t.Errorf("Expected Bearer token in Authorization header, got: %s", authHeader)
		}

		// Verify cookies are present
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value != "abc123" {
			t.Errorf("Expected session cookie with value abc123")
		}

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Authenticated</body></html>"))
	}))
	defer backend.Close()

	// Create MCP server
	input := bytes.NewBuffer(nil)
	output := &bytes.Buffer{}

	server := NewServer()
	server.reader = input
	server.writer = output

	// Construct request with auth parameters
	args := map[string]interface{}{
		"target":       backend.URL,
		"timeout":      30,
		"active":       false,
		"bearer_token": "test-token",
		"cookies":      []string{"session=abc123"},
	}
	argsJSON, _ := json.Marshal(args)

	params := map[string]interface{}{
		"name":      "wast_scan",
		"arguments": json.RawMessage(argsJSON),
	}
	paramsJSON, _ := json.Marshal(params)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  paramsJSON,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server.handleRequest(ctx, &request)

	// Verify response
	outputStr := output.String()
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")

	var response JSONRPCResponse
	for i := len(lines) - 1; i >= 0; i-- {
		if err := json.Unmarshal([]byte(lines[i]), &response); err == nil {
			if response.ID != nil {
				break
			}
		}
	}

	if response.Error != nil {
		t.Errorf("Unexpected error: %v", response.Error)
	}

	if response.Result == nil {
		t.Fatal("Result should not be nil")
	}
}

// TestMCPServerIntegration_CrawlTool tests end-to-end crawl tool execution
func TestMCPServerIntegration_CrawlTool(t *testing.T) {
	// Create mock HTTP backend with multiple pages
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><a href="/page1">Page 1</a></body></html>`))
	})
	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><a href="/page2">Page 2</a></body></html>`))
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>End</body></html>`))
	})

	backend := httptest.NewServer(mux)
	defer backend.Close()

	// Create MCP server
	input := bytes.NewBuffer(nil)
	output := &bytes.Buffer{}

	server := NewServer()
	server.reader = input
	server.writer = output

	// Construct crawl request
	args := map[string]interface{}{
		"target":         backend.URL,
		"depth":          2,
		"timeout":        "30s",
		"respect_robots": false,
	}
	argsJSON, _ := json.Marshal(args)

	params := map[string]interface{}{
		"name":      "wast_crawl",
		"arguments": json.RawMessage(argsJSON),
	}
	paramsJSON, _ := json.Marshal(params)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  paramsJSON,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server.handleRequest(ctx, &request)

	// Parse output
	outputStr := output.String()
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")

	// Verify progress notifications were sent
	var progressCount int
	for _, line := range lines {
		var notif JSONRPCNotification
		if err := json.Unmarshal([]byte(line), &notif); err == nil {
			if notif.Method == "notifications/progress" {
				progressCount++
			}
		}
	}

	if progressCount == 0 {
		t.Error("Expected progress notifications during crawl operation")
	}

	// Find response
	var response JSONRPCResponse
	for i := len(lines) - 1; i >= 0; i-- {
		if err := json.Unmarshal([]byte(lines[i]), &response); err == nil {
			if response.ID != nil {
				break
			}
		}
	}

	if response.Error != nil {
		t.Errorf("Unexpected error: %v", response.Error)
	}

	if response.Result == nil {
		t.Fatal("Result should not be nil")
	}
}

// TestMCPServerIntegration_APITool tests end-to-end API tool execution
func TestMCPServerIntegration_APITool(t *testing.T) {
	// Create mock API backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok", "data": []}`))
	}))
	defer backend.Close()

	// Create MCP server
	input := bytes.NewBuffer(nil)
	output := &bytes.Buffer{}

	server := NewServer()
	server.reader = input
	server.writer = output

	// Construct API discovery request
	args := map[string]interface{}{
		"target":  backend.URL,
		"timeout": 30,
	}
	argsJSON, _ := json.Marshal(args)

	params := map[string]interface{}{
		"name":      "wast_api",
		"arguments": json.RawMessage(argsJSON),
	}
	paramsJSON, _ := json.Marshal(params)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  paramsJSON,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server.handleRequest(ctx, &request)

	// Parse output
	outputStr := output.String()
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")

	var response JSONRPCResponse
	for i := len(lines) - 1; i >= 0; i-- {
		if err := json.Unmarshal([]byte(lines[i]), &response); err == nil {
			if response.ID != nil {
				break
			}
		}
	}

	if response.Error != nil {
		t.Errorf("Unexpected error: %v", response.Error)
	}

	if response.Result == nil {
		t.Fatal("Result should not be nil")
	}
}

// TestMCPServerIntegration_HeadersTool tests end-to-end headers tool execution
func TestMCPServerIntegration_HeadersTool(t *testing.T) {
	// Create mock HTTP backend with security headers
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Test</body></html>"))
	}))
	defer backend.Close()

	// Create MCP server
	input := bytes.NewBuffer(nil)
	output := &bytes.Buffer{}

	server := NewServer()
	server.reader = input
	server.writer = output

	// Construct headers scan request
	args := map[string]interface{}{
		"target":  backend.URL,
		"timeout": 30,
	}
	argsJSON, _ := json.Marshal(args)

	params := map[string]interface{}{
		"name":      "wast_headers",
		"arguments": json.RawMessage(argsJSON),
	}
	paramsJSON, _ := json.Marshal(params)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  paramsJSON,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server.handleRequest(ctx, &request)

	// Parse output
	outputStr := output.String()
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")

	var response JSONRPCResponse
	for i := len(lines) - 1; i >= 0; i-- {
		if err := json.Unmarshal([]byte(lines[i]), &response); err == nil {
			if response.ID != nil {
				break
			}
		}
	}

	if response.Error != nil {
		t.Errorf("Unexpected error: %v", response.Error)
	}

	if response.Result == nil {
		t.Fatal("Result should not be nil")
	}

	// Verify result format
	resultMap := response.Result.(map[string]interface{})
	content := resultMap["content"].([]interface{})
	firstContent := content[0].(map[string]interface{})
	textContent := firstContent["text"].(string)

	// Parse headers result
	var headersResult map[string]interface{}
	if err := json.Unmarshal([]byte(textContent), &headersResult); err != nil {
		t.Errorf("Content should be valid JSON: %v", err)
	}

	// Verify target
	if target, ok := headersResult["target"].(string); !ok || target != backend.URL {
		t.Errorf("Expected target %s, got %v", backend.URL, headersResult["target"])
	}

	// Verify headers array is present
	if _, ok := headersResult["headers"]; !ok {
		t.Error("Expected headers array to be present")
	}
}

// TestMCPServerIntegration_ErrorHandling tests error handling for invalid targets
func TestMCPServerIntegration_ErrorHandling(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		args     map[string]interface{}
		wantErr  bool
	}{
		{
			name:     "invalid target URL",
			toolName: "wast_scan",
			args: map[string]interface{}{
				"target": "not-a-valid-url",
			},
			wantErr: false, // Should complete but may have errors in result
		},
		{
			name:     "missing required target",
			toolName: "wast_scan",
			args:     map[string]interface{}{},
			wantErr:  true,
		},
		{
			name:     "invalid timeout format",
			toolName: "wast_recon",
			args: map[string]interface{}{
				"target":  "example.com",
				"timeout": "invalid-timeout",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := bytes.NewBuffer(nil)
			output := &bytes.Buffer{}

			server := NewServer()
			server.reader = input
			server.writer = output

			argsJSON, _ := json.Marshal(tt.args)
			params := map[string]interface{}{
				"name":      tt.toolName,
				"arguments": json.RawMessage(argsJSON),
			}
			paramsJSON, _ := json.Marshal(params)

			request := JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "tools/call",
				Params:  paramsJSON,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			server.handleRequest(ctx, &request)

			outputStr := output.String()
			lines := strings.Split(strings.TrimSpace(outputStr), "\n")

			var response JSONRPCResponse
			for i := len(lines) - 1; i >= 0; i-- {
				if err := json.Unmarshal([]byte(lines[i]), &response); err == nil {
					if response.ID != nil {
						break
					}
				}
			}

			if tt.wantErr {
				if response.Error == nil {
					t.Error("Expected error in response")
				}
			} else {
				if response.Error != nil {
					t.Logf("Got error (may be expected): %v", response.Error)
				}
			}
		})
	}
}

// TestMCPServerIntegration_AuthFailure tests authentication failure handling
func TestMCPServerIntegration_AuthFailure(t *testing.T) {
	// Create backend that requires auth
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>OK</body></html>"))
	}))
	defer backend.Close()

	input := bytes.NewBuffer(nil)
	output := &bytes.Buffer{}

	server := NewServer()
	server.reader = input
	server.writer = output

	// Request without auth credentials
	args := map[string]interface{}{
		"target":  backend.URL,
		"timeout": 30,
	}
	argsJSON, _ := json.Marshal(args)

	params := map[string]interface{}{
		"name":      "wast_scan",
		"arguments": json.RawMessage(argsJSON),
	}
	paramsJSON, _ := json.Marshal(params)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  paramsJSON,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server.handleRequest(ctx, &request)

	// Should complete without JSON-RPC error (auth failure is part of scan result)
	outputStr := output.String()
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")

	var response JSONRPCResponse
	for i := len(lines) - 1; i >= 0; i-- {
		if err := json.Unmarshal([]byte(lines[i]), &response); err == nil {
			if response.ID != nil {
				break
			}
		}
	}

	if response.Result == nil {
		t.Fatal("Result should not be nil even on auth failure")
	}
}

// TestMCPServerIntegration_Timeout tests timeout handling
func TestMCPServerIntegration_Timeout(t *testing.T) {
	// Create slow backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	input := bytes.NewBuffer(nil)
	output := &bytes.Buffer{}

	server := NewServer()
	server.reader = input
	server.writer = output

	// Request with short timeout
	args := map[string]interface{}{
		"target":  backend.URL,
		"timeout": 1, // 1 second timeout
	}
	argsJSON, _ := json.Marshal(args)

	params := map[string]interface{}{
		"name":      "wast_scan",
		"arguments": json.RawMessage(argsJSON),
	}
	paramsJSON, _ := json.Marshal(params)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  paramsJSON,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server.handleRequest(ctx, &request)

	// Should complete (timeout is handled at scan level, not JSON-RPC level)
	outputStr := output.String()
	if outputStr == "" {
		t.Fatal("Expected output from server")
	}
}

// TestMCPServerIntegration_ProgressNotifications tests progress notification format
func TestMCPServerIntegration_ProgressNotifications(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html></html>"))
	}))
	defer backend.Close()

	input := bytes.NewBuffer(nil)
	output := &bytes.Buffer{}

	server := NewServer()
	server.reader = input
	server.writer = output

	args := map[string]interface{}{
		"target": backend.URL,
	}
	argsJSON, _ := json.Marshal(args)

	params := map[string]interface{}{
		"name":      "wast_scan",
		"arguments": json.RawMessage(argsJSON),
	}
	paramsJSON, _ := json.Marshal(params)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  paramsJSON,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server.handleRequest(ctx, &request)

	outputStr := output.String()
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")

	// Check for progress notifications
	for _, line := range lines {
		var notif JSONRPCNotification
		if err := json.Unmarshal([]byte(line), &notif); err == nil {
			if notif.Method == "notifications/progress" {
				// Verify notification structure
				if notif.JSONRPC != "2.0" {
					t.Errorf("Expected jsonrpc 2.0 in notification, got %s", notif.JSONRPC)
				}

				paramsMap, ok := notif.Params.(map[string]interface{})
				if !ok {
					t.Fatal("Notification params should be a map")
				}

				// Verify required fields
				if _, ok := paramsMap["phase"]; !ok {
					t.Error("Progress notification should have phase field")
				}
				if _, ok := paramsMap["completed"]; !ok {
					t.Error("Progress notification should have completed field")
				}
				if _, ok := paramsMap["total"]; !ok {
					t.Error("Progress notification should have total field")
				}
				if _, ok := paramsMap["message"]; !ok {
					t.Error("Progress notification should have message field")
				}
			}
		}
	}
}

// TestMCPServerIntegration_MultipleRequests tests handling multiple sequential requests
func TestMCPServerIntegration_MultipleRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html></html>"))
	}))
	defer backend.Close()

	// Build input with multiple requests
	var inputBuf bytes.Buffer
	writer := bufio.NewWriter(&inputBuf)

	// Request 1: Initialize
	initReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}
	initJSON, _ := json.Marshal(initReq)
	writer.Write(initJSON)
	writer.Write([]byte("\n"))

	// Request 2: Tools list
	listReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	listJSON, _ := json.Marshal(listReq)
	writer.Write(listJSON)
	writer.Write([]byte("\n"))

	// Request 3: Scan
	args := map[string]interface{}{
		"target": backend.URL,
	}
	argsJSON, _ := json.Marshal(args)
	params := map[string]interface{}{
		"name":      "wast_scan",
		"arguments": json.RawMessage(argsJSON),
	}
	paramsJSON, _ := json.Marshal(params)

	scanReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params:  paramsJSON,
	}
	scanJSON, _ := json.Marshal(scanReq)
	writer.Write(scanJSON)
	writer.Write([]byte("\n"))

	writer.Flush()

	output := &bytes.Buffer{}

	server := NewServer()
	server.reader = &inputBuf
	server.writer = output

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run server to process all requests
	go func() {
		time.Sleep(20 * time.Second)
		cancel() // Stop server after processing
	}()

	err := server.Run(ctx)
	if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		t.Errorf("Server Run failed: %v", err)
	}

	// Verify we got multiple responses
	outputStr := output.String()
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")

	responseCount := 0
	for _, line := range lines {
		var response JSONRPCResponse
		if err := json.Unmarshal([]byte(line), &response); err == nil {
			if response.ID != nil {
				responseCount++
			}
		}
	}

	if responseCount < 3 {
		t.Errorf("Expected at least 3 responses, got %d", responseCount)
	}
}

// TestMCPServerIntegration_ResponseFormat tests AI agent response format consistency
func TestMCPServerIntegration_ResponseFormat(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html></html>"))
	}))
	defer backend.Close()

	toolTests := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{
			name: "recon",
			tool: "wast_recon",
			args: map[string]interface{}{
				"target":  "example.com",
				"timeout": "5s",
			},
		},
		{
			name: "scan",
			tool: "wast_scan",
			args: map[string]interface{}{
				"target": backend.URL,
			},
		},
		{
			name: "headers",
			tool: "wast_headers",
			args: map[string]interface{}{
				"target": backend.URL,
			},
		},
	}

	for _, tt := range toolTests {
		t.Run(tt.name, func(t *testing.T) {
			input := bytes.NewBuffer(nil)
			output := &bytes.Buffer{}

			server := NewServer()
			server.reader = input
			server.writer = output

			argsJSON, _ := json.Marshal(tt.args)
			params := map[string]interface{}{
				"name":      tt.tool,
				"arguments": json.RawMessage(argsJSON),
			}
			paramsJSON, _ := json.Marshal(params)

			request := JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      fmt.Sprintf("%s-test", tt.name),
				Method:  "tools/call",
				Params:  paramsJSON,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			server.handleRequest(ctx, &request)

			outputStr := output.String()
			lines := strings.Split(strings.TrimSpace(outputStr), "\n")

			// Find response
			var response JSONRPCResponse
			for i := len(lines) - 1; i >= 0; i-- {
				if err := json.Unmarshal([]byte(lines[i]), &response); err == nil {
					if response.ID != nil {
						break
					}
				}
			}

			// Verify consistent response structure for AI agents
			if response.JSONRPC != "2.0" {
				t.Error("Response must include JSON-RPC version")
			}

			if response.ID == nil {
				t.Error("Response must include request ID")
			}

			if response.Result == nil && response.Error == nil {
				t.Error("Response must include either result or error")
			}

			// If successful, verify content structure
			if response.Result != nil {
				resultMap, ok := response.Result.(map[string]interface{})
				if !ok {
					t.Fatal("Result should be a map")
				}

				content, ok := resultMap["content"]
				if !ok {
					t.Error("Result must have content field")
				}

				contentArray, ok := content.([]interface{})
				if !ok {
					t.Error("Content must be an array")
				}

				if len(contentArray) == 0 {
					t.Error("Content array should not be empty")
				}

				// Verify first content item structure
				firstItem := contentArray[0].(map[string]interface{})
				if firstItem["type"] != "text" {
					t.Error("Content item must have type 'text'")
				}

				text, ok := firstItem["text"].(string)
				if !ok || text == "" {
					t.Error("Content item must have non-empty text field")
				}

				// Verify text is valid JSON
				var parsedResult interface{}
				if err := json.Unmarshal([]byte(text), &parsedResult); err != nil {
					t.Errorf("Content text must be valid JSON: %v", err)
				}
			}
		})
	}
}
