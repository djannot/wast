package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	server := NewServer()
	if server == nil {
		t.Fatal("NewServer() returned nil")
	}

	// Verify tools are registered
	expectedTools := []string{"wast_recon", "wast_scan", "wast_crawl", "wast_api"}
	for _, toolName := range expectedTools {
		if _, ok := server.tools[toolName]; !ok {
			t.Errorf("Expected tool %s to be registered", toolName)
		}
	}
}

func TestToolsListRequest(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	server.handleRequest(context.Background(), &request)

	// Parse response
	var response JSONRPCResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify response
	if response.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc 2.0, got %s", response.JSONRPC)
	}
	// ID could be int or float64 after JSON unmarshaling
	if idFloat, ok := response.ID.(float64); !ok || idFloat != 1.0 {
		if idInt, ok := response.ID.(int); !ok || idInt != 1 {
			t.Errorf("Expected id 1, got %v (type %T)", response.ID, response.ID)
		}
	}
	if response.Error != nil {
		t.Errorf("Unexpected error: %v", response.Error)
	}

	// Verify tools are listed
	resultMap, ok := response.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Result is not a map")
	}
	toolsList, ok := resultMap["tools"].([]interface{})
	if !ok {
		t.Fatal("Tools is not a list")
	}
	if len(toolsList) != 4 {
		t.Errorf("Expected 4 tools, got %d", len(toolsList))
	}
}

func TestInitializeRequest(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}

	server.handleRequest(context.Background(), &request)

	// Parse response
	var response JSONRPCResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify response structure
	if response.Error != nil {
		t.Errorf("Unexpected error: %v", response.Error)
	}

	resultMap, ok := response.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Result is not a map")
	}

	// Check for required fields
	if _, ok := resultMap["protocolVersion"]; !ok {
		t.Error("Missing protocolVersion in initialize response")
	}
	if _, ok := resultMap["serverInfo"]; !ok {
		t.Error("Missing serverInfo in initialize response")
	}
	if _, ok := resultMap["capabilities"]; !ok {
		t.Error("Missing capabilities in initialize response")
	}
}

func TestInvalidJSONRPCVersion(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	request := JSONRPCRequest{
		JSONRPC: "1.0",
		ID:      1,
		Method:  "tools/list",
	}

	server.handleRequest(context.Background(), &request)

	// Parse response
	var response JSONRPCResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should return error
	if response.Error == nil {
		t.Error("Expected error for invalid JSON-RPC version")
	}
	if response.Error.Code != -32600 {
		t.Errorf("Expected error code -32600, got %d", response.Error.Code)
	}
}

func TestUnknownMethod(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "unknown/method",
	}

	server.handleRequest(context.Background(), &request)

	// Parse response
	var response JSONRPCResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should return method not found error
	if response.Error == nil {
		t.Error("Expected error for unknown method")
	}
	if response.Error.Code != -32601 {
		t.Errorf("Expected error code -32601, got %d", response.Error.Code)
	}
}

func TestReconToolSchema(t *testing.T) {
	tool := &ReconTool{}

	if tool.Name() != "wast_recon" {
		t.Errorf("Expected name wast_recon, got %s", tool.Name())
	}

	if tool.Description() == "" {
		t.Error("Description should not be empty")
	}

	schema := tool.InputSchema()
	if schema == nil {
		t.Fatal("Schema should not be nil")
	}

	// Verify required field
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	if _, ok := props["target"]; !ok {
		t.Error("Schema should have target property")
	}

	required, ok := schema["required"].([]string)
	if !ok {
		t.Fatal("required should be a string array")
	}

	if len(required) != 1 || required[0] != "target" {
		t.Error("target should be required")
	}
}

func TestScanToolSchema(t *testing.T) {
	tool := &ScanTool{}

	if tool.Name() != "wast_scan" {
		t.Errorf("Expected name wast_scan, got %s", tool.Name())
	}

	schema := tool.InputSchema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	// Verify active flag exists and defaults to false
	if active, ok := props["active"].(map[string]interface{}); ok {
		if defaultVal, ok := active["default"].(bool); !ok || defaultVal != false {
			t.Error("active flag should default to false for safe mode")
		}
	} else {
		t.Error("Schema should have active property")
	}
}

func TestCrawlToolSchema(t *testing.T) {
	tool := &CrawlTool{}

	if tool.Name() != "wast_crawl" {
		t.Errorf("Expected name wast_crawl, got %s", tool.Name())
	}

	schema := tool.InputSchema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	// Verify respect_robots flag exists and defaults to true
	if respectRobots, ok := props["respect_robots"].(map[string]interface{}); ok {
		if defaultVal, ok := respectRobots["default"].(bool); !ok || defaultVal != true {
			t.Error("respect_robots should default to true")
		}
	} else {
		t.Error("Schema should have respect_robots property")
	}
}

func TestAPIToolSchema(t *testing.T) {
	tool := &APITool{}

	if tool.Name() != "wast_api" {
		t.Errorf("Expected name wast_api, got %s", tool.Name())
	}

	schema := tool.InputSchema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	// Verify both target and spec_file are available
	if _, ok := props["target"]; !ok {
		t.Error("Schema should have target property")
	}
	if _, ok := props["spec_file"]; !ok {
		t.Error("Schema should have spec_file property")
	}
}

func TestToolsCallWithUnknownTool(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	params := map[string]interface{}{
		"name":      "unknown_tool",
		"arguments": map[string]interface{}{},
	}
	paramsJSON, _ := json.Marshal(params)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  paramsJSON,
	}

	server.handleRequest(context.Background(), &request)

	// Parse response
	var response JSONRPCResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should return error
	if response.Error == nil {
		t.Error("Expected error for unknown tool")
	}
	if response.Error.Code != -32602 {
		t.Errorf("Expected error code -32602, got %d", response.Error.Code)
	}
}

func TestReconToolExecuteMissingTarget(t *testing.T) {
	tool := &ReconTool{}

	args := map[string]interface{}{}
	argsJSON, _ := json.Marshal(args)

	ctx := context.Background()
	_, err := tool.Execute(ctx, argsJSON)

	if err == nil {
		t.Error("Expected error when target is missing")
	}
	if !strings.Contains(err.Error(), "target") {
		t.Errorf("Error should mention target, got: %v", err)
	}
}

func TestScanToolExecuteMissingTarget(t *testing.T) {
	tool := &ScanTool{}

	args := map[string]interface{}{}
	argsJSON, _ := json.Marshal(args)

	ctx := context.Background()
	_, err := tool.Execute(ctx, argsJSON)

	if err == nil {
		t.Error("Expected error when target is missing")
	}
	if !strings.Contains(err.Error(), "target") {
		t.Errorf("Error should mention target, got: %v", err)
	}
}

func TestCrawlToolExecuteMissingTarget(t *testing.T) {
	tool := &CrawlTool{}

	args := map[string]interface{}{}
	argsJSON, _ := json.Marshal(args)

	ctx := context.Background()
	_, err := tool.Execute(ctx, argsJSON)

	if err == nil {
		t.Error("Expected error when target is missing")
	}
	if !strings.Contains(err.Error(), "target") {
		t.Errorf("Error should mention target, got: %v", err)
	}
}

func TestAPIToolExecuteMissingBoth(t *testing.T) {
	tool := &APITool{}

	args := map[string]interface{}{}
	argsJSON, _ := json.Marshal(args)

	ctx := context.Background()
	_, err := tool.Execute(ctx, argsJSON)

	if err == nil {
		t.Error("Expected error when both target and spec_file are missing")
	}
}

func TestReconToolExecuteWithInvalidTimeout(t *testing.T) {
	tool := &ReconTool{}

	args := map[string]interface{}{
		"target":  "example.com",
		"timeout": "invalid",
	}
	argsJSON, _ := json.Marshal(args)

	ctx := context.Background()
	_, err := tool.Execute(ctx, argsJSON)

	if err == nil {
		t.Error("Expected error for invalid timeout")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("Error should mention timeout, got: %v", err)
	}
}

func TestCrawlToolExecuteWithInvalidTimeout(t *testing.T) {
	tool := &CrawlTool{}

	args := map[string]interface{}{
		"target":  "https://example.com",
		"timeout": "invalid",
	}
	argsJSON, _ := json.Marshal(args)

	ctx := context.Background()
	_, err := tool.Execute(ctx, argsJSON)

	if err == nil {
		t.Error("Expected error for invalid timeout")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("Error should mention timeout, got: %v", err)
	}
}

func TestServerRunWithContext(t *testing.T) {
	server := NewServer()

	// Create a context that's already canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Use empty reader
	server.reader = strings.NewReader("")

	var output bytes.Buffer
	server.writer = &output

	// Should return context.Canceled error
	err := server.Run(ctx)
	if err != nil && err != context.Canceled {
		t.Logf("Run returned: %v", err)
	}
}

func TestFormatToolResult(t *testing.T) {
	result := map[string]interface{}{
		"target": "example.com",
		"status": "success",
	}

	formatted := formatToolResult(result)

	if !strings.Contains(formatted, "example.com") {
		t.Error("Formatted result should contain the target")
	}
	if !strings.Contains(formatted, "success") {
		t.Error("Formatted result should contain the status")
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(formatted), &parsed); err != nil {
		t.Errorf("Formatted result should be valid JSON: %v", err)
	}
}

func TestReconToolExecuteDefaults(t *testing.T) {
	tool := &ReconTool{}

	args := map[string]interface{}{
		"target": "example.com",
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify result structure
	reconResult, ok := result.(ReconResult)
	if !ok {
		t.Fatal("Result should be a ReconResult")
	}

	if reconResult.Target != "example.com" {
		t.Errorf("Expected target example.com, got %s", reconResult.Target)
	}
}
