package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/scanner"
)

func TestNewServer(t *testing.T) {
	server := NewServer()
	if server == nil {
		t.Fatal("NewServer() returned nil")
	}

	// Verify tools are registered
	expectedTools := []string{"wast_recon", "wast_scan", "wast_crawl", "wast_api", "wast_intercept", "wast_headers", "wast_verify"}
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
	if len(toolsList) != 7 {
		t.Errorf("Expected 7 tools, got %d", len(toolsList))
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
	server := NewServer()
	tool := &ReconTool{server: server}

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
	server := NewServer()
	tool := &ScanTool{server: server}

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
	server := NewServer()
	tool := &CrawlTool{server: server}

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
	server := NewServer()
	tool := &APITool{server: server}

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
	server := NewServer()
	tool := &ReconTool{server: server}

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
	server := NewServer()
	tool := &ScanTool{server: server}

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
	server := NewServer()
	tool := &CrawlTool{server: server}

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
	server := NewServer()
	tool := &APITool{server: server}

	args := map[string]interface{}{}
	argsJSON, _ := json.Marshal(args)

	ctx := context.Background()
	_, err := tool.Execute(ctx, argsJSON)

	if err == nil {
		t.Error("Expected error when both target and spec_file are missing")
	}
}

func TestReconToolExecuteWithInvalidTimeout(t *testing.T) {
	server := NewServer()
	tool := &ReconTool{server: server}

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
	server := NewServer()
	tool := &CrawlTool{server: server}

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
	server := NewServer()
	tool := &ReconTool{server: server}

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

func TestScanToolWithAuthParameters(t *testing.T) {
	server := NewServer()
	tool := &ScanTool{server: server}

	// Verify schema includes auth parameters
	schema := tool.InputSchema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	authParams := []string{"bearer_token", "basic_auth", "auth_header", "cookies"}
	for _, param := range authParams {
		if _, ok := props[param]; !ok {
			t.Errorf("Schema should have %s property", param)
		}
	}

	// Test execution with auth parameters
	args := map[string]interface{}{
		"target":       "https://example.com",
		"bearer_token": "test-token-123",
		"basic_auth":   "user:pass",
		"cookies":      []string{"session=abc123", "user_id=456"},
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tool.Execute(ctx, argsJSON)
	// We expect this to succeed (even if the target is unreachable)
	// The important part is that it doesn't fail during parsing
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should parse auth parameters correctly: %v", err)
	}
}

func TestCrawlToolWithAuthParameters(t *testing.T) {
	server := NewServer()
	tool := &CrawlTool{server: server}

	// Verify schema includes auth parameters
	schema := tool.InputSchema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	authParams := []string{"bearer_token", "basic_auth", "auth_header", "cookies"}
	for _, param := range authParams {
		if _, ok := props[param]; !ok {
			t.Errorf("Schema should have %s property", param)
		}
	}

	// Test execution with auth parameters
	args := map[string]interface{}{
		"target":      "https://example.com",
		"auth_header": "X-API-Key: secret-key-789",
		"cookies":     []string{"token=xyz789"},
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tool.Execute(ctx, argsJSON)
	// We expect this to succeed (even if the target is unreachable)
	// The important part is that it doesn't fail during parsing
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should parse auth parameters correctly: %v", err)
	}
}

func TestAPIToolWithAuthParameters(t *testing.T) {
	server := NewServer()
	tool := &APITool{server: server}

	// Verify schema includes auth parameters
	schema := tool.InputSchema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	authParams := []string{"bearer_token", "basic_auth", "auth_header", "cookies"}
	for _, param := range authParams {
		if _, ok := props[param]; !ok {
			t.Errorf("Schema should have %s property", param)
		}
	}

	// Test execution with auth parameters
	args := map[string]interface{}{
		"target":       "https://api.example.com",
		"bearer_token": "Bearer xyz-123-abc",
		"cookies":      []string{"api_session=def456"},
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tool.Execute(ctx, argsJSON)
	// We expect this to succeed (even if the target is unreachable)
	// The important part is that it doesn't fail during parsing
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should parse auth parameters correctly: %v", err)
	}
}

func TestScanToolAuthConfigConstruction(t *testing.T) {
	server := NewServer()
	tool := &ScanTool{server: server}

	args := map[string]interface{}{
		"target":       "https://example.com",
		"bearer_token": "test-token",
		"basic_auth":   "admin:secret",
		"auth_header":  "X-Custom-Auth: value123",
		"cookies":      []string{"session=abc", "user=john"},
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The Execute method should construct AuthConfig properly
	// This test verifies the arguments are parsed correctly
	_, err := tool.Execute(ctx, argsJSON)
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should handle all auth parameters: %v", err)
	}
}

func TestCrawlToolAuthConfigConstruction(t *testing.T) {
	server := NewServer()
	tool := &CrawlTool{server: server}

	args := map[string]interface{}{
		"target":      "https://example.com",
		"basic_auth":  "user:password",
		"auth_header": "Authorization: Custom xyz",
		"cookies":     []string{"token=abc123"},
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The Execute method should construct AuthConfig properly
	_, err := tool.Execute(ctx, argsJSON)
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should handle all auth parameters: %v", err)
	}
}

func TestAPIToolAuthConfigConstruction(t *testing.T) {
	server := NewServer()
	tool := &APITool{server: server}

	args := map[string]interface{}{
		"target":       "https://api.example.com",
		"bearer_token": "my-api-token",
		"cookies":      []string{"api_key=secret"},
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The Execute method should construct AuthConfig properly
	_, err := tool.Execute(ctx, argsJSON)
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should handle all auth parameters: %v", err)
	}
}

func TestInterceptToolSchema(t *testing.T) {
	server := NewServer()
	tool := &InterceptTool{server: server}

	if tool.Name() != "wast_intercept" {
		t.Errorf("Expected name wast_intercept, got %s", tool.Name())
	}

	if tool.Description() == "" {
		t.Error("Description should not be empty")
	}

	schema := tool.InputSchema()
	if schema == nil {
		t.Fatal("Schema should not be nil")
	}

	// Verify properties
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	// Check for expected properties
	expectedProps := []string{"port", "duration", "save_file", "https_interception", "max_requests"}
	for _, prop := range expectedProps {
		if _, ok := props[prop]; !ok {
			t.Errorf("Schema should have %s property", prop)
		}
	}

	// Verify port default
	if portProp, ok := props["port"].(map[string]interface{}); ok {
		if defaultVal, ok := portProp["default"].(int); !ok || defaultVal != 8080 {
			t.Error("port should default to 8080")
		}
	}

	// Verify duration default
	if durationProp, ok := props["duration"].(map[string]interface{}); ok {
		if defaultVal, ok := durationProp["default"].(string); !ok || defaultVal != "60s" {
			t.Error("duration should default to 60s")
		}
	}

	// Verify https_interception default
	if httpsProp, ok := props["https_interception"].(map[string]interface{}); ok {
		if defaultVal, ok := httpsProp["default"].(bool); !ok || defaultVal != false {
			t.Error("https_interception should default to false")
		}
	}
}

func TestInterceptToolExecuteDefaults(t *testing.T) {
	server := NewServer()
	tool := &InterceptTool{server: server}

	// Test with minimal arguments (should use defaults)
	args := map[string]interface{}{}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// This will start a proxy for 60s by default, but we'll cancel after 2s
	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// The result could be either a ProxyResult or an error map
	// Let's verify it's not nil
	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestInterceptToolExecuteCustomPort(t *testing.T) {
	server := NewServer()
	tool := &InterceptTool{server: server}

	args := map[string]interface{}{
		"port":     9090,
		"duration": "1s",
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestInterceptToolExecuteInvalidDuration(t *testing.T) {
	server := NewServer()
	tool := &InterceptTool{server: server}

	args := map[string]interface{}{
		"duration": "invalid-duration",
	}
	argsJSON, _ := json.Marshal(args)

	ctx := context.Background()
	_, err := tool.Execute(ctx, argsJSON)

	if err == nil {
		t.Error("Expected error for invalid duration")
	}
	if !strings.Contains(err.Error(), "duration") {
		t.Errorf("Error should mention duration, got: %v", err)
	}
}

func TestInterceptToolExecuteWithSaveFile(t *testing.T) {
	server := NewServer()
	tool := &InterceptTool{server: server}

	args := map[string]interface{}{
		"port":      9091,
		"duration":  "1s",
		"save_file": "/tmp/test_traffic.json",
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestInterceptToolExecuteWithMaxRequests(t *testing.T) {
	server := NewServer()
	tool := &InterceptTool{server: server}

	args := map[string]interface{}{
		"port":         9092,
		"duration":     "30s",
		"max_requests": 10,
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestInterceptToolExecuteInvalidJSON(t *testing.T) {
	server := NewServer()
	tool := &InterceptTool{server: server}

	invalidJSON := []byte(`{"port": "not-a-number"}`)

	ctx := context.Background()
	_, err := tool.Execute(ctx, invalidJSON)

	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Error should mention invalid arguments, got: %v", err)
	}
}

func TestInterceptToolSchemaProperties(t *testing.T) {
	server := NewServer()
	tool := &InterceptTool{server: server}
	schema := tool.InputSchema()

	// Verify schema structure
	if schemaType, ok := schema["type"].(string); !ok || schemaType != "object" {
		t.Error("Schema type should be 'object'")
	}

	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	// Test port property
	if portProp, ok := props["port"].(map[string]interface{}); ok {
		if portType, ok := portProp["type"].(string); !ok || portType != "integer" {
			t.Error("port type should be 'integer'")
		}
		if desc, ok := portProp["description"].(string); !ok || desc == "" {
			t.Error("port should have a description")
		}
	} else {
		t.Error("Schema should have port property")
	}

	// Test duration property
	if durationProp, ok := props["duration"].(map[string]interface{}); ok {
		if durationType, ok := durationProp["type"].(string); !ok || durationType != "string" {
			t.Error("duration type should be 'string'")
		}
	} else {
		t.Error("Schema should have duration property")
	}

	// Test save_file property
	if saveFileProp, ok := props["save_file"].(map[string]interface{}); ok {
		if saveFileType, ok := saveFileProp["type"].(string); !ok || saveFileType != "string" {
			t.Error("save_file type should be 'string'")
		}
	} else {
		t.Error("Schema should have save_file property")
	}

	// Test https_interception property
	if httpsProp, ok := props["https_interception"].(map[string]interface{}); ok {
		if httpsType, ok := httpsProp["type"].(string); !ok || httpsType != "boolean" {
			t.Error("https_interception type should be 'boolean'")
		}
	} else {
		t.Error("Schema should have https_interception property")
	}

	// Test max_requests property
	if maxReqProp, ok := props["max_requests"].(map[string]interface{}); ok {
		if maxReqType, ok := maxReqProp["type"].(string); !ok || maxReqType != "integer" {
			t.Error("max_requests type should be 'integer'")
		}
	} else {
		t.Error("Schema should have max_requests property")
	}
}

func TestScanToolRateLimitingSchema(t *testing.T) {
	server := NewServer()
	tool := &ScanTool{server: server}
	schema := tool.InputSchema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	// Verify requests_per_second exists and defaults to 0
	if rpsParam, ok := props["requests_per_second"].(map[string]interface{}); ok {
		if rpsType, ok := rpsParam["type"].(string); !ok || rpsType != "number" {
			t.Error("requests_per_second type should be 'number'")
		}
		if defaultVal, ok := rpsParam["default"].(int); !ok || defaultVal != 0 {
			t.Error("requests_per_second should default to 0")
		}
		if desc, ok := rpsParam["description"].(string); !ok || desc == "" {
			t.Error("requests_per_second should have a description")
		}
	} else {
		t.Error("Schema should have requests_per_second property")
	}
}

func TestCrawlToolRateLimitingSchema(t *testing.T) {
	server := NewServer()
	tool := &CrawlTool{server: server}
	schema := tool.InputSchema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	// Verify requests_per_second exists and defaults to 0
	if rpsParam, ok := props["requests_per_second"].(map[string]interface{}); ok {
		if rpsType, ok := rpsParam["type"].(string); !ok || rpsType != "number" {
			t.Error("requests_per_second type should be 'number'")
		}
		if defaultVal, ok := rpsParam["default"].(int); !ok || defaultVal != 0 {
			t.Error("requests_per_second should default to 0")
		}
		if desc, ok := rpsParam["description"].(string); !ok || desc == "" {
			t.Error("requests_per_second should have a description")
		}
	} else {
		t.Error("Schema should have requests_per_second property")
	}
}

func TestAPIToolRateLimitingSchema(t *testing.T) {
	server := NewServer()
	tool := &APITool{server: server}
	schema := tool.InputSchema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	// Verify requests_per_second exists and defaults to 0
	if rpsParam, ok := props["requests_per_second"].(map[string]interface{}); ok {
		if rpsType, ok := rpsParam["type"].(string); !ok || rpsType != "number" {
			t.Error("requests_per_second type should be 'number'")
		}
		if defaultVal, ok := rpsParam["default"].(int); !ok || defaultVal != 0 {
			t.Error("requests_per_second should default to 0")
		}
		if desc, ok := rpsParam["description"].(string); !ok || desc == "" {
			t.Error("requests_per_second should have a description")
		}
	} else {
		t.Error("Schema should have requests_per_second property")
	}
}

func TestScanToolWithRateLimitParameter(t *testing.T) {
	server := NewServer()
	tool := &ScanTool{server: server}

	// Test execution with rate limiting parameter
	args := map[string]interface{}{
		"target":              "https://example.com",
		"requests_per_second": 5.0,
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tool.Execute(ctx, argsJSON)
	// We expect this to succeed (even if the target is unreachable)
	// The important part is that it doesn't fail during parsing
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should parse requests_per_second parameter correctly: %v", err)
	}
}

func TestCrawlToolWithRateLimitParameter(t *testing.T) {
	server := NewServer()
	tool := &CrawlTool{server: server}

	// Test execution with rate limiting parameter
	args := map[string]interface{}{
		"target":              "https://example.com",
		"requests_per_second": 2.5,
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tool.Execute(ctx, argsJSON)
	// We expect this to succeed (even if the target is unreachable)
	// The important part is that it doesn't fail during parsing
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should parse requests_per_second parameter correctly: %v", err)
	}
}

func TestAPIToolWithRateLimitParameter(t *testing.T) {
	server := NewServer()
	tool := &APITool{server: server}

	// Test execution with rate limiting parameter
	args := map[string]interface{}{
		"target":              "https://api.example.com",
		"requests_per_second": 10.0,
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tool.Execute(ctx, argsJSON)
	// We expect this to succeed (even if the target is unreachable)
	// The important part is that it doesn't fail during parsing
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should parse requests_per_second parameter correctly: %v", err)
	}
}

func TestScanToolRateLimitingDefault(t *testing.T) {
	server := NewServer()
	tool := &ScanTool{server: server}

	// Test execution without rate limiting parameter (should default to 0)
	args := map[string]interface{}{
		"target": "https://example.com",
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tool.Execute(ctx, argsJSON)
	// Should work fine with default rate limiting (no rate limit)
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should work with default rate limiting: %v", err)
	}
}

func TestCrawlToolRateLimitingDefault(t *testing.T) {
	server := NewServer()
	tool := &CrawlTool{server: server}

	// Test execution without rate limiting parameter (should default to 0)
	args := map[string]interface{}{
		"target": "https://example.com",
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tool.Execute(ctx, argsJSON)
	// Should work fine with default rate limiting (no rate limit)
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should work with default rate limiting: %v", err)
	}
}

func TestAPIToolRateLimitingDefault(t *testing.T) {
	server := NewServer()
	tool := &APITool{server: server}

	// Test execution without rate limiting parameter (should default to 0)
	args := map[string]interface{}{
		"target": "https://api.example.com",
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tool.Execute(ctx, argsJSON)
	// Should work fine with default rate limiting (no rate limit)
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should work with default rate limiting: %v", err)
	}
}

// TestServerRunWithMalformedJSON tests handling of malformed JSON requests
func TestServerRunWithMalformedJSON(t *testing.T) {
	server := NewServer()

	malformedInputs := []string{
		`{"jsonrpc": "2.0", "id": 1, "method": "initialize"`,    // Missing closing brace
		`{"jsonrpc": "2.0", "id": 1, "method": initialize}`,     // Unquoted value
		`{"jsonrpc": "2.0", "id": 1, "method": "initialize", }`, // Trailing comma
		`not-json-at-all`, // Not JSON
		`{"jsonrpc": "2.0", "id": null, "method": "initialize"}`,        // Null ID (valid JSON-RPC but edge case)
		`{"jsonrpc": "2.0", "id": "string-id", "method": "initialize"}`, // String ID (valid)
	}

	for _, input := range malformedInputs {
		t.Run("malformed_"+input[:min(len(input), 20)], func(t *testing.T) {
			var output bytes.Buffer
			server.reader = strings.NewReader(input + "\n")
			server.writer = &output

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			// Run the server
			err := server.Run(ctx)

			// Should return without error (malformed JSON should be handled gracefully)
			if err != nil && err != context.DeadlineExceeded {
				t.Logf("Run returned error: %v (may be expected)", err)
			}

			// For truly malformed JSON, we should see a parse error response
			outputStr := output.String()
			if !strings.Contains(input, "null") && !strings.Contains(input, "string-id") {
				if !strings.Contains(outputStr, "Parse error") && !strings.Contains(outputStr, "error") {
					t.Logf("Expected error response for malformed JSON, got: %s", outputStr)
				}
			}
		})
	}
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestServerRunWithMultipleRequests tests processing multiple sequential requests
func TestServerRunWithMultipleRequests(t *testing.T) {
	server := NewServer()

	requests := `{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"initialize"}
`

	var output bytes.Buffer
	server.reader = strings.NewReader(requests)
	server.writer = &output

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := server.Run(ctx)
	if err != nil && err != context.DeadlineExceeded {
		t.Logf("Run returned error: %v", err)
	}

	// Should have received multiple responses
	outputStr := output.String()
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")

	if len(lines) < 3 {
		t.Errorf("Expected at least 3 response lines, got %d", len(lines))
	}

	// Verify each response is valid JSON
	for i, line := range lines {
		if line == "" {
			continue
		}
		var resp JSONRPCResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Errorf("Response %d is not valid JSON: %v", i, err)
		}
	}
}

// TestServerRunWithEmptyLines tests handling of empty lines
func TestServerRunWithEmptyLines(t *testing.T) {
	server := NewServer()

	requests := `
{"jsonrpc":"2.0","id":1,"method":"initialize"}

{"jsonrpc":"2.0","id":2,"method":"tools/list"}

`

	var output bytes.Buffer
	server.reader = strings.NewReader(requests)
	server.writer = &output

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := server.Run(ctx)
	if err != nil && err != context.DeadlineExceeded {
		t.Logf("Run returned error: %v", err)
	}

	// Should have processed valid requests and ignored empty lines
	outputStr := output.String()
	if !strings.Contains(outputStr, "jsonrpc") {
		t.Error("Expected at least one valid response")
	}
}

// TestHandleToolsCallSuccess tests successful tool execution
func TestHandleToolsCallSuccess(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	// Test with recon tool (minimal execution)
	params := map[string]interface{}{
		"name": "wast_recon",
		"arguments": map[string]interface{}{
			"target":  "example.com",
			"timeout": "1s",
		},
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

	// Output may contain multiple JSON objects (notifications + response)
	// Find the last line which should be the response
	outputStr := output.String()
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")
	if len(lines) == 0 {
		t.Fatal("No output received")
	}

	// Parse the last line as the response
	var response JSONRPCResponse
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &response); err != nil {
		t.Fatalf("Failed to parse response: %v (output: %s)", err, outputStr)
	}

	// Should return success
	if response.Error != nil {
		t.Errorf("Expected success, got error: %v", response.Error)
	}

	// Result should have content field
	if response.Result == nil {
		t.Error("Result should not be nil")
	}

	resultMap, ok := response.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Result should be a map")
	}

	if _, ok := resultMap["content"]; !ok {
		t.Error("Result should have content field")
	}
}

// TestFormatToolResultWithComplexTypes tests formatToolResult with various data types
func TestFormatToolResultWithComplexTypes(t *testing.T) {
	tests := []struct {
		name   string
		input  interface{}
		verify func(string) bool
	}{
		{
			name: "nested map",
			input: map[string]interface{}{
				"outer": map[string]interface{}{
					"inner": "value",
				},
			},
			verify: func(s string) bool {
				return strings.Contains(s, "outer") && strings.Contains(s, "inner")
			},
		},
		{
			name: "array of objects",
			input: []map[string]interface{}{
				{"id": 1, "name": "first"},
				{"id": 2, "name": "second"},
			},
			verify: func(s string) bool {
				return strings.Contains(s, "first") && strings.Contains(s, "second")
			},
		},
		{
			name:  "nil value",
			input: nil,
			verify: func(s string) bool {
				return s == "null"
			},
		},
		{
			name:  "string value",
			input: "simple string",
			verify: func(s string) bool {
				return strings.Contains(s, "simple string")
			},
		},
		{
			name:  "numeric value",
			input: 42,
			verify: func(s string) bool {
				return strings.Contains(s, "42")
			},
		},
		{
			name:  "boolean value",
			input: true,
			verify: func(s string) bool {
				return strings.Contains(s, "true")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatToolResult(tt.input)

			if result == "" {
				t.Error("formatToolResult should not return empty string")
			}

			if !tt.verify(result) {
				t.Errorf("formatToolResult output doesn't match expectations: %s", result)
			}

			// Verify output is valid JSON
			var parsed interface{}
			if err := json.Unmarshal([]byte(result), &parsed); err != nil {
				t.Errorf("formatToolResult should return valid JSON: %v", err)
			}
		})
	}
}

// TestSendResponseWithMarshalError tests sendResponse error handling
func TestSendResponseWithMarshalError(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	// Create a value that can't be marshaled (channels can't be marshaled to JSON)
	ch := make(chan int)
	defer close(ch)

	server.sendResponse(1, ch)

	// Should have received a fallback error response
	outputStr := output.String()
	if !strings.Contains(outputStr, "error") {
		t.Error("Expected error response for unmarshalable result")
	}

	if !strings.Contains(outputStr, "Internal error") {
		t.Error("Expected 'Internal error' in fallback response")
	}
}

// TestSendErrorWithMarshalError tests sendError error handling
func TestSendErrorWithMarshalError(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	// Create a value that can't be marshaled
	ch := make(chan int)
	defer close(ch)

	server.sendError(1, -32603, "Test error", ch)

	// Should have received a fallback error response
	outputStr := output.String()
	if !strings.Contains(outputStr, "error") {
		t.Error("Expected error response")
	}
}

// TestSendErrorWithComplexData tests sendError with various data types
func TestSendErrorWithComplexData(t *testing.T) {
	tests := []struct {
		name string
		id   interface{}
		code int
		msg  string
		data interface{}
	}{
		{
			name: "error with string data",
			id:   1,
			code: -32602,
			msg:  "Invalid params",
			data: "parameter 'x' is required",
		},
		{
			name: "error with map data",
			id:   2,
			code: -32603,
			msg:  "Internal error",
			data: map[string]interface{}{"details": "database connection failed"},
		},
		{
			name: "error with array data",
			id:   3,
			code: -32602,
			msg:  "Invalid params",
			data: []string{"param1", "param2"},
		},
		{
			name: "error with nil data",
			id:   4,
			code: -32601,
			msg:  "Method not found",
			data: nil,
		},
		{
			name: "error with null id",
			id:   nil,
			code: -32700,
			msg:  "Parse error",
			data: "invalid JSON",
		},
		{
			name: "error with string id",
			id:   "request-abc-123",
			code: -32600,
			msg:  "Invalid Request",
			data: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer()

			var output bytes.Buffer
			server.writer = &output

			server.sendError(tt.id, tt.code, tt.msg, tt.data)

			// Parse response
			var response JSONRPCResponse
			if err := json.Unmarshal(output.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse error response: %v", err)
			}

			// Verify error is present
			if response.Error == nil {
				t.Fatal("Error should not be nil")
			}

			if response.Error.Code != tt.code {
				t.Errorf("Expected error code %d, got %d", tt.code, response.Error.Code)
			}

			if response.Error.Message != tt.msg {
				t.Errorf("Expected error message %s, got %s", tt.msg, response.Error.Message)
			}

			// Verify ID matches
			if tt.id == nil && response.ID != nil {
				t.Errorf("Expected nil ID, got %v", response.ID)
			}
		})
	}
}

// TestToolsCallWithInvalidParams tests tools/call with invalid parameters
func TestToolsCallWithInvalidParams(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	// Invalid JSON in params
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "wast_scan"`), // Invalid JSON
	}

	server.handleRequest(context.Background(), &request)

	// Parse response
	var response JSONRPCResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should return error
	if response.Error == nil {
		t.Error("Expected error for invalid params JSON")
	}
	if response.Error.Code != -32602 {
		t.Errorf("Expected error code -32602, got %d", response.Error.Code)
	}
}

// TestHandleRequestWithContextCancellation tests request handling with canceled context
func TestHandleRequestWithContextCancellation(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	// Create already-canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}

	// Should still handle the request even with canceled context
	server.handleRequest(ctx, &request)

	// Should have a response
	if output.Len() == 0 {
		t.Error("Expected a response even with canceled context")
	}
}

// TestServerConcurrentRequests tests handling multiple concurrent requests
func TestServerConcurrentRequests(t *testing.T) {
	numRequests := 10
	done := make(chan bool, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(id int) {
			// Create a new server instance for each goroutine to avoid writer conflicts
			server := NewServer()
			var output bytes.Buffer
			server.writer = &output

			request := JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      id,
				Method:  "initialize",
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			server.handleRequest(ctx, &request)

			// Verify we got a response
			var response JSONRPCResponse
			if err := json.Unmarshal(output.Bytes(), &response); err != nil {
				t.Errorf("Request %d: Failed to parse response: %v", id, err)
			}

			done <- true
		}(i)
	}

	// Wait for all requests to complete
	timeout := time.After(10 * time.Second)
	for i := 0; i < numRequests; i++ {
		select {
		case <-done:
			// Success
		case <-timeout:
			t.Fatal("Timeout waiting for concurrent requests to complete")
		}
	}
}

// TestReconToolExecuteWithSubdomains tests recon with subdomain discovery
func TestReconToolExecuteWithSubdomains(t *testing.T) {
	server := NewServer()
	tool := &ReconTool{server: server}

	args := map[string]interface{}{
		"target":             "example.com",
		"timeout":            "5s",
		"include_subdomains": true,
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	// DNS result should be present
	if reconResult.DNS == nil {
		t.Error("DNS result should not be nil")
	}
}

// TestScanToolTimeoutDefault tests scan tool timeout default handling
func TestScanToolTimeoutDefault(t *testing.T) {
	server := NewServer()
	tool := &ScanTool{server: server}

	args := map[string]interface{}{
		"target":  "https://example.com",
		"timeout": -1, // Invalid timeout, should use default
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Should succeed with default timeout
	scanResult, ok := result.(*scanner.UnifiedScanResult)
	if !ok {
		t.Fatal("Result should be a *scanner.UnifiedScanResult")
	}

	if scanResult.Target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", scanResult.Target)
	}
}

// TestCrawlToolDepthDefault tests crawl tool depth default handling
func TestCrawlToolDepthDefault(t *testing.T) {
	server := NewServer()
	tool := &CrawlTool{server: server}

	args := map[string]interface{}{
		"target": "https://example.com",
		"depth":  0, // Should use default depth of 3
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Should succeed with default depth
	if result == nil {
		t.Error("Result should not be nil")
	}
}

// TestAPIToolWithSpecFile tests API tool with spec file
func TestAPIToolWithSpecFile(t *testing.T) {
	server := NewServer()
	tool := &APITool{server: server}

	args := map[string]interface{}{
		"spec_file": "/nonexistent/spec.yaml",
		"dry_run":   true,
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Should return a result (likely an error map due to nonexistent file)
	if result == nil {
		t.Error("Result should not be nil")
	}

	// Check if it's an error result
	resultMap, ok := result.(map[string]interface{})
	if ok {
		if _, hasError := resultMap["error"]; hasError {
			// Expected for nonexistent file
			t.Log("Received expected error for nonexistent spec file")
		}
	}
}

// TestAPIToolTimeoutDefault tests API tool timeout default handling
func TestAPIToolTimeoutDefault(t *testing.T) {
	server := NewServer()
	tool := &APITool{server: server}

	args := map[string]interface{}{
		"target":  "https://api.example.com",
		"timeout": -5, // Invalid timeout, should use default
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Should succeed with default timeout
	if result == nil {
		t.Error("Result should not be nil")
	}
}

// TestInterceptToolWithHTTPSAndSaveFile tests intercept with both HTTPS and save file
func TestInterceptToolWithHTTPSAndSaveFile(t *testing.T) {
	server := NewServer()
	tool := &InterceptTool{server: server}

	args := map[string]interface{}{
		"port":               9100,
		"duration":           "1s",
		"save_file":          "/tmp/https_intercept_test.json",
		"https_interception": true,
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result == nil {
		t.Error("Result should not be nil")
	}
}

// TestInterceptToolPortDefault tests intercept port default handling
func TestInterceptToolPortDefault(t *testing.T) {
	server := NewServer()
	tool := &InterceptTool{server: server}

	args := map[string]interface{}{
		"port":     -1, // Invalid port, should use default
		"duration": "1s",
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Should succeed with default port
	if result == nil {
		t.Error("Result should not be nil")
	}
}

// TestInterceptToolDurationDefault tests intercept duration default handling
func TestInterceptToolDurationDefault(t *testing.T) {
	server := NewServer()
	tool := &InterceptTool{server: server}

	args := map[string]interface{}{
		"port":     9101,
		"duration": "", // Empty duration, should use default
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Should succeed with default duration
	if result == nil {
		t.Error("Result should not be nil")
	}
}

// TestHeadersToolSchema tests the HeadersTool schema validation
func TestHeadersToolSchema(t *testing.T) {
	server := NewServer()
	tool := &HeadersTool{server: server}

	// Test tool name
	if tool.Name() != "wast_headers" {
		t.Errorf("Expected name wast_headers, got %s", tool.Name())
	}

	// Test description is non-empty
	if tool.Description() == "" {
		t.Error("Description should not be empty")
	}

	schema := tool.InputSchema()
	if schema == nil {
		t.Fatal("Schema should not be nil")
	}

	// Verify required properties
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	// Verify target property exists
	if _, ok := props["target"]; !ok {
		t.Error("Schema should have target property")
	}

	// Verify timeout property exists
	if timeoutProp, ok := props["timeout"].(map[string]interface{}); ok {
		if defaultVal, ok := timeoutProp["default"].(int); !ok || defaultVal != 30 {
			t.Error("timeout should default to 30")
		}
	} else {
		t.Error("Schema should have timeout property")
	}

	// Verify bearer_token property exists
	if _, ok := props["bearer_token"]; !ok {
		t.Error("Schema should have bearer_token property")
	}

	// Verify basic_auth property exists
	if _, ok := props["basic_auth"]; !ok {
		t.Error("Schema should have basic_auth property")
	}

	// Verify auth_header property exists
	if _, ok := props["auth_header"]; !ok {
		t.Error("Schema should have auth_header property")
	}

	// Verify cookies property exists
	if _, ok := props["cookies"]; !ok {
		t.Error("Schema should have cookies property")
	}

	// Verify requests_per_second property exists
	if rpsProp, ok := props["requests_per_second"].(map[string]interface{}); ok {
		if defaultVal, ok := rpsProp["default"].(int); !ok || defaultVal != 0 {
			t.Error("requests_per_second should default to 0")
		}
	} else {
		t.Error("Schema should have requests_per_second property")
	}

	// Verify target is required
	required, ok := schema["required"].([]string)
	if !ok {
		t.Fatal("required should be a string array")
	}

	if len(required) != 1 || required[0] != "target" {
		t.Error("target should be required")
	}
}

// TestHeadersToolExecuteMissingTarget tests error handling when target is missing
func TestHeadersToolExecuteMissingTarget(t *testing.T) {
	server := NewServer()
	tool := &HeadersTool{server: server}

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

// TestHeadersToolExecuteDefaults tests execution with minimal arguments
func TestHeadersToolExecuteDefaults(t *testing.T) {
	server := NewServer()
	tool := &HeadersTool{server: server}

	args := map[string]interface{}{
		"target": "https://example.com",
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify result is not nil
	if result == nil {
		t.Error("Result should not be nil")
	}
}

// TestHeadersToolWithAuthParameters tests auth parameters parsing
func TestHeadersToolWithAuthParameters(t *testing.T) {
	server := NewServer()
	tool := &HeadersTool{server: server}

	// Verify schema includes auth parameters
	schema := tool.InputSchema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	authParams := []string{"bearer_token", "basic_auth", "auth_header", "cookies"}
	for _, param := range authParams {
		if _, ok := props[param]; !ok {
			t.Errorf("Schema should have %s property", param)
		}
	}

	// Test execution with auth parameters
	args := map[string]interface{}{
		"target":       "https://example.com",
		"bearer_token": "test-token-123",
		"basic_auth":   "user:pass",
		"cookies":      []string{"session=abc123", "user_id=456"},
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tool.Execute(ctx, argsJSON)
	// We expect this to succeed (even if the target is unreachable)
	// The important part is that it doesn't fail during parsing
	if err != nil && strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("Execute should parse auth parameters correctly: %v", err)
	}
}

// TestHeadersToolRateLimitingSchema tests rate limiting schema properties
func TestHeadersToolRateLimitingSchema(t *testing.T) {
	server := NewServer()
	tool := &HeadersTool{server: server}
	schema := tool.InputSchema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	// Verify requests_per_second exists and defaults to 0
	if rpsParam, ok := props["requests_per_second"].(map[string]interface{}); ok {
		if rpsType, ok := rpsParam["type"].(string); !ok || rpsType != "number" {
			t.Error("requests_per_second type should be 'number'")
		}
		if defaultVal, ok := rpsParam["default"].(int); !ok || defaultVal != 0 {
			t.Error("requests_per_second should default to 0")
		}
		if desc, ok := rpsParam["description"].(string); !ok || desc == "" {
			t.Error("requests_per_second should have a description")
		}
	} else {
		t.Error("Schema should have requests_per_second property")
	}
}

// TestHeadersToolTimeoutDefault tests timeout default handling
func TestHeadersToolTimeoutDefault(t *testing.T) {
	server := NewServer()
	tool := &HeadersTool{server: server}

	args := map[string]interface{}{
		"target":  "https://example.com",
		"timeout": -1, // Invalid timeout, should use default of 30
	}
	argsJSON, _ := json.Marshal(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := tool.Execute(ctx, argsJSON)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Should succeed with default timeout
	if result == nil {
		t.Error("Result should not be nil")
	}
}

// TestSendProgress tests the sendProgress method
func TestSendProgress(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	// Send a progress notification
	server.sendProgress("crawling", 5, 10, "crawling: visited 5 pages")

	// Parse the notification
	var notif JSONRPCNotification
	if err := json.Unmarshal(output.Bytes(), &notif); err != nil {
		t.Fatalf("Failed to parse notification: %v", err)
	}

	// Verify notification structure
	if notif.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc 2.0, got %s", notif.JSONRPC)
	}
	if notif.Method != "notifications/progress" {
		t.Errorf("Expected method notifications/progress, got %s", notif.Method)
	}

	// Verify progress params
	paramsMap, ok := notif.Params.(map[string]interface{})
	if !ok {
		t.Fatal("Params should be a map")
	}

	if phase, ok := paramsMap["phase"].(string); !ok || phase != "crawling" {
		t.Errorf("Expected phase crawling, got %v", paramsMap["phase"])
	}
	if completed, ok := paramsMap["completed"].(float64); !ok || int(completed) != 5 {
		t.Errorf("Expected completed 5, got %v", paramsMap["completed"])
	}
	if total, ok := paramsMap["total"].(float64); !ok || int(total) != 10 {
		t.Errorf("Expected total 10, got %v", paramsMap["total"])
	}
	if message, ok := paramsMap["message"].(string); !ok || message != "crawling: visited 5 pages" {
		t.Errorf("Expected message 'crawling: visited 5 pages', got %v", paramsMap["message"])
	}
}

// TestSendNotification tests the sendNotification method
func TestSendNotification(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	// Send a custom notification
	params := map[string]interface{}{
		"status": "running",
		"phase":  "scanning",
	}
	server.sendNotification("custom/notification", params)

	// Parse the notification
	var notif JSONRPCNotification
	if err := json.Unmarshal(output.Bytes(), &notif); err != nil {
		t.Fatalf("Failed to parse notification: %v", err)
	}

	// Verify notification structure
	if notif.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc 2.0, got %s", notif.JSONRPC)
	}
	if notif.Method != "custom/notification" {
		t.Errorf("Expected method custom/notification, got %s", notif.Method)
	}

	// Verify params
	paramsMap, ok := notif.Params.(map[string]interface{})
	if !ok {
		t.Fatal("Params should be a map")
	}
	if status, ok := paramsMap["status"].(string); !ok || status != "running" {
		t.Errorf("Expected status running, got %v", paramsMap["status"])
	}
}

// TestConcurrentProgressNotifications tests thread-safety of progress notifications
func TestConcurrentProgressNotifications(t *testing.T) {
	server := NewServer()

	var output bytes.Buffer
	server.writer = &output

	numNotifications := 20
	done := make(chan bool, numNotifications)

	// Send multiple progress notifications concurrently
	for i := 0; i < numNotifications; i++ {
		go func(n int) {
			server.sendProgress("test", n, numNotifications, fmt.Sprintf("progress %d", n))
			done <- true
		}(i)
	}

	// Wait for all notifications
	timeout := time.After(5 * time.Second)
	for i := 0; i < numNotifications; i++ {
		select {
		case <-done:
			// Success
		case <-timeout:
			t.Fatal("Timeout waiting for concurrent notifications")
		}
	}

	// Verify we got notifications (should have multiple JSON objects in output)
	outputStr := output.String()
	if outputStr == "" {
		t.Error("Should have received notifications")
	}

	// Count number of notifications
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")
	if len(lines) != numNotifications {
		t.Errorf("Expected %d notifications, got %d", numNotifications, len(lines))
	}
}

func TestVerifyToolSchema(t *testing.T) {
	server := NewServer()
	tool := &VerifyTool{server: server}

	if tool.Name() != "wast_verify" {
		t.Errorf("Expected name wast_verify, got %s", tool.Name())
	}

	if tool.Description() == "" {
		t.Error("Description should not be empty")
	}

	schema := tool.InputSchema()
	if schema == nil {
		t.Fatal("Schema should not be nil")
	}

	// Verify required fields
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("properties should be a map")
	}

	requiredFields := []string{"finding_type", "finding_url", "parameter", "payload"}
	for _, field := range requiredFields {
		if _, ok := props[field]; !ok {
			t.Errorf("Schema should have %s property", field)
		}
	}

	required, ok := schema["required"].([]string)
	if !ok {
		t.Fatal("required should be a string array")
	}

	if len(required) != 4 {
		t.Errorf("Expected 4 required fields, got %d", len(required))
	}

	// Verify finding_type has enum constraint
	findingType, ok := props["finding_type"].(map[string]interface{})
	if !ok {
		t.Fatal("finding_type should be a map")
	}

	enum, ok := findingType["enum"].([]string)
	if !ok {
		t.Fatal("finding_type should have enum constraint")
	}

	expectedTypes := []string{"sqli", "xss", "ssrf", "cmdi", "pathtraversal", "redirect", "csrf"}
	if len(enum) != len(expectedTypes) {
		t.Errorf("Expected %d finding types in enum, got %d", len(expectedTypes), len(enum))
	}
}

func TestVerifyToolValidation(t *testing.T) {
	server := NewServer()
	tool := &VerifyTool{server: server}

	tests := []struct {
		name        string
		params      map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name: "missing finding_type",
			params: map[string]interface{}{
				"finding_url": "http://example.com/test",
				"parameter":   "id",
				"payload":     "' OR '1'='1",
			},
			expectError: true,
			errorMsg:    "finding_type is required",
		},
		{
			name: "missing finding_url",
			params: map[string]interface{}{
				"finding_type": "sqli",
				"parameter":    "id",
				"payload":      "' OR '1'='1",
			},
			expectError: true,
			errorMsg:    "finding_url is required",
		},
		{
			name: "missing parameter",
			params: map[string]interface{}{
				"finding_type": "sqli",
				"finding_url":  "http://example.com/test",
				"payload":      "' OR '1'='1",
			},
			expectError: true,
			errorMsg:    "parameter is required",
		},
		{
			name: "missing payload",
			params: map[string]interface{}{
				"finding_type": "sqli",
				"finding_url":  "http://example.com/test",
				"parameter":    "id",
			},
			expectError: true,
			errorMsg:    "payload is required",
		},
		{
			name: "invalid finding_type",
			params: map[string]interface{}{
				"finding_type": "invalid_type",
				"finding_url":  "http://example.com/test",
				"parameter":    "id",
				"payload":      "test",
			},
			expectError: true,
			errorMsg:    "invalid finding_type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramsJSON, err := json.Marshal(tt.params)
			if err != nil {
				t.Fatalf("Failed to marshal params: %v", err)
			}

			_, err = tool.Execute(context.Background(), paramsJSON)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got no error", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
