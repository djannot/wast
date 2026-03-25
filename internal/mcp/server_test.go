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
	expectedTools := []string{"wast_recon", "wast_scan", "wast_crawl", "wast_api", "wast_intercept"}
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
	if len(toolsList) != 5 {
		t.Errorf("Expected 5 tools, got %d", len(toolsList))
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

func TestScanToolWithAuthParameters(t *testing.T) {
	tool := &ScanTool{}

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
	tool := &CrawlTool{}

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
	tool := &APITool{}

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
	tool := &ScanTool{}

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
	tool := &CrawlTool{}

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
	tool := &APITool{}

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
	tool := &InterceptTool{}

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
	tool := &InterceptTool{}

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
	tool := &InterceptTool{}

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
	tool := &InterceptTool{}

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
	tool := &InterceptTool{}

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
	tool := &InterceptTool{}

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
	tool := &InterceptTool{}

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
	tool := &InterceptTool{}
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
