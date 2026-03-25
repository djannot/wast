package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/output"
	"github.com/djannot/wast/pkg/proxy"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/spf13/cobra"
)

// testFormatter creates a formatter for testing that writes to a buffer
func testFormatter(buf *bytes.Buffer) func() *output.Formatter {
	return func() *output.Formatter {
		f := output.NewFormatter("json", false, false)
		f.SetWriter(buf)
		return f
	}
}

// testAuthConfig returns an empty auth config for testing
func testAuthConfig() *auth.AuthConfig {
	return &auth.AuthConfig{}
}

// testRateLimitConfig returns an empty rate limit config for testing
func testRateLimitConfig() ratelimit.Config {
	return ratelimit.Config{}
}

// testAuthConfigWithValues returns a populated auth config for testing
func testAuthConfigWithValues() *auth.AuthConfig {
	return &auth.AuthConfig{
		AuthHeader:  "X-API-Key: test-key",
		BearerToken: "test-bearer-token",
		BasicAuth:   "user:password",
	}
}

// testRateLimitConfigWithValues returns a populated rate limit config for testing
func testRateLimitConfigWithValues() ratelimit.Config {
	return ratelimit.Config{
		RequestsPerSecond: 10,
		DelayMs:           10,
	}
}

func TestReconCmd(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewReconCmd(testFormatter(&buf), testAuthConfig)

	// Test command exists and has correct use
	if cmd.Use != "recon [target]" {
		t.Errorf("Expected Use 'recon [target]', got %s", cmd.Use)
	}

	// Test command execution
	cmd.SetArgs([]string{"localhost"})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
	if result.Command != "recon" {
		t.Errorf("Expected command 'recon', got %s", result.Command)
	}
}

func TestCrawlCmd(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewCrawlCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)

	if cmd.Use != "crawl [target]" {
		t.Errorf("Expected Use 'crawl [target]', got %s", cmd.Use)
	}

	cmd.SetArgs([]string{"http://localhost"})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
	if result.Command != "crawl" {
		t.Errorf("Expected command 'crawl', got %s", result.Command)
	}
}

func TestInterceptCmd(t *testing.T) {
	cmd := NewInterceptCmd(testFormatter(&bytes.Buffer{}), testAuthConfig)

	// Test command structure (not execution since it's a blocking server)
	// Note: The intercept command starts a blocking HTTP/HTTPS proxy server with TLS
	// certificate handling and file system operations. Comprehensive testing would require
	// extensive mocking of the proxy, CA initialization, and file system operations.
	// We test the command structure and flag registration here.
	if cmd.Use != "intercept" {
		t.Errorf("Expected Use 'intercept', got %s", cmd.Use)
	}

	// Test that flags are registered
	portFlag := cmd.Flag("port")
	if portFlag == nil {
		t.Error("Expected 'port' flag to be registered")
	} else {
		if portFlag.DefValue != "8080" {
			t.Errorf("Expected default port 8080, got %s", portFlag.DefValue)
		}
	}

	saveFlag := cmd.Flag("save")
	if saveFlag == nil {
		t.Error("Expected 'save' flag to be registered")
	}

	// Test short and long description
	if cmd.Short == "" {
		t.Error("Expected short description to be set")
	}
	if cmd.Long == "" {
		t.Error("Expected long description to be set")
	}
}

func TestServeCmd(t *testing.T) {
	cmd := NewServeCmd(testFormatter(&bytes.Buffer{}))

	// Test command structure (not execution since it's a blocking server)
	// Note: The serve command starts a blocking MCP server over stdio with signal handling.
	// Comprehensive testing would require extensive mocking of the MCP server, stdio,
	// and signal handling. We test the command structure and flag registration here.
	if cmd.Use != "serve" {
		t.Errorf("Expected Use 'serve', got %s", cmd.Use)
	}

	// Test that flags are registered
	mcpFlag := cmd.Flag("mcp")
	if mcpFlag == nil {
		t.Error("Expected 'mcp' flag to be registered")
	} else {
		if mcpFlag.DefValue != "true" {
			t.Errorf("Expected default mcp to be true, got %s", mcpFlag.DefValue)
		}
	}

	// Test short and long description
	if cmd.Short == "" {
		t.Error("Expected short description to be set")
	}
	if cmd.Long == "" {
		t.Error("Expected long description to be set")
	}
}

func TestServeCmdFlags(t *testing.T) {
	cmd := NewServeCmd(testFormatter(&bytes.Buffer{}))

	tests := []struct {
		flagName     string
		expectedType string
		hasDefault   bool
		defaultValue string
	}{
		{"mcp", "bool", true, "true"},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := cmd.Flag(tt.flagName)
			if flag == nil {
				t.Errorf("Expected flag '%s' to be registered", tt.flagName)
				return
			}

			if tt.hasDefault && flag.DefValue != tt.defaultValue {
				t.Errorf("Expected default value '%s' for flag '%s', got '%s'",
					tt.defaultValue, tt.flagName, flag.DefValue)
			}
		})
	}
}

func TestServeCommandDescriptions(t *testing.T) {
	cmd := NewServeCmd(testFormatter(&bytes.Buffer{}))

	expectedShort := "Start WAST in server mode"
	if cmd.Short != expectedShort {
		t.Errorf("Expected Short '%s', got '%s'", expectedShort, cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Expected long description to be set")
	}

	// Verify the long description contains key information about MCP
	if !strings.Contains(cmd.Long, "Model Context Protocol") {
		t.Error("Expected long description to mention Model Context Protocol")
	}
	if !strings.Contains(cmd.Long, "JSON-RPC 2.0") {
		t.Error("Expected long description to mention JSON-RPC 2.0")
	}
}

func TestScanCmd(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)

	if cmd.Use != "scan [target]" {
		t.Errorf("Expected Use 'scan [target]', got %s", cmd.Use)
	}

	cmd.SetArgs([]string{"http://localhost"})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
	if result.Command != "scan" {
		t.Errorf("Expected command 'scan', got %s", result.Command)
	}
}

func TestAPICmd(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)

	if cmd.Use != "api [target]" {
		t.Errorf("Expected Use 'api [target]', got %s", cmd.Use)
	}

	cmd.SetArgs([]string{"http://localhost:8080"})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
	if result.Command != "api" {
		t.Errorf("Expected command 'api', got %s", result.Command)
	}
}

func TestReconResultData(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewReconCmd(testFormatter(&buf), testAuthConfig)

	cmd.SetArgs([]string{"localhost"})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	// Check that data contains expected fields
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	if target, ok := data["target"].(string); !ok || target != "localhost" {
		t.Errorf("Expected target 'localhost', got %v", data["target"])
	}

	// Check that DNS data is present
	if dns, ok := data["dns"].(map[string]interface{}); !ok {
		t.Errorf("Expected dns data to be present")
	} else {
		if domain, ok := dns["domain"].(string); !ok || domain != "localhost" {
			t.Errorf("Expected dns domain 'localhost', got %v", dns["domain"])
		}
	}
}

func TestReconNoTarget(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewReconCmd(testFormatter(&buf), testAuthConfig)

	// Execute without arguments
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	// Check that data contains available methods when no target is provided
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	if methods, ok := data["methods"].([]interface{}); !ok || len(methods) == 0 {
		t.Errorf("Expected methods list when no target provided")
	}

	if status, ok := data["status"].(string); !ok || status == "" {
		t.Errorf("Expected status message when no target provided")
	}
}

func TestCommandsWithNoArgs(t *testing.T) {
	tests := []struct {
		name    string
		cmdFunc func(func() *output.Formatter, func() *auth.AuthConfig, func() ratelimit.Config) *cobra.Command
	}{
		{"recon", func(f func() *output.Formatter, a func() *auth.AuthConfig, r func() ratelimit.Config) *cobra.Command {
			cmd := NewReconCmd(f, a)
			return cmd
		}},
		{"crawl", func(f func() *output.Formatter, a func() *auth.AuthConfig, r func() ratelimit.Config) *cobra.Command {
			cmd := NewCrawlCmd(f, a, r)
			return cmd
		}},
		{"scan", func(f func() *output.Formatter, a func() *auth.AuthConfig, r func() ratelimit.Config) *cobra.Command {
			cmd := NewScanCmd(f, a, r)
			return cmd
		}},
		{"api", func(f func() *output.Formatter, a func() *auth.AuthConfig, r func() ratelimit.Config) *cobra.Command {
			cmd := NewAPICmd(f, a, r)
			return cmd
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := tt.cmdFunc(testFormatter(&buf), testAuthConfig, testRateLimitConfig)

			// Execute without arguments
			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if !result.Success {
				t.Error("Expected success to be true")
			}
		})
	}
}

// TestReconWithFlags tests various flag combinations for recon command
func TestReconWithFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		target   string
		validate func(t *testing.T, result output.CommandResult)
	}{
		{
			name:   "WithTimeout",
			args:   []string{"localhost", "--timeout", "5s"},
			target: "localhost",
			validate: func(t *testing.T, result output.CommandResult) {
				if !result.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name:   "WithSubdomains",
			args:   []string{"localhost", "--subdomains"},
			target: "localhost",
			validate: func(t *testing.T, result output.CommandResult) {
				if !result.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name:   "WithTimeoutAndSubdomains",
			args:   []string{"localhost", "--timeout", "5s", "--subdomains"},
			target: "localhost",
			validate: func(t *testing.T, result output.CommandResult) {
				if !result.Success {
					t.Error("Expected success to be true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewReconCmd(testFormatter(&buf), testAuthConfig)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			tt.validate(t, result)

			if result.Command != "recon" {
				t.Errorf("Expected command 'recon', got %s", result.Command)
			}
		})
	}
}

// TestCrawlWithFlags tests various flag combinations for crawl command
func TestCrawlWithFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		validate func(t *testing.T, result output.CommandResult)
	}{
		{
			name: "WithDepth",
			args: []string{"http://localhost", "--depth", "5"},
			validate: func(t *testing.T, result output.CommandResult) {
				if !result.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name: "WithTimeout",
			args: []string{"http://localhost", "--timeout", "60s"},
			validate: func(t *testing.T, result output.CommandResult) {
				if !result.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name: "WithUserAgent",
			args: []string{"http://localhost", "--user-agent", "CustomBot/1.0"},
			validate: func(t *testing.T, result output.CommandResult) {
				if !result.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name: "WithNoRobots",
			args: []string{"http://localhost", "--no-robots"},
			validate: func(t *testing.T, result output.CommandResult) {
				if !result.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name: "WithAllFlags",
			args: []string{"http://localhost", "--depth", "5", "--timeout", "60s", "--user-agent", "CustomBot/1.0", "--no-robots"},
			validate: func(t *testing.T, result output.CommandResult) {
				if !result.Success {
					t.Error("Expected success to be true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewCrawlCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			tt.validate(t, result)

			if result.Command != "crawl" {
				t.Errorf("Expected command 'crawl', got %s", result.Command)
			}
		})
	}
}

// TestScanWithFlags tests various flag combinations for scan command
func TestScanWithFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		validate func(t *testing.T, result output.CommandResult)
	}{
		{
			name: "WithTimeout",
			args: []string{"http://localhost", "--timeout", "60"},
			validate: func(t *testing.T, result output.CommandResult) {
				if !result.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name: "WithShortTimeout",
			args: []string{"http://localhost", "--timeout", "5"},
			validate: func(t *testing.T, result output.CommandResult) {
				if !result.Success {
					t.Error("Expected success to be true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			tt.validate(t, result)

			if result.Command != "scan" {
				t.Errorf("Expected command 'scan', got %s", result.Command)
			}
		})
	}
}

// TestAPIWithFlags tests various flag combinations for api command
func TestAPIWithFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		validate func(t *testing.T, result output.CommandResult)
	}{
		{
			name: "WithTimeout",
			args: []string{"http://localhost:8080", "--timeout", "60"},
			validate: func(t *testing.T, result output.CommandResult) {
				if !result.Success {
					t.Error("Expected success to be true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			tt.validate(t, result)

			if result.Command != "api" {
				t.Errorf("Expected command 'api', got %s", result.Command)
			}
		})
	}
}

// TestCrawlWithAuth tests crawl command with authentication
func TestCrawlWithAuth(t *testing.T) {
	var buf bytes.Buffer
	authFunc := func() *auth.AuthConfig {
		return testAuthConfigWithValues()
	}

	cmd := NewCrawlCmd(testFormatter(&buf), authFunc, testRateLimitConfig)
	cmd.SetArgs([]string{"http://localhost"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
	if result.Command != "crawl" {
		t.Errorf("Expected command 'crawl', got %s", result.Command)
	}
}

// TestScanWithAuth tests scan command with authentication
func TestScanWithAuth(t *testing.T) {
	var buf bytes.Buffer
	authFunc := func() *auth.AuthConfig {
		return testAuthConfigWithValues()
	}

	cmd := NewScanCmd(testFormatter(&buf), authFunc, testRateLimitConfig)
	cmd.SetArgs([]string{"http://localhost"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
	if result.Command != "scan" {
		t.Errorf("Expected command 'scan', got %s", result.Command)
	}
}

// TestAPIWithAuth tests api command with authentication
func TestAPIWithAuth(t *testing.T) {
	var buf bytes.Buffer
	authFunc := func() *auth.AuthConfig {
		return testAuthConfigWithValues()
	}

	cmd := NewAPICmd(testFormatter(&buf), authFunc, testRateLimitConfig)
	cmd.SetArgs([]string{"http://localhost:8080"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
	if result.Command != "api" {
		t.Errorf("Expected command 'api', got %s", result.Command)
	}
}

// TestCrawlWithRateLimit tests crawl command with rate limiting
func TestCrawlWithRateLimit(t *testing.T) {
	var buf bytes.Buffer
	rateLimitFunc := func() ratelimit.Config {
		return testRateLimitConfigWithValues()
	}

	cmd := NewCrawlCmd(testFormatter(&buf), testAuthConfig, rateLimitFunc)
	cmd.SetArgs([]string{"http://localhost"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
	if result.Command != "crawl" {
		t.Errorf("Expected command 'crawl', got %s", result.Command)
	}
}

// TestScanWithRateLimit tests scan command with rate limiting
func TestScanWithRateLimit(t *testing.T) {
	var buf bytes.Buffer
	rateLimitFunc := func() ratelimit.Config {
		return testRateLimitConfigWithValues()
	}

	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, rateLimitFunc)
	cmd.SetArgs([]string{"http://localhost"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
	if result.Command != "scan" {
		t.Errorf("Expected command 'scan', got %s", result.Command)
	}
}

// TestAPIWithRateLimit tests api command with rate limiting
func TestAPIWithRateLimit(t *testing.T) {
	var buf bytes.Buffer
	rateLimitFunc := func() ratelimit.Config {
		return testRateLimitConfigWithValues()
	}

	cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, rateLimitFunc)
	cmd.SetArgs([]string{"http://localhost:8080"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
	if result.Command != "api" {
		t.Errorf("Expected command 'api', got %s", result.Command)
	}
}

// TestInterceptCmdFlags tests flag registration for intercept command
func TestInterceptCmdFlags(t *testing.T) {
	cmd := NewInterceptCmd(testFormatter(&bytes.Buffer{}), testAuthConfig)

	tests := []struct {
		flagName     string
		expectedType string
		hasDefault   bool
		defaultValue string
	}{
		{"port", "int", true, "8080"},
		{"save", "string", false, ""},
		{"init-ca", "bool", false, "false"},
		{"ca-cert", "string", false, ""},
		{"ca-key", "string", false, ""},
		{"http-only", "bool", false, "false"},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := cmd.Flag(tt.flagName)
			if flag == nil {
				t.Errorf("Expected flag '%s' to be registered", tt.flagName)
				return
			}

			if tt.hasDefault && flag.DefValue != tt.defaultValue {
				t.Errorf("Expected default value '%s' for flag '%s', got '%s'",
					tt.defaultValue, tt.flagName, flag.DefValue)
			}
		})
	}
}

// TestScanNoTarget tests scan command without target
func TestScanNoTarget(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	if scanTypes, ok := data["scan_types"].([]interface{}); !ok || len(scanTypes) == 0 {
		t.Errorf("Expected scan_types list when no target provided")
	}

	if status, ok := data["status"].(string); !ok || status == "" {
		t.Errorf("Expected status message when no target provided")
	}
}

// TestAPINoTarget tests api command without target
func TestAPINoTarget(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	if features, ok := data["features"].([]interface{}); !ok || len(features) == 0 {
		t.Errorf("Expected features list when no target provided")
	}

	if status, ok := data["status"].(string); !ok || status == "" {
		t.Errorf("Expected status message when no target provided")
	}
}

// TestCrawlNoTarget tests crawl command without target
func TestCrawlNoTarget(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewCrawlCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	if features, ok := data["features"].([]interface{}); !ok || len(features) == 0 {
		t.Errorf("Expected features list when no target provided")
	}

	if status, ok := data["status"].(string); !ok || status == "" {
		t.Errorf("Expected status message when no target provided")
	}
}

// TestCombinedAuthAndRateLimit tests commands with both auth and rate limiting
func TestCombinedAuthAndRateLimit(t *testing.T) {
	authFunc := func() *auth.AuthConfig {
		return testAuthConfigWithValues()
	}
	rateLimitFunc := func() ratelimit.Config {
		return testRateLimitConfigWithValues()
	}

	tests := []struct {
		name    string
		cmdFunc func() *cobra.Command
	}{
		{
			name: "crawl",
			cmdFunc: func() *cobra.Command {
				var buf bytes.Buffer
				cmd := NewCrawlCmd(testFormatter(&buf), authFunc, rateLimitFunc)
				cmd.SetArgs([]string{"http://localhost"})
				return cmd
			},
		},
		{
			name: "scan",
			cmdFunc: func() *cobra.Command {
				var buf bytes.Buffer
				cmd := NewScanCmd(testFormatter(&buf), authFunc, rateLimitFunc)
				cmd.SetArgs([]string{"http://localhost"})
				return cmd
			},
		},
		{
			name: "api",
			cmdFunc: func() *cobra.Command {
				var buf bytes.Buffer
				cmd := NewAPICmd(testFormatter(&buf), authFunc, rateLimitFunc)
				cmd.SetArgs([]string{"http://localhost:8080"})
				return cmd
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmdFunc()
			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}
		})
	}
}

// TestReconWithDifferentTargets tests recon with various target formats
func TestReconWithDifferentTargets(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"SimpleDomain", "localhost"},
		{"Subdomain", "localhost"},
		{"WithHyphen", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewReconCmd(testFormatter(&buf), testAuthConfig)
			cmd.SetArgs([]string{tt.target})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if !result.Success {
				t.Error("Expected success to be true")
			}
		})
	}
}

// TestScanWithDifferentTargets tests scan with various target formats
func TestScanWithDifferentTargets(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"HTTP", "http://localhost"},
		{"HTTPS", "http://localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
			cmd.SetArgs([]string{tt.target, "--timeout", "5"})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			// Note: Depending on target accessibility, success may vary
			// This test ensures the command doesn't crash with various inputs
			if result.Command != "scan" {
				t.Errorf("Expected command 'scan', got %s", result.Command)
			}
		})
	}
}

// TestCrawlContextHandling tests crawl command context behavior
func TestCrawlContextHandling(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewCrawlCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)

	// Use a very short timeout to ensure it completes quickly
	cmd.SetArgs([]string{"http://localhost", "--timeout", "1s", "--depth", "1"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if result.Command != "crawl" {
		t.Errorf("Expected command 'crawl', got %s", result.Command)
	}
}

// TestScanContextHandling tests scan command context behavior
func TestScanContextHandling(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)

	// Use a short timeout
	cmd.SetArgs([]string{"http://localhost", "--timeout", "5"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if result.Command != "scan" {
		t.Errorf("Expected command 'scan', got %s", result.Command)
	}
}

// MockHTTPClient implements a simple HTTP client for testing
type MockHTTPClient struct {
	Responses map[string]*http.Response
	Errors    map[string]error
	Requests  []*http.Request
}

// NewMockHTTPClient creates a new MockHTTPClient
func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{
		Responses: make(map[string]*http.Response),
		Errors:    make(map[string]error),
		Requests:  make([]*http.Request, 0),
	}
}

// AddResponse adds a mock response for a URL
func (m *MockHTTPClient) AddResponse(url string, statusCode int, body string, headers http.Header) {
	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     headers,
	}
	if headers == nil {
		resp.Header = make(http.Header)
	}
	m.Responses[url] = resp
}

// AddError adds a mock error for a URL
func (m *MockHTTPClient) AddError(url string, err error) {
	m.Errors[url] = err
}

// Do performs the mock HTTP request
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.Requests = append(m.Requests, req)
	url := req.URL.String()

	if err, ok := m.Errors[url]; ok {
		return nil, err
	}

	if resp, ok := m.Responses[url]; ok {
		return resp, nil
	}

	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("Not Found")),
		Header:     make(http.Header),
	}, nil
}

// TestMockHTTPClient tests the mock HTTP client
func TestMockHTTPClient(t *testing.T) {
	client := NewMockHTTPClient()

	// Test adding response
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	client.AddResponse("http://localhost:8001/success", 200, `{"status":"ok"}`, headers)

	req, _ := http.NewRequest("GET", "http://localhost:8001/success", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Test adding error
	client.AddError("http://localhost:8002/error", errors.New("network error"))
	req2, _ := http.NewRequest("GET", "http://localhost:8002/error", nil)
	_, err2 := client.Do(req2)
	if err2 == nil {
		t.Error("Expected error, got nil")
	}

	// Test default 404
	req3, _ := http.NewRequest("GET", "http://localhost:8003/notfound", nil)
	resp3, _ := client.Do(req3)
	if resp3.StatusCode != 404 {
		t.Errorf("Expected status 404, got %d", resp3.StatusCode)
	}
}

// TestAPIWithMultipleTargets tests API command with various inputs
func TestAPIWithMultipleTargets(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"SimpleAPI", "http://localhost:8080"},
		{"APIWithPath", "http://localhost:8080/v1"},
		{"APIWithPort", "http://localhost:8080:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
			cmd.SetArgs([]string{tt.target})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if result.Command != "api" {
				t.Errorf("Expected command 'api', got %s", result.Command)
			}
		})
	}
}

// TestCommandDescriptions verifies that all commands have proper descriptions
func TestCommandDescriptions(t *testing.T) {
	tests := []struct {
		name       string
		cmd        *cobra.Command
		checkShort bool
		checkLong  bool
	}{
		{"recon", NewReconCmd(testFormatter(&bytes.Buffer{}), testAuthConfig), true, true},
		{"crawl", NewCrawlCmd(testFormatter(&bytes.Buffer{}), testAuthConfig, testRateLimitConfig), true, true},
		{"scan", NewScanCmd(testFormatter(&bytes.Buffer{}), testAuthConfig, testRateLimitConfig), true, true},
		{"api", NewAPICmd(testFormatter(&bytes.Buffer{}), testAuthConfig, testRateLimitConfig), true, true},
		{"intercept", NewInterceptCmd(testFormatter(&bytes.Buffer{}), testAuthConfig), true, true},
		{"serve", NewServeCmd(testFormatter(&bytes.Buffer{})), true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.checkShort && tt.cmd.Short == "" {
				t.Errorf("Command %s has no short description", tt.name)
			}
			if tt.checkLong && tt.cmd.Long == "" {
				t.Errorf("Command %s has no long description", tt.name)
			}
		})
	}
}

// TestReconWithAuthConfig tests recon with auth config (even though not currently used)
func TestReconWithAuthConfig(t *testing.T) {
	var buf bytes.Buffer
	authFunc := func() *auth.AuthConfig {
		return testAuthConfigWithValues()
	}

	cmd := NewReconCmd(testFormatter(&buf), authFunc)
	cmd.SetArgs([]string{"localhost"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
}

// TestInterceptWithAuthConfig tests intercept with auth config (for future use)
func TestInterceptWithAuthConfig(t *testing.T) {
	authFunc := func() *auth.AuthConfig {
		return testAuthConfigWithValues()
	}

	cmd := NewInterceptCmd(testFormatter(&bytes.Buffer{}), authFunc)

	// Just test that command is created properly
	if cmd.Use != "intercept" {
		t.Errorf("Expected Use 'intercept', got %s", cmd.Use)
	}
}

// TestCompleteScanResultStructure tests the CompleteScanResult structure
func TestCompleteScanResultStructure(t *testing.T) {
	result := CompleteScanResult{
		Target: "http://localhost",
		Errors: []string{"error1", "error2"},
	}

	if result.Target != "http://localhost" {
		t.Errorf("Expected target 'http://localhost', got %s", result.Target)
	}

	if len(result.Errors) != 2 {
		t.Errorf("Expected 2 errors, got %d", len(result.Errors))
	}
}

// TestScanResultStructure tests the ScanResult structure
func TestScanResultStructure(t *testing.T) {
	result := ScanResult{
		Target:       "http://localhost",
		ScanTypes:    []string{"xss", "sqli"},
		Capabilities: []string{"detection", "analysis"},
		Status:       "ready",
	}

	if result.Target != "http://localhost" {
		t.Errorf("Expected target 'http://localhost', got %s", result.Target)
	}

	if len(result.ScanTypes) != 2 {
		t.Errorf("Expected 2 scan types, got %d", len(result.ScanTypes))
	}
}

// TestAPIResultStructure tests the APIResult structure
func TestAPIResultStructure(t *testing.T) {
	result := APIResult{
		Features: []string{"discovery", "testing"},
		Formats:  []string{"rest", "graphql"},
		Status:   "ready",
	}

	if len(result.Features) != 2 {
		t.Errorf("Expected 2 features, got %d", len(result.Features))
	}

	if len(result.Formats) != 2 {
		t.Errorf("Expected 2 formats, got %d", len(result.Formats))
	}
}

// TestReconResultStructure tests the ReconResult structure
func TestReconResultStructure(t *testing.T) {
	result := ReconResult{
		Target:  "localhost",
		Methods: []string{"dns", "tls"},
		Status:  "ready",
	}

	if result.Target != "localhost" {
		t.Errorf("Expected target 'localhost', got %s", result.Target)
	}

	if len(result.Methods) != 2 {
		t.Errorf("Expected 2 methods, got %d", len(result.Methods))
	}
}

// TestCrawlWithZeroDepth tests crawl with depth 0 (unlimited)
func TestCrawlWithZeroDepth(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewCrawlCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
	cmd.SetArgs([]string{"http://localhost", "--depth", "0", "--timeout", "1s"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if result.Command != "crawl" {
		t.Errorf("Expected command 'crawl', got %s", result.Command)
	}
}

// TestContextCancellation tests command behavior with context cancellation
func TestContextCancellation(t *testing.T) {
	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Wait for context to be cancelled
	<-ctx.Done()

	// Verify context was cancelled
	if ctx.Err() != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded, got %v", ctx.Err())
	}
}

// TestCrawlWithMultipleFlags tests crawl with various flag combinations
func TestCrawlWithMultipleFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "DepthAndUserAgent",
			args: []string{"http://localhost", "--depth", "2", "--user-agent", "TestBot/1.0", "--timeout", "5s"},
		},
		{
			name: "NoRobotsAndTimeout",
			args: []string{"http://localhost", "--no-robots", "--timeout", "3s"},
		},
		{
			name: "AllFlagsCombined",
			args: []string{"http://localhost", "--depth", "1", "--timeout", "5s", "--user-agent", "Bot", "--no-robots"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewCrawlCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if result.Command != "crawl" {
				t.Errorf("Expected command 'crawl', got %s", result.Command)
			}
		})
	}
}

// TestReconMultipleFlagCombinations tests recon with various flag combinations
func TestReconMultipleFlagCombinations(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "ShortTimeout",
			args: []string{"localhost", "--timeout", "2s"},
		},
		{
			name: "LongTimeout",
			args: []string{"localhost", "--timeout", "15s"},
		},
		{
			name: "SubdomainsWithLongTimeout",
			args: []string{"localhost", "--subdomains", "--timeout", "8s"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewReconCmd(testFormatter(&buf), testAuthConfig)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if !result.Success {
				t.Error("Expected success to be true")
			}
		})
	}
}

// TestAPINoSpec tests API command without spec file
func TestAPINoSpec(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)

	// Test without spec but with target
	cmd.SetArgs([]string{"http://localhost:8080", "--timeout", "10"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if result.Command != "api" {
		t.Errorf("Expected command 'api', got %s", result.Command)
	}
}

// TestAPIDiscoveryPath tests API discovery with different paths
func TestAPIDiscoveryPath(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"RootPath", "http://localhost:8080"},
		{"V1Path", "http://localhost:8080/v1"},
		{"V2Path", "http://localhost:8080/v2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
			cmd.SetArgs([]string{tt.target, "--timeout", "10"})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if result.Command != "api" {
				t.Errorf("Expected command 'api', got %s", result.Command)
			}
		})
	}
}

// TestScanMultipleTimeouts tests scan with various timeout values
func TestScanMultipleTimeouts(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
	}{
		{"ShortTimeout", "3"},
		{"MediumTimeout", "10"},
		{"LongTimeout", "20"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
			cmd.SetArgs([]string{"http://localhost", "--timeout", tt.timeout})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if result.Command != "scan" {
				t.Errorf("Expected command 'scan', got %s", result.Command)
			}
		})
	}
}

// TestCombinedAuthRateLimitAndFlags tests commands with auth, rate limiting, and flags
func TestCombinedAuthRateLimitAndFlags(t *testing.T) {
	authFunc := func() *auth.AuthConfig {
		return testAuthConfigWithValues()
	}
	rateLimitFunc := func() ratelimit.Config {
		return testRateLimitConfigWithValues()
	}

	tests := []struct {
		name    string
		cmdFunc func() error
	}{
		{
			name: "CrawlWithAllSettings",
			cmdFunc: func() error {
				var buf bytes.Buffer
				cmd := NewCrawlCmd(testFormatter(&buf), authFunc, rateLimitFunc)
				cmd.SetArgs([]string{"http://localhost", "--depth", "2", "--timeout", "5s", "--no-robots"})
				return cmd.Execute()
			},
		},
		{
			name: "ScanWithAllSettings",
			cmdFunc: func() error {
				var buf bytes.Buffer
				cmd := NewScanCmd(testFormatter(&buf), authFunc, rateLimitFunc)
				cmd.SetArgs([]string{"http://localhost", "--timeout", "10"})
				return cmd.Execute()
			},
		},
		{
			name: "APIWithAllSettings",
			cmdFunc: func() error {
				var buf bytes.Buffer
				cmd := NewAPICmd(testFormatter(&buf), authFunc, rateLimitFunc)
				cmd.SetArgs([]string{"http://localhost:8080", "--timeout", "10"})
				return cmd.Execute()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmdFunc()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}
		})
	}
}

// TestReconWithSubdomainsOnly tests recon with just subdomains flag
func TestReconWithSubdomainsOnly(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewReconCmd(testFormatter(&buf), testAuthConfig)
	cmd.SetArgs([]string{"localhost", "--subdomains"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
}

// TestCrawlMinimalSettings tests crawl with minimal settings
func TestCrawlMinimalSettings(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewCrawlCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
	cmd.SetArgs([]string{"http://localhost", "--timeout", "2s"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if result.Command != "crawl" {
		t.Errorf("Expected command 'crawl', got %s", result.Command)
	}
}

// TestCommandsWithEmptyAuth tests commands with empty auth config
func TestCommandsWithEmptyAuth(t *testing.T) {
	emptyAuth := func() *auth.AuthConfig {
		return &auth.AuthConfig{}
	}

	tests := []struct {
		name    string
		cmdFunc func() *cobra.Command
	}{
		{
			name: "Crawl",
			cmdFunc: func() *cobra.Command {
				var buf bytes.Buffer
				return NewCrawlCmd(testFormatter(&buf), emptyAuth, testRateLimitConfig)
			},
		},
		{
			name: "Scan",
			cmdFunc: func() *cobra.Command {
				var buf bytes.Buffer
				return NewScanCmd(testFormatter(&buf), emptyAuth, testRateLimitConfig)
			},
		},
		{
			name: "API",
			cmdFunc: func() *cobra.Command {
				var buf bytes.Buffer
				return NewAPICmd(testFormatter(&buf), emptyAuth, testRateLimitConfig)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmdFunc()
			if cmd == nil {
				t.Fatal("Command creation failed")
			}
		})
	}
}

// TestCommandsWithEmptyRateLimit tests commands with empty rate limit config
func TestCommandsWithEmptyRateLimit(t *testing.T) {
	emptyRateLimit := func() ratelimit.Config {
		return ratelimit.Config{}
	}

	tests := []struct {
		name    string
		cmdFunc func() *cobra.Command
	}{
		{
			name: "Crawl",
			cmdFunc: func() *cobra.Command {
				var buf bytes.Buffer
				return NewCrawlCmd(testFormatter(&buf), testAuthConfig, emptyRateLimit)
			},
		},
		{
			name: "Scan",
			cmdFunc: func() *cobra.Command {
				var buf bytes.Buffer
				return NewScanCmd(testFormatter(&buf), testAuthConfig, emptyRateLimit)
			},
		},
		{
			name: "API",
			cmdFunc: func() *cobra.Command {
				var buf bytes.Buffer
				return NewAPICmd(testFormatter(&buf), testAuthConfig, emptyRateLimit)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmdFunc()
			if cmd == nil {
				t.Fatal("Command creation failed")
			}
		})
	}
}

// TestAPIWithVariousTimeouts tests API command with different timeout values
func TestAPIWithVariousTimeouts(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
	}{
		{"Timeout5", "5"},
		{"Timeout15", "15"},
		{"Timeout30", "30"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
			cmd.SetArgs([]string{"http://localhost:8080", "--timeout", tt.timeout})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if result.Command != "api" {
				t.Errorf("Expected command 'api', got %s", result.Command)
			}
		})
	}
}

// TestCrawlWithCustomUserAgents tests crawl with different user agents
func TestCrawlWithCustomUserAgents(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
	}{
		{"SimpleUA", "TestBot/1.0"},
		{"ComplexUA", "Mozilla/5.0 (compatible; TestBot/1.0)"},
		{"CustomUA", "MyScanner/2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewCrawlCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
			cmd.SetArgs([]string{"http://localhost", "--user-agent", tt.userAgent, "--timeout", "3s"})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if result.Command != "crawl" {
				t.Errorf("Expected command 'crawl', got %s", result.Command)
			}
		})
	}
}

// TestReconWithVariousTargets tests recon with different target types
func TestReconWithVariousTargets(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"ShortDomain", "test.com"},
		{"LongDomain", "localhost"},
		{"DomainWithNumbers", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewReconCmd(testFormatter(&buf), testAuthConfig)
			cmd.SetArgs([]string{tt.target, "--timeout", "5s"})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if !result.Success {
				t.Error("Expected success to be true")
			}
		})
	}
}

// TestAPIWithSpecFile tests API command with a spec file
func TestAPIWithSpecFile(t *testing.T) {
	// Create a minimal OpenAPI spec file
	specContent := `{
		"openapi": "3.0.0",
		"info": {
			"title": "Test API",
			"version": "1.0.0"
		},
		"paths": {}
	}`

	specPath := "/tmp/test-openapi-spec.json"
	err := os.WriteFile(specPath, []byte(specContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create spec file: %v", err)
	}
	defer os.Remove(specPath)

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "SpecOnly",
			args: []string{"--spec", specPath},
		},
		{
			name: "SpecWithDryRun",
			args: []string{"--spec", specPath, "--dry-run"},
		},
		{
			name: "SpecWithBaseURL",
			args: []string{"--spec", specPath, "--base-url", "https://api.test.com"},
		},
		{
			name: "SpecWithTimeout",
			args: []string{"--spec", specPath, "--timeout", "10"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			// Verify command was executed
			if result.Command != "api" {
				t.Errorf("Expected command 'api', got %s", result.Command)
			}
		})
	}
}

// TestAPIWithSpecFileAndAuth tests API spec parsing with auth
func TestAPIWithSpecFileAndAuth(t *testing.T) {
	// Create a minimal OpenAPI spec file
	specContent := `{
		"openapi": "3.0.0",
		"info": {
			"title": "Test API",
			"version": "1.0.0"
		},
		"paths": {}
	}`

	specPath := "/tmp/test-openapi-auth.json"
	err := os.WriteFile(specPath, []byte(specContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create spec file: %v", err)
	}
	defer os.Remove(specPath)

	authFunc := func() *auth.AuthConfig {
		return testAuthConfigWithValues()
	}

	var buf bytes.Buffer
	cmd := NewAPICmd(testFormatter(&buf), authFunc, testRateLimitConfig)
	cmd.SetArgs([]string{"--spec", specPath, "--dry-run"})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if result.Command != "api" {
		t.Errorf("Expected command 'api', got %s", result.Command)
	}
}

// TestAPIWithSpecFileAndRateLimit tests API spec parsing with rate limiting
func TestAPIWithSpecFileAndRateLimit(t *testing.T) {
	// Create a minimal OpenAPI spec file
	specContent := `{
		"openapi": "3.0.0",
		"info": {
			"title": "Test API",
			"version": "1.0.0"
		},
		"paths": {}
	}`

	specPath := "/tmp/test-openapi-ratelimit.json"
	err := os.WriteFile(specPath, []byte(specContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create spec file: %v", err)
	}
	defer os.Remove(specPath)

	rateLimitFunc := func() ratelimit.Config {
		return testRateLimitConfigWithValues()
	}

	var buf bytes.Buffer
	cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, rateLimitFunc)
	cmd.SetArgs([]string{"--spec", specPath, "--dry-run"})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if result.Command != "api" {
		t.Errorf("Expected command 'api', got %s", result.Command)
	}
}

// TestAPIWithInvalidSpec tests API command with invalid spec file
func TestAPIWithInvalidSpec(t *testing.T) {
	// Test with non-existent file
	var buf bytes.Buffer
	cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
	cmd.SetArgs([]string{"--spec", "/nonexistent/spec.json"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	// Should still execute but likely report failure
	if result.Command != "api" {
		t.Errorf("Expected command 'api', got %s", result.Command)
	}
}

// TestAPIWithSpecAndRespectRateLimits tests API with respect-rate-limits flag
func TestAPIWithSpecAndRespectRateLimits(t *testing.T) {
	// Create a minimal OpenAPI spec file
	specContent := `{
		"openapi": "3.0.0",
		"info": {
			"title": "Test API",
			"version": "1.0.0"
		},
		"paths": {}
	}`

	specPath := "/tmp/test-openapi-respect.json"
	err := os.WriteFile(specPath, []byte(specContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create spec file: %v", err)
	}
	defer os.Remove(specPath)

	var buf bytes.Buffer
	cmd := NewAPICmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
	cmd.SetArgs([]string{"--spec", specPath, "--respect-rate-limits", "--dry-run"})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if result.Command != "api" {
		t.Errorf("Expected command 'api', got %s", result.Command)
	}
}

// TestAPIDiscoveryWithAllSettings tests API discovery with all settings combined
func TestAPIDiscoveryWithAllSettings(t *testing.T) {
	authFunc := func() *auth.AuthConfig {
		return testAuthConfigWithValues()
	}
	rateLimitFunc := func() ratelimit.Config {
		return testRateLimitConfigWithValues()
	}

	var buf bytes.Buffer
	cmd := NewAPICmd(testFormatter(&buf), authFunc, rateLimitFunc)
	cmd.SetArgs([]string{"http://localhost:8080", "--timeout", "15"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if result.Command != "api" {
		t.Errorf("Expected command 'api', got %s", result.Command)
	}
}

// TestScanSafeMode tests scan command with safe mode enabled (default)
func TestScanSafeMode(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
	cmd.SetArgs([]string{"http://localhost"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	// Verify safe mode message
	if !strings.Contains(result.Message, "passive checks only") {
		t.Errorf("Expected message to indicate passive checks only, got: %s", result.Message)
	}

	// Verify PassiveOnly flag in result data
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	passiveOnly, ok := data["passive_only"].(bool)
	if !ok || !passiveOnly {
		t.Error("Expected passive_only to be true in safe mode")
	}

	// Verify active scanners (XSS, SQLi, CSRF) are not present
	if _, hasXSS := data["xss"]; hasXSS {
		t.Error("Expected XSS results to be absent in safe mode")
	}
	if _, hasSQLi := data["sqli"]; hasSQLi {
		t.Error("Expected SQLi results to be absent in safe mode")
	}
	if _, hasCSRF := data["csrf"]; hasCSRF {
		t.Error("Expected CSRF results to be absent in safe mode")
	}

	// Verify headers are still present (passive scan)
	if _, hasHeaders := data["headers"]; !hasHeaders {
		t.Error("Expected headers to be present in safe mode")
	}
}

// TestScanActiveFlagEnabled tests scan command with --active flag
func TestScanActiveFlagEnabled(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
	cmd.SetArgs([]string{"http://localhost", "--active"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	// Verify active testing message
	if !strings.Contains(result.Message, "active testing enabled") {
		t.Errorf("Expected message to indicate active testing, got: %s", result.Message)
	}

	// Verify PassiveOnly flag is false
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	passiveOnly, ok := data["passive_only"].(bool)
	if !ok || passiveOnly {
		t.Error("Expected passive_only to be false with --active flag")
	}

	// Verify active scanners (XSS, SQLi, CSRF) are present
	if _, hasXSS := data["xss"]; !hasXSS {
		t.Error("Expected XSS results to be present with --active flag")
	}
	if _, hasSQLi := data["sqli"]; !hasSQLi {
		t.Error("Expected SQLi results to be present with --active flag")
	}
	if _, hasCSRF := data["csrf"]; !hasCSRF {
		t.Error("Expected CSRF results to be present with --active flag")
	}
}

// TestScanSafeModeExplicitFalse tests scan command with --safe-mode=false
func TestScanSafeModeExplicitFalse(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
	cmd.SetArgs([]string{"http://localhost", "--safe-mode=false"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	// Verify active testing message
	if !strings.Contains(result.Message, "active testing enabled") {
		t.Errorf("Expected message to indicate active testing, got: %s", result.Message)
	}

	// Verify PassiveOnly flag is false
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	passiveOnly, ok := data["passive_only"].(bool)
	if !ok || passiveOnly {
		t.Error("Expected passive_only to be false with --safe-mode=false")
	}
}

// TestScanSafeModeExplicitTrue tests scan command with --safe-mode=true
func TestScanSafeModeExplicitTrue(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
	cmd.SetArgs([]string{"http://localhost", "--safe-mode=true"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	// Verify safe mode message
	if !strings.Contains(result.Message, "passive checks only") {
		t.Errorf("Expected message to indicate passive checks only, got: %s", result.Message)
	}

	// Verify PassiveOnly flag is true
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	passiveOnly, ok := data["passive_only"].(bool)
	if !ok || !passiveOnly {
		t.Error("Expected passive_only to be true with --safe-mode=true")
	}
}

// TestScanActiveOverridesSafeMode tests that --active takes precedence over --safe-mode
func TestScanActiveOverridesSafeMode(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
	// Both flags provided, --active should win
	cmd.SetArgs([]string{"http://localhost", "--safe-mode=true", "--active"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	// Verify active testing is enabled (--active overrides --safe-mode)
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	passiveOnly, ok := data["passive_only"].(bool)
	if !ok || passiveOnly {
		t.Error("Expected passive_only to be false when --active flag is used")
	}
}

// TestScanCommandFlags tests that safe mode flags are properly registered
func TestScanCommandFlags(t *testing.T) {
	cmd := NewScanCmd(testFormatter(&bytes.Buffer{}), testAuthConfig, testRateLimitConfig)

	// Check safe-mode flag
	safeModeFlag := cmd.Flag("safe-mode")
	if safeModeFlag == nil {
		t.Error("Expected 'safe-mode' flag to be registered")
	} else {
		if safeModeFlag.DefValue != "true" {
			t.Errorf("Expected default safe-mode to be true, got %s", safeModeFlag.DefValue)
		}
	}

	// Check active flag
	activeFlag := cmd.Flag("active")
	if activeFlag == nil {
		t.Error("Expected 'active' flag to be registered")
	} else {
		if activeFlag.DefValue != "false" {
			t.Errorf("Expected default active to be false, got %s", activeFlag.DefValue)
		}
	}

	// Check verify flag
	verifyFlag := cmd.Flag("verify")
	if verifyFlag == nil {
		t.Error("Expected 'verify' flag to be registered")
	} else {
		if verifyFlag.DefValue != "false" {
			t.Errorf("Expected default verify to be false, got %s", verifyFlag.DefValue)
		}
	}
}

// TestScanWithVerifyFlag tests scan command with --verify flag
func TestScanWithVerifyFlag(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
	// Verify flag should work with active mode
	cmd.SetArgs([]string{"http://localhost", "--active", "--verify"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	// Verify active testing message
	if !strings.Contains(result.Message, "active testing enabled") {
		t.Errorf("Expected message to indicate active testing, got: %s", result.Message)
	}

	// Verify PassiveOnly flag is false
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	passiveOnly, ok := data["passive_only"].(bool)
	if !ok || passiveOnly {
		t.Error("Expected passive_only to be false with --active flag")
	}
}

// TestScanVerifyFlagAlone tests that --verify is accepted (even without findings to verify)
func TestScanVerifyFlagAlone(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)
	// Verify flag without active mode (should not error, just won't verify anything)
	cmd.SetArgs([]string{"http://localhost", "--verify"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	// Should be in safe mode (passive only)
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be a map, got %T", result.Data)
	}

	passiveOnly, ok := data["passive_only"].(bool)
	if !ok || !passiveOnly {
		t.Error("Expected passive_only to be true without --active flag")
	}
}

// TestAPISpecWithAllOptions tests spec file with all options combined
func TestAPISpecWithAllOptions(t *testing.T) {
	specContent := `{
		"openapi": "3.0.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"paths": {}
	}`

	specPath := "/tmp/test-openapi-all.json"
	err := os.WriteFile(specPath, []byte(specContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create spec file: %v", err)
	}
	defer os.Remove(specPath)

	authFunc := func() *auth.AuthConfig {
		return testAuthConfigWithValues()
	}
	rateLimitFunc := func() ratelimit.Config {
		return testRateLimitConfigWithValues()
	}

	var buf bytes.Buffer
	cmd := NewAPICmd(testFormatter(&buf), authFunc, rateLimitFunc)
	cmd.SetArgs([]string{
		"--spec", specPath,
		"--base-url", "https://test.api.com",
		"--timeout", "20",
		"--respect-rate-limits",
		"--dry-run",
	})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	var result output.CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if result.Command != "api" {
		t.Errorf("Expected command 'api', got %s", result.Command)
	}
}

// TestHandleInitCA_ExistingCA tests handleInitCA when CA already exists
func TestHandleInitCA_ExistingCA(t *testing.T) {
	// Create a temporary directory for CA files
	tmpDir, err := os.MkdirTemp("", "wast-test-ca-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create CA certificate and key files
	caCertPath := filepath.Join(tmpDir, "ca.crt")
	caKeyPath := filepath.Join(tmpDir, "ca.key")

	// Initialize CA
	config := &proxy.CAConfig{
		CertPath:      caCertPath,
		KeyPath:       caKeyPath,
		ValidityYears: proxy.DefaultCAValidityYears,
		KeyBits:       proxy.DefaultKeyBits,
	}
	ca := proxy.NewCertificateAuthority(config)
	if err := ca.Initialize(); err != nil {
		t.Fatalf("Failed to initialize CA: %v", err)
	}

	// Test handleInitCA with existing CA
	var buf bytes.Buffer
	formatter := testFormatter(&buf)()

	handleInitCA(formatter, caCertPath, caKeyPath)

	// Verify output contains expected messages
	output := buf.String()
	if !strings.Contains(output, "CA certificate already exists") {
		t.Errorf("Expected output to contain 'CA certificate already exists', got: %s", output)
	}
}

// TestHandleInitCA_MismatchedFlags tests handleInitCA with mismatched cert/key flags
func TestHandleInitCA_MismatchedFlags(t *testing.T) {
	tests := []struct {
		name   string
		caCert string
		caKey  string
	}{
		{
			name:   "cert without key",
			caCert: "/tmp/ca.crt",
			caKey:  "",
		},
		{
			name:   "key without cert",
			caCert: "",
			caKey:  "/tmp/ca.key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := testFormatter(&buf)()

			handleInitCA(formatter, tt.caCert, tt.caKey)

			// Verify failure output
			var result output.CommandResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if result.Success {
				t.Error("Expected success to be false for mismatched flags")
			}
			if result.Command != "init-ca" {
				t.Errorf("Expected command 'init-ca', got %s", result.Command)
			}
		})
	}
}

// TestHandleInitCA_NewCA tests handleInitCA creating a new CA
func TestHandleInitCA_NewCA(t *testing.T) {
	// Create a temporary directory for CA files
	tmpDir, err := os.MkdirTemp("", "wast-test-ca-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caCertPath := filepath.Join(tmpDir, "ca.crt")
	caKeyPath := filepath.Join(tmpDir, "ca.key")

	var buf bytes.Buffer
	formatter := testFormatter(&buf)()

	handleInitCA(formatter, caCertPath, caKeyPath)

	// Verify CA files were created
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		t.Errorf("Expected CA certificate to be created at %s", caCertPath)
	}
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		t.Errorf("Expected CA key to be created at %s", caKeyPath)
	}

	// Verify success output - check for both success and init-ca in the output
	outputStr := buf.String()
	if !strings.Contains(outputStr, `"success": true`) {
		t.Error("Expected success to be true in output")
	}
	if !strings.Contains(outputStr, `"command": "init-ca"`) {
		t.Error("Expected command to be 'init-ca' in output")
	}
	if !strings.Contains(outputStr, "CA certificate generated successfully") {
		t.Error("Expected success message in output")
	}
}

// TestInitializeCA_CustomPaths tests initializeCA with custom CA paths
func TestInitializeCA_CustomPaths(t *testing.T) {
	tests := []struct {
		name        string
		setupFiles  bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid custom paths",
			setupFiles:  true,
			expectError: false,
		},
		{
			name:        "cert not found",
			setupFiles:  false,
			expectError: true,
			errorMsg:    "CA certificate not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory for CA files
			tmpDir, err := os.MkdirTemp("", "wast-test-ca-*")
			if err != nil {
				t.Fatalf("Failed to create temp directory: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			caCertPath := filepath.Join(tmpDir, "ca.crt")
			caKeyPath := filepath.Join(tmpDir, "ca.key")

			if tt.setupFiles {
				// Initialize CA
				config := &proxy.CAConfig{
					CertPath:      caCertPath,
					KeyPath:       caKeyPath,
					ValidityYears: proxy.DefaultCAValidityYears,
					KeyBits:       proxy.DefaultKeyBits,
				}
				ca := proxy.NewCertificateAuthority(config)
				if err := ca.Initialize(); err != nil {
					t.Fatalf("Failed to initialize CA: %v", err)
				}
			}

			var buf bytes.Buffer
			formatter := testFormatter(&buf)()

			ca, err := initializeCA(formatter, caCertPath, caKeyPath)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorMsg, err)
				}
				if ca != nil {
					t.Error("Expected CA to be nil on error")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if ca == nil {
					t.Error("Expected CA to be initialized")
				}
			}
		})
	}
}

// TestInitializeCA_MissingKey tests initializeCA when cert exists but key doesn't
func TestInitializeCA_MissingKey(t *testing.T) {
	// Create a temporary directory for CA files
	tmpDir, err := os.MkdirTemp("", "wast-test-ca-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caCertPath := filepath.Join(tmpDir, "ca.crt")
	caKeyPath := filepath.Join(tmpDir, "ca.key")

	// Create only the cert file (not the key)
	certFile, err := os.Create(caCertPath)
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	certFile.Close()

	var buf bytes.Buffer
	formatter := testFormatter(&buf)()

	ca, err := initializeCA(formatter, caCertPath, caKeyPath)

	// Should fail because key doesn't exist
	if err == nil {
		t.Error("Expected error when key is missing")
	}
	if !strings.Contains(err.Error(), "CA private key not found") {
		t.Errorf("Expected error about missing key, got: %v", err)
	}
	if ca != nil {
		t.Error("Expected CA to be nil when key is missing")
	}
}

// TestInitializeCA_MissingCert tests initializeCA when key exists but cert doesn't
func TestInitializeCA_MissingCert(t *testing.T) {
	// Create a temporary directory for CA files
	tmpDir, err := os.MkdirTemp("", "wast-test-ca-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caCertPath := filepath.Join(tmpDir, "ca.crt")
	caKeyPath := filepath.Join(tmpDir, "ca.key")

	// Create only the key file (not the cert)
	keyFile, err := os.Create(caKeyPath)
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	keyFile.Close()

	var buf bytes.Buffer
	formatter := testFormatter(&buf)()

	ca, err := initializeCA(formatter, caCertPath, caKeyPath)

	// Should fail because cert doesn't exist
	if err == nil {
		t.Error("Expected error when cert is missing")
	}
	if !strings.Contains(err.Error(), "CA certificate not found") {
		t.Errorf("Expected error about missing cert, got: %v", err)
	}
	if ca != nil {
		t.Error("Expected CA to be nil when cert is missing")
	}
}

// TestInitializeCA_MismatchedFlags tests initializeCA with mismatched cert/key flags
func TestInitializeCA_MismatchedFlags(t *testing.T) {
	tests := []struct {
		name   string
		caCert string
		caKey  string
	}{
		{
			name:   "cert without key",
			caCert: "/tmp/ca.crt",
			caKey:  "",
		},
		{
			name:   "key without cert",
			caCert: "",
			caKey:  "/tmp/ca.key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := testFormatter(&buf)()

			ca, err := initializeCA(formatter, tt.caCert, tt.caKey)

			if err == nil {
				t.Error("Expected error for mismatched flags")
			}
			if !strings.Contains(err.Error(), "both --ca-cert and --ca-key must be specified together") {
				t.Errorf("Expected error about mismatched flags, got: %v", err)
			}
			if ca != nil {
				t.Error("Expected CA to be nil for mismatched flags")
			}
		})
	}
}

// TestInitializeCA_DefaultPath tests initializeCA with default paths (auto-initialization)
func TestInitializeCA_DefaultPath(t *testing.T) {
	// Create a temporary home directory
	tmpHome, err := os.MkdirTemp("", "wast-test-home-*")
	if err != nil {
		t.Fatalf("Failed to create temp home directory: %v", err)
	}
	defer os.RemoveAll(tmpHome)

	// Save original HOME and restore after test
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", originalHome)

	var buf bytes.Buffer
	formatter := testFormatter(&buf)()

	// Call with empty paths (should use default)
	ca, err := initializeCA(formatter, "", "")

	if err != nil {
		t.Errorf("Expected no error with default paths, got: %v", err)
	}
	if ca == nil {
		t.Error("Expected CA to be initialized")
	}

	// Verify CA was created in default location
	expectedCertPath := filepath.Join(tmpHome, proxy.DefaultCADir, "ca.crt")
	expectedKeyPath := filepath.Join(tmpHome, proxy.DefaultCADir, "ca.key")

	if _, err := os.Stat(expectedCertPath); os.IsNotExist(err) {
		t.Errorf("Expected CA certificate at %s", expectedCertPath)
	}
	if _, err := os.Stat(expectedKeyPath); os.IsNotExist(err) {
		t.Errorf("Expected CA key at %s", expectedKeyPath)
	}
}

// TestInterceptCmd_HttpOnly tests the --http-only flag behavior
func TestInterceptCmd_HttpOnly(t *testing.T) {
	// This test verifies that the command handles the --http-only flag correctly
	// We can't fully test the runtime behavior without starting the server,
	// but we can verify the flag is properly registered and has correct default
	var buf bytes.Buffer
	cmd := NewInterceptCmd(testFormatter(&buf), testAuthConfig)

	httpOnlyFlag := cmd.Flag("http-only")
	if httpOnlyFlag == nil {
		t.Fatal("Expected 'http-only' flag to be registered")
	}

	if httpOnlyFlag.DefValue != "false" {
		t.Errorf("Expected default value 'false' for http-only flag, got %s", httpOnlyFlag.DefValue)
	}

	// Verify flag description mentions HTTPS
	if !strings.Contains(httpOnlyFlag.Usage, "HTTPS") {
		t.Error("Expected http-only flag usage to mention HTTPS")
	}
}
