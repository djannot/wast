package commands

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/output"
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

func TestReconCmd(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewReconCmd(testFormatter(&buf), testAuthConfig)

	// Test command exists and has correct use
	if cmd.Use != "recon [target]" {
		t.Errorf("Expected Use 'recon [target]', got %s", cmd.Use)
	}

	// Test command execution
	cmd.SetArgs([]string{"example.com"})
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

	cmd.SetArgs([]string{"https://example.com"})
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

func TestScanCmd(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf), testAuthConfig, testRateLimitConfig)

	if cmd.Use != "scan [target]" {
		t.Errorf("Expected Use 'scan [target]', got %s", cmd.Use)
	}

	cmd.SetArgs([]string{"https://example.com"})
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

	cmd.SetArgs([]string{"https://api.example.com"})
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

	cmd.SetArgs([]string{"example.com"})
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

	if target, ok := data["target"].(string); !ok || target != "example.com" {
		t.Errorf("Expected target 'example.com', got %v", data["target"])
	}

	// Check that DNS data is present
	if dns, ok := data["dns"].(map[string]interface{}); !ok {
		t.Errorf("Expected dns data to be present")
	} else {
		if domain, ok := dns["domain"].(string); !ok || domain != "example.com" {
			t.Errorf("Expected dns domain 'example.com', got %v", dns["domain"])
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
