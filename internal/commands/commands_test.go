package commands

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/djannot/wast/pkg/output"
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

func TestReconCmd(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewReconCmd(testFormatter(&buf))

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
	cmd := NewCrawlCmd(testFormatter(&buf))

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
	var buf bytes.Buffer
	cmd := NewInterceptCmd(testFormatter(&buf))

	if cmd.Use != "intercept" {
		t.Errorf("Expected Use 'intercept', got %s", cmd.Use)
	}

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
	if result.Command != "intercept" {
		t.Errorf("Expected command 'intercept', got %s", result.Command)
	}
}

func TestScanCmd(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewScanCmd(testFormatter(&buf))

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
	cmd := NewAPICmd(testFormatter(&buf))

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
	cmd := NewReconCmd(testFormatter(&buf))

	cmd.SetArgs([]string{"test-target.com"})
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

	if target, ok := data["target"].(string); !ok || target != "test-target.com" {
		t.Errorf("Expected target 'test-target.com', got %v", data["target"])
	}

	if status, ok := data["status"].(string); !ok || status != "placeholder - not yet implemented" {
		t.Errorf("Unexpected status: %v", data["status"])
	}
}

func TestCommandsWithNoArgs(t *testing.T) {
	tests := []struct {
		name    string
		cmdFunc func(func() *output.Formatter) *cobra.Command
	}{
		{"recon", func(f func() *output.Formatter) *cobra.Command {
			cmd := NewReconCmd(f)
			return cmd
		}},
		{"crawl", func(f func() *output.Formatter) *cobra.Command {
			cmd := NewCrawlCmd(f)
			return cmd
		}},
		{"scan", func(f func() *output.Formatter) *cobra.Command {
			cmd := NewScanCmd(f)
			return cmd
		}},
		{"api", func(f func() *output.Formatter) *cobra.Command {
			cmd := NewAPICmd(f)
			return cmd
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := tt.cmdFunc(testFormatter(&buf))

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
