package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidFormats(t *testing.T) {
	formats := ValidFormats()
	if len(formats) != 3 {
		t.Errorf("Expected 3 formats, got %d", len(formats))
	}

	expected := []string{"json", "yaml", "text"}
	for i, f := range formats {
		if f != expected[i] {
			t.Errorf("Expected format %s at index %d, got %s", expected[i], i, f)
		}
	}
}

func TestIsValidFormat(t *testing.T) {
	tests := []struct {
		format   string
		expected bool
	}{
		{"json", true},
		{"yaml", true},
		{"text", true},
		{"JSON", false}, // case sensitive
		{"xml", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			result := IsValidFormat(tt.format)
			if result != tt.expected {
				t.Errorf("IsValidFormat(%q) = %v, expected %v", tt.format, result, tt.expected)
			}
		})
	}
}

func TestNewFormatter(t *testing.T) {
	t.Run("valid format", func(t *testing.T) {
		f := NewFormatter("json", false, false)
		if f.Format() != FormatJSON {
			t.Errorf("Expected format JSON, got %s", f.Format())
		}
	})

	t.Run("invalid format defaults to text", func(t *testing.T) {
		f := NewFormatter("invalid", false, false)
		if f.Format() != FormatText {
			t.Errorf("Expected format Text, got %s", f.Format())
		}
	})

	t.Run("quiet mode", func(t *testing.T) {
		f := NewFormatter("text", true, false)
		if !f.IsQuiet() {
			t.Error("Expected quiet mode to be enabled")
		}
	})

	t.Run("verbose mode", func(t *testing.T) {
		f := NewFormatter("text", false, true)
		if !f.IsVerbose() {
			t.Error("Expected verbose mode to be enabled")
		}
	})
}

func TestFormatterOutputJSON(t *testing.T) {
	var buf bytes.Buffer
	f := NewFormatter("json", false, false)
	f.SetWriter(&buf)

	data := map[string]string{"key": "value"}
	err := f.Output(data)
	if err != nil {
		t.Fatalf("Output failed: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("Expected key=value, got key=%s", result["key"])
	}
}

func TestFormatterOutputYAML(t *testing.T) {
	var buf bytes.Buffer
	f := NewFormatter("yaml", false, false)
	f.SetWriter(&buf)

	data := map[string]string{"key": "value"}
	err := f.Output(data)
	if err != nil {
		t.Fatalf("Output failed: %v", err)
	}

	var result map[string]string
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("Expected key=value, got key=%s", result["key"])
	}
}

func TestFormatterOutputText(t *testing.T) {
	t.Run("string output", func(t *testing.T) {
		var buf bytes.Buffer
		f := NewFormatter("text", false, false)
		f.SetWriter(&buf)

		err := f.Output("hello world")
		if err != nil {
			t.Fatalf("Output failed: %v", err)
		}

		expected := "hello world\n"
		if buf.String() != expected {
			t.Errorf("Expected %q, got %q", expected, buf.String())
		}
	})

	t.Run("struct output", func(t *testing.T) {
		var buf bytes.Buffer
		f := NewFormatter("text", false, false)
		f.SetWriter(&buf)

		data := struct {
			Name string
			Age  int
		}{Name: "test", Age: 25}

		err := f.Output(data)
		if err != nil {
			t.Fatalf("Output failed: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "test") || !strings.Contains(output, "25") {
			t.Errorf("Output should contain struct fields, got %q", output)
		}
	})
}

func TestFormatterQuietMode(t *testing.T) {
	var buf bytes.Buffer
	f := NewFormatter("text", true, false)
	f.SetWriter(&buf)

	err := f.Output("this should not appear")
	if err != nil {
		t.Fatalf("Output failed: %v", err)
	}

	if buf.Len() != 0 {
		t.Errorf("Expected empty output in quiet mode, got %q", buf.String())
	}
}

func TestFormatterInfo(t *testing.T) {
	var buf bytes.Buffer
	f := NewFormatter("json", false, false)
	f.SetWriter(&buf)

	err := f.Info("test message")
	if err != nil {
		t.Fatalf("Info failed: %v", err)
	}

	var result Message
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if result.Type != "info" || result.Message != "test message" {
		t.Errorf("Unexpected result: %+v", result)
	}
}

func TestFormatterError(t *testing.T) {
	var buf bytes.Buffer
	f := NewFormatter("json", false, false)
	f.SetWriter(&buf)

	err := f.Error("error message")
	if err != nil {
		t.Fatalf("Error failed: %v", err)
	}

	var result Message
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if result.Type != "error" || result.Message != "error message" {
		t.Errorf("Unexpected result: %+v", result)
	}
}

func TestFormatterVerbose(t *testing.T) {
	t.Run("verbose enabled", func(t *testing.T) {
		var buf bytes.Buffer
		f := NewFormatter("json", false, true)
		f.SetWriter(&buf)

		err := f.Verbose("verbose message")
		if err != nil {
			t.Fatalf("Verbose failed: %v", err)
		}

		var result Message
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}

		if result.Type != "verbose" {
			t.Errorf("Expected type 'verbose', got %s", result.Type)
		}
	})

	t.Run("verbose disabled", func(t *testing.T) {
		var buf bytes.Buffer
		f := NewFormatter("json", false, false)
		f.SetWriter(&buf)

		err := f.Verbose("verbose message")
		if err != nil {
			t.Fatalf("Verbose failed: %v", err)
		}

		if buf.Len() != 0 {
			t.Errorf("Expected empty output when verbose disabled, got %q", buf.String())
		}
	})

	t.Run("verbose with quiet", func(t *testing.T) {
		var buf bytes.Buffer
		f := NewFormatter("json", true, true)
		f.SetWriter(&buf)

		err := f.Verbose("verbose message")
		if err != nil {
			t.Fatalf("Verbose failed: %v", err)
		}

		if buf.Len() != 0 {
			t.Errorf("Expected empty output when quiet is set, got %q", buf.String())
		}
	})
}

func TestFormatterSuccess(t *testing.T) {
	var buf bytes.Buffer
	f := NewFormatter("json", false, false)
	f.SetWriter(&buf)

	err := f.Success("test", "success message", map[string]int{"count": 42})
	if err != nil {
		t.Fatalf("Success failed: %v", err)
	}

	var result CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
	if result.Command != "test" {
		t.Errorf("Expected command 'test', got %s", result.Command)
	}
	if result.Message != "success message" {
		t.Errorf("Expected message 'success message', got %s", result.Message)
	}
}

func TestFormatterFailure(t *testing.T) {
	var buf bytes.Buffer
	f := NewFormatter("json", false, false)
	f.SetWriter(&buf)

	err := f.Failure("test", "failure message", nil)
	if err != nil {
		t.Fatalf("Failure failed: %v", err)
	}

	var result CommandResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if result.Success {
		t.Error("Expected success to be false")
	}
	if result.Command != "test" {
		t.Errorf("Expected command 'test', got %s", result.Command)
	}
}
