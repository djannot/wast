// Package output provides formatters for CLI output in JSON, YAML, and text formats.
// This package is essential for AI agent integration, enabling structured, machine-readable output.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Format represents the output format type.
type Format string

const (
	// FormatJSON outputs data as JSON.
	FormatJSON Format = "json"
	// FormatYAML outputs data as YAML.
	FormatYAML Format = "yaml"
	// FormatText outputs data as human-readable text.
	FormatText Format = "text"
	// FormatSARIF outputs data as SARIF 2.1.0 (Static Analysis Results Interchange Format).
	FormatSARIF Format = "sarif"
)

// ValidFormats returns all valid output format strings.
func ValidFormats() []string {
	return []string{string(FormatJSON), string(FormatYAML), string(FormatText), string(FormatSARIF)}
}

// IsValidFormat checks if the given format string is valid.
func IsValidFormat(format string) bool {
	for _, f := range ValidFormats() {
		if f == format {
			return true
		}
	}
	return false
}

// Formatter handles output formatting for CLI commands.
type Formatter struct {
	format  Format
	writer  io.Writer
	quiet   bool
	verbose bool
}

// NewFormatter creates a new Formatter with the specified options.
func NewFormatter(format string, quiet, verbose bool) *Formatter {
	f := Format(format)
	if !IsValidFormat(format) {
		f = FormatText
	}
	return &Formatter{
		format:  f,
		writer:  os.Stdout,
		quiet:   quiet,
		verbose: verbose,
	}
}

// SetWriter sets a custom writer for the formatter (useful for testing).
func (f *Formatter) SetWriter(w io.Writer) {
	f.writer = w
}

// Format returns the current output format.
func (f *Formatter) Format() Format {
	return f.format
}

// IsQuiet returns whether quiet mode is enabled.
func (f *Formatter) IsQuiet() bool {
	return f.quiet
}

// IsVerbose returns whether verbose mode is enabled.
func (f *Formatter) IsVerbose() bool {
	return f.verbose
}

// Output formats and outputs the given data according to the configured format.
func (f *Formatter) Output(data interface{}) error {
	if f.quiet {
		return nil
	}

	switch f.format {
	case FormatJSON:
		return f.outputJSON(data)
	case FormatYAML:
		return f.outputYAML(data)
	case FormatSARIF:
		return f.outputSARIF(data)
	default:
		return f.outputText(data)
	}
}

// outputJSON outputs data as formatted JSON.
func (f *Formatter) outputJSON(data interface{}) error {
	encoder := json.NewEncoder(f.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// outputYAML outputs data as YAML.
func (f *Formatter) outputYAML(data interface{}) error {
	encoder := yaml.NewEncoder(f.writer)
	encoder.SetIndent(2)
	defer encoder.Close()
	return encoder.Encode(data)
}

// outputText outputs data as human-readable text.
func (f *Formatter) outputText(data interface{}) error {
	switch v := data.(type) {
	case string:
		_, err := fmt.Fprintln(f.writer, v)
		return err
	case fmt.Stringer:
		_, err := fmt.Fprintln(f.writer, v.String())
		return err
	default:
		_, err := fmt.Fprintf(f.writer, "%+v\n", data)
		return err
	}
}

// Message represents a generic message output.
type Message struct {
	Type    string `json:"type" yaml:"type"`
	Message string `json:"message" yaml:"message"`
}

// Info outputs an informational message.
func (f *Formatter) Info(message string) error {
	if f.quiet {
		return nil
	}
	return f.Output(Message{Type: "info", Message: message})
}

// Error outputs an error message.
func (f *Formatter) Error(message string) error {
	return f.Output(Message{Type: "error", Message: message})
}

// Verbose outputs a verbose message (only if verbose mode is enabled).
func (f *Formatter) Verbose(message string) error {
	if !f.verbose || f.quiet {
		return nil
	}
	return f.Output(Message{Type: "verbose", Message: message})
}

// CommandResult represents the result of a command execution.
type CommandResult struct {
	Success bool        `json:"success" yaml:"success"`
	Command string      `json:"command" yaml:"command"`
	Message string      `json:"message,omitempty" yaml:"message,omitempty"`
	Data    interface{} `json:"data,omitempty" yaml:"data,omitempty"`
}

// Success outputs a successful command result.
func (f *Formatter) Success(command, message string, data interface{}) error {
	return f.Output(CommandResult{
		Success: true,
		Command: command,
		Message: message,
		Data:    data,
	})
}

// Failure outputs a failed command result.
func (f *Formatter) Failure(command, message string, data interface{}) error {
	return f.Output(CommandResult{
		Success: false,
		Command: command,
		Message: message,
		Data:    data,
	})
}
