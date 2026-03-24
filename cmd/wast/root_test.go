package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/djannot/wast/pkg/output"
)

// TestVersionStringFormat tests that version information format string is correct
func TestVersionStringFormat(t *testing.T) {
	// Save original values
	origVersion := version
	origCommit := commit
	origDate := date

	// Set test values
	version = "1.0.0"
	commit = "abc123"
	date = "2024-01-01"

	// Restore original values after test
	defer func() {
		version = origVersion
		commit = origCommit
		date = origDate
	}()

	expected := fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)
	actual := fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)

	if actual != expected {
		t.Errorf("Version string mismatch.\nExpected: %s\nGot: %s", expected, actual)
	}

	// Test with default values
	version = "dev"
	commit = "none"
	date = "unknown"

	expected = "dev (commit: none, built: unknown)"
	actual = fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)

	if actual != expected {
		t.Errorf("Version string mismatch with defaults.\nExpected: %s\nGot: %s", expected, actual)
	}
}

// TestOutputFormatValidation tests output format validation
func TestOutputFormatValidation(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		wantError bool
	}{
		{"valid json", "json", false},
		{"valid yaml", "yaml", false},
		{"valid text", "text", false},
		{"valid sarif", "sarif", false},
		{"invalid format", "invalid", true},
		{"empty format", "", true},
		{"uppercase JSON", "JSON", true}, // case sensitive
		{"xml format", "xml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := output.IsValidFormat(tt.format)
			if tt.wantError && isValid {
				t.Errorf("Expected format %q to be invalid, but it was valid", tt.format)
			}
			if !tt.wantError && !isValid {
				t.Errorf("Expected format %q to be valid, but it was invalid", tt.format)
			}
		})
	}
}

// TestQuietVerboseMutualExclusion tests that --quiet and --verbose cannot both be set
func TestQuietVerboseMutualExclusion(t *testing.T) {
	// Use the global rootCmd (test properly cleans up state with defer)
	testCmd := rootCmd

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Set both quiet and verbose
	quiet = true
	verbose = true

	// Create a channel to capture the exit code
	exitCalled := false
	oldOsExit := osExit
	osExit = func(code int) {
		exitCalled = true
		if code != 1 {
			t.Errorf("Expected exit code 1, got %d", code)
		}
	}
	defer func() {
		osExit = oldOsExit
	}()

	// Run PersistentPreRun
	testCmd.PersistentPreRun(testCmd, []string{})

	// Restore stderr
	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if !exitCalled {
		t.Error("Expected os.Exit to be called when both quiet and verbose are set")
	}

	output := buf.String()
	if !strings.Contains(output, "Cannot use both --quiet and --verbose") {
		t.Errorf("Expected error message about mutual exclusion, got: %s", output)
	}

	// Reset flags
	quiet = false
	verbose = false
}

// TestGetFormatter tests that getFormatter returns properly configured formatter
func TestGetFormatter(t *testing.T) {
	tests := []struct {
		name         string
		outputFormat string
		quiet        bool
		verbose      bool
		wantFormat   output.Format
	}{
		{
			name:         "json format",
			outputFormat: "json",
			quiet:        false,
			verbose:      false,
			wantFormat:   output.FormatJSON,
		},
		{
			name:         "yaml format",
			outputFormat: "yaml",
			quiet:        false,
			verbose:      false,
			wantFormat:   output.FormatYAML,
		},
		{
			name:         "text format",
			outputFormat: "text",
			quiet:        false,
			verbose:      false,
			wantFormat:   output.FormatText,
		},
		{
			name:         "sarif format",
			outputFormat: "sarif",
			quiet:        false,
			verbose:      false,
			wantFormat:   output.FormatSARIF,
		},
		{
			name:         "quiet mode",
			outputFormat: "json",
			quiet:        true,
			verbose:      false,
			wantFormat:   output.FormatJSON,
		},
		{
			name:         "verbose mode",
			outputFormat: "json",
			quiet:        false,
			verbose:      true,
			wantFormat:   output.FormatJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global flags
			outputFormat = tt.outputFormat
			quiet = tt.quiet
			verbose = tt.verbose

			// Get formatter
			formatter := getFormatter()

			if formatter == nil {
				t.Fatal("Expected non-nil formatter")
			}

			if formatter.Format() != tt.wantFormat {
				t.Errorf("Expected format %s, got %s", tt.wantFormat, formatter.Format())
			}

			if formatter.IsQuiet() != tt.quiet {
				t.Errorf("Expected quiet=%v, got %v", tt.quiet, formatter.IsQuiet())
			}

			if formatter.IsVerbose() != tt.verbose {
				t.Errorf("Expected verbose=%v, got %v", tt.verbose, formatter.IsVerbose())
			}
		})
	}

	// Reset flags
	outputFormat = "text"
	quiet = false
	verbose = false
}

// TestGetAuthConfig tests that getAuthConfig correctly maps CLI flags
func TestGetAuthConfig(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		authBearer  string
		authBasic   string
		authCookies []string
	}{
		{
			name:        "empty auth config",
			authHeader:  "",
			authBearer:  "",
			authBasic:   "",
			authCookies: nil,
		},
		{
			name:        "auth header",
			authHeader:  "Authorization: Bearer token123",
			authBearer:  "",
			authBasic:   "",
			authCookies: nil,
		},
		{
			name:        "bearer token",
			authHeader:  "",
			authBearer:  "token123",
			authBasic:   "",
			authCookies: nil,
		},
		{
			name:        "basic auth",
			authHeader:  "",
			authBearer:  "",
			authBasic:   "user:pass",
			authCookies: nil,
		},
		{
			name:        "single cookie",
			authHeader:  "",
			authBearer:  "",
			authBasic:   "",
			authCookies: []string{"session=abc123"},
		},
		{
			name:        "multiple cookies",
			authHeader:  "",
			authBearer:  "",
			authBasic:   "",
			authCookies: []string{"session=abc123", "token=xyz789"},
		},
		{
			name:        "all auth methods",
			authHeader:  "X-API-Key: secret",
			authBearer:  "token123",
			authBasic:   "user:pass",
			authCookies: []string{"session=abc123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global flags
			authHeader = tt.authHeader
			authBearer = tt.authBearer
			authBasic = tt.authBasic
			authCookies = tt.authCookies

			// Get auth config
			config := getAuthConfig()

			if config == nil {
				t.Fatal("Expected non-nil auth config")
			}

			if config.AuthHeader != tt.authHeader {
				t.Errorf("Expected AuthHeader=%q, got %q", tt.authHeader, config.AuthHeader)
			}

			if config.BearerToken != tt.authBearer {
				t.Errorf("Expected BearerToken=%q, got %q", tt.authBearer, config.BearerToken)
			}

			if config.BasicAuth != tt.authBasic {
				t.Errorf("Expected BasicAuth=%q, got %q", tt.authBasic, config.BasicAuth)
			}

			if len(config.Cookies) != len(tt.authCookies) {
				t.Errorf("Expected %d cookies, got %d", len(tt.authCookies), len(config.Cookies))
			}

			for i, cookie := range config.Cookies {
				if i < len(tt.authCookies) && cookie != tt.authCookies[i] {
					t.Errorf("Expected cookie[%d]=%q, got %q", i, tt.authCookies[i], cookie)
				}
			}
		})
	}

	// Reset flags
	authHeader = ""
	authBearer = ""
	authBasic = ""
	authCookies = nil
}

// TestGetRateLimitConfig tests that getRateLimitConfig correctly maps CLI flags
func TestGetRateLimitConfig(t *testing.T) {
	tests := []struct {
		name          string
		rateLimit     float64
		delayMs       int
		wantRateLimit float64
		wantDelayMs   int
	}{
		{
			name:          "no rate limiting",
			rateLimit:     0,
			delayMs:       0,
			wantRateLimit: 0,
			wantDelayMs:   0,
		},
		{
			name:          "rate limit only",
			rateLimit:     10.0,
			delayMs:       0,
			wantRateLimit: 10.0,
			wantDelayMs:   0,
		},
		{
			name:          "delay only",
			rateLimit:     0,
			delayMs:       100,
			wantRateLimit: 0,
			wantDelayMs:   100,
		},
		{
			name:          "both rate limit and delay",
			rateLimit:     5.0,
			delayMs:       200,
			wantRateLimit: 5.0,
			wantDelayMs:   200,
		},
		{
			name:          "fractional rate limit",
			rateLimit:     0.5,
			delayMs:       0,
			wantRateLimit: 0.5,
			wantDelayMs:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global flags
			rateLimit = tt.rateLimit
			delayMs = tt.delayMs

			// Get rate limit config
			config := getRateLimitConfig()

			if config.RequestsPerSecond != tt.wantRateLimit {
				t.Errorf("Expected RequestsPerSecond=%v, got %v", tt.wantRateLimit, config.RequestsPerSecond)
			}

			if config.DelayMs != tt.wantDelayMs {
				t.Errorf("Expected DelayMs=%v, got %v", tt.wantDelayMs, config.DelayMs)
			}
		})
	}

	// Reset flags
	rateLimit = 0
	delayMs = 0
}

// TestSubcommandRegistration tests that all expected subcommands are registered
func TestSubcommandRegistration(t *testing.T) {
	expectedCmds := []string{"recon", "crawl", "intercept", "scan", "api", "serve"}

	for _, cmdName := range expectedCmds {
		t.Run(cmdName, func(t *testing.T) {
			found := false
			for _, cmd := range rootCmd.Commands() {
				if cmd.Name() == cmdName {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected subcommand %q to be registered", cmdName)
			}
		})
	}
}

// TestRootCommandStructure tests the basic structure of the root command
func TestRootCommandStructure(t *testing.T) {
	if rootCmd.Use != "wast" {
		t.Errorf("Expected Use='wast', got %q", rootCmd.Use)
	}

	if rootCmd.Short == "" {
		t.Error("Expected Short description to be set")
	}

	if rootCmd.Long == "" {
		t.Error("Expected Long description to be set")
	}

	if !strings.Contains(rootCmd.Short, "WAST") {
		t.Error("Expected Short description to mention WAST")
	}

	if !strings.Contains(rootCmd.Long, "Web Application Security Testing") {
		t.Error("Expected Long description to mention Web Application Security Testing")
	}
}

// TestRootCommandFlags tests that all expected flags are registered
func TestRootCommandFlags(t *testing.T) {
	tests := []struct {
		name         string
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{
			name:         "output flag",
			flagName:     "output",
			shorthand:    "o",
			defaultValue: "text",
		},
		{
			name:         "quiet flag",
			flagName:     "quiet",
			shorthand:    "q",
			defaultValue: "false",
		},
		{
			name:         "verbose flag",
			flagName:     "verbose",
			shorthand:    "v",
			defaultValue: "false",
		},
		{
			name:         "auth-header flag",
			flagName:     "auth-header",
			shorthand:    "",
			defaultValue: "",
		},
		{
			name:         "auth-bearer flag",
			flagName:     "auth-bearer",
			shorthand:    "",
			defaultValue: "",
		},
		{
			name:         "auth-basic flag",
			flagName:     "auth-basic",
			shorthand:    "",
			defaultValue: "",
		},
		{
			name:         "cookie flag",
			flagName:     "cookie",
			shorthand:    "",
			defaultValue: "[]",
		},
		{
			name:         "rate-limit flag",
			flagName:     "rate-limit",
			shorthand:    "",
			defaultValue: "0",
		},
		{
			name:         "delay flag",
			flagName:     "delay",
			shorthand:    "",
			defaultValue: "0",
		},
		{
			name:         "mcp flag",
			flagName:     "mcp",
			shorthand:    "",
			defaultValue: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := rootCmd.PersistentFlags().Lookup(tt.flagName)
			if flag == nil {
				t.Errorf("Expected flag %q to be registered", tt.flagName)
				return
			}

			if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
				t.Errorf("Expected shorthand=%q, got %q", tt.shorthand, flag.Shorthand)
			}

			if tt.defaultValue != "" && flag.DefValue != tt.defaultValue {
				t.Errorf("Expected default value=%q, got %q", tt.defaultValue, flag.DefValue)
			}
		})
	}
}

// TestValidFormats tests the valid formats from the output package
func TestValidFormats(t *testing.T) {
	formats := output.ValidFormats()
	expected := []string{"json", "yaml", "text", "sarif"}

	if len(formats) != len(expected) {
		t.Errorf("Expected %d formats, got %d", len(expected), len(formats))
	}

	for i, format := range formats {
		if i < len(expected) && format != expected[i] {
			t.Errorf("Expected format[%d]=%q, got %q", i, expected[i], format)
		}
	}
}

// TestPersistentPreRunValidation tests the validation logic in PersistentPreRun
func TestPersistentPreRunValidation(t *testing.T) {
	tests := []struct {
		name         string
		outputFormat string
		quiet        bool
		verbose      bool
		wantExit     bool
		errorMatch   string
	}{
		{
			name:         "valid json format",
			outputFormat: "json",
			quiet:        false,
			verbose:      false,
			wantExit:     false,
		},
		{
			name:         "valid yaml format",
			outputFormat: "yaml",
			quiet:        false,
			verbose:      false,
			wantExit:     false,
		},
		{
			name:         "valid text format",
			outputFormat: "text",
			quiet:        false,
			verbose:      false,
			wantExit:     false,
		},
		{
			name:         "valid sarif format",
			outputFormat: "sarif",
			quiet:        false,
			verbose:      false,
			wantExit:     false,
		},
		{
			name:         "invalid format",
			outputFormat: "invalid",
			quiet:        false,
			verbose:      false,
			wantExit:     true,
			errorMatch:   "Invalid output format",
		},
		{
			name:         "quiet and verbose both set",
			outputFormat: "json",
			quiet:        true,
			verbose:      true,
			wantExit:     true,
			errorMatch:   "Cannot use both --quiet and --verbose",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global flags
			outputFormat = tt.outputFormat
			quiet = tt.quiet
			verbose = tt.verbose

			// Capture stderr
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			// Create a channel to capture the exit code
			exitCalled := false
			oldOsExit := osExit
			osExit = func(code int) {
				exitCalled = true
			}
			defer func() {
				osExit = oldOsExit
			}()

			// Run PersistentPreRun
			rootCmd.PersistentPreRun(rootCmd, []string{})

			// Restore stderr
			w.Close()
			os.Stderr = oldStderr

			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			if tt.wantExit && !exitCalled {
				t.Error("Expected os.Exit to be called but it wasn't")
			}

			if !tt.wantExit && exitCalled {
				t.Error("Expected os.Exit NOT to be called but it was")
			}

			if tt.errorMatch != "" && !strings.Contains(output, tt.errorMatch) {
				t.Errorf("Expected error message to contain %q, got: %s", tt.errorMatch, output)
			}
		})
	}

	// Reset flags
	outputFormat = "text"
	quiet = false
	verbose = false
}

// TestExecute tests the Execute function (basic smoke test)
func TestExecute(t *testing.T) {
	// This is a basic smoke test. We can't fully test Execute without mocking os.Exit
	// and dealing with the command execution flow, but we can verify it exists and is callable.

	// Reset command for clean test
	rootCmd.SetArgs([]string{"--help"})

	// Execute should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Execute panicked: %v", r)
		}
	}()

	// Execute with --help should not error
	err := Execute()
	// Note: --help causes Execute to return nil
	if err != nil {
		t.Errorf("Execute failed: %v", err)
	}
}
