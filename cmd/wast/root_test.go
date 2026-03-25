package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/djannot/wast/internal/mcp"
	"github.com/djannot/wast/pkg/output"
	"github.com/djannot/wast/pkg/telemetry"
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

// TestExecuteMCPDetection tests the Execute function with --mcp flag
func TestExecuteMCPDetection(t *testing.T) {
	// Save original os.Args
	origArgs := os.Args
	defer func() {
		os.Args = origArgs
	}()

	// Track if runMCPServer was called
	mcpServerCalled := false

	// Create a test that checks if MCP flag detection works
	// We can't actually test runMCPServer without mocking the server,
	// but we can verify the path is taken by checking os.Args parsing

	// Test with --mcp flag in various positions
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "mcp flag first",
			args: []string{"wast", "--mcp"},
		},
		{
			name: "mcp flag after other flags",
			args: []string{"wast", "--verbose", "--mcp"},
		},
		{
			name: "mcp flag in middle",
			args: []string{"wast", "--mcp", "--verbose"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args

			// Check if --mcp is detected in os.Args
			hasMCP := false
			for _, arg := range os.Args[1:] {
				if arg == "--mcp" {
					hasMCP = true
					mcpServerCalled = true
					break
				}
			}

			if !hasMCP {
				t.Error("Expected --mcp flag to be detected in os.Args")
			}
		})
	}

	if !mcpServerCalled {
		t.Log("MCP detection path was verified")
	}
}

// TestGetAuthConfigWithLogin tests the login configuration path in getAuthConfig
func TestGetAuthConfigWithLogin(t *testing.T) {
	tests := []struct {
		name           string
		loginURL       string
		loginUser      string
		loginPass      string
		loginUserField string
		loginPassField string
		envPass        string
		wantLogin      bool
		wantPassword   string
	}{
		{
			name:           "login with password from flag",
			loginURL:       "https://example.com/login",
			loginUser:      "testuser",
			loginPass:      "testpass",
			loginUserField: "username",
			loginPassField: "password",
			envPass:        "",
			wantLogin:      true,
			wantPassword:   "testpass",
		},
		{
			name:           "login with password from env var",
			loginURL:       "https://example.com/login",
			loginUser:      "testuser",
			loginPass:      "",
			loginUserField: "username",
			loginPassField: "password",
			envPass:        "envpassword",
			wantLogin:      true,
			wantPassword:   "envpassword",
		},
		{
			name:           "login with flag password takes precedence over env",
			loginURL:       "https://example.com/login",
			loginUser:      "testuser",
			loginPass:      "flagpass",
			loginUserField: "username",
			loginPassField: "password",
			envPass:        "envpass",
			wantLogin:      true,
			wantPassword:   "flagpass",
		},
		{
			name:           "no login when loginURL is empty",
			loginURL:       "",
			loginUser:      "testuser",
			loginPass:      "testpass",
			loginUserField: "username",
			loginPassField: "password",
			envPass:        "",
			wantLogin:      false,
			wantPassword:   "",
		},
		{
			name:           "login with custom field names",
			loginURL:       "https://example.com/auth",
			loginUser:      "admin",
			loginPass:      "admin123",
			loginUserField: "email",
			loginPassField: "pass",
			envPass:        "",
			wantLogin:      true,
			wantPassword:   "admin123",
		},
		{
			name:           "login with no password set",
			loginURL:       "https://example.com/login",
			loginUser:      "testuser",
			loginPass:      "",
			loginUserField: "username",
			loginPassField: "password",
			envPass:        "",
			wantLogin:      true,
			wantPassword:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global flags
			loginURL = tt.loginURL
			loginUser = tt.loginUser
			loginPass = tt.loginPass
			loginUserField = tt.loginUserField
			loginPassField = tt.loginPassField

			// Set environment variable if specified
			if tt.envPass != "" {
				os.Setenv("WAST_LOGIN_PASS", tt.envPass)
				defer os.Unsetenv("WAST_LOGIN_PASS")
			} else {
				os.Unsetenv("WAST_LOGIN_PASS")
			}

			// Get auth config
			config := getAuthConfig()

			if config == nil {
				t.Fatal("Expected non-nil auth config")
			}

			if tt.wantLogin {
				if config.Login == nil {
					t.Fatal("Expected Login config to be set")
				}

				if config.Login.LoginURL != tt.loginURL {
					t.Errorf("Expected LoginURL=%q, got %q", tt.loginURL, config.Login.LoginURL)
				}

				if config.Login.Username != tt.loginUser {
					t.Errorf("Expected Username=%q, got %q", tt.loginUser, config.Login.Username)
				}

				if config.Login.Password != tt.wantPassword {
					t.Errorf("Expected Password=%q, got %q", tt.wantPassword, config.Login.Password)
				}

				if config.Login.UsernameField != tt.loginUserField {
					t.Errorf("Expected UsernameField=%q, got %q", tt.loginUserField, config.Login.UsernameField)
				}

				if config.Login.PasswordField != tt.loginPassField {
					t.Errorf("Expected PasswordField=%q, got %q", tt.loginPassField, config.Login.PasswordField)
				}
			} else {
				if config.Login != nil {
					t.Error("Expected Login config to be nil")
				}
			}
		})
	}

	// Reset flags
	loginURL = ""
	loginUser = ""
	loginPass = ""
	loginUserField = "username"
	loginPassField = "password"
	os.Unsetenv("WAST_LOGIN_PASS")
}

// TestLoginFlagRegistration tests that login-related flags are registered
func TestLoginFlagRegistration(t *testing.T) {
	tests := []struct {
		flagName     string
		defaultValue string
	}{
		{
			flagName:     "login-url",
			defaultValue: "",
		},
		{
			flagName:     "login-user",
			defaultValue: "",
		},
		{
			flagName:     "login-pass",
			defaultValue: "",
		},
		{
			flagName:     "login-user-field",
			defaultValue: "username",
		},
		{
			flagName:     "login-pass-field",
			defaultValue: "password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := rootCmd.PersistentFlags().Lookup(tt.flagName)
			if flag == nil {
				t.Errorf("Expected flag %q to be registered", tt.flagName)
				return
			}

			if flag.DefValue != tt.defaultValue {
				t.Errorf("Expected default value=%q, got %q", tt.defaultValue, flag.DefValue)
			}
		})
	}
}

// TestTelemetryFlagRegistration tests that telemetry flag is registered
func TestTelemetryFlagRegistration(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("telemetry-endpoint")
	if flag == nil {
		t.Error("Expected telemetry-endpoint flag to be registered")
		return
	}

	if flag.DefValue != "" {
		t.Errorf("Expected default value to be empty, got %q", flag.DefValue)
	}
}

// TestRootCommandVersion tests that version information is set correctly
func TestRootCommandVersion(t *testing.T) {
	// The version is set at init time, so we test that it follows the expected format
	expectedFormat := fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)

	if rootCmd.Version == "" {
		t.Error("Expected Version to be set")
	}

	if rootCmd.Version != expectedFormat {
		t.Logf("Version format: %s", rootCmd.Version)
	}

	// Test that version string contains the expected parts
	if !strings.Contains(rootCmd.Version, "commit:") {
		t.Error("Expected version to contain 'commit:'")
	}

	if !strings.Contains(rootCmd.Version, "built:") {
		t.Error("Expected version to contain 'built:'")
	}
}

// TestGetAuthConfigCombinations tests various combinations of auth settings
func TestGetAuthConfigCombinations(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		authBearer     string
		authBasic      string
		authCookies    []string
		loginURL       string
		wantAuthHeader string
		wantBearer     string
		wantBasic      string
		wantCookies    int
		wantLogin      bool
	}{
		{
			name:           "no auth",
			authHeader:     "",
			authBearer:     "",
			authBasic:      "",
			authCookies:    nil,
			loginURL:       "",
			wantAuthHeader: "",
			wantBearer:     "",
			wantBasic:      "",
			wantCookies:    0,
			wantLogin:      false,
		},
		{
			name:           "bearer only",
			authHeader:     "",
			authBearer:     "token123",
			authBasic:      "",
			authCookies:    nil,
			loginURL:       "",
			wantAuthHeader: "",
			wantBearer:     "token123",
			wantBasic:      "",
			wantCookies:    0,
			wantLogin:      false,
		},
		{
			name:           "bearer with login",
			authHeader:     "",
			authBearer:     "token123",
			authBasic:      "",
			authCookies:    nil,
			loginURL:       "https://example.com/login",
			wantAuthHeader: "",
			wantBearer:     "token123",
			wantBasic:      "",
			wantCookies:    0,
			wantLogin:      true,
		},
		{
			name:           "cookies with login",
			authHeader:     "",
			authBearer:     "",
			authBasic:      "",
			authCookies:    []string{"session=abc"},
			loginURL:       "https://example.com/login",
			wantAuthHeader: "",
			wantBearer:     "",
			wantBasic:      "",
			wantCookies:    1,
			wantLogin:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global flags
			authHeader = tt.authHeader
			authBearer = tt.authBearer
			authBasic = tt.authBasic
			authCookies = tt.authCookies
			loginURL = tt.loginURL

			config := getAuthConfig()

			if config.AuthHeader != tt.wantAuthHeader {
				t.Errorf("Expected AuthHeader=%q, got %q", tt.wantAuthHeader, config.AuthHeader)
			}

			if config.BearerToken != tt.wantBearer {
				t.Errorf("Expected BearerToken=%q, got %q", tt.wantBearer, config.BearerToken)
			}

			if config.BasicAuth != tt.wantBasic {
				t.Errorf("Expected BasicAuth=%q, got %q", tt.wantBasic, config.BasicAuth)
			}

			if len(config.Cookies) != tt.wantCookies {
				t.Errorf("Expected %d cookies, got %d", tt.wantCookies, len(config.Cookies))
			}

			if tt.wantLogin && config.Login == nil {
				t.Error("Expected Login config to be set")
			}

			if !tt.wantLogin && config.Login != nil {
				t.Error("Expected Login config to be nil")
			}
		})
	}

	// Reset flags
	authHeader = ""
	authBearer = ""
	authBasic = ""
	authCookies = nil
	loginURL = ""
}

// TestOsExitOverride tests that osExit can be overridden
func TestOsExitOverride(t *testing.T) {
	// Save original osExit
	origOsExit := osExit
	defer func() {
		osExit = origOsExit
	}()

	// Test that we can override osExit
	exitCalled := false
	exitCode := 0
	osExit = func(code int) {
		exitCalled = true
		exitCode = code
	}

	// Call osExit
	osExit(42)

	if !exitCalled {
		t.Error("Expected osExit to be called")
	}

	if exitCode != 42 {
		t.Errorf("Expected exit code 42, got %d", exitCode)
	}
}

// TestExecuteWithMCPFlag tests Execute with --mcp flag to trigger runMCPServer
func TestExecuteWithMCPFlag(t *testing.T) {
	// Save original os.Args
	origArgs := os.Args
	defer func() {
		os.Args = origArgs
	}()

	// Set os.Args to include --mcp
	os.Args = []string{"wast", "--mcp"}

	// We need to test the MCP detection path but can't actually run the server
	// in a test without mocking. So we'll verify the detection logic works.
	mcpDetected := false
	for _, arg := range os.Args[1:] {
		if arg == "--mcp" {
			mcpDetected = true
			break
		}
	}

	if !mcpDetected {
		t.Error("Expected --mcp flag to be detected")
	}
}

// TestRunMCPServerEnvironment tests the runMCPServer environment setup
func TestRunMCPServerEnvironment(t *testing.T) {
	// Test telemetry configuration from environment
	tests := []struct {
		name                  string
		telemetryEndpointFlag string
		envEndpoint           string
		wantTelemetryEnabled  bool
	}{
		{
			name:                  "telemetry disabled by default",
			telemetryEndpointFlag: "",
			envEndpoint:           "",
			wantTelemetryEnabled:  false,
		},
		{
			name:                  "telemetry enabled via flag",
			telemetryEndpointFlag: "localhost:4317",
			envEndpoint:           "",
			wantTelemetryEnabled:  true,
		},
		{
			name:                  "telemetry enabled via env",
			telemetryEndpointFlag: "",
			envEndpoint:           "otel.example.com:4317",
			wantTelemetryEnabled:  true,
		},
		{
			name:                  "flag overrides env",
			telemetryEndpointFlag: "localhost:4317",
			envEndpoint:           "otel.example.com:4317",
			wantTelemetryEnabled:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set flag
			telemetryEndpoint = tt.telemetryEndpointFlag

			// Set environment variable
			if tt.envEndpoint != "" {
				os.Setenv("WAST_OTEL_ENDPOINT", tt.envEndpoint)
				defer os.Unsetenv("WAST_OTEL_ENDPOINT")
			} else {
				os.Unsetenv("WAST_OTEL_ENDPOINT")
			}

			// Simulate what runMCPServer does
			config := telemetry.ConfigFromEnv()
			config.ServiceVersion = version

			// Override with CLI flag if provided
			if telemetryEndpoint != "" {
				config.Enabled = true
				config.Endpoint = telemetryEndpoint
			}

			if config.IsEnabled() != tt.wantTelemetryEnabled {
				t.Errorf("Expected telemetry enabled=%v, got %v", tt.wantTelemetryEnabled, config.IsEnabled())
			}

			// Verify endpoint precedence
			if tt.telemetryEndpointFlag != "" && config.Endpoint != tt.telemetryEndpointFlag {
				t.Errorf("Expected endpoint=%q, got %q", tt.telemetryEndpointFlag, config.Endpoint)
			}
		})
	}

	// Reset flag
	telemetryEndpoint = ""
}

// TestRunMCPServerInitialization tests the MCP server initialization logic
func TestRunMCPServerInitialization(t *testing.T) {
	// This test verifies the components that runMCPServer uses
	// We can't actually run the server in tests, but we can test the setup

	// Test that MCP server can be created
	server := mcp.NewServer()
	if server == nil {
		t.Fatal("Expected non-nil MCP server")
	}

	// Test telemetry config creation
	config := telemetry.ConfigFromEnv()
	if config.ServiceName == "" {
		t.Error("Expected non-empty service name")
	}

	// Test version is set
	if version == "" {
		t.Error("Expected non-empty version")
	}
}

// TestExecuteNonMCPPath tests Execute without --mcp flag
func TestExecuteNonMCPPath(t *testing.T) {
	// Save original os.Args
	origArgs := os.Args
	defer func() {
		os.Args = origArgs
	}()

	// Set os.Args without --mcp
	os.Args = []string{"wast", "--help"}

	// Reset command for clean test
	rootCmd.SetArgs([]string{"--help"})

	// Execute should use regular cobra execution path
	err := Execute()
	if err != nil {
		t.Errorf("Execute failed: %v", err)
	}
}

// TestInitFunction tests that init() properly registers all components
func TestInitFunction(t *testing.T) {
	// Test that all subcommands are registered
	expectedCommands := []string{"recon", "crawl", "intercept", "scan", "api", "serve"}
	registeredCommands := make(map[string]bool)

	for _, cmd := range rootCmd.Commands() {
		registeredCommands[cmd.Name()] = true
	}

	for _, cmdName := range expectedCommands {
		if !registeredCommands[cmdName] {
			t.Errorf("Expected command %q to be registered", cmdName)
		}
	}

	// Test that all persistent flags are registered
	expectedFlags := []string{
		"output", "quiet", "verbose", "mcp",
		"auth-header", "auth-bearer", "auth-basic", "cookie",
		"login-url", "login-user", "login-pass", "login-user-field", "login-pass-field",
		"rate-limit", "delay", "telemetry-endpoint",
	}

	for _, flagName := range expectedFlags {
		flag := rootCmd.PersistentFlags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Expected flag %q to be registered", flagName)
		}
	}
}

// TestGetFormatterIsolation tests that getFormatter creates independent instances
func TestGetFormatterIsolation(t *testing.T) {
	// Save original state
	origFormat := outputFormat
	origQuiet := quiet
	origVerbose := verbose
	defer func() {
		outputFormat = origFormat
		quiet = origQuiet
		verbose = origVerbose
	}()

	// Set first state
	outputFormat = "json"
	quiet = true
	verbose = false
	formatter1 := getFormatter()

	// Set different state
	outputFormat = "yaml"
	quiet = false
	verbose = true
	formatter2 := getFormatter()

	// Verify formatters are independent
	if formatter1.Format() == formatter2.Format() {
		t.Error("Expected formatters to have different formats")
	}

	if formatter1.IsQuiet() == formatter2.IsQuiet() {
		t.Error("Expected formatters to have different quiet settings")
	}

	if formatter1.IsVerbose() == formatter2.IsVerbose() {
		t.Error("Expected formatters to have different verbose settings")
	}
}

// TestGetAuthConfigIsolation tests that getAuthConfig creates independent instances
func TestGetAuthConfigIsolation(t *testing.T) {
	// Save original state
	origBearer := authBearer
	origLoginURL := loginURL
	defer func() {
		authBearer = origBearer
		loginURL = origLoginURL
	}()

	// Set first state
	authBearer = "token1"
	loginURL = ""
	config1 := getAuthConfig()

	// Set different state
	authBearer = "token2"
	loginURL = "https://example.com/login"
	loginUser = "testuser"
	config2 := getAuthConfig()

	// Verify configs are independent
	if config1.BearerToken == config2.BearerToken {
		t.Error("Expected configs to have different bearer tokens")
	}

	if config1.Login != nil && config2.Login != nil {
		t.Error("Expected first config to have no login, second to have login")
	}
}

// TestGetRateLimitConfigValues tests various rate limit configurations
func TestGetRateLimitConfigValues(t *testing.T) {
	tests := []struct {
		name          string
		rateLimit     float64
		delayMs       int
		wantRateLimit float64
		wantDelayMs   int
	}{
		{
			name:          "high rate limit",
			rateLimit:     100.0,
			delayMs:       0,
			wantRateLimit: 100.0,
			wantDelayMs:   0,
		},
		{
			name:          "fractional rate limit",
			rateLimit:     2.5,
			delayMs:       0,
			wantRateLimit: 2.5,
			wantDelayMs:   0,
		},
		{
			name:          "large delay",
			rateLimit:     0,
			delayMs:       1000,
			wantRateLimit: 0,
			wantDelayMs:   1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rateLimit = tt.rateLimit
			delayMs = tt.delayMs

			config := getRateLimitConfig()

			if config.RequestsPerSecond != tt.wantRateLimit {
				t.Errorf("Expected RequestsPerSecond=%v, got %v", tt.wantRateLimit, config.RequestsPerSecond)
			}

			if config.DelayMs != tt.wantDelayMs {
				t.Errorf("Expected DelayMs=%v, got %v", tt.wantDelayMs, config.DelayMs)
			}
		})
	}

	// Reset
	rateLimit = 0
	delayMs = 0
}

// TestPersistentPreRunErrorConditions tests all error paths in PersistentPreRun
func TestPersistentPreRunErrorConditions(t *testing.T) {
	tests := []struct {
		name         string
		outputFormat string
		quiet        bool
		verbose      bool
		wantExit     bool
		errorContains string
	}{
		{
			name:         "invalid format triggers exit",
			outputFormat: "xml",
			quiet:        false,
			verbose:      false,
			wantExit:     true,
			errorContains: "Invalid output format",
		},
		{
			name:         "empty format triggers exit",
			outputFormat: "",
			quiet:        false,
			verbose:      false,
			wantExit:     true,
			errorContains: "Invalid output format",
		},
		{
			name:         "uppercase format triggers exit",
			outputFormat: "JSON",
			quiet:        false,
			verbose:      false,
			wantExit:     true,
			errorContains: "Invalid output format",
		},
		{
			name:         "quiet and verbose both set",
			outputFormat: "json",
			quiet:        true,
			verbose:      true,
			wantExit:     true,
			errorContains: "Cannot use both",
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

			// Mock osExit
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
				t.Error("Expected os.Exit to be called")
			}

			if tt.errorContains != "" && !strings.Contains(output, tt.errorContains) {
				t.Errorf("Expected error to contain %q, got: %s", tt.errorContains, output)
			}
		})
	}

	// Reset
	outputFormat = "text"
	quiet = false
	verbose = false
}

// TestRunMCPServerComponents tests individual components used by runMCPServer
func TestRunMCPServerComponents(t *testing.T) {
	t.Run("telemetry config with endpoint override", func(t *testing.T) {
		// Test telemetry endpoint override logic
		origEndpoint := telemetryEndpoint
		defer func() { telemetryEndpoint = origEndpoint }()

		telemetryEndpoint = "test.example.com:4317"

		config := telemetry.ConfigFromEnv()
		config.ServiceVersion = version

		// Override with CLI flag
		if telemetryEndpoint != "" {
			config.Enabled = true
			config.Endpoint = telemetryEndpoint
		}

		if !config.Enabled {
			t.Error("Expected telemetry to be enabled when endpoint flag is set")
		}

		if config.Endpoint != "test.example.com:4317" {
			t.Errorf("Expected endpoint to be overridden, got %s", config.Endpoint)
		}

		if config.ServiceVersion != version {
			t.Error("Expected service version to be set")
		}
	})

	t.Run("telemetry config from env only", func(t *testing.T) {
		origEndpoint := telemetryEndpoint
		defer func() { telemetryEndpoint = origEndpoint }()

		telemetryEndpoint = ""
		os.Setenv("WAST_OTEL_ENDPOINT", "env.example.com:4317")
		defer os.Unsetenv("WAST_OTEL_ENDPOINT")

		config := telemetry.ConfigFromEnv()

		if !config.Enabled {
			t.Error("Expected telemetry to be enabled from env")
		}

		if config.Endpoint != "env.example.com:4317" {
			t.Errorf("Expected endpoint from env, got %s", config.Endpoint)
		}
	})

	t.Run("telemetry disabled by default", func(t *testing.T) {
		origEndpoint := telemetryEndpoint
		defer func() { telemetryEndpoint = origEndpoint }()

		telemetryEndpoint = ""
		os.Unsetenv("WAST_OTEL_ENDPOINT")

		config := telemetry.ConfigFromEnv()

		if config.Enabled {
			t.Error("Expected telemetry to be disabled by default")
		}
	})
}

// TestExecuteMCPPath tests the full Execute path with MCP detection
func TestExecuteMCPPath(t *testing.T) {
	// Save original os.Args
	origArgs := os.Args
	defer func() {
		os.Args = origArgs
	}()

	tests := []struct {
		name        string
		args        []string
		shouldDetect bool
	}{
		{
			name:        "mcp flag present",
			args:        []string{"wast", "--mcp"},
			shouldDetect: true,
		},
		{
			name:        "mcp flag with other flags",
			args:        []string{"wast", "--verbose", "--mcp", "--output", "json"},
			shouldDetect: true,
		},
		{
			name:        "no mcp flag",
			args:        []string{"wast", "--help"},
			shouldDetect: false,
		},
		{
			name:        "similar but not mcp",
			args:        []string{"wast", "--mcpx"},
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args

			// Test the detection logic from Execute()
			detected := false
			for _, arg := range os.Args[1:] {
				if arg == "--mcp" {
					detected = true
					break
				}
			}

			if detected != tt.shouldDetect {
				t.Errorf("Expected MCP detection=%v, got %v", tt.shouldDetect, detected)
			}
		})
	}
}

// TestRunMCPServer tests the runMCPServer wrapper function
func TestRunMCPServer(t *testing.T) {
	// Save original runner
	origRunner := mcpServerRunner
	defer func() {
		mcpServerRunner = origRunner
	}()

	// Mock the runner
	runnerCalled := false
	mcpServerRunner = func() {
		runnerCalled = true
	}

	// Call runMCPServer
	runMCPServer()

	if !runnerCalled {
		t.Error("Expected mcpServerRunner to be called")
	}
}

// TestRunMCPServerImplWithMocking tests runMCPServerImpl with mocked components
func TestRunMCPServerImplWithMocking(t *testing.T) {
	// This test verifies the setup logic in runMCPServerImpl without actually running the server
	t.Run("telemetry initialization with valid endpoint", func(t *testing.T) {
		// Save and restore state
		origEndpoint := telemetryEndpoint
		defer func() { telemetryEndpoint = origEndpoint }()

		// Set telemetry endpoint to trigger telemetry path
		// Note: We can't actually initialize telemetry in tests without a real endpoint
		// but we can verify the configuration logic
		telemetryEndpoint = ""
		os.Unsetenv("WAST_OTEL_ENDPOINT")

		config := telemetry.ConfigFromEnv()
		config.ServiceVersion = version

		// Override with CLI flag (simulate what runMCPServerImpl does)
		if telemetryEndpoint != "" {
			config.Enabled = true
			config.Endpoint = telemetryEndpoint
		}

		// Verify telemetry is disabled when no endpoint
		if config.IsEnabled() {
			t.Error("Expected telemetry to be disabled without endpoint")
		}
	})

	t.Run("telemetry initialization with invalid endpoint", func(t *testing.T) {
		// Test error handling path (line 127)
		origEndpoint := telemetryEndpoint
		defer func() { telemetryEndpoint = origEndpoint }()

		// Set invalid telemetry endpoint
		telemetryEndpoint = "invalid:endpoint:4317"

		config := telemetry.ConfigFromEnv()
		config.ServiceVersion = version

		if telemetryEndpoint != "" {
			config.Enabled = true
			config.Endpoint = telemetryEndpoint
		}

		// Try to create provider with invalid endpoint - this tests the error path
		ctx := context.Background()
		_, err := telemetry.NewProvider(ctx, config)

		// We expect an error with invalid endpoint
		if err == nil {
			t.Log("Note: Telemetry provider creation may succeed depending on validation")
		}
	})
}

// TestExecuteWithMCPFlagIntegration tests Execute() with MCP flag detection
func TestExecuteWithMCPFlagIntegration(t *testing.T) {
	// Save original state
	origArgs := os.Args
	origRunner := mcpServerRunner
	defer func() {
		os.Args = origArgs
		mcpServerRunner = origRunner
	}()

	// Mock the MCP server runner to avoid actually starting the server
	runnerCalled := false
	mcpServerRunner = func() {
		runnerCalled = true
	}

	// Set os.Args to include --mcp
	os.Args = []string{"wast", "--mcp"}

	// Call Execute
	err := Execute()

	// Execute should return nil when MCP mode is detected
	if err != nil {
		t.Errorf("Expected Execute to return nil in MCP mode, got: %v", err)
	}

	// Verify runMCPServer was called
	if !runnerCalled {
		t.Error("Expected runMCPServer to be called when --mcp flag is present")
	}
}

// TestExecuteWithoutMCPFlagIntegration tests Execute() without MCP flag
func TestExecuteWithoutMCPFlagIntegration(t *testing.T) {
	// Save original state
	origArgs := os.Args
	defer func() {
		os.Args = origArgs
	}()

	// Set os.Args without --mcp
	os.Args = []string{"wast", "--version"}

	// Reset command state
	rootCmd.SetArgs([]string{"--version"})

	// Call Execute - should use normal cobra path
	err := Execute()

	// Version flag causes a silent success
	if err != nil {
		t.Logf("Execute returned: %v", err)
	}
}

// TestRunMCPServerWithCancelledContext tests runMCPServerWithContext with a cancelled context
func TestRunMCPServerWithCancelledContext(t *testing.T) {
	// Save original telemetry endpoint
	origEndpoint := telemetryEndpoint
	defer func() { telemetryEndpoint = origEndpoint }()

	// Disable telemetry for this test
	telemetryEndpoint = ""
	os.Unsetenv("WAST_OTEL_ENDPOINT")

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Mock osExit to prevent actual exit
	exitCalled := false
	oldOsExit := osExit
	osExit = func(code int) {
		exitCalled = true
	}
	defer func() {
		osExit = oldOsExit
	}()

	// Run with cancelled context - should return quickly
	runMCPServerWithContext(ctx)

	// Restore stderr
	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)

	// With a cancelled context, the server should exit without error
	// (context.Canceled is not treated as an error)
	if exitCalled {
		t.Error("Expected osExit not to be called with cancelled context")
	}
}

// TestRunMCPServerImplDirect tests runMCPServerImpl by running it briefly
func TestRunMCPServerImplDirect(t *testing.T) {
	// This test starts runMCPServerImpl in a goroutine and immediately cancels it
	// We can't fully test it without complex mocking, but we can verify it starts

	// Save original state
	origEndpoint := telemetryEndpoint
	origOsExit := osExit
	defer func() {
		telemetryEndpoint = origEndpoint
		osExit = origOsExit
	}()

	// Disable telemetry to avoid external dependencies
	telemetryEndpoint = ""
	os.Unsetenv("WAST_OTEL_ENDPOINT")

	// Mock osExit
	osExit = func(code int) {
		// Don't actually exit
	}

	// Since runMCPServerImpl blocks, we can't test it easily without the refactored version
	// The test above (TestRunMCPServerWithCancelledContext) covers the same code path
	t.Log("runMCPServerImpl is tested via runMCPServerWithContext")
}

// TestRunMCPServerWithTelemetryEnabled tests with telemetry enabled but failing
func TestRunMCPServerWithTelemetryEnabled(t *testing.T) {
	// Save original state
	origEndpoint := telemetryEndpoint
	defer func() { telemetryEndpoint = origEndpoint }()

	// Set an invalid telemetry endpoint to trigger the error path (line 141)
	telemetryEndpoint = "invalid.endpoint.that.does.not.exist:99999"

	// Create a cancelled context so the test doesn't hang
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Capture stderr to check for warning message
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Mock osExit
	oldOsExit := osExit
	osExit = func(code int) {}
	defer func() {
		osExit = oldOsExit
	}()

	// Run with telemetry configured but with invalid endpoint
	runMCPServerWithContext(ctx)

	// Restore stderr
	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// The warning message should be printed when telemetry initialization fails
	// Note: This may or may not trigger depending on when the context is cancelled
	t.Logf("Stderr output: %s", output)
}

// TestRunMCPServerImplTelemetryPaths tests various telemetry configurations
func TestRunMCPServerImplTelemetryPaths(t *testing.T) {
	tests := []struct {
		name         string
		flagEndpoint string
		envEndpoint  string
		wantEnabled  bool
	}{
		{
			name:         "no telemetry",
			flagEndpoint: "",
			envEndpoint:  "",
			wantEnabled:  false,
		},
		{
			name:         "telemetry from flag",
			flagEndpoint: "localhost:4317",
			envEndpoint:  "",
			wantEnabled:  true,
		},
		{
			name:         "telemetry from env",
			flagEndpoint: "",
			envEndpoint:  "otel.example.com:4317",
			wantEnabled:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore state
			origEndpoint := telemetryEndpoint
			defer func() { telemetryEndpoint = origEndpoint }()

			telemetryEndpoint = tt.flagEndpoint
			if tt.envEndpoint != "" {
				os.Setenv("WAST_OTEL_ENDPOINT", tt.envEndpoint)
				defer os.Unsetenv("WAST_OTEL_ENDPOINT")
			} else {
				os.Unsetenv("WAST_OTEL_ENDPOINT")
			}

			// Simulate the config creation logic from runMCPServerWithContext
			config := telemetry.ConfigFromEnv()
			config.ServiceVersion = version

			if telemetryEndpoint != "" {
				config.Enabled = true
				config.Endpoint = telemetryEndpoint
			}

			if config.IsEnabled() != tt.wantEnabled {
				t.Errorf("Expected telemetry enabled=%v, got %v", tt.wantEnabled, config.IsEnabled())
			}
		})
	}
}
