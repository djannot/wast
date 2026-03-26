package urlutil

import (
	"strings"
	"testing"
)

func TestValidateTargetURL(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expected      string
		shouldError   bool
		errorContains string
	}{
		// Valid URLs - should normalize
		{
			name:     "valid URL with https scheme",
			input:    "https://example.com",
			expected: "https://example.com",
		},
		{
			name:     "valid URL with http scheme",
			input:    "http://example.com",
			expected: "http://example.com",
		},
		{
			name:     "URL without scheme - should add https",
			input:    "example.com",
			expected: "https://example.com",
		},
		{
			name:     "URL with path",
			input:    "https://example.com/path/to/resource",
			expected: "https://example.com/path/to/resource",
		},
		{
			name:     "URL with query parameters",
			input:    "https://example.com/search?q=test",
			expected: "https://example.com/search?q=test",
		},
		{
			name:     "URL with port",
			input:    "https://example.com:8443",
			expected: "https://example.com:8443",
		},
		{
			name:     "URL with port and path",
			input:    "http://example.com:8080/api",
			expected: "http://example.com:8080/api",
		},
		{
			name:     "URL with subdomain",
			input:    "https://api.example.com",
			expected: "https://api.example.com",
		},
		{
			name:     "URL without scheme and with subdomain",
			input:    "api.example.com",
			expected: "https://api.example.com",
		},
		{
			name:     "URL with whitespace - should trim",
			input:    "  https://example.com  ",
			expected: "https://example.com",
		},
		{
			name:     "URL without scheme and with whitespace",
			input:    "  example.com  ",
			expected: "https://example.com",
		},

		// IPv4 addresses
		{
			name:     "IPv4 localhost",
			input:    "http://127.0.0.1",
			expected: "http://127.0.0.1",
		},
		{
			name:     "IPv4 with port",
			input:    "http://192.168.1.1:8080",
			expected: "http://192.168.1.1:8080",
		},
		{
			name:     "IPv4 without scheme",
			input:    "192.168.1.1",
			expected: "https://192.168.1.1",
		},

		// IPv6 addresses
		{
			name:     "IPv6 localhost",
			input:    "http://[::1]",
			expected: "http://[::1]",
		},
		{
			name:     "IPv6 with port",
			input:    "https://[2001:db8::1]:8080",
			expected: "https://[2001:db8::1]:8080",
		},

		// Internationalized Domain Names (IDN)
		{
			name:     "IDN domain",
			input:    "https://münchen.de",
			expected: "https://xn--mnchen-3ya.de",
		},

		// Error cases - empty string
		{
			name:          "empty string",
			input:         "",
			shouldError:   true,
			errorContains: "cannot be empty",
		},
		{
			name:          "whitespace only",
			input:         "   ",
			shouldError:   true,
			errorContains: "cannot be empty",
		},

		// Error cases - invalid schemes
		{
			name:          "ftp scheme",
			input:         "ftp://example.com",
			shouldError:   true,
			errorContains: "got scheme 'ftp'",
		},
		{
			name:          "file scheme",
			input:         "file:///etc/passwd",
			shouldError:   true,
			errorContains: "got scheme 'file'",
		},
		{
			name:          "custom scheme",
			input:         "custom://example.com",
			shouldError:   true,
			errorContains: "got scheme 'custom'",
		},

		// Error cases - malformed URLs
		{
			name:          "double slashes in path",
			input:         "http://",
			shouldError:   true,
			errorContains: "must include a host",
		},
		{
			name:          "scheme without host",
			input:         "https://",
			shouldError:   true,
			errorContains: "must include a host",
		},
		{
			name:          "invalid port - too high",
			input:         "http://example.com:99999",
			shouldError:   true,
			errorContains: "port number must be between",
		},
		{
			name:          "invalid port - zero",
			input:         "http://example.com:0",
			shouldError:   true,
			errorContains: "port number must be between",
		},
		{
			name:          "invalid port - negative",
			input:         "http://example.com:-1",
			shouldError:   true,
			errorContains: "invalid port",
		},
		{
			name:          "invalid port - non-numeric",
			input:         "http://example.com:abc",
			shouldError:   true,
			errorContains: "invalid port",
		},

		// Error cases - invalid domains
		{
			name:          "domain starting with hyphen",
			input:         "https://-example.com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "domain ending with hyphen",
			input:         "https://example-.com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "domain with double dots",
			input:         "https://example..com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "domain starting with dot",
			input:         "https://.example.com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "domain ending with dot",
			input:         "https://example.com.",
			shouldError:   true,
			errorContains: "invalid domain",
		},

		// Error cases - invalid IPv6
		{
			name:          "invalid IPv6",
			input:         "http://[invalid]",
			shouldError:   true,
			errorContains: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateTargetURL(tt.input)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain '%s', got: %s", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result != tt.expected {
					t.Errorf("expected '%s', got '%s'", tt.expected, result)
				}
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expected      string
		shouldError   bool
		errorContains string
	}{
		// Valid domains
		{
			name:     "simple domain",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "subdomain",
			input:    "api.example.com",
			expected: "api.example.com",
		},
		{
			name:     "multiple subdomains",
			input:    "api.staging.example.com",
			expected: "api.staging.example.com",
		},
		{
			name:     "domain with hyphens",
			input:    "my-example-site.com",
			expected: "my-example-site.com",
		},
		{
			name:     "domain with numbers",
			input:    "example123.com",
			expected: "example123.com",
		},
		{
			name:     "TLD with multiple parts",
			input:    "example.co.uk",
			expected: "example.co.uk",
		},
		{
			name:     "domain with whitespace - should trim",
			input:    "  example.com  ",
			expected: "example.com",
		},

		// Stripping schemes and ports
		{
			name:     "domain with https scheme - should strip",
			input:    "https://example.com",
			expected: "example.com",
		},
		{
			name:     "domain with http scheme - should strip",
			input:    "http://example.com",
			expected: "example.com",
		},
		{
			name:     "domain with port - should strip",
			input:    "example.com:443",
			expected: "example.com",
		},
		{
			name:     "domain with scheme and port - should strip both",
			input:    "https://example.com:443",
			expected: "example.com",
		},
		{
			name:     "domain with scheme, port, and path - should extract domain",
			input:    "https://example.com:443/path",
			expected: "example.com",
		},

		// IP addresses
		{
			name:     "IPv4 address",
			input:    "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv4 localhost",
			input:    "127.0.0.1",
			expected: "127.0.0.1",
		},
		{
			name:     "IPv6 address",
			input:    "2001:db8::1",
			expected: "2001:db8::1",
		},
		{
			name:     "IPv6 localhost",
			input:    "::1",
			expected: "::1",
		},
		{
			name:     "IPv6 with brackets - should remove",
			input:    "[2001:db8::1]",
			expected: "2001:db8::1",
		},

		// Internationalized Domain Names (IDN)
		{
			name:     "IDN domain",
			input:    "münchen.de",
			expected: "xn--mnchen-3ya.de",
		},
		{
			name:     "IDN with scheme",
			input:    "https://münchen.de",
			expected: "xn--mnchen-3ya.de",
		},

		// Error cases - empty
		{
			name:          "empty string",
			input:         "",
			shouldError:   true,
			errorContains: "cannot be empty",
		},
		{
			name:          "whitespace only",
			input:         "   ",
			shouldError:   true,
			errorContains: "cannot be empty",
		},

		// Error cases - invalid formats
		{
			name:          "domain starting with dot",
			input:         ".example.com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "domain ending with dot",
			input:         "example.com.",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "domain with double dots",
			input:         "example..com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "domain starting with hyphen",
			input:         "-example.com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "domain ending with hyphen",
			input:         "example-.com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "label starting with hyphen",
			input:         "ex-ample.-test.com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "label ending with hyphen",
			input:         "example.test-.com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "domain with spaces",
			input:         "example .com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "domain with special characters",
			input:         "example@.com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "single label too long",
			input:         "a" + strings.Repeat("b", 63) + ".com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
		{
			name:          "domain too long",
			input:         strings.Repeat("a.", 127) + "com",
			shouldError:   true,
			errorContains: "invalid domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateDomain(tt.input)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain '%s', got: %s", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result != tt.expected {
					t.Errorf("expected '%s', got '%s'", tt.expected, result)
				}
			}
		})
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid simple domain", "example.com", true},
		{"valid subdomain", "api.example.com", true},
		{"valid with numbers", "example123.com", true},
		{"valid with hyphens", "my-example.com", true},
		{"valid single label", "localhost", true},
		{"empty string", "", false},
		{"too long", strings.Repeat("a", 254), false},
		{"starts with dot", ".example.com", false},
		{"ends with dot", "example.com.", false},
		{"double dots", "example..com", false},
		{"label too long", strings.Repeat("a", 64) + ".com", false},
		{"starts with hyphen", "-example.com", false},
		{"ends with hyphen", "example-.com", false},
		{"label starts with hyphen", "example.-test.com", false},
		{"label ends with hyphen", "example.test-.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidDomain(tt.input)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
