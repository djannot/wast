// Package urlutil provides URL validation and sanitization utilities for WAST.
// This package ensures consistent handling of user-supplied URLs across MCP tools and CLI commands.
package urlutil

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

var (
	// domainRegex validates domain names (basic check for valid characters)
	domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
)

// ValidateTargetURL validates and normalizes a web URL for HTTP(S)-based tools.
// It ensures the URL has a valid HTTP(S) scheme, normalizes the format, and provides
// helpful error messages for AI agents to self-correct.
//
// Parameters:
//   - rawURL: The user-supplied URL string (may be missing scheme, have whitespace, etc.)
//
// Returns:
//   - Normalized URL string with https:// scheme if valid
//   - Error with actionable message if invalid
//
// Examples:
//   - "example.com" -> "https://example.com" (adds https scheme)
//   - "  http://example.com  " -> "http://example.com" (trims whitespace)
//   - "ftp://example.com" -> error (invalid scheme)
//   - "https://127.0.0.1:8080" -> "https://127.0.0.1:8080" (valid localhost)
func ValidateTargetURL(rawURL string) (string, error) {
	// Trim whitespace
	rawURL = strings.TrimSpace(rawURL)

	// Check for empty string
	if rawURL == "" {
		return "", fmt.Errorf("target URL cannot be empty")
	}

	// If URL doesn't have a scheme, add https:// by default
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %w. Please provide a valid HTTP(S) URL", err)
	}

	// Validate scheme (must be http or https)
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("target must be a valid HTTP(S) URL, got scheme '%s'. Did you mean 'https://%s'?", parsedURL.Scheme, parsedURL.Host)
	}

	// Validate host is present
	if parsedURL.Host == "" {
		return "", fmt.Errorf("target URL must include a host/domain. Got: '%s'", rawURL)
	}

	// Validate host format (domain or IP)
	host := parsedURL.Host
	// Remove port if present for validation
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		// Check if this is IPv6 (has brackets)
		if strings.HasPrefix(host, "[") {
			// IPv6 with or without port - extract just the IPv6 part
			if closeBracket := strings.Index(host, "]"); closeBracket != -1 {
				ipv6Part := host[1:closeBracket]
				if net.ParseIP(ipv6Part) == nil {
					return "", fmt.Errorf("invalid IPv6 address in URL: %s", host)
				}
				// IPv6 is valid, return the URL as-is
				return parsedURL.String(), nil
			}
		} else {
			// Regular host with possible port
			hostWithoutPort, portStr, err := net.SplitHostPort(host)
			if err == nil {
				host = hostWithoutPort
				// Validate port is numeric
				if portStr != "" {
					// Port validation - check it's a valid number
					var port int
					if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
						return "", fmt.Errorf("invalid port number '%s' in URL", portStr)
					}
					if port < 1 || port > 65535 {
						return "", fmt.Errorf("port number must be between 1 and 65535, got %d", port)
					}
				}
			}
		}
	}

	// Check if host is an IP address
	if ip := net.ParseIP(host); ip != nil {
		// Valid IP address (IPv4 or IPv6)
		return parsedURL.String(), nil
	}

	// Check if host is a valid domain name
	// Try IDN (Internationalized Domain Name) conversion
	asciiHost, err := idna.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("invalid domain name '%s': %w", host, err)
	}

	// Validate the ASCII domain format
	if !isValidDomain(asciiHost) {
		return "", fmt.Errorf("invalid domain name format: %s", host)
	}

	// If IDN conversion changed the host, rebuild the URL with ASCII host
	if asciiHost != host {
		parsedURL.Host = asciiHost
		return parsedURL.String(), nil
	}

	// Return the normalized URL
	return parsedURL.String(), nil
}

// ValidateDomain validates a domain name for DNS-based reconnaissance tools.
// It accepts domain names without schemes and validates their format.
//
// Parameters:
//   - rawDomain: The user-supplied domain string (may have whitespace, scheme, etc.)
//
// Returns:
//   - Normalized domain name if valid
//   - Error with actionable message if invalid
//
// Examples:
//   - "example.com" -> "example.com" (valid)
//   - "  example.com  " -> "example.com" (trimmed)
//   - "https://example.com" -> "example.com" (strips scheme)
//   - "example.com:443" -> "example.com" (strips port)
//   - "192.168.1.1" -> "192.168.1.1" (valid IP)
//   - "sub.domain.example.com" -> "sub.domain.example.com" (valid subdomain)
func ValidateDomain(rawDomain string) (string, error) {
	// Trim whitespace
	rawDomain = strings.TrimSpace(rawDomain)

	// Check for empty string
	if rawDomain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	// If domain has a scheme, strip it (be helpful to users who provide full URLs)
	if strings.Contains(rawDomain, "://") {
		parsedURL, err := url.Parse(rawDomain)
		if err != nil {
			return "", fmt.Errorf("invalid URL format: %w. Please provide a domain name (e.g., 'example.com')", err)
		}
		rawDomain = parsedURL.Host
	}

	// Remove port if present
	if colonIdx := strings.LastIndex(rawDomain, ":"); colonIdx != -1 {
		// Check if this is IPv6 (has brackets)
		if !strings.HasPrefix(rawDomain, "[") {
			// Might have a port - try to split
			host, _, err := net.SplitHostPort(rawDomain)
			if err == nil {
				rawDomain = host
			}
			// If error, might be IPv6 without brackets or domain without port - continue
		}
	}

	// Remove surrounding brackets if present (IPv6)
	rawDomain = strings.Trim(rawDomain, "[]")

	// Check if it's an IP address
	if ip := net.ParseIP(rawDomain); ip != nil {
		// Valid IP address
		return rawDomain, nil
	}

	// Try IDN (Internationalized Domain Name) conversion
	asciiDomain, err := idna.ToASCII(rawDomain)
	if err != nil {
		return "", fmt.Errorf("invalid domain name '%s': %w", rawDomain, err)
	}

	// Validate domain format
	if !isValidDomain(asciiDomain) {
		return "", fmt.Errorf("invalid domain name format: %s. Domain must contain valid characters and proper structure (e.g., 'example.com')", rawDomain)
	}

	// Return the normalized domain
	return asciiDomain, nil
}

// isValidDomain checks if a domain name has valid format.
// It performs basic validation of domain structure and characters.
func isValidDomain(domain string) bool {
	// Check length constraints
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Check for invalid patterns
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	if strings.Contains(domain, "..") {
		return false
	}

	// Split into labels and validate each
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return false
	}

	for _, label := range labels {
		// Each label must be 1-63 characters
		if len(label) == 0 || len(label) > 63 {
			return false
		}

		// Each label must start and end with alphanumeric
		if !isAlphanumeric(label[0]) || !isAlphanumeric(label[len(label)-1]) {
			return false
		}

		// Each character must be alphanumeric or hyphen
		for _, ch := range label {
			if !isAlphanumeric(byte(ch)) && ch != '-' {
				return false
			}
		}
	}

	return true
}

// isAlphanumeric checks if a byte is alphanumeric (a-z, A-Z, 0-9)
func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
