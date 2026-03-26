// Package crawler provides web crawling functionality for reconnaissance operations.
package crawler

import (
	"bufio"
	"io"
	"net/url"
	"strings"
)

// RobotsData contains parsed robots.txt rules.
type RobotsData struct {
	Disallow []string
	Allow    []string
	Sitemaps []string
}

// ParseRobots parses robots.txt content and returns the rules.
func ParseRobots(content io.Reader) *RobotsData {
	data := &RobotsData{
		Disallow: make([]string, 0),
		Allow:    make([]string, 0),
		Sitemaps: make([]string, 0),
	}

	scanner := bufio.NewScanner(content)
	inUserAgentAll := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse directive
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		directive := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch directive {
		case "user-agent":
			// We only care about rules that apply to all user agents (*)
			// or when no specific user-agent is specified
			inUserAgentAll = value == "*" || value == ""
		case "disallow":
			if inUserAgentAll && value != "" {
				data.Disallow = append(data.Disallow, value)
			}
		case "allow":
			if inUserAgentAll && value != "" {
				data.Allow = append(data.Allow, value)
			}
		case "sitemap":
			if value != "" {
				data.Sitemaps = append(data.Sitemaps, value)
			}
		}
	}

	return data
}

// IsAllowed checks if a URL path is allowed according to robots.txt rules.
// It returns true if the path is allowed, false if disallowed.
func (r *RobotsData) IsAllowed(urlPath string) bool {
	// If no rules, everything is allowed
	if len(r.Disallow) == 0 && len(r.Allow) == 0 {
		return true
	}

	// Normalize the path
	if urlPath == "" {
		urlPath = "/"
	}

	// Check Allow rules first (they take precedence over Disallow)
	for _, allowPath := range r.Allow {
		if matchesRobotsPath(urlPath, allowPath) {
			return true
		}
	}

	// Check Disallow rules
	for _, disallowPath := range r.Disallow {
		if matchesRobotsPath(urlPath, disallowPath) {
			return false
		}
	}

	// Default: allowed
	return true
}

// matchesRobotsPath checks if a URL path matches a robots.txt path pattern.
// Supports simple prefix matching and * wildcards.
func matchesRobotsPath(urlPath, robotsPath string) bool {
	// Handle wildcards
	if strings.Contains(robotsPath, "*") {
		return matchWildcard(urlPath, robotsPath)
	}

	// Handle $ end anchor
	if strings.HasSuffix(robotsPath, "$") {
		pattern := strings.TrimSuffix(robotsPath, "$")
		return urlPath == pattern
	}

	// Simple prefix match
	return strings.HasPrefix(urlPath, robotsPath)
}

// matchWildcard performs simple wildcard matching.
// Supports * for any characters.
func matchWildcard(s, pattern string) bool {
	// Handle $ end anchor on the pattern
	hasEndAnchor := strings.HasSuffix(pattern, "$")
	if hasEndAnchor {
		pattern = strings.TrimSuffix(pattern, "$")
	}

	// Split pattern by wildcards
	parts := strings.Split(pattern, "*")

	// Check first part (must be prefix if not starting with *)
	if len(parts[0]) > 0 && !strings.HasPrefix(s, parts[0]) {
		return false
	}

	pos := len(parts[0])

	// Check middle and end parts
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}

		// Find this part in the remaining string
		idx := strings.Index(s[pos:], parts[i])
		if idx == -1 {
			return false
		}
		pos += idx + len(parts[i])
	}

	// If end anchor is present, verify the match ends exactly
	if hasEndAnchor {
		lastPart := parts[len(parts)-1]
		return strings.HasSuffix(s, lastPart)
	}

	return true
}

// GetRobotsURL returns the robots.txt URL for a given target URL.
func GetRobotsURL(targetURL string) (string, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	robotsURL := &url.URL{
		Scheme: parsed.Scheme,
		Host:   parsed.Host,
		Path:   "/robots.txt",
	}

	return robotsURL.String(), nil
}
