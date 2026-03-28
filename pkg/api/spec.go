package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SpecFormat represents the detected specification format.
type SpecFormat string

const (
	// FormatOpenAPI3 represents OpenAPI 3.x specification.
	FormatOpenAPI3 SpecFormat = "openapi3"
	// FormatSwagger2 represents Swagger 2.0 specification.
	FormatSwagger2 SpecFormat = "swagger2"
	// FormatUnknown represents an unknown specification format.
	FormatUnknown SpecFormat = "unknown"
)

// ParseSpec parses an API specification from a file path or URL.
// It automatically detects the specification format (OpenAPI 3.x or Swagger 2.0).
func ParseSpec(pathOrURL string) (*APISpec, error) {
	data, err := loadSpec(pathOrURL)
	if err != nil {
		return nil, fmt.Errorf("failed to load specification: %w", err)
	}

	format, err := detectFormat(data)
	if err != nil {
		return nil, fmt.Errorf("failed to detect specification format: %w", err)
	}

	switch format {
	case FormatOpenAPI3:
		return ParseOpenAPI3(data)
	case FormatSwagger2:
		return ParseSwagger2(data)
	default:
		return nil, fmt.Errorf("unsupported specification format")
	}
}

// loadSpec loads specification data from a file path or URL.
func loadSpec(pathOrURL string) ([]byte, error) {
	if isURL(pathOrURL) {
		return loadFromURL(pathOrURL)
	}
	return loadFromFile(pathOrURL)
}

// isURL checks if the given string is a URL.
func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// loadFromFile loads data from a local file.
func loadFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return data, nil
}

// loadFromURL loads data from a URL.
func loadFromURL(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from %s: %w", url, err)
	}

	return data, nil
}

// detectFormat detects whether the specification is OpenAPI 3.x or Swagger 2.0.
func detectFormat(data []byte) (SpecFormat, error) {
	// Try to parse as generic map to detect format
	var spec map[string]interface{}

	// Try JSON first, then YAML
	if err := json.Unmarshal(data, &spec); err != nil {
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return FormatUnknown, fmt.Errorf("failed to parse specification as JSON or YAML: %w", err)
		}
	}

	// Check for OpenAPI 3.x
	if openapi, ok := spec["openapi"].(string); ok {
		if strings.HasPrefix(openapi, "3.") {
			return FormatOpenAPI3, nil
		}
	}

	// Check for Swagger 2.0
	if swagger, ok := spec["swagger"].(string); ok {
		if swagger == "2.0" {
			return FormatSwagger2, nil
		}
	}

	return FormatUnknown, fmt.Errorf("could not detect specification format (missing 'openapi' or 'swagger' field)")
}

// parseYAMLOrJSON parses data as either YAML or JSON into the target.
func parseYAMLOrJSON(data []byte, target interface{}) error {
	// Try JSON first (more strict)
	if err := json.Unmarshal(data, target); err == nil {
		return nil
	}

	// Fall back to YAML
	if err := yaml.Unmarshal(data, target); err != nil {
		return fmt.Errorf("failed to parse as JSON or YAML: %w", err)
	}

	return nil
}
