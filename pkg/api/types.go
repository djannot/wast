// Package api provides OpenAPI/Swagger specification parsing for API security testing.
package api

import (
	"fmt"
	"strings"
)

// APISpec represents a parsed API specification.
type APISpec struct {
	Title       string           `json:"title" yaml:"title"`
	Version     string           `json:"version" yaml:"version"`
	Description string           `json:"description,omitempty" yaml:"description,omitempty"`
	SpecVersion string           `json:"spec_version" yaml:"spec_version"`
	Servers     []ServerInfo     `json:"servers,omitempty" yaml:"servers,omitempty"`
	Endpoints   []EndpointInfo   `json:"endpoints" yaml:"endpoints"`
	AuthSchemes []AuthSchemeInfo `json:"auth_schemes,omitempty" yaml:"auth_schemes,omitempty"`
	Errors      []string         `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// ServerInfo represents a server/base URL in the API specification.
type ServerInfo struct {
	URL         string `json:"url" yaml:"url"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// EndpointInfo represents an API endpoint with its details.
type EndpointInfo struct {
	Path        string          `json:"path" yaml:"path"`
	Method      string          `json:"method" yaml:"method"`
	OperationID string          `json:"operation_id,omitempty" yaml:"operation_id,omitempty"`
	Summary     string          `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description string          `json:"description,omitempty" yaml:"description,omitempty"`
	Tags        []string        `json:"tags,omitempty" yaml:"tags,omitempty"`
	Parameters  []ParameterInfo `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBody *SchemaInfo     `json:"request_body,omitempty" yaml:"request_body,omitempty"`
	Responses   []ResponseInfo  `json:"responses,omitempty" yaml:"responses,omitempty"`
	Security    []string        `json:"security,omitempty" yaml:"security,omitempty"`
	Deprecated  bool            `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
}

// ParameterInfo represents a parameter in an API endpoint.
type ParameterInfo struct {
	Name        string      `json:"name" yaml:"name"`
	In          string      `json:"in" yaml:"in"` // path, query, header, cookie
	Required    bool        `json:"required" yaml:"required"`
	Description string      `json:"description,omitempty" yaml:"description,omitempty"`
	Schema      *SchemaInfo `json:"schema,omitempty" yaml:"schema,omitempty"`
}

// SchemaInfo represents a schema definition for request/response bodies.
type SchemaInfo struct {
	Type        string            `json:"type,omitempty" yaml:"type,omitempty"`
	Format      string            `json:"format,omitempty" yaml:"format,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	ContentType string            `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	Required    []string          `json:"required,omitempty" yaml:"required,omitempty"`
	Properties  map[string]string `json:"properties,omitempty" yaml:"properties,omitempty"`
	Example     string            `json:"example,omitempty" yaml:"example,omitempty"`
}

// ResponseInfo represents a response definition.
type ResponseInfo struct {
	StatusCode  string      `json:"status_code" yaml:"status_code"`
	Description string      `json:"description,omitempty" yaml:"description,omitempty"`
	Schema      *SchemaInfo `json:"schema,omitempty" yaml:"schema,omitempty"`
}

// AuthSchemeInfo represents an authentication scheme defined in the spec.
type AuthSchemeInfo struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type" yaml:"type"` // apiKey, http, oauth2, openIdConnect
	Scheme      string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	In          string `json:"in,omitempty" yaml:"in,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// String returns a human-readable representation of the API specification.
func (s *APISpec) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("API Specification: %s\n", s.Title))
	sb.WriteString(strings.Repeat("=", 50) + "\n")
	sb.WriteString(fmt.Sprintf("Version: %s\n", s.Version))
	sb.WriteString(fmt.Sprintf("Spec Version: %s\n", s.SpecVersion))

	if s.Description != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", s.Description))
	}

	if len(s.Servers) > 0 {
		sb.WriteString("\nServers:\n")
		for _, server := range s.Servers {
			sb.WriteString(fmt.Sprintf("  - %s", server.URL))
			if server.Description != "" {
				sb.WriteString(fmt.Sprintf(" (%s)", server.Description))
			}
			sb.WriteString("\n")
		}
	}

	if len(s.AuthSchemes) > 0 {
		sb.WriteString("\nAuthentication Schemes:\n")
		for _, auth := range s.AuthSchemes {
			sb.WriteString(fmt.Sprintf("  - %s: %s", auth.Name, auth.Type))
			if auth.Scheme != "" {
				sb.WriteString(fmt.Sprintf(" (%s)", auth.Scheme))
			}
			sb.WriteString("\n")
		}
	}

	if len(s.Endpoints) > 0 {
		sb.WriteString(fmt.Sprintf("\nEndpoints (%d):\n", len(s.Endpoints)))
		for _, ep := range s.Endpoints {
			sb.WriteString(fmt.Sprintf("  %s %s", ep.Method, ep.Path))
			if ep.Summary != "" {
				sb.WriteString(fmt.Sprintf(" - %s", ep.Summary))
			}
			sb.WriteString("\n")
		}
	}

	if len(s.Errors) > 0 {
		sb.WriteString("\nErrors encountered:\n")
		for _, err := range s.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	return sb.String()
}

// HasEndpoints returns true if any endpoints were found.
func (s *APISpec) HasEndpoints() bool {
	return len(s.Endpoints) > 0
}

// EndpointCount returns the number of endpoints.
func (s *APISpec) EndpointCount() int {
	return len(s.Endpoints)
}

// GetEndpointsByMethod returns all endpoints with the specified HTTP method.
func (s *APISpec) GetEndpointsByMethod(method string) []EndpointInfo {
	var result []EndpointInfo
	method = strings.ToUpper(method)
	for _, ep := range s.Endpoints {
		if strings.ToUpper(ep.Method) == method {
			result = append(result, ep)
		}
	}
	return result
}

// GetEndpointsByTag returns all endpoints with the specified tag.
func (s *APISpec) GetEndpointsByTag(tag string) []EndpointInfo {
	var result []EndpointInfo
	for _, ep := range s.Endpoints {
		for _, t := range ep.Tags {
			if strings.EqualFold(t, tag) {
				result = append(result, ep)
				break
			}
		}
	}
	return result
}
