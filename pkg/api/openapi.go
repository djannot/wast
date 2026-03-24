package api

import (
	"fmt"
	"sort"
	"strings"
)

// OpenAPI3Spec represents an OpenAPI 3.x specification.
type OpenAPI3Spec struct {
	OpenAPI    string                      `json:"openapi" yaml:"openapi"`
	Info       OpenAPI3Info                `json:"info" yaml:"info"`
	Servers    []OpenAPI3Server            `json:"servers,omitempty" yaml:"servers,omitempty"`
	Paths      map[string]OpenAPI3PathItem `json:"paths" yaml:"paths"`
	Components *OpenAPI3Components         `json:"components,omitempty" yaml:"components,omitempty"`
	Security   []map[string][]string       `json:"security,omitempty" yaml:"security,omitempty"`
}

// OpenAPI3Info represents the info section of an OpenAPI 3.x specification.
type OpenAPI3Info struct {
	Title       string `json:"title" yaml:"title"`
	Version     string `json:"version" yaml:"version"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// OpenAPI3Server represents a server in an OpenAPI 3.x specification.
type OpenAPI3Server struct {
	URL         string `json:"url" yaml:"url"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// OpenAPI3PathItem represents a path item in an OpenAPI 3.x specification.
type OpenAPI3PathItem struct {
	Get        *OpenAPI3Operation  `json:"get,omitempty" yaml:"get,omitempty"`
	Post       *OpenAPI3Operation  `json:"post,omitempty" yaml:"post,omitempty"`
	Put        *OpenAPI3Operation  `json:"put,omitempty" yaml:"put,omitempty"`
	Delete     *OpenAPI3Operation  `json:"delete,omitempty" yaml:"delete,omitempty"`
	Patch      *OpenAPI3Operation  `json:"patch,omitempty" yaml:"patch,omitempty"`
	Options    *OpenAPI3Operation  `json:"options,omitempty" yaml:"options,omitempty"`
	Head       *OpenAPI3Operation  `json:"head,omitempty" yaml:"head,omitempty"`
	Trace      *OpenAPI3Operation  `json:"trace,omitempty" yaml:"trace,omitempty"`
	Parameters []OpenAPI3Parameter `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// OpenAPI3Operation represents an operation in an OpenAPI 3.x specification.
type OpenAPI3Operation struct {
	OperationID string                      `json:"operationId,omitempty" yaml:"operationId,omitempty"`
	Summary     string                      `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description string                      `json:"description,omitempty" yaml:"description,omitempty"`
	Tags        []string                    `json:"tags,omitempty" yaml:"tags,omitempty"`
	Parameters  []OpenAPI3Parameter         `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBody *OpenAPI3RequestBody        `json:"requestBody,omitempty" yaml:"requestBody,omitempty"`
	Responses   map[string]OpenAPI3Response `json:"responses,omitempty" yaml:"responses,omitempty"`
	Security    []map[string][]string       `json:"security,omitempty" yaml:"security,omitempty"`
	Deprecated  bool                        `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
}

// OpenAPI3Parameter represents a parameter in an OpenAPI 3.x specification.
type OpenAPI3Parameter struct {
	Name        string          `json:"name" yaml:"name"`
	In          string          `json:"in" yaml:"in"`
	Required    bool            `json:"required,omitempty" yaml:"required,omitempty"`
	Description string          `json:"description,omitempty" yaml:"description,omitempty"`
	Schema      *OpenAPI3Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
	Ref         string          `json:"$ref,omitempty" yaml:"$ref,omitempty"`
}

// OpenAPI3RequestBody represents a request body in an OpenAPI 3.x specification.
type OpenAPI3RequestBody struct {
	Description string                       `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool                         `json:"required,omitempty" yaml:"required,omitempty"`
	Content     map[string]OpenAPI3MediaType `json:"content,omitempty" yaml:"content,omitempty"`
	Ref         string                       `json:"$ref,omitempty" yaml:"$ref,omitempty"`
}

// OpenAPI3MediaType represents a media type in an OpenAPI 3.x specification.
type OpenAPI3MediaType struct {
	Schema  *OpenAPI3Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
	Example interface{}     `json:"example,omitempty" yaml:"example,omitempty"`
}

// OpenAPI3Response represents a response in an OpenAPI 3.x specification.
type OpenAPI3Response struct {
	Description string                       `json:"description,omitempty" yaml:"description,omitempty"`
	Content     map[string]OpenAPI3MediaType `json:"content,omitempty" yaml:"content,omitempty"`
	Ref         string                       `json:"$ref,omitempty" yaml:"$ref,omitempty"`
}

// OpenAPI3Schema represents a schema in an OpenAPI 3.x specification.
type OpenAPI3Schema struct {
	Type        string                     `json:"type,omitempty" yaml:"type,omitempty"`
	Format      string                     `json:"format,omitempty" yaml:"format,omitempty"`
	Description string                     `json:"description,omitempty" yaml:"description,omitempty"`
	Required    []string                   `json:"required,omitempty" yaml:"required,omitempty"`
	Properties  map[string]*OpenAPI3Schema `json:"properties,omitempty" yaml:"properties,omitempty"`
	Items       *OpenAPI3Schema            `json:"items,omitempty" yaml:"items,omitempty"`
	Ref         string                     `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	Example     interface{}                `json:"example,omitempty" yaml:"example,omitempty"`
}

// OpenAPI3Components represents the components section of an OpenAPI 3.x specification.
type OpenAPI3Components struct {
	Schemas         map[string]*OpenAPI3Schema         `json:"schemas,omitempty" yaml:"schemas,omitempty"`
	SecuritySchemes map[string]*OpenAPI3SecurityScheme `json:"securitySchemes,omitempty" yaml:"securitySchemes,omitempty"`
	Parameters      map[string]*OpenAPI3Parameter      `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBodies   map[string]*OpenAPI3RequestBody    `json:"requestBodies,omitempty" yaml:"requestBodies,omitempty"`
}

// OpenAPI3SecurityScheme represents a security scheme in an OpenAPI 3.x specification.
type OpenAPI3SecurityScheme struct {
	Type        string `json:"type" yaml:"type"`
	Scheme      string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	In          string `json:"in,omitempty" yaml:"in,omitempty"`
	Name        string `json:"name,omitempty" yaml:"name,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// ParseOpenAPI3 parses an OpenAPI 3.x specification from raw data.
func ParseOpenAPI3(data []byte) (*APISpec, error) {
	var spec OpenAPI3Spec
	if err := parseYAMLOrJSON(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI 3.x specification: %w", err)
	}

	return convertOpenAPI3ToAPISpec(&spec), nil
}

// convertOpenAPI3ToAPISpec converts an OpenAPI3Spec to an APISpec.
func convertOpenAPI3ToAPISpec(spec *OpenAPI3Spec) *APISpec {
	result := &APISpec{
		Title:       spec.Info.Title,
		Version:     spec.Info.Version,
		Description: spec.Info.Description,
		SpecVersion: "OpenAPI " + spec.OpenAPI,
	}

	// Convert servers
	for _, server := range spec.Servers {
		result.Servers = append(result.Servers, ServerInfo{
			URL:         server.URL,
			Description: server.Description,
		})
	}

	// Convert security schemes
	if spec.Components != nil && spec.Components.SecuritySchemes != nil {
		for name, scheme := range spec.Components.SecuritySchemes {
			result.AuthSchemes = append(result.AuthSchemes, AuthSchemeInfo{
				Name:        name,
				Type:        scheme.Type,
				Scheme:      scheme.Scheme,
				In:          scheme.In,
				Description: scheme.Description,
			})
		}
		// Sort auth schemes by name for consistent output
		sort.Slice(result.AuthSchemes, func(i, j int) bool {
			return result.AuthSchemes[i].Name < result.AuthSchemes[j].Name
		})
	}

	// Convert paths to endpoints
	result.Endpoints = extractOpenAPI3Endpoints(spec)

	return result
}

// extractOpenAPI3Endpoints extracts all endpoints from an OpenAPI 3.x specification.
func extractOpenAPI3Endpoints(spec *OpenAPI3Spec) []EndpointInfo {
	var endpoints []EndpointInfo

	// Get sorted paths for consistent output
	paths := make([]string, 0, len(spec.Paths))
	for path := range spec.Paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	methods := []struct {
		name string
		get  func(*OpenAPI3PathItem) *OpenAPI3Operation
	}{
		{"GET", func(p *OpenAPI3PathItem) *OpenAPI3Operation { return p.Get }},
		{"POST", func(p *OpenAPI3PathItem) *OpenAPI3Operation { return p.Post }},
		{"PUT", func(p *OpenAPI3PathItem) *OpenAPI3Operation { return p.Put }},
		{"DELETE", func(p *OpenAPI3PathItem) *OpenAPI3Operation { return p.Delete }},
		{"PATCH", func(p *OpenAPI3PathItem) *OpenAPI3Operation { return p.Patch }},
		{"OPTIONS", func(p *OpenAPI3PathItem) *OpenAPI3Operation { return p.Options }},
		{"HEAD", func(p *OpenAPI3PathItem) *OpenAPI3Operation { return p.Head }},
		{"TRACE", func(p *OpenAPI3PathItem) *OpenAPI3Operation { return p.Trace }},
	}

	for _, path := range paths {
		pathItem := spec.Paths[path]

		for _, m := range methods {
			op := m.get(&pathItem)
			if op == nil {
				continue
			}

			endpoint := EndpointInfo{
				Path:        path,
				Method:      m.name,
				OperationID: op.OperationID,
				Summary:     op.Summary,
				Description: op.Description,
				Tags:        op.Tags,
				Deprecated:  op.Deprecated,
			}

			// Combine path-level and operation-level parameters
			allParams := append(pathItem.Parameters, op.Parameters...)
			for _, param := range allParams {
				// Skip $ref parameters for now (simplified)
				if param.Ref != "" {
					continue
				}
				endpoint.Parameters = append(endpoint.Parameters, convertOpenAPI3Parameter(&param))
			}

			// Convert request body
			if op.RequestBody != nil {
				endpoint.RequestBody = convertOpenAPI3RequestBody(op.RequestBody)
			}

			// Convert responses
			for statusCode, response := range op.Responses {
				endpoint.Responses = append(endpoint.Responses, convertOpenAPI3Response(statusCode, &response))
			}
			// Sort responses by status code for consistent output
			sort.Slice(endpoint.Responses, func(i, j int) bool {
				return endpoint.Responses[i].StatusCode < endpoint.Responses[j].StatusCode
			})

			// Extract security requirements
			security := op.Security
			if security == nil && spec.Security != nil {
				security = spec.Security
			}
			for _, secReq := range security {
				for name := range secReq {
					endpoint.Security = append(endpoint.Security, name)
				}
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// convertOpenAPI3Parameter converts an OpenAPI 3.x parameter to a ParameterInfo.
func convertOpenAPI3Parameter(param *OpenAPI3Parameter) ParameterInfo {
	result := ParameterInfo{
		Name:        param.Name,
		In:          param.In,
		Required:    param.Required,
		Description: param.Description,
	}

	if param.Schema != nil {
		result.Schema = convertOpenAPI3Schema(param.Schema, "")
	}

	return result
}

// convertOpenAPI3RequestBody converts an OpenAPI 3.x request body to a SchemaInfo.
func convertOpenAPI3RequestBody(body *OpenAPI3RequestBody) *SchemaInfo {
	result := &SchemaInfo{
		Description: body.Description,
	}

	// Get the first content type's schema
	for contentType, mediaType := range body.Content {
		result.ContentType = contentType
		if mediaType.Schema != nil {
			schemaInfo := convertOpenAPI3Schema(mediaType.Schema, contentType)
			result.Type = schemaInfo.Type
			result.Format = schemaInfo.Format
			result.Required = schemaInfo.Required
			result.Properties = schemaInfo.Properties
		}
		break // Only use the first content type
	}

	return result
}

// convertOpenAPI3Response converts an OpenAPI 3.x response to a ResponseInfo.
func convertOpenAPI3Response(statusCode string, response *OpenAPI3Response) ResponseInfo {
	result := ResponseInfo{
		StatusCode:  statusCode,
		Description: response.Description,
	}

	// Get the first content type's schema
	for contentType, mediaType := range response.Content {
		if mediaType.Schema != nil {
			result.Schema = convertOpenAPI3Schema(mediaType.Schema, contentType)
		}
		break
	}

	return result
}

// convertOpenAPI3Schema converts an OpenAPI 3.x schema to a SchemaInfo.
func convertOpenAPI3Schema(schema *OpenAPI3Schema, contentType string) *SchemaInfo {
	if schema == nil {
		return nil
	}

	result := &SchemaInfo{
		Type:        schema.Type,
		Format:      schema.Format,
		Description: schema.Description,
		ContentType: contentType,
		Required:    schema.Required,
	}

	// Convert properties (simplified - just type information)
	if schema.Properties != nil {
		result.Properties = make(map[string]string)
		for name, prop := range schema.Properties {
			propType := prop.Type
			if prop.Format != "" {
				propType = fmt.Sprintf("%s (%s)", prop.Type, prop.Format)
			}
			result.Properties[name] = propType
		}
	}

	// Handle array items
	if schema.Type == "array" && schema.Items != nil {
		result.Type = fmt.Sprintf("array[%s]", schema.Items.Type)
	}

	// Convert example to string
	if schema.Example != nil {
		result.Example = fmt.Sprintf("%v", schema.Example)
	}

	return result
}

// extractRefName extracts the reference name from a $ref string.
func extractRefName(ref string) string {
	parts := strings.Split(ref, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ref
}
