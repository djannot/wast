package api

import (
	"fmt"
	"sort"
)

// Swagger2Spec represents a Swagger 2.0 specification.
type Swagger2Spec struct {
	Swagger             string                          `json:"swagger" yaml:"swagger"`
	Info                Swagger2Info                    `json:"info" yaml:"info"`
	Host                string                          `json:"host,omitempty" yaml:"host,omitempty"`
	BasePath            string                          `json:"basePath,omitempty" yaml:"basePath,omitempty"`
	Schemes             []string                        `json:"schemes,omitempty" yaml:"schemes,omitempty"`
	Paths               map[string]Swagger2PathItem     `json:"paths" yaml:"paths"`
	Definitions         map[string]*Swagger2Schema      `json:"definitions,omitempty" yaml:"definitions,omitempty"`
	SecurityDefinitions map[string]*Swagger2SecurityDef `json:"securityDefinitions,omitempty" yaml:"securityDefinitions,omitempty"`
	Security            []map[string][]string           `json:"security,omitempty" yaml:"security,omitempty"`
}

// Swagger2Info represents the info section of a Swagger 2.0 specification.
type Swagger2Info struct {
	Title       string `json:"title" yaml:"title"`
	Version     string `json:"version" yaml:"version"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// Swagger2PathItem represents a path item in a Swagger 2.0 specification.
type Swagger2PathItem struct {
	Get        *Swagger2Operation  `json:"get,omitempty" yaml:"get,omitempty"`
	Post       *Swagger2Operation  `json:"post,omitempty" yaml:"post,omitempty"`
	Put        *Swagger2Operation  `json:"put,omitempty" yaml:"put,omitempty"`
	Delete     *Swagger2Operation  `json:"delete,omitempty" yaml:"delete,omitempty"`
	Patch      *Swagger2Operation  `json:"patch,omitempty" yaml:"patch,omitempty"`
	Options    *Swagger2Operation  `json:"options,omitempty" yaml:"options,omitempty"`
	Head       *Swagger2Operation  `json:"head,omitempty" yaml:"head,omitempty"`
	Parameters []Swagger2Parameter `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// Swagger2Operation represents an operation in a Swagger 2.0 specification.
type Swagger2Operation struct {
	OperationID string                      `json:"operationId,omitempty" yaml:"operationId,omitempty"`
	Summary     string                      `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description string                      `json:"description,omitempty" yaml:"description,omitempty"`
	Tags        []string                    `json:"tags,omitempty" yaml:"tags,omitempty"`
	Consumes    []string                    `json:"consumes,omitempty" yaml:"consumes,omitempty"`
	Produces    []string                    `json:"produces,omitempty" yaml:"produces,omitempty"`
	Parameters  []Swagger2Parameter         `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	Responses   map[string]Swagger2Response `json:"responses,omitempty" yaml:"responses,omitempty"`
	Security    []map[string][]string       `json:"security,omitempty" yaml:"security,omitempty"`
	Deprecated  bool                        `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
}

// Swagger2Parameter represents a parameter in a Swagger 2.0 specification.
type Swagger2Parameter struct {
	Name        string          `json:"name" yaml:"name"`
	In          string          `json:"in" yaml:"in"`
	Required    bool            `json:"required,omitempty" yaml:"required,omitempty"`
	Description string          `json:"description,omitempty" yaml:"description,omitempty"`
	Type        string          `json:"type,omitempty" yaml:"type,omitempty"`
	Format      string          `json:"format,omitempty" yaml:"format,omitempty"`
	Schema      *Swagger2Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
	Ref         string          `json:"$ref,omitempty" yaml:"$ref,omitempty"`
}

// Swagger2Response represents a response in a Swagger 2.0 specification.
type Swagger2Response struct {
	Description string          `json:"description,omitempty" yaml:"description,omitempty"`
	Schema      *Swagger2Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
	Ref         string          `json:"$ref,omitempty" yaml:"$ref,omitempty"`
}

// Swagger2Schema represents a schema in a Swagger 2.0 specification.
type Swagger2Schema struct {
	Type        string                     `json:"type,omitempty" yaml:"type,omitempty"`
	Format      string                     `json:"format,omitempty" yaml:"format,omitempty"`
	Description string                     `json:"description,omitempty" yaml:"description,omitempty"`
	Required    []string                   `json:"required,omitempty" yaml:"required,omitempty"`
	Properties  map[string]*Swagger2Schema `json:"properties,omitempty" yaml:"properties,omitempty"`
	Items       *Swagger2Schema            `json:"items,omitempty" yaml:"items,omitempty"`
	Ref         string                     `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	Example     interface{}                `json:"example,omitempty" yaml:"example,omitempty"`
}

// Swagger2SecurityDef represents a security definition in a Swagger 2.0 specification.
type Swagger2SecurityDef struct {
	Type        string `json:"type" yaml:"type"`
	Name        string `json:"name,omitempty" yaml:"name,omitempty"`
	In          string `json:"in,omitempty" yaml:"in,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Flow        string `json:"flow,omitempty" yaml:"flow,omitempty"`
}

// ParseSwagger2 parses a Swagger 2.0 specification from raw data.
func ParseSwagger2(data []byte) (*APISpec, error) {
	var spec Swagger2Spec
	if err := parseYAMLOrJSON(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse Swagger 2.0 specification: %w", err)
	}

	return convertSwagger2ToAPISpec(&spec), nil
}

// convertSwagger2ToAPISpec converts a Swagger2Spec to an APISpec.
func convertSwagger2ToAPISpec(spec *Swagger2Spec) *APISpec {
	result := &APISpec{
		Title:       spec.Info.Title,
		Version:     spec.Info.Version,
		Description: spec.Info.Description,
		SpecVersion: "Swagger " + spec.Swagger,
	}

	// Build servers from host, basePath, and schemes
	if spec.Host != "" {
		schemes := spec.Schemes
		if len(schemes) == 0 {
			schemes = []string{"https"} // Default to HTTPS
		}

		basePath := spec.BasePath
		if basePath == "" {
			basePath = "/"
		}

		for _, scheme := range schemes {
			url := fmt.Sprintf("%s://%s%s", scheme, spec.Host, basePath)
			result.Servers = append(result.Servers, ServerInfo{
				URL: url,
			})
		}
	}

	// Convert security definitions
	if spec.SecurityDefinitions != nil {
		for name, secDef := range spec.SecurityDefinitions {
			result.AuthSchemes = append(result.AuthSchemes, AuthSchemeInfo{
				Name:        name,
				Type:        secDef.Type,
				In:          secDef.In,
				Description: secDef.Description,
			})
		}
		// Sort auth schemes by name for consistent output
		sort.Slice(result.AuthSchemes, func(i, j int) bool {
			return result.AuthSchemes[i].Name < result.AuthSchemes[j].Name
		})
	}

	// Convert paths to endpoints
	result.Endpoints = extractSwagger2Endpoints(spec)

	return result
}

// extractSwagger2Endpoints extracts all endpoints from a Swagger 2.0 specification.
func extractSwagger2Endpoints(spec *Swagger2Spec) []EndpointInfo {
	var endpoints []EndpointInfo

	// Get sorted paths for consistent output
	paths := make([]string, 0, len(spec.Paths))
	for path := range spec.Paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	methods := []struct {
		name string
		get  func(*Swagger2PathItem) *Swagger2Operation
	}{
		{"GET", func(p *Swagger2PathItem) *Swagger2Operation { return p.Get }},
		{"POST", func(p *Swagger2PathItem) *Swagger2Operation { return p.Post }},
		{"PUT", func(p *Swagger2PathItem) *Swagger2Operation { return p.Put }},
		{"DELETE", func(p *Swagger2PathItem) *Swagger2Operation { return p.Delete }},
		{"PATCH", func(p *Swagger2PathItem) *Swagger2Operation { return p.Patch }},
		{"OPTIONS", func(p *Swagger2PathItem) *Swagger2Operation { return p.Options }},
		{"HEAD", func(p *Swagger2PathItem) *Swagger2Operation { return p.Head }},
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
				converted := convertSwagger2Parameter(&param)

				// Handle body parameters as request body
				if param.In == "body" {
					endpoint.RequestBody = converted.Schema
					if endpoint.RequestBody != nil && len(op.Consumes) > 0 {
						endpoint.RequestBody.ContentType = op.Consumes[0]
					}
				} else {
					endpoint.Parameters = append(endpoint.Parameters, converted)
				}
			}

			// Convert responses
			for statusCode, response := range op.Responses {
				endpoint.Responses = append(endpoint.Responses, convertSwagger2Response(statusCode, &response, op.Produces))
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

// convertSwagger2Parameter converts a Swagger 2.0 parameter to a ParameterInfo.
func convertSwagger2Parameter(param *Swagger2Parameter) ParameterInfo {
	result := ParameterInfo{
		Name:        param.Name,
		In:          param.In,
		Required:    param.Required,
		Description: param.Description,
	}

	// Build schema from parameter type or nested schema
	if param.Type != "" {
		result.Schema = &SchemaInfo{
			Type:   param.Type,
			Format: param.Format,
		}
	} else if param.Schema != nil {
		result.Schema = convertSwagger2Schema(param.Schema, "")
	}

	return result
}

// convertSwagger2Response converts a Swagger 2.0 response to a ResponseInfo.
func convertSwagger2Response(statusCode string, response *Swagger2Response, produces []string) ResponseInfo {
	result := ResponseInfo{
		StatusCode:  statusCode,
		Description: response.Description,
	}

	if response.Schema != nil {
		contentType := ""
		if len(produces) > 0 {
			contentType = produces[0]
		}
		result.Schema = convertSwagger2Schema(response.Schema, contentType)
	}

	return result
}

// convertSwagger2Schema converts a Swagger 2.0 schema to a SchemaInfo.
func convertSwagger2Schema(schema *Swagger2Schema, contentType string) *SchemaInfo {
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
