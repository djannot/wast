package api

import (
	"testing"
)

func TestParseOpenAPI3_ValidSpec(t *testing.T) {
	tests := []struct {
		name string
		spec string
	}{
		{
			name: "Complete YAML spec",
			spec: `
openapi: "3.0.3"
info:
  title: Test API
  version: "1.0.0"
  description: A test API
servers:
  - url: https://api.example.com
    description: Production server
paths:
  /users:
    get:
      operationId: listUsers
      summary: List users
      responses:
        "200":
          description: Success
`,
		},
		{
			name: "Complete JSON spec",
			spec: `{
  "openapi": "3.0.0",
  "info": {
    "title": "JSON API",
    "version": "1.0.0"
  },
  "paths": {
    "/test": {
      "get": {
        "responses": {
          "200": {
            "description": "OK"
          }
        }
      }
    }
  }
}`,
		},
		{
			name: "Minimal spec",
			spec: `
openapi: "3.0.0"
info:
  title: Minimal API
  version: "1.0"
paths: {}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseOpenAPI3([]byte(tt.spec))
			if err != nil {
				t.Errorf("ParseOpenAPI3() error = %v", err)
				return
			}
			if spec == nil {
				t.Error("ParseOpenAPI3() returned nil spec")
			}
		})
	}
}

func TestParseOpenAPI3_InvalidSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantErr bool
	}{
		{
			name:    "Invalid YAML",
			spec:    "invalid: [",
			wantErr: true,
		},
		{
			name:    "Invalid JSON",
			spec:    "{invalid json",
			wantErr: true,
		},
		{
			name:    "Empty spec",
			spec:    "",
			wantErr: false, // Empty string parses as empty YAML object
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseOpenAPI3([]byte(tt.spec))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOpenAPI3() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConvertOpenAPI3ToAPISpec(t *testing.T) {
	tests := []struct {
		name string
		spec *OpenAPI3Spec
		want func(*APISpec) bool
	}{
		{
			name: "Basic info conversion",
			spec: &OpenAPI3Spec{
				OpenAPI: "3.0.3",
				Info: OpenAPI3Info{
					Title:       "Test API",
					Version:     "1.0.0",
					Description: "Test Description",
				},
			},
			want: func(result *APISpec) bool {
				return result.Title == "Test API" &&
					result.Version == "1.0.0" &&
					result.Description == "Test Description" &&
					result.SpecVersion == "OpenAPI 3.0.3"
			},
		},
		{
			name: "Server conversion",
			spec: &OpenAPI3Spec{
				OpenAPI: "3.0.0",
				Info: OpenAPI3Info{
					Title:   "Test",
					Version: "1.0",
				},
				Servers: []OpenAPI3Server{
					{
						URL:         "https://api.example.com",
						Description: "Production",
					},
					{
						URL:         "https://staging.example.com",
						Description: "Staging",
					},
				},
			},
			want: func(result *APISpec) bool {
				return len(result.Servers) == 2 &&
					result.Servers[0].URL == "https://api.example.com" &&
					result.Servers[0].Description == "Production"
			},
		},
		{
			name: "Security schemes conversion",
			spec: &OpenAPI3Spec{
				OpenAPI: "3.0.0",
				Info: OpenAPI3Info{
					Title:   "Test",
					Version: "1.0",
				},
				Components: &OpenAPI3Components{
					SecuritySchemes: map[string]*OpenAPI3SecurityScheme{
						"bearerAuth": {
							Type:        "http",
							Scheme:      "bearer",
							Description: "JWT token",
						},
						"apiKey": {
							Type: "apiKey",
							In:   "header",
							Name: "X-API-Key",
						},
					},
				},
			},
			want: func(result *APISpec) bool {
				if len(result.AuthSchemes) != 2 {
					return false
				}
				// Should be sorted by name
				return result.AuthSchemes[0].Name == "apiKey" &&
					result.AuthSchemes[1].Name == "bearerAuth"
			},
		},
		{
			name: "Empty components",
			spec: &OpenAPI3Spec{
				OpenAPI: "3.0.0",
				Info: OpenAPI3Info{
					Title:   "Test",
					Version: "1.0",
				},
				Components: nil,
			},
			want: func(result *APISpec) bool {
				return len(result.AuthSchemes) == 0
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertOpenAPI3ToAPISpec(tt.spec)
			if !tt.want(result) {
				t.Errorf("convertOpenAPI3ToAPISpec() validation failed")
			}
		})
	}
}

func TestExtractOpenAPI3Endpoints(t *testing.T) {
	tests := []struct {
		name          string
		spec          *OpenAPI3Spec
		wantEndpoints int
		validate      func(*testing.T, []EndpointInfo)
	}{
		{
			name: "Empty paths",
			spec: &OpenAPI3Spec{
				Paths: map[string]OpenAPI3PathItem{},
			},
			wantEndpoints: 0,
		},
		{
			name: "Single GET endpoint",
			spec: &OpenAPI3Spec{
				Paths: map[string]OpenAPI3PathItem{
					"/users": {
						Get: &OpenAPI3Operation{
							OperationID: "listUsers",
							Summary:     "List all users",
							Description: "Returns a list of users",
							Tags:        []string{"users"},
						},
					},
				},
			},
			wantEndpoints: 1,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				if endpoints[0].Method != "GET" {
					t.Errorf("Expected method GET, got %s", endpoints[0].Method)
				}
				if endpoints[0].Path != "/users" {
					t.Errorf("Expected path /users, got %s", endpoints[0].Path)
				}
				if endpoints[0].OperationID != "listUsers" {
					t.Errorf("Expected operationId listUsers, got %s", endpoints[0].OperationID)
				}
			},
		},
		{
			name: "All HTTP methods",
			spec: &OpenAPI3Spec{
				Paths: map[string]OpenAPI3PathItem{
					"/resource": {
						Get:     &OpenAPI3Operation{OperationID: "get"},
						Post:    &OpenAPI3Operation{OperationID: "post"},
						Put:     &OpenAPI3Operation{OperationID: "put"},
						Delete:  &OpenAPI3Operation{OperationID: "delete"},
						Patch:   &OpenAPI3Operation{OperationID: "patch"},
						Options: &OpenAPI3Operation{OperationID: "options"},
						Head:    &OpenAPI3Operation{OperationID: "head"},
						Trace:   &OpenAPI3Operation{OperationID: "trace"},
					},
				},
			},
			wantEndpoints: 8,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				methods := map[string]bool{}
				for _, ep := range endpoints {
					methods[ep.Method] = true
				}
				expectedMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"}
				for _, method := range expectedMethods {
					if !methods[method] {
						t.Errorf("Missing method %s", method)
					}
				}
			},
		},
		{
			name: "Endpoint with parameters",
			spec: &OpenAPI3Spec{
				Paths: map[string]OpenAPI3PathItem{
					"/users/{id}": {
						Parameters: []OpenAPI3Parameter{
							{
								Name:        "id",
								In:          "path",
								Required:    true,
								Description: "User ID",
								Schema: &OpenAPI3Schema{
									Type: "integer",
								},
							},
						},
						Get: &OpenAPI3Operation{
							OperationID: "getUser",
							Parameters: []OpenAPI3Parameter{
								{
									Name:     "expand",
									In:       "query",
									Required: false,
									Schema: &OpenAPI3Schema{
										Type: "string",
									},
								},
							},
						},
					},
				},
			},
			wantEndpoints: 1,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				if len(endpoints[0].Parameters) != 2 {
					t.Errorf("Expected 2 parameters, got %d", len(endpoints[0].Parameters))
				}
			},
		},
		{
			name: "Endpoint with request body",
			spec: &OpenAPI3Spec{
				Paths: map[string]OpenAPI3PathItem{
					"/users": {
						Post: &OpenAPI3Operation{
							OperationID: "createUser",
							RequestBody: &OpenAPI3RequestBody{
								Description: "User data",
								Required:    true,
								Content: map[string]OpenAPI3MediaType{
									"application/json": {
										Schema: &OpenAPI3Schema{
											Type: "object",
											Properties: map[string]*OpenAPI3Schema{
												"name":  {Type: "string"},
												"email": {Type: "string", Format: "email"},
											},
											Required: []string{"name", "email"},
										},
									},
								},
							},
						},
					},
				},
			},
			wantEndpoints: 1,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				if endpoints[0].RequestBody == nil {
					t.Error("Expected request body")
					return
				}
				if endpoints[0].RequestBody.ContentType != "application/json" {
					t.Errorf("Expected content type application/json, got %s", endpoints[0].RequestBody.ContentType)
				}
			},
		},
		{
			name: "Endpoint with responses",
			spec: &OpenAPI3Spec{
				Paths: map[string]OpenAPI3PathItem{
					"/users": {
						Get: &OpenAPI3Operation{
							OperationID: "listUsers",
							Responses: map[string]OpenAPI3Response{
								"200": {
									Description: "Success",
									Content: map[string]OpenAPI3MediaType{
										"application/json": {
											Schema: &OpenAPI3Schema{
												Type: "array",
												Items: &OpenAPI3Schema{
													Type: "object",
												},
											},
										},
									},
								},
								"500": {
									Description: "Server error",
								},
							},
						},
					},
				},
			},
			wantEndpoints: 1,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				if len(endpoints[0].Responses) != 2 {
					t.Errorf("Expected 2 responses, got %d", len(endpoints[0].Responses))
				}
				// Responses should be sorted by status code
				if endpoints[0].Responses[0].StatusCode != "200" {
					t.Errorf("Expected first response to be 200, got %s", endpoints[0].Responses[0].StatusCode)
				}
			},
		},
		{
			name: "Deprecated endpoint",
			spec: &OpenAPI3Spec{
				Paths: map[string]OpenAPI3PathItem{
					"/old": {
						Get: &OpenAPI3Operation{
							OperationID: "oldEndpoint",
							Deprecated:  true,
						},
					},
				},
			},
			wantEndpoints: 1,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				if !endpoints[0].Deprecated {
					t.Error("Expected endpoint to be deprecated")
				}
			},
		},
		{
			name: "Endpoint with security",
			spec: &OpenAPI3Spec{
				Security: []map[string][]string{
					{"globalAuth": {}},
				},
				Paths: map[string]OpenAPI3PathItem{
					"/secure": {
						Get: &OpenAPI3Operation{
							OperationID: "secureEndpoint",
							Security: []map[string][]string{
								{"bearerAuth": {}},
								{"apiKey": {}},
							},
						},
					},
					"/global": {
						Get: &OpenAPI3Operation{
							OperationID: "globalSecure",
						},
					},
				},
			},
			wantEndpoints: 2,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				// Find secureEndpoint
				var secureEp *EndpointInfo
				var globalEp *EndpointInfo
				for i := range endpoints {
					if endpoints[i].OperationID == "secureEndpoint" {
						secureEp = &endpoints[i]
					}
					if endpoints[i].OperationID == "globalSecure" {
						globalEp = &endpoints[i]
					}
				}
				if secureEp == nil || globalEp == nil {
					t.Fatal("Could not find endpoints")
				}
				if len(secureEp.Security) != 2 {
					t.Errorf("Expected 2 security requirements, got %d", len(secureEp.Security))
				}
				if len(globalEp.Security) != 1 {
					t.Errorf("Expected 1 global security requirement, got %d", len(globalEp.Security))
				}
			},
		},
		{
			name: "Endpoint with $ref parameter (skipped)",
			spec: &OpenAPI3Spec{
				Paths: map[string]OpenAPI3PathItem{
					"/users": {
						Get: &OpenAPI3Operation{
							OperationID: "listUsers",
							Parameters: []OpenAPI3Parameter{
								{
									Ref: "#/components/parameters/PageParam",
								},
								{
									Name: "limit",
									In:   "query",
									Schema: &OpenAPI3Schema{
										Type: "integer",
									},
								},
							},
						},
					},
				},
			},
			wantEndpoints: 1,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				// $ref parameters should be skipped
				if len(endpoints[0].Parameters) != 1 {
					t.Errorf("Expected 1 parameter (ref should be skipped), got %d", len(endpoints[0].Parameters))
				}
				if endpoints[0].Parameters[0].Name != "limit" {
					t.Errorf("Expected parameter 'limit', got '%s'", endpoints[0].Parameters[0].Name)
				}
			},
		},
		{
			name: "Multiple paths sorted",
			spec: &OpenAPI3Spec{
				Paths: map[string]OpenAPI3PathItem{
					"/zebra": {
						Get: &OpenAPI3Operation{OperationID: "zebra"},
					},
					"/apple": {
						Get: &OpenAPI3Operation{OperationID: "apple"},
					},
					"/middle": {
						Get: &OpenAPI3Operation{OperationID: "middle"},
					},
				},
			},
			wantEndpoints: 3,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				// Paths should be sorted alphabetically
				if endpoints[0].Path != "/apple" {
					t.Errorf("Expected first path to be /apple, got %s", endpoints[0].Path)
				}
				if endpoints[1].Path != "/middle" {
					t.Errorf("Expected second path to be /middle, got %s", endpoints[1].Path)
				}
				if endpoints[2].Path != "/zebra" {
					t.Errorf("Expected third path to be /zebra, got %s", endpoints[2].Path)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoints := extractOpenAPI3Endpoints(tt.spec)
			if len(endpoints) != tt.wantEndpoints {
				t.Errorf("extractOpenAPI3Endpoints() returned %d endpoints, want %d", len(endpoints), tt.wantEndpoints)
			}
			if tt.validate != nil {
				tt.validate(t, endpoints)
			}
		})
	}
}

func TestConvertOpenAPI3Parameter(t *testing.T) {
	tests := []struct {
		name  string
		param *OpenAPI3Parameter
		want  ParameterInfo
	}{
		{
			name: "Simple parameter",
			param: &OpenAPI3Parameter{
				Name:        "id",
				In:          "path",
				Required:    true,
				Description: "User ID",
				Schema: &OpenAPI3Schema{
					Type: "integer",
				},
			},
			want: ParameterInfo{
				Name:        "id",
				In:          "path",
				Required:    true,
				Description: "User ID",
				Schema: &SchemaInfo{
					Type: "integer",
				},
			},
		},
		{
			name: "Query parameter with format",
			param: &OpenAPI3Parameter{
				Name:     "email",
				In:       "query",
				Required: false,
				Schema: &OpenAPI3Schema{
					Type:   "string",
					Format: "email",
				},
			},
			want: ParameterInfo{
				Name:     "email",
				In:       "query",
				Required: false,
				Schema: &SchemaInfo{
					Type:   "string",
					Format: "email",
				},
			},
		},
		{
			name: "Parameter without schema",
			param: &OpenAPI3Parameter{
				Name:     "test",
				In:       "header",
				Required: false,
			},
			want: ParameterInfo{
				Name:     "test",
				In:       "header",
				Required: false,
				Schema:   nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertOpenAPI3Parameter(tt.param)
			if got.Name != tt.want.Name {
				t.Errorf("Name = %v, want %v", got.Name, tt.want.Name)
			}
			if got.In != tt.want.In {
				t.Errorf("In = %v, want %v", got.In, tt.want.In)
			}
			if got.Required != tt.want.Required {
				t.Errorf("Required = %v, want %v", got.Required, tt.want.Required)
			}
			if got.Description != tt.want.Description {
				t.Errorf("Description = %v, want %v", got.Description, tt.want.Description)
			}
		})
	}
}

func TestConvertOpenAPI3RequestBody(t *testing.T) {
	tests := []struct {
		name string
		body *OpenAPI3RequestBody
		want func(*SchemaInfo) bool
	}{
		{
			name: "JSON request body",
			body: &OpenAPI3RequestBody{
				Description: "User data",
				Required:    true,
				Content: map[string]OpenAPI3MediaType{
					"application/json": {
						Schema: &OpenAPI3Schema{
							Type: "object",
							Properties: map[string]*OpenAPI3Schema{
								"name":  {Type: "string"},
								"email": {Type: "string", Format: "email"},
							},
							Required: []string{"name"},
						},
					},
				},
			},
			want: func(result *SchemaInfo) bool {
				return result.ContentType == "application/json" &&
					result.Type == "object" &&
					len(result.Properties) == 2 &&
					result.Properties["name"] == "string" &&
					result.Properties["email"] == "string (email)"
			},
		},
		{
			name: "Empty content",
			body: &OpenAPI3RequestBody{
				Description: "Empty body",
				Content:     map[string]OpenAPI3MediaType{},
			},
			want: func(result *SchemaInfo) bool {
				return result.Description == "Empty body" &&
					result.ContentType == ""
			},
		},
		{
			name: "Multiple content types (first is used)",
			body: &OpenAPI3RequestBody{
				Content: map[string]OpenAPI3MediaType{
					"application/json": {
						Schema: &OpenAPI3Schema{Type: "object"},
					},
					"application/xml": {
						Schema: &OpenAPI3Schema{Type: "string"},
					},
				},
			},
			want: func(result *SchemaInfo) bool {
				// Only the first content type should be used
				return result.ContentType != "" && result.Type != ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertOpenAPI3RequestBody(tt.body)
			if !tt.want(result) {
				t.Errorf("convertOpenAPI3RequestBody() validation failed")
			}
		})
	}
}

func TestConvertOpenAPI3Response(t *testing.T) {
	tests := []struct {
		name       string
		statusCode string
		response   *OpenAPI3Response
		want       func(*ResponseInfo) bool
	}{
		{
			name:       "Success response with schema",
			statusCode: "200",
			response: &OpenAPI3Response{
				Description: "Success",
				Content: map[string]OpenAPI3MediaType{
					"application/json": {
						Schema: &OpenAPI3Schema{
							Type: "object",
						},
					},
				},
			},
			want: func(result *ResponseInfo) bool {
				return result.StatusCode == "200" &&
					result.Description == "Success" &&
					result.Schema != nil &&
					result.Schema.Type == "object"
			},
		},
		{
			name:       "Error response without schema",
			statusCode: "404",
			response: &OpenAPI3Response{
				Description: "Not found",
			},
			want: func(result *ResponseInfo) bool {
				return result.StatusCode == "404" &&
					result.Description == "Not found" &&
					result.Schema == nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertOpenAPI3Response(tt.statusCode, tt.response)
			if !tt.want(&result) {
				t.Errorf("convertOpenAPI3Response() validation failed")
			}
		})
	}
}

func TestConvertOpenAPI3Schema(t *testing.T) {
	tests := []struct {
		name        string
		schema      *OpenAPI3Schema
		contentType string
		want        func(*SchemaInfo) bool
	}{
		{
			name:   "Nil schema",
			schema: nil,
			want: func(result *SchemaInfo) bool {
				return result == nil
			},
		},
		{
			name: "Simple string schema",
			schema: &OpenAPI3Schema{
				Type:        "string",
				Format:      "email",
				Description: "Email address",
			},
			contentType: "application/json",
			want: func(result *SchemaInfo) bool {
				return result.Type == "string" &&
					result.Format == "email" &&
					result.Description == "Email address" &&
					result.ContentType == "application/json"
			},
		},
		{
			name: "Object with properties",
			schema: &OpenAPI3Schema{
				Type: "object",
				Properties: map[string]*OpenAPI3Schema{
					"id":    {Type: "integer"},
					"name":  {Type: "string"},
					"email": {Type: "string", Format: "email"},
				},
				Required: []string{"id", "name"},
			},
			want: func(result *SchemaInfo) bool {
				return result.Type == "object" &&
					len(result.Properties) == 3 &&
					result.Properties["id"] == "integer" &&
					result.Properties["name"] == "string" &&
					result.Properties["email"] == "string (email)" &&
					len(result.Required) == 2
			},
		},
		{
			name: "Array with items",
			schema: &OpenAPI3Schema{
				Type: "array",
				Items: &OpenAPI3Schema{
					Type: "string",
				},
			},
			want: func(result *SchemaInfo) bool {
				return result.Type == "array[string]"
			},
		},
		{
			name: "Array with object items",
			schema: &OpenAPI3Schema{
				Type: "array",
				Items: &OpenAPI3Schema{
					Type: "object",
				},
			},
			want: func(result *SchemaInfo) bool {
				return result.Type == "array[object]"
			},
		},
		{
			name: "Schema with example",
			schema: &OpenAPI3Schema{
				Type:    "string",
				Example: "test@example.com",
			},
			want: func(result *SchemaInfo) bool {
				return result.Example == "test@example.com"
			},
		},
		{
			name: "Schema with complex example",
			schema: &OpenAPI3Schema{
				Type:    "object",
				Example: map[string]interface{}{"key": "value"},
			},
			want: func(result *SchemaInfo) bool {
				return result.Example != ""
			},
		},
		{
			name: "Nested properties",
			schema: &OpenAPI3Schema{
				Type: "object",
				Properties: map[string]*OpenAPI3Schema{
					"address": {
						Type: "object",
						Properties: map[string]*OpenAPI3Schema{
							"street": {Type: "string"},
							"city":   {Type: "string"},
						},
					},
				},
			},
			want: func(result *SchemaInfo) bool {
				// Nested properties are simplified to just type
				return result.Type == "object" &&
					len(result.Properties) == 1 &&
					result.Properties["address"] == "object"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertOpenAPI3Schema(tt.schema, tt.contentType)
			if !tt.want(result) {
				t.Errorf("convertOpenAPI3Schema() validation failed")
			}
		})
	}
}

func TestExtractRefName(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{
			name: "Component schema reference",
			ref:  "#/components/schemas/User",
			want: "User",
		},
		{
			name: "Component parameter reference",
			ref:  "#/components/parameters/PageParam",
			want: "PageParam",
		},
		{
			name: "Simple name",
			ref:  "User",
			want: "User",
		},
		{
			name: "Empty ref",
			ref:  "",
			want: "",
		},
		{
			name: "Deep nested reference",
			ref:  "#/components/schemas/nested/User",
			want: "User",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRefName(tt.ref)
			if got != tt.want {
				t.Errorf("extractRefName(%s) = %s, want %s", tt.ref, got, tt.want)
			}
		})
	}
}

func TestOpenAPI3_EdgeCases(t *testing.T) {
	t.Run("Empty operations", func(t *testing.T) {
		spec := &OpenAPI3Spec{
			Paths: map[string]OpenAPI3PathItem{
				"/test": {
					Get: &OpenAPI3Operation{
						OperationID: "test",
						// No parameters, request body, or responses
					},
				},
			},
		}
		endpoints := extractOpenAPI3Endpoints(spec)
		if len(endpoints) != 1 {
			t.Errorf("Expected 1 endpoint, got %d", len(endpoints))
		}
		if len(endpoints[0].Parameters) != 0 {
			t.Errorf("Expected 0 parameters, got %d", len(endpoints[0].Parameters))
		}
		if endpoints[0].RequestBody != nil {
			t.Error("Expected nil request body")
		}
		if len(endpoints[0].Responses) != 0 {
			t.Errorf("Expected 0 responses, got %d", len(endpoints[0].Responses))
		}
	})

	t.Run("Path-level and operation-level parameters combined", func(t *testing.T) {
		spec := &OpenAPI3Spec{
			Paths: map[string]OpenAPI3PathItem{
				"/users/{id}": {
					Parameters: []OpenAPI3Parameter{
						{Name: "id", In: "path", Required: true, Schema: &OpenAPI3Schema{Type: "integer"}},
					},
					Get: &OpenAPI3Operation{
						OperationID: "getUser",
						Parameters: []OpenAPI3Parameter{
							{Name: "expand", In: "query", Schema: &OpenAPI3Schema{Type: "string"}},
						},
					},
				},
			},
		}
		endpoints := extractOpenAPI3Endpoints(spec)
		if len(endpoints[0].Parameters) != 2 {
			t.Errorf("Expected 2 parameters (path + operation level), got %d", len(endpoints[0].Parameters))
		}
	})

	t.Run("Missing info fields", func(t *testing.T) {
		spec := `
openapi: "3.0.0"
info:
  title: ""
  version: ""
paths: {}
`
		result, err := ParseOpenAPI3([]byte(spec))
		if err != nil {
			t.Errorf("ParseOpenAPI3() error = %v", err)
		}
		if result.Title != "" || result.Version != "" {
			t.Error("Expected empty title and version to be preserved")
		}
	})
}
