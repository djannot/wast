package api

import (
	"testing"
)

func TestParseSwagger2_ValidSpec(t *testing.T) {
	tests := []struct {
		name string
		spec string
	}{
		{
			name: "Complete YAML spec",
			spec: `
swagger: "2.0"
info:
  title: Test API
  version: "1.0.0"
  description: A test API
host: api.example.com
basePath: /v1
schemes:
  - https
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
  "swagger": "2.0",
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
swagger: "2.0"
info:
  title: Minimal API
  version: "1.0"
paths: {}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseSwagger2([]byte(tt.spec))
			if err != nil {
				t.Errorf("ParseSwagger2() error = %v", err)
				return
			}
			if spec == nil {
				t.Error("ParseSwagger2() returned nil spec")
			}
		})
	}
}

func TestParseSwagger2_InvalidSpec(t *testing.T) {
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
			_, err := ParseSwagger2([]byte(tt.spec))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSwagger2() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConvertSwagger2ToAPISpec(t *testing.T) {
	tests := []struct {
		name string
		spec *Swagger2Spec
		want func(*APISpec) bool
	}{
		{
			name: "Basic info conversion",
			spec: &Swagger2Spec{
				Swagger: "2.0",
				Info: Swagger2Info{
					Title:       "Test API",
					Version:     "1.0.0",
					Description: "Test Description",
				},
			},
			want: func(result *APISpec) bool {
				return result.Title == "Test API" &&
					result.Version == "1.0.0" &&
					result.Description == "Test Description" &&
					result.SpecVersion == "Swagger 2.0"
			},
		},
		{
			name: "Server from host and basePath with schemes",
			spec: &Swagger2Spec{
				Swagger: "2.0",
				Info: Swagger2Info{
					Title:   "Test",
					Version: "1.0",
				},
				Host:     "api.example.com",
				BasePath: "/v1",
				Schemes:  []string{"https", "http"},
			},
			want: func(result *APISpec) bool {
				if len(result.Servers) != 2 {
					return false
				}
				return result.Servers[0].URL == "https://api.example.com/v1" &&
					result.Servers[1].URL == "http://api.example.com/v1"
			},
		},
		{
			name: "Server with default scheme",
			spec: &Swagger2Spec{
				Swagger: "2.0",
				Info: Swagger2Info{
					Title:   "Test",
					Version: "1.0",
				},
				Host:     "api.example.com",
				BasePath: "/v1",
				// No schemes specified - should default to https
			},
			want: func(result *APISpec) bool {
				if len(result.Servers) != 1 {
					return false
				}
				return result.Servers[0].URL == "https://api.example.com/v1"
			},
		},
		{
			name: "Server with default basePath",
			spec: &Swagger2Spec{
				Swagger: "2.0",
				Info: Swagger2Info{
					Title:   "Test",
					Version: "1.0",
				},
				Host:    "api.example.com",
				Schemes: []string{"https"},
				// No basePath specified - should default to /
			},
			want: func(result *APISpec) bool {
				if len(result.Servers) != 1 {
					return false
				}
				return result.Servers[0].URL == "https://api.example.com/"
			},
		},
		{
			name: "No host - no servers",
			spec: &Swagger2Spec{
				Swagger: "2.0",
				Info: Swagger2Info{
					Title:   "Test",
					Version: "1.0",
				},
			},
			want: func(result *APISpec) bool {
				return len(result.Servers) == 0
			},
		},
		{
			name: "Security definitions conversion",
			spec: &Swagger2Spec{
				Swagger: "2.0",
				Info: Swagger2Info{
					Title:   "Test",
					Version: "1.0",
				},
				SecurityDefinitions: map[string]*Swagger2SecurityDef{
					"oauth2": {
						Type:        "oauth2",
						Flow:        "accessCode",
						Description: "OAuth2",
					},
					"apiKey": {
						Type: "apiKey",
						In:   "header",
						Name: "X-API-Key",
					},
				},
			},
			want: func(result *APISpec) bool {
				if len(result.AuthSchemes) != 2 {
					return false
				}
				// Should be sorted by name
				return result.AuthSchemes[0].Name == "apiKey" &&
					result.AuthSchemes[1].Name == "oauth2"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertSwagger2ToAPISpec(tt.spec)
			if !tt.want(result) {
				t.Errorf("convertSwagger2ToAPISpec() validation failed")
			}
		})
	}
}

func TestExtractSwagger2Endpoints(t *testing.T) {
	tests := []struct {
		name          string
		spec          *Swagger2Spec
		wantEndpoints int
		validate      func(*testing.T, []EndpointInfo)
	}{
		{
			name: "Empty paths",
			spec: &Swagger2Spec{
				Paths: map[string]Swagger2PathItem{},
			},
			wantEndpoints: 0,
		},
		{
			name: "Single GET endpoint",
			spec: &Swagger2Spec{
				Paths: map[string]Swagger2PathItem{
					"/users": {
						Get: &Swagger2Operation{
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
			name: "All HTTP methods (except TRACE)",
			spec: &Swagger2Spec{
				Paths: map[string]Swagger2PathItem{
					"/resource": {
						Get:     &Swagger2Operation{OperationID: "get"},
						Post:    &Swagger2Operation{OperationID: "post"},
						Put:     &Swagger2Operation{OperationID: "put"},
						Delete:  &Swagger2Operation{OperationID: "delete"},
						Patch:   &Swagger2Operation{OperationID: "patch"},
						Options: &Swagger2Operation{OperationID: "options"},
						Head:    &Swagger2Operation{OperationID: "head"},
					},
				},
			},
			wantEndpoints: 7,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				methods := map[string]bool{}
				for _, ep := range endpoints {
					methods[ep.Method] = true
				}
				expectedMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
				for _, method := range expectedMethods {
					if !methods[method] {
						t.Errorf("Missing method %s", method)
					}
				}
			},
		},
		{
			name: "Endpoint with query parameters",
			spec: &Swagger2Spec{
				Paths: map[string]Swagger2PathItem{
					"/users": {
						Get: &Swagger2Operation{
							OperationID: "listUsers",
							Parameters: []Swagger2Parameter{
								{
									Name:     "page",
									In:       "query",
									Type:     "integer",
									Required: false,
								},
								{
									Name:     "limit",
									In:       "query",
									Type:     "integer",
									Required: false,
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
			name: "Endpoint with path parameters",
			spec: &Swagger2Spec{
				Paths: map[string]Swagger2PathItem{
					"/users/{id}": {
						Parameters: []Swagger2Parameter{
							{
								Name:     "id",
								In:       "path",
								Type:     "integer",
								Required: true,
							},
						},
						Get: &Swagger2Operation{
							OperationID: "getUser",
						},
					},
				},
			},
			wantEndpoints: 1,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				if len(endpoints[0].Parameters) != 1 {
					t.Errorf("Expected 1 parameter, got %d", len(endpoints[0].Parameters))
				}
				if endpoints[0].Parameters[0].In != "path" {
					t.Errorf("Expected parameter in 'path', got '%s'", endpoints[0].Parameters[0].In)
				}
			},
		},
		{
			name: "Endpoint with body parameter",
			spec: &Swagger2Spec{
				Paths: map[string]Swagger2PathItem{
					"/users": {
						Post: &Swagger2Operation{
							OperationID: "createUser",
							Consumes:    []string{"application/json"},
							Parameters: []Swagger2Parameter{
								{
									Name:     "body",
									In:       "body",
									Required: true,
									Schema: &Swagger2Schema{
										Type: "object",
										Properties: map[string]*Swagger2Schema{
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
			wantEndpoints: 1,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				if endpoints[0].RequestBody == nil {
					t.Error("Expected request body")
					return
				}
				if endpoints[0].RequestBody.ContentType != "application/json" {
					t.Errorf("Expected content type application/json, got %s", endpoints[0].RequestBody.ContentType)
				}
				// Body parameter should not appear in parameters list
				if len(endpoints[0].Parameters) != 0 {
					t.Errorf("Expected 0 parameters (body params become request body), got %d", len(endpoints[0].Parameters))
				}
			},
		},
		{
			name: "Endpoint with responses and produces",
			spec: &Swagger2Spec{
				Paths: map[string]Swagger2PathItem{
					"/users": {
						Get: &Swagger2Operation{
							OperationID: "listUsers",
							Produces:    []string{"application/json", "application/xml"},
							Responses: map[string]Swagger2Response{
								"200": {
									Description: "Success",
									Schema: &Swagger2Schema{
										Type: "array",
										Items: &Swagger2Schema{
											Type: "object",
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
				// Schema should use first produces content type
				if endpoints[0].Responses[0].Schema == nil {
					t.Error("Expected response schema")
				}
			},
		},
		{
			name: "Deprecated endpoint",
			spec: &Swagger2Spec{
				Paths: map[string]Swagger2PathItem{
					"/old": {
						Get: &Swagger2Operation{
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
			spec: &Swagger2Spec{
				Security: []map[string][]string{
					{"globalAuth": {}},
				},
				Paths: map[string]Swagger2PathItem{
					"/secure": {
						Get: &Swagger2Operation{
							OperationID: "secureEndpoint",
							Security: []map[string][]string{
								{"oauth2": {}},
								{"apiKey": {}},
							},
						},
					},
					"/global": {
						Get: &Swagger2Operation{
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
			spec: &Swagger2Spec{
				Paths: map[string]Swagger2PathItem{
					"/users": {
						Get: &Swagger2Operation{
							OperationID: "listUsers",
							Parameters: []Swagger2Parameter{
								{
									Ref: "#/parameters/PageParam",
								},
								{
									Name: "limit",
									In:   "query",
									Type: "integer",
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
			spec: &Swagger2Spec{
				Paths: map[string]Swagger2PathItem{
					"/zebra": {
						Get: &Swagger2Operation{OperationID: "zebra"},
					},
					"/apple": {
						Get: &Swagger2Operation{OperationID: "apple"},
					},
					"/middle": {
						Get: &Swagger2Operation{OperationID: "middle"},
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
		{
			name: "Path and operation level parameters combined",
			spec: &Swagger2Spec{
				Paths: map[string]Swagger2PathItem{
					"/users/{id}": {
						Parameters: []Swagger2Parameter{
							{Name: "id", In: "path", Type: "string", Required: true},
						},
						Get: &Swagger2Operation{
							OperationID: "getUser",
							Parameters: []Swagger2Parameter{
								{Name: "expand", In: "query", Type: "string"},
							},
						},
					},
				},
			},
			wantEndpoints: 1,
			validate: func(t *testing.T, endpoints []EndpointInfo) {
				if len(endpoints[0].Parameters) != 2 {
					t.Errorf("Expected 2 parameters (path + operation level), got %d", len(endpoints[0].Parameters))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoints := extractSwagger2Endpoints(tt.spec)
			if len(endpoints) != tt.wantEndpoints {
				t.Errorf("extractSwagger2Endpoints() returned %d endpoints, want %d", len(endpoints), tt.wantEndpoints)
			}
			if tt.validate != nil {
				tt.validate(t, endpoints)
			}
		})
	}
}

func TestConvertSwagger2Parameter(t *testing.T) {
	tests := []struct {
		name  string
		param *Swagger2Parameter
		want  func(*ParameterInfo) bool
	}{
		{
			name: "Simple type parameter",
			param: &Swagger2Parameter{
				Name:     "id",
				In:       "path",
				Type:     "integer",
				Required: true,
			},
			want: func(result *ParameterInfo) bool {
				return result.Name == "id" &&
					result.In == "path" &&
					result.Required == true &&
					result.Schema != nil &&
					result.Schema.Type == "integer"
			},
		},
		{
			name: "Parameter with format",
			param: &Swagger2Parameter{
				Name:   "email",
				In:     "query",
				Type:   "string",
				Format: "email",
			},
			want: func(result *ParameterInfo) bool {
				return result.Schema != nil &&
					result.Schema.Type == "string" &&
					result.Schema.Format == "email"
			},
		},
		{
			name: "Parameter with schema",
			param: &Swagger2Parameter{
				Name:     "filter",
				In:       "query",
				Required: false,
				Schema: &Swagger2Schema{
					Type: "object",
					Properties: map[string]*Swagger2Schema{
						"name": {Type: "string"},
					},
				},
			},
			want: func(result *ParameterInfo) bool {
				return result.Schema != nil &&
					result.Schema.Type == "object" &&
					len(result.Schema.Properties) == 1
			},
		},
		{
			name: "Body parameter",
			param: &Swagger2Parameter{
				Name:     "body",
				In:       "body",
				Required: true,
				Schema: &Swagger2Schema{
					Type: "object",
					Properties: map[string]*Swagger2Schema{
						"name":  {Type: "string"},
						"email": {Type: "string", Format: "email"},
					},
				},
			},
			want: func(result *ParameterInfo) bool {
				return result.In == "body" &&
					result.Schema != nil &&
					result.Schema.Type == "object"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertSwagger2Parameter(tt.param)
			if !tt.want(&result) {
				t.Errorf("convertSwagger2Parameter() validation failed")
			}
		})
	}
}

func TestConvertSwagger2Response(t *testing.T) {
	tests := []struct {
		name       string
		statusCode string
		response   *Swagger2Response
		produces   []string
		want       func(*ResponseInfo) bool
	}{
		{
			name:       "Success response with schema",
			statusCode: "200",
			response: &Swagger2Response{
				Description: "Success",
				Schema: &Swagger2Schema{
					Type: "object",
				},
			},
			produces: []string{"application/json"},
			want: func(result *ResponseInfo) bool {
				return result.StatusCode == "200" &&
					result.Description == "Success" &&
					result.Schema != nil &&
					result.Schema.Type == "object" &&
					result.Schema.ContentType == "application/json"
			},
		},
		{
			name:       "Error response without schema",
			statusCode: "404",
			response: &Swagger2Response{
				Description: "Not found",
			},
			produces: nil,
			want: func(result *ResponseInfo) bool {
				return result.StatusCode == "404" &&
					result.Description == "Not found" &&
					result.Schema == nil
			},
		},
		{
			name:       "Response with multiple produces (uses first)",
			statusCode: "200",
			response: &Swagger2Response{
				Description: "Success",
				Schema: &Swagger2Schema{
					Type: "string",
				},
			},
			produces: []string{"application/json", "application/xml"},
			want: func(result *ResponseInfo) bool {
				return result.Schema != nil &&
					result.Schema.ContentType == "application/json"
			},
		},
		{
			name:       "Response without produces",
			statusCode: "200",
			response: &Swagger2Response{
				Schema: &Swagger2Schema{
					Type: "object",
				},
			},
			produces: []string{},
			want: func(result *ResponseInfo) bool {
				return result.Schema != nil &&
					result.Schema.ContentType == ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertSwagger2Response(tt.statusCode, tt.response, tt.produces)
			if !tt.want(&result) {
				t.Errorf("convertSwagger2Response() validation failed")
			}
		})
	}
}

func TestConvertSwagger2Schema(t *testing.T) {
	tests := []struct {
		name        string
		schema      *Swagger2Schema
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
			schema: &Swagger2Schema{
				Type:        "string",
				Format:      "date-time",
				Description: "Creation timestamp",
			},
			contentType: "application/json",
			want: func(result *SchemaInfo) bool {
				return result.Type == "string" &&
					result.Format == "date-time" &&
					result.Description == "Creation timestamp" &&
					result.ContentType == "application/json"
			},
		},
		{
			name: "Object with properties",
			schema: &Swagger2Schema{
				Type: "object",
				Properties: map[string]*Swagger2Schema{
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
			schema: &Swagger2Schema{
				Type: "array",
				Items: &Swagger2Schema{
					Type: "integer",
				},
			},
			want: func(result *SchemaInfo) bool {
				return result.Type == "array[integer]"
			},
		},
		{
			name: "Array with object items",
			schema: &Swagger2Schema{
				Type: "array",
				Items: &Swagger2Schema{
					Type: "object",
					Properties: map[string]*Swagger2Schema{
						"id": {Type: "integer"},
					},
				},
			},
			want: func(result *SchemaInfo) bool {
				return result.Type == "array[object]"
			},
		},
		{
			name: "Schema with example",
			schema: &Swagger2Schema{
				Type:    "string",
				Example: "example@test.com",
			},
			want: func(result *SchemaInfo) bool {
				return result.Example == "example@test.com"
			},
		},
		{
			name: "Schema with complex example",
			schema: &Swagger2Schema{
				Type:    "object",
				Example: map[string]interface{}{"key": "value"},
			},
			want: func(result *SchemaInfo) bool {
				return result.Example != ""
			},
		},
		{
			name: "Nested object properties",
			schema: &Swagger2Schema{
				Type: "object",
				Properties: map[string]*Swagger2Schema{
					"user": {
						Type: "object",
						Properties: map[string]*Swagger2Schema{
							"name": {Type: "string"},
						},
					},
				},
			},
			want: func(result *SchemaInfo) bool {
				// Nested properties are simplified to just type
				return result.Type == "object" &&
					len(result.Properties) == 1 &&
					result.Properties["user"] == "object"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertSwagger2Schema(tt.schema, tt.contentType)
			if !tt.want(result) {
				t.Errorf("convertSwagger2Schema() validation failed")
			}
		})
	}
}

func TestSwagger2_EdgeCases(t *testing.T) {
	t.Run("Empty operations", func(t *testing.T) {
		spec := &Swagger2Spec{
			Paths: map[string]Swagger2PathItem{
				"/test": {
					Get: &Swagger2Operation{
						OperationID: "test",
						// No parameters or responses
					},
				},
			},
		}
		endpoints := extractSwagger2Endpoints(spec)
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

	t.Run("Body parameter without consumes", func(t *testing.T) {
		spec := &Swagger2Spec{
			Paths: map[string]Swagger2PathItem{
				"/users": {
					Post: &Swagger2Operation{
						OperationID: "createUser",
						// No consumes
						Parameters: []Swagger2Parameter{
							{
								Name: "body",
								In:   "body",
								Schema: &Swagger2Schema{
									Type: "object",
								},
							},
						},
					},
				},
			},
		}
		endpoints := extractSwagger2Endpoints(spec)
		if endpoints[0].RequestBody == nil {
			t.Error("Expected request body")
			return
		}
		// ContentType should be empty if no consumes
		if endpoints[0].RequestBody.ContentType != "" {
			t.Errorf("Expected empty content type, got %s", endpoints[0].RequestBody.ContentType)
		}
	})

	t.Run("Missing info fields", func(t *testing.T) {
		spec := `
swagger: "2.0"
info:
  title: ""
  version: ""
paths: {}
`
		result, err := ParseSwagger2([]byte(spec))
		if err != nil {
			t.Errorf("ParseSwagger2() error = %v", err)
		}
		if result.Title != "" || result.Version != "" {
			t.Error("Expected empty title and version to be preserved")
		}
	})

	t.Run("Parameter with both type and schema", func(t *testing.T) {
		// According to Swagger 2.0 spec, parameters should have either type OR schema
		// If type is present, it should be used
		param := &Swagger2Parameter{
			Name: "test",
			In:   "query",
			Type: "string",
			Schema: &Swagger2Schema{
				Type: "object", // Should be ignored
			},
		}
		result := convertSwagger2Parameter(param)
		if result.Schema == nil {
			t.Error("Expected schema to be created from type")
			return
		}
		if result.Schema.Type != "string" {
			t.Errorf("Expected type 'string' from parameter.Type, got '%s'", result.Schema.Type)
		}
	})
}

func TestSwagger2_ComprehensiveParsing(t *testing.T) {
	spec := `
swagger: "2.0"
info:
  title: Complete API
  version: "2.0.0"
  description: A comprehensive test API
host: api.example.com
basePath: /api/v2
schemes:
  - https
  - http
paths:
  /items:
    get:
      operationId: listItems
      summary: List items
      tags:
        - items
      produces:
        - application/json
      parameters:
        - name: page
          in: query
          type: integer
          description: Page number
        - name: size
          in: query
          type: integer
          description: Page size
      responses:
        "200":
          description: Success
          schema:
            type: array
            items:
              type: object
              properties:
                id:
                  type: integer
                name:
                  type: string
        "400":
          description: Bad request
    post:
      operationId: createItem
      summary: Create item
      tags:
        - items
      consumes:
        - application/json
      produces:
        - application/json
      parameters:
        - name: body
          in: body
          required: true
          schema:
            type: object
            required:
              - name
            properties:
              name:
                type: string
              description:
                type: string
      responses:
        "201":
          description: Created
      security:
        - apiKey: []
  /items/{id}:
    parameters:
      - name: id
        in: path
        required: true
        type: integer
        description: Item ID
    get:
      operationId: getItem
      summary: Get item by ID
      tags:
        - items
      produces:
        - application/json
      responses:
        "200":
          description: Success
        "404":
          description: Not found
    put:
      operationId: updateItem
      summary: Update item
      deprecated: true
      tags:
        - items
      consumes:
        - application/json
      parameters:
        - name: body
          in: body
          required: true
          schema:
            type: object
            properties:
              name:
                type: string
      responses:
        "200":
          description: Updated
securityDefinitions:
  apiKey:
    type: apiKey
    in: header
    name: X-API-Key
    description: API key authentication
  oauth2:
    type: oauth2
    flow: implicit
    description: OAuth2 authentication
security:
  - apiKey: []
`

	result, err := ParseSwagger2([]byte(spec))
	if err != nil {
		t.Fatalf("Failed to parse comprehensive spec: %v", err)
	}

	// Verify basic info
	if result.Title != "Complete API" {
		t.Errorf("Expected title 'Complete API', got '%s'", result.Title)
	}
	if result.Version != "2.0.0" {
		t.Errorf("Expected version '2.0.0', got '%s'", result.Version)
	}

	// Verify servers
	if len(result.Servers) != 2 {
		t.Errorf("Expected 2 servers, got %d", len(result.Servers))
	}

	// Verify endpoints (GET /items, POST /items, GET /items/{id}, PUT /items/{id})
	if len(result.Endpoints) != 4 {
		t.Errorf("Expected 4 endpoints, got %d", len(result.Endpoints))
	}

	// Verify auth schemes
	if len(result.AuthSchemes) != 2 {
		t.Errorf("Expected 2 auth schemes, got %d", len(result.AuthSchemes))
	}

	// Find specific endpoints
	var listItems, createItem, getItem, updateItem *EndpointInfo
	for i := range result.Endpoints {
		switch result.Endpoints[i].OperationID {
		case "listItems":
			listItems = &result.Endpoints[i]
		case "createItem":
			createItem = &result.Endpoints[i]
		case "getItem":
			getItem = &result.Endpoints[i]
		case "updateItem":
			updateItem = &result.Endpoints[i]
		}
	}

	// Verify listItems
	if listItems == nil {
		t.Fatal("listItems endpoint not found")
	}
	if len(listItems.Parameters) != 2 {
		t.Errorf("listItems: Expected 2 query parameters, got %d", len(listItems.Parameters))
	}
	if len(listItems.Responses) != 2 {
		t.Errorf("listItems: Expected 2 responses, got %d", len(listItems.Responses))
	}

	// Verify createItem
	if createItem == nil {
		t.Fatal("createItem endpoint not found")
	}
	if createItem.RequestBody == nil {
		t.Error("createItem: Expected request body")
	}
	if len(createItem.Security) == 0 {
		t.Error("createItem: Expected security requirements")
	}

	// Verify getItem (path parameter from path level)
	if getItem == nil {
		t.Fatal("getItem endpoint not found")
	}
	if len(getItem.Parameters) != 1 {
		t.Errorf("getItem: Expected 1 path parameter, got %d", len(getItem.Parameters))
	}

	// Verify updateItem (deprecated)
	if updateItem == nil {
		t.Fatal("updateItem endpoint not found")
	}
	if !updateItem.Deprecated {
		t.Error("updateItem: Expected endpoint to be deprecated")
	}
}
