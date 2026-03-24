package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Sample OpenAPI 3.0 specification for testing
const openAPI3Spec = `
openapi: "3.0.3"
info:
  title: Pet Store API
  version: "1.0.0"
  description: A sample Pet Store API
servers:
  - url: https://api.petstore.example.com/v1
    description: Production server
  - url: https://staging.petstore.example.com/v1
    description: Staging server
paths:
  /pets:
    get:
      operationId: listPets
      summary: List all pets
      tags:
        - pets
      parameters:
        - name: limit
          in: query
          description: Maximum number of pets to return
          required: false
          schema:
            type: integer
            format: int32
      responses:
        "200":
          description: A list of pets
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
        "500":
          description: Server error
    post:
      operationId: createPet
      summary: Create a pet
      tags:
        - pets
      requestBody:
        description: Pet to create
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - name
              properties:
                name:
                  type: string
                tag:
                  type: string
      responses:
        "201":
          description: Pet created
      security:
        - bearerAuth: []
  /pets/{petId}:
    get:
      operationId: getPetById
      summary: Get a pet by ID
      tags:
        - pets
      parameters:
        - name: petId
          in: path
          required: true
          description: The ID of the pet
          schema:
            type: integer
      responses:
        "200":
          description: A pet
        "404":
          description: Pet not found
    delete:
      operationId: deletePet
      summary: Delete a pet
      deprecated: true
      tags:
        - pets
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: integer
      responses:
        "204":
          description: Pet deleted
      security:
        - bearerAuth: []
        - apiKeyAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      description: JWT Bearer token authentication
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
      description: API Key authentication
`

// Sample Swagger 2.0 specification for testing
const swagger2Spec = `
swagger: "2.0"
info:
  title: User Service API
  version: "2.0.0"
  description: A sample User Service API
host: api.users.example.com
basePath: /v2
schemes:
  - https
  - http
paths:
  /users:
    get:
      operationId: listUsers
      summary: List all users
      tags:
        - users
      produces:
        - application/json
      parameters:
        - name: page
          in: query
          type: integer
          description: Page number
        - name: limit
          in: query
          type: integer
          description: Items per page
      responses:
        "200":
          description: A list of users
          schema:
            type: array
            items:
              type: object
    post:
      operationId: createUser
      summary: Create a user
      tags:
        - users
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
              - email
              - name
            properties:
              email:
                type: string
                format: email
              name:
                type: string
      responses:
        "201":
          description: User created
      security:
        - oauth2: []
  /users/{userId}:
    get:
      operationId: getUserById
      summary: Get a user by ID
      tags:
        - users
      parameters:
        - name: userId
          in: path
          required: true
          type: string
      responses:
        "200":
          description: A user
        "404":
          description: User not found
securityDefinitions:
  oauth2:
    type: oauth2
    flow: accessCode
    description: OAuth2 authentication
  basicAuth:
    type: basic
    description: HTTP Basic authentication
`

// Sample OpenAPI 3.0 specification in JSON format
const openAPI3JSONSpec = `{
  "openapi": "3.0.0",
  "info": {
    "title": "Simple API",
    "version": "1.0.0"
  },
  "paths": {
    "/health": {
      "get": {
        "operationId": "healthCheck",
        "summary": "Health check endpoint",
        "responses": {
          "200": {
            "description": "OK"
          }
        }
      }
    }
  }
}`

func TestParseOpenAPI3(t *testing.T) {
	spec, err := ParseOpenAPI3([]byte(openAPI3Spec))
	if err != nil {
		t.Fatalf("Failed to parse OpenAPI 3 spec: %v", err)
	}

	// Test basic info
	if spec.Title != "Pet Store API" {
		t.Errorf("Expected title 'Pet Store API', got '%s'", spec.Title)
	}
	if spec.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", spec.Version)
	}
	if spec.Description != "A sample Pet Store API" {
		t.Errorf("Expected description 'A sample Pet Store API', got '%s'", spec.Description)
	}
	if spec.SpecVersion != "OpenAPI 3.0.3" {
		t.Errorf("Expected spec version 'OpenAPI 3.0.3', got '%s'", spec.SpecVersion)
	}

	// Test servers
	if len(spec.Servers) != 2 {
		t.Errorf("Expected 2 servers, got %d", len(spec.Servers))
	}
	if spec.Servers[0].URL != "https://api.petstore.example.com/v1" {
		t.Errorf("Unexpected server URL: %s", spec.Servers[0].URL)
	}

	// Test endpoints (GET /pets, POST /pets, GET /pets/{petId}, DELETE /pets/{petId})
	if len(spec.Endpoints) != 4 {
		t.Errorf("Expected 4 endpoints, got %d", len(spec.Endpoints))
	}

	// Find and test specific endpoints
	var listPetsEndpoint, deletePetEndpoint *EndpointInfo
	for i := range spec.Endpoints {
		if spec.Endpoints[i].OperationID == "listPets" {
			listPetsEndpoint = &spec.Endpoints[i]
		}
		if spec.Endpoints[i].OperationID == "deletePet" {
			deletePetEndpoint = &spec.Endpoints[i]
		}
	}

	if listPetsEndpoint == nil {
		t.Fatal("listPets endpoint not found")
	}
	if listPetsEndpoint.Path != "/pets" {
		t.Errorf("Expected path '/pets', got '%s'", listPetsEndpoint.Path)
	}
	if listPetsEndpoint.Method != "GET" {
		t.Errorf("Expected method 'GET', got '%s'", listPetsEndpoint.Method)
	}
	if len(listPetsEndpoint.Parameters) != 1 {
		t.Errorf("Expected 1 parameter, got %d", len(listPetsEndpoint.Parameters))
	}
	if listPetsEndpoint.Parameters[0].Name != "limit" {
		t.Errorf("Expected parameter 'limit', got '%s'", listPetsEndpoint.Parameters[0].Name)
	}

	if deletePetEndpoint == nil {
		t.Fatal("deletePet endpoint not found")
	}
	if !deletePetEndpoint.Deprecated {
		t.Error("Expected deletePet endpoint to be deprecated")
	}

	// Test auth schemes
	if len(spec.AuthSchemes) != 2 {
		t.Errorf("Expected 2 auth schemes, got %d", len(spec.AuthSchemes))
	}
}

func TestParseSwagger2(t *testing.T) {
	spec, err := ParseSwagger2([]byte(swagger2Spec))
	if err != nil {
		t.Fatalf("Failed to parse Swagger 2 spec: %v", err)
	}

	// Test basic info
	if spec.Title != "User Service API" {
		t.Errorf("Expected title 'User Service API', got '%s'", spec.Title)
	}
	if spec.Version != "2.0.0" {
		t.Errorf("Expected version '2.0.0', got '%s'", spec.Version)
	}
	if spec.SpecVersion != "Swagger 2.0" {
		t.Errorf("Expected spec version 'Swagger 2.0', got '%s'", spec.SpecVersion)
	}

	// Test servers (derived from host, basePath, schemes)
	if len(spec.Servers) != 2 {
		t.Errorf("Expected 2 servers, got %d", len(spec.Servers))
	}
	expectedServers := map[string]bool{
		"https://api.users.example.com/v2": true,
		"http://api.users.example.com/v2":  true,
	}
	for _, server := range spec.Servers {
		if !expectedServers[server.URL] {
			t.Errorf("Unexpected server URL: %s", server.URL)
		}
	}

	// Test endpoints
	if len(spec.Endpoints) != 3 {
		t.Errorf("Expected 3 endpoints, got %d", len(spec.Endpoints))
	}

	// Find and test specific endpoints
	var listUsersEndpoint, createUserEndpoint *EndpointInfo
	for i := range spec.Endpoints {
		if spec.Endpoints[i].OperationID == "listUsers" {
			listUsersEndpoint = &spec.Endpoints[i]
		}
		if spec.Endpoints[i].OperationID == "createUser" {
			createUserEndpoint = &spec.Endpoints[i]
		}
	}

	if listUsersEndpoint == nil {
		t.Fatal("listUsers endpoint not found")
	}
	if len(listUsersEndpoint.Parameters) != 2 {
		t.Errorf("Expected 2 parameters, got %d", len(listUsersEndpoint.Parameters))
	}

	if createUserEndpoint == nil {
		t.Fatal("createUser endpoint not found")
	}
	if createUserEndpoint.RequestBody == nil {
		t.Error("Expected createUser to have a request body")
	} else {
		if createUserEndpoint.RequestBody.ContentType != "application/json" {
			t.Errorf("Expected content type 'application/json', got '%s'", createUserEndpoint.RequestBody.ContentType)
		}
	}

	// Test auth schemes
	if len(spec.AuthSchemes) != 2 {
		t.Errorf("Expected 2 auth schemes, got %d", len(spec.AuthSchemes))
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		spec     string
		expected SpecFormat
		wantErr  bool
	}{
		{
			name:     "OpenAPI 3.0 YAML",
			spec:     openAPI3Spec,
			expected: FormatOpenAPI3,
			wantErr:  false,
		},
		{
			name:     "Swagger 2.0 YAML",
			spec:     swagger2Spec,
			expected: FormatSwagger2,
			wantErr:  false,
		},
		{
			name:     "OpenAPI 3.0 JSON",
			spec:     openAPI3JSONSpec,
			expected: FormatOpenAPI3,
			wantErr:  false,
		},
		{
			name:     "Invalid spec",
			spec:     "invalid: [",
			expected: FormatUnknown,
			wantErr:  true,
		},
		{
			name:     "Missing version field",
			spec:     `title: Test API`,
			expected: FormatUnknown,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, err := detectFormat([]byte(tt.spec))
			if (err != nil) != tt.wantErr {
				t.Errorf("detectFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if format != tt.expected {
				t.Errorf("detectFormat() = %v, expected %v", format, tt.expected)
			}
		})
	}
}

func TestParseSpecFromFile(t *testing.T) {
	// Create a temporary file with OpenAPI 3 spec
	tempDir := t.TempDir()
	specFile := filepath.Join(tempDir, "openapi.yaml")
	if err := os.WriteFile(specFile, []byte(openAPI3Spec), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	spec, err := ParseSpec(specFile)
	if err != nil {
		t.Fatalf("Failed to parse spec from file: %v", err)
	}

	if spec.Title != "Pet Store API" {
		t.Errorf("Expected title 'Pet Store API', got '%s'", spec.Title)
	}
	if len(spec.Endpoints) != 4 {
		t.Errorf("Expected 4 endpoints, got %d", len(spec.Endpoints))
	}
}

func TestParseSpecFromURL(t *testing.T) {
	// Create a test server that returns the OpenAPI spec
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(openAPI3JSONSpec))
	}))
	defer server.Close()

	spec, err := ParseSpec(server.URL)
	if err != nil {
		t.Fatalf("Failed to parse spec from URL: %v", err)
	}

	if spec.Title != "Simple API" {
		t.Errorf("Expected title 'Simple API', got '%s'", spec.Title)
	}
}

func TestParseSpecFromURLError(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := ParseSpec(server.URL)
	if err == nil {
		t.Error("Expected error when server returns 500")
	}
}

func TestParseSpecFileNotFound(t *testing.T) {
	_, err := ParseSpec("/nonexistent/path/spec.yaml")
	if err == nil {
		t.Error("Expected error when file does not exist")
	}
}

func TestAPISpecMethods(t *testing.T) {
	spec, err := ParseOpenAPI3([]byte(openAPI3Spec))
	if err != nil {
		t.Fatalf("Failed to parse spec: %v", err)
	}

	// Test HasEndpoints
	if !spec.HasEndpoints() {
		t.Error("Expected HasEndpoints to return true")
	}

	// Test EndpointCount
	if spec.EndpointCount() != 4 {
		t.Errorf("Expected EndpointCount to return 4, got %d", spec.EndpointCount())
	}

	// Test GetEndpointsByMethod (GET /pets, GET /pets/{petId})
	getEndpoints := spec.GetEndpointsByMethod("GET")
	if len(getEndpoints) != 2 {
		t.Errorf("Expected 2 GET endpoints, got %d", len(getEndpoints))
	}

	deleteEndpoints := spec.GetEndpointsByMethod("DELETE")
	if len(deleteEndpoints) != 1 {
		t.Errorf("Expected 1 DELETE endpoint, got %d", len(deleteEndpoints))
	}

	// Test GetEndpointsByTag
	petsEndpoints := spec.GetEndpointsByTag("pets")
	if len(petsEndpoints) != 4 {
		t.Errorf("Expected 4 endpoints with 'pets' tag, got %d", len(petsEndpoints))
	}

	// Test String method
	str := spec.String()
	if str == "" {
		t.Error("Expected String() to return non-empty string")
	}
}

func TestEmptySpec(t *testing.T) {
	spec := &APISpec{}

	if spec.HasEndpoints() {
		t.Error("Expected HasEndpoints to return false for empty spec")
	}

	if spec.EndpointCount() != 0 {
		t.Error("Expected EndpointCount to return 0 for empty spec")
	}

	endpoints := spec.GetEndpointsByMethod("GET")
	if len(endpoints) != 0 {
		t.Error("Expected GetEndpointsByMethod to return empty slice")
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"https://example.com/api.yaml", true},
		{"http://example.com/api.yaml", true},
		{"./api.yaml", false},
		{"/path/to/api.yaml", false},
		{"api.yaml", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isURL(tt.input); got != tt.expected {
				t.Errorf("isURL(%s) = %v, expected %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseSwagger2WithJSON(t *testing.T) {
	jsonSpec := `{
		"swagger": "2.0",
		"info": {
			"title": "JSON API",
			"version": "1.0.0"
		},
		"paths": {
			"/test": {
				"get": {
					"operationId": "testEndpoint",
					"responses": {
						"200": {
							"description": "OK"
						}
					}
				}
			}
		}
	}`

	spec, err := ParseSwagger2([]byte(jsonSpec))
	if err != nil {
		t.Fatalf("Failed to parse JSON Swagger spec: %v", err)
	}

	if spec.Title != "JSON API" {
		t.Errorf("Expected title 'JSON API', got '%s'", spec.Title)
	}
}

func TestOpenAPI3WithSecurityRequirements(t *testing.T) {
	spec, err := ParseOpenAPI3([]byte(openAPI3Spec))
	if err != nil {
		t.Fatalf("Failed to parse spec: %v", err)
	}

	// Find createPet endpoint
	var createPetEndpoint *EndpointInfo
	for i := range spec.Endpoints {
		if spec.Endpoints[i].OperationID == "createPet" {
			createPetEndpoint = &spec.Endpoints[i]
			break
		}
	}

	if createPetEndpoint == nil {
		t.Fatal("createPet endpoint not found")
	}

	if len(createPetEndpoint.Security) == 0 {
		t.Error("Expected createPet to have security requirements")
	}
}

func TestResponsesExtraction(t *testing.T) {
	spec, err := ParseOpenAPI3([]byte(openAPI3Spec))
	if err != nil {
		t.Fatalf("Failed to parse spec: %v", err)
	}

	// Find listPets endpoint
	var listPetsEndpoint *EndpointInfo
	for i := range spec.Endpoints {
		if spec.Endpoints[i].OperationID == "listPets" {
			listPetsEndpoint = &spec.Endpoints[i]
			break
		}
	}

	if listPetsEndpoint == nil {
		t.Fatal("listPets endpoint not found")
	}

	if len(listPetsEndpoint.Responses) != 2 {
		t.Errorf("Expected 2 responses, got %d", len(listPetsEndpoint.Responses))
	}

	// Check that responses are sorted by status code
	if listPetsEndpoint.Responses[0].StatusCode != "200" {
		t.Errorf("Expected first response to be 200, got %s", listPetsEndpoint.Responses[0].StatusCode)
	}
}
