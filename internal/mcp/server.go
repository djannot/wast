// Package mcp provides Model Context Protocol (MCP) server implementation for WAST.
// This enables AI agents to integrate with WAST through a standardized protocol.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
)

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Server represents an MCP server instance.
type Server struct {
	reader io.Reader
	writer io.Writer
	tools  map[string]Tool
}

// Tool represents an MCP tool implementation.
type Tool interface {
	Name() string
	Description() string
	InputSchema() map[string]interface{}
	Execute(ctx context.Context, params json.RawMessage) (interface{}, error)
}

// NewServer creates a new MCP server instance.
func NewServer() *Server {
	s := &Server{
		reader: os.Stdin,
		writer: os.Stdout,
		tools:  make(map[string]Tool),
	}

	// Register all WAST tools
	s.registerTools()

	return s
}

// registerTools registers all WAST command tools.
func (s *Server) registerTools() {
	s.tools["wast_recon"] = &ReconTool{}
	s.tools["wast_scan"] = &ScanTool{}
	s.tools["wast_crawl"] = &CrawlTool{}
	s.tools["wast_api"] = &APITool{}
	s.tools["wast_intercept"] = &InterceptTool{}
}

// Run starts the MCP server and processes requests.
func (s *Server) Run(ctx context.Context) error {
	scanner := bufio.NewScanner(s.reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer for large requests

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			// Parse JSON-RPC request
			var req JSONRPCRequest
			if err := json.Unmarshal(line, &req); err != nil {
				s.sendError(nil, -32700, "Parse error", err.Error())
				continue
			}

			// Handle request
			s.handleRequest(ctx, &req)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}

	return nil
}

// handleRequest processes a JSON-RPC request.
func (s *Server) handleRequest(ctx context.Context, req *JSONRPCRequest) {
	// Validate JSON-RPC version
	if req.JSONRPC != "2.0" {
		s.sendError(req.ID, -32600, "Invalid Request", "jsonrpc must be 2.0")
		return
	}

	// Handle different methods
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(ctx, req)
	default:
		s.sendError(req.ID, -32601, "Method not found", fmt.Sprintf("Unknown method: %s", req.Method))
	}
}

// handleInitialize handles the MCP initialize request.
func (s *Server) handleInitialize(req *JSONRPCRequest) {
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"serverInfo": map[string]interface{}{
			"name":    "wast",
			"version": "1.0.0",
		},
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
	}

	s.sendResponse(req.ID, result)
}

// handleToolsList handles the tools/list request.
func (s *Server) handleToolsList(req *JSONRPCRequest) {
	toolsList := make([]map[string]interface{}, 0, len(s.tools))
	for _, tool := range s.tools {
		toolsList = append(toolsList, map[string]interface{}{
			"name":        tool.Name(),
			"description": tool.Description(),
			"inputSchema": tool.InputSchema(),
		})
	}

	result := map[string]interface{}{
		"tools": toolsList,
	}

	s.sendResponse(req.ID, result)
}

// handleToolsCall handles the tools/call request.
func (s *Server) handleToolsCall(ctx context.Context, req *JSONRPCRequest) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}

	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, -32602, "Invalid params", err.Error())
		return
	}

	// Find tool
	tool, ok := s.tools[params.Name]
	if !ok {
		s.sendError(req.ID, -32602, "Invalid params", fmt.Sprintf("Unknown tool: %s", params.Name))
		return
	}

	// Execute tool
	result, err := tool.Execute(ctx, params.Arguments)
	if err != nil {
		s.sendError(req.ID, -32603, "Internal error", err.Error())
		return
	}

	// Send response
	response := map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": formatToolResult(result),
			},
		},
	}

	s.sendResponse(req.ID, response)
}

// formatToolResult formats tool execution result as JSON text.
func formatToolResult(result interface{}) string {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting result: %v", err)
	}
	return string(data)
}

// sendResponse sends a JSON-RPC success response.
func (s *Server) sendResponse(id interface{}, result interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		// Fallback response for marshal errors
		fallback := fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"error":{"code":-32603,"message":"Internal error: failed to marshal response"}}`, id)
		fmt.Fprintln(s.writer, fallback)
		return
	}
	fmt.Fprintln(s.writer, string(data))
}

// sendError sends a JSON-RPC error response.
func (s *Server) sendError(id interface{}, code int, message string, data interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}

	responseData, err := json.Marshal(resp)
	if err != nil {
		// Fallback response for marshal errors
		fallback := fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"error":{"code":-32603,"message":"Internal error: failed to marshal error response"}}`, id)
		fmt.Fprintln(s.writer, fallback)
		return
	}
	fmt.Fprintln(s.writer, string(responseData))
}

// ReconTool implements the wast_recon MCP tool.
type ReconTool struct{}

func (t *ReconTool) Name() string {
	return "wast_recon"
}

func (t *ReconTool) Description() string {
	return "Perform reconnaissance on a target domain. Includes DNS enumeration, subdomain discovery, and TLS certificate analysis."
}

func (t *ReconTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target": map[string]interface{}{
				"type":        "string",
				"description": "Target domain to perform reconnaissance on",
			},
			"timeout": map[string]interface{}{
				"type":        "string",
				"description": "Timeout for DNS queries (e.g., '10s', '1m')",
				"default":     "10s",
			},
			"include_subdomains": map[string]interface{}{
				"type":        "boolean",
				"description": "Enable subdomain discovery via CT logs and zone transfer",
				"default":     false,
			},
		},
		"required": []string{"target"},
	}
}

func (t *ReconTool) Execute(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var args struct {
		Target            string `json:"target"`
		Timeout           string `json:"timeout"`
		IncludeSubdomains bool   `json:"include_subdomains"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if args.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	// Parse timeout
	timeout := 10 * time.Second
	if args.Timeout != "" {
		var err error
		timeout, err = time.ParseDuration(args.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout: %w", err)
		}
	}

	// Execute recon command logic
	result := executeRecon(ctx, args.Target, timeout, args.IncludeSubdomains)

	return result, nil
}

// ScanTool implements the wast_scan MCP tool.
type ScanTool struct{}

func (t *ScanTool) Name() string {
	return "wast_scan"
}

func (t *ScanTool) Description() string {
	return "Run security vulnerability scans on a target. Defaults to safe mode (passive checks only). Use active=true to enable active vulnerability testing."
}

func (t *ScanTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target": map[string]interface{}{
				"type":        "string",
				"description": "Target URL to scan",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "HTTP request timeout in seconds",
				"default":     30,
			},
			"active": map[string]interface{}{
				"type":        "boolean",
				"description": "Enable active vulnerability testing (SQLi, XSS, CSRF). Defaults to false for safe mode.",
				"default":     false,
			},
			"verify": map[string]interface{}{
				"type":        "boolean",
				"description": "Enable finding verification to reduce false positives. Re-tests findings with payload variants.",
				"default":     false,
			},
			"bearer_token": map[string]interface{}{
				"type":        "string",
				"description": "Bearer token for Authorization header",
			},
			"basic_auth": map[string]interface{}{
				"type":        "string",
				"description": "Basic auth credentials in format 'user:pass'",
			},
			"auth_header": map[string]interface{}{
				"type":        "string",
				"description": "Custom auth header in format 'HeaderName: Value'",
			},
			"cookies": map[string]interface{}{
				"type":        "array",
				"description": "Cookies to include in requests (format: 'name=value')",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
			"requests_per_second": map[string]interface{}{
				"type":        "number",
				"description": "Rate limit for requests per second (0 for unlimited)",
				"default":     0,
			},
		},
		"required": []string{"target"},
	}
}

func (t *ScanTool) Execute(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var args struct {
		Target            string   `json:"target"`
		Timeout           int      `json:"timeout"`
		Active            bool     `json:"active"`
		Verify            bool     `json:"verify"`
		BearerToken       string   `json:"bearer_token"`
		BasicAuth         string   `json:"basic_auth"`
		AuthHeader        string   `json:"auth_header"`
		Cookies           []string `json:"cookies"`
		RequestsPerSecond float64  `json:"requests_per_second"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if args.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	if args.Timeout <= 0 {
		args.Timeout = 30
	}

	// Construct auth config from arguments
	authConfig := &auth.AuthConfig{
		BearerToken: args.BearerToken,
		BasicAuth:   args.BasicAuth,
		AuthHeader:  args.AuthHeader,
		Cookies:     args.Cookies,
	}
	rateLimitConfig := ratelimit.Config{RequestsPerSecond: args.RequestsPerSecond}

	// Execute scan command logic
	result := executeScan(ctx, args.Target, args.Timeout, !args.Active, args.Verify, authConfig, rateLimitConfig)

	return result, nil
}

// CrawlTool implements the wast_crawl MCP tool.
type CrawlTool struct{}

func (t *CrawlTool) Name() string {
	return "wast_crawl"
}

func (t *CrawlTool) Description() string {
	return "Crawl a web application to discover URLs, endpoints, and content. Respects robots.txt by default."
}

func (t *CrawlTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target": map[string]interface{}{
				"type":        "string",
				"description": "Target URL to crawl",
			},
			"depth": map[string]interface{}{
				"type":        "integer",
				"description": "Maximum crawl depth (0 for unlimited)",
				"default":     3,
			},
			"timeout": map[string]interface{}{
				"type":        "string",
				"description": "Timeout for HTTP requests (e.g., '30s', '1m')",
				"default":     "30s",
			},
			"respect_robots": map[string]interface{}{
				"type":        "boolean",
				"description": "Respect robots.txt rules",
				"default":     true,
			},
			"bearer_token": map[string]interface{}{
				"type":        "string",
				"description": "Bearer token for Authorization header",
			},
			"basic_auth": map[string]interface{}{
				"type":        "string",
				"description": "Basic auth credentials in format 'user:pass'",
			},
			"auth_header": map[string]interface{}{
				"type":        "string",
				"description": "Custom auth header in format 'HeaderName: Value'",
			},
			"cookies": map[string]interface{}{
				"type":        "array",
				"description": "Cookies to include in requests (format: 'name=value')",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
			"requests_per_second": map[string]interface{}{
				"type":        "number",
				"description": "Rate limit for requests per second (0 for unlimited)",
				"default":     0,
			},
		},
		"required": []string{"target"},
	}
}

func (t *CrawlTool) Execute(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var args struct {
		Target            string   `json:"target"`
		Depth             int      `json:"depth"`
		Timeout           string   `json:"timeout"`
		RespectRobots     bool     `json:"respect_robots"`
		BearerToken       string   `json:"bearer_token"`
		BasicAuth         string   `json:"basic_auth"`
		AuthHeader        string   `json:"auth_header"`
		Cookies           []string `json:"cookies"`
		RequestsPerSecond float64  `json:"requests_per_second"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if args.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	if args.Depth == 0 {
		args.Depth = 3
	}

	// Parse timeout
	timeout := 30 * time.Second
	if args.Timeout != "" {
		var err error
		timeout, err = time.ParseDuration(args.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout: %w", err)
		}
	}

	// Construct auth config from arguments
	authConfig := &auth.AuthConfig{
		BearerToken: args.BearerToken,
		BasicAuth:   args.BasicAuth,
		AuthHeader:  args.AuthHeader,
		Cookies:     args.Cookies,
	}
	rateLimitConfig := ratelimit.Config{RequestsPerSecond: args.RequestsPerSecond}

	// Execute crawl command logic
	result := executeCrawl(ctx, args.Target, args.Depth, timeout, args.RespectRobots, authConfig, rateLimitConfig)

	return result, nil
}

// APITool implements the wast_api MCP tool.
type APITool struct{}

func (t *APITool) Name() string {
	return "wast_api"
}

func (t *APITool) Description() string {
	return "Discover and test API endpoints. Can parse OpenAPI/Swagger specifications or perform API discovery on a target URL."
}

func (t *APITool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target": map[string]interface{}{
				"type":        "string",
				"description": "Target URL for API discovery (optional if spec_file is provided)",
			},
			"spec_file": map[string]interface{}{
				"type":        "string",
				"description": "Path or URL to OpenAPI/Swagger specification",
			},
			"dry_run": map[string]interface{}{
				"type":        "boolean",
				"description": "List endpoints without making requests",
				"default":     false,
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "HTTP request timeout in seconds",
				"default":     30,
			},
			"bearer_token": map[string]interface{}{
				"type":        "string",
				"description": "Bearer token for Authorization header",
			},
			"basic_auth": map[string]interface{}{
				"type":        "string",
				"description": "Basic auth credentials in format 'user:pass'",
			},
			"auth_header": map[string]interface{}{
				"type":        "string",
				"description": "Custom auth header in format 'HeaderName: Value'",
			},
			"cookies": map[string]interface{}{
				"type":        "array",
				"description": "Cookies to include in requests (format: 'name=value')",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
			"requests_per_second": map[string]interface{}{
				"type":        "number",
				"description": "Rate limit for requests per second (0 for unlimited)",
				"default":     0,
			},
		},
	}
}

func (t *APITool) Execute(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var args struct {
		Target            string   `json:"target"`
		SpecFile          string   `json:"spec_file"`
		DryRun            bool     `json:"dry_run"`
		Timeout           int      `json:"timeout"`
		BearerToken       string   `json:"bearer_token"`
		BasicAuth         string   `json:"basic_auth"`
		AuthHeader        string   `json:"auth_header"`
		Cookies           []string `json:"cookies"`
		RequestsPerSecond float64  `json:"requests_per_second"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if args.Target == "" && args.SpecFile == "" {
		return nil, fmt.Errorf("either target or spec_file is required")
	}

	if args.Timeout <= 0 {
		args.Timeout = 30
	}

	// Construct auth config from arguments
	authConfig := &auth.AuthConfig{
		BearerToken: args.BearerToken,
		BasicAuth:   args.BasicAuth,
		AuthHeader:  args.AuthHeader,
		Cookies:     args.Cookies,
	}
	rateLimitConfig := ratelimit.Config{RequestsPerSecond: args.RequestsPerSecond}

	// Execute API command logic
	result := executeAPI(ctx, args.Target, args.SpecFile, args.DryRun, args.Timeout, authConfig, rateLimitConfig)

	return result, nil
}

// InterceptTool implements the wast_intercept MCP tool.
type InterceptTool struct{}

func (t *InterceptTool) Name() string {
	return "wast_intercept"
}

func (t *InterceptTool) Description() string {
	return "Start a proxy server to intercept and analyze HTTP/HTTPS traffic. The proxy captures requests and responses for security testing and analysis."
}

func (t *InterceptTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"port": map[string]interface{}{
				"type":        "integer",
				"description": "Port to listen on for the proxy",
				"default":     8080,
			},
			"duration": map[string]interface{}{
				"type":        "string",
				"description": "Duration to capture traffic (e.g., '30s', '5m')",
				"default":     "60s",
			},
			"save_file": map[string]interface{}{
				"type":        "string",
				"description": "Path to save intercepted traffic as JSON",
			},
			"https_interception": map[string]interface{}{
				"type":        "boolean",
				"description": "Enable HTTPS traffic interception (requires CA setup)",
				"default":     false,
			},
			"max_requests": map[string]interface{}{
				"type":        "integer",
				"description": "Stop after capturing N requests (alternative to duration)",
			},
		},
	}
}

func (t *InterceptTool) Execute(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var args struct {
		Port              int    `json:"port"`
		Duration          string `json:"duration"`
		SaveFile          string `json:"save_file"`
		HTTPSInterception bool   `json:"https_interception"`
		MaxRequests       int    `json:"max_requests"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	// Set defaults
	if args.Port <= 0 {
		args.Port = 8080
	}
	if args.Duration == "" {
		args.Duration = "60s"
	}

	// Parse duration
	duration, err := time.ParseDuration(args.Duration)
	if err != nil {
		return nil, fmt.Errorf("invalid duration: %w", err)
	}

	// Execute intercept command logic
	result := executeIntercept(ctx, args.Port, duration, args.SaveFile, args.HTTPSInterception, args.MaxRequests)

	return result, nil
}
