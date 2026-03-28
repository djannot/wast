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
	"sync"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/urlutil"
	"go.opentelemetry.io/otel/trace"
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

// JSONRPCNotification represents a JSON-RPC 2.0 notification (no ID field).
type JSONRPCNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// ProgressNotification represents progress information for long-running operations.
type ProgressNotification struct {
	Phase     string `json:"phase"`     // e.g., "crawling", "scanning", "recon"
	Completed int    `json:"completed"` // items processed
	Total     int    `json:"total"`     // total items (if known, 0 if unknown)
	Message   string `json:"message"`   // human-readable status
}

// Server represents an MCP server instance.
type Server struct {
	reader      io.Reader
	writer      io.Writer
	tools       map[string]Tool
	tracer      trace.Tracer
	writerMutex sync.Mutex // protects concurrent writes to writer
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

// SetTracer sets the OpenTelemetry tracer for the server.
func (s *Server) SetTracer(tracer trace.Tracer) {
	s.tracer = tracer
}

// registerTools registers all WAST command tools.
func (s *Server) registerTools() {
	s.tools["wast_recon"] = &ReconTool{server: s}
	s.tools["wast_scan"] = &ScanTool{server: s}
	s.tools["wast_crawl"] = &CrawlTool{server: s}
	s.tools["wast_api"] = &APITool{server: s}
	s.tools["wast_intercept"] = &InterceptTool{server: s}
	s.tools["wast_headers"] = &HeadersTool{server: s}
	s.tools["wast_verify"] = &VerifyTool{server: s}
	s.tools["wast_websocket"] = &WebSocketTool{server: s}
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
	s.writerMutex.Lock()
	defer s.writerMutex.Unlock()

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

// sendNotification sends a JSON-RPC notification (no response expected).
func (s *Server) sendNotification(method string, params interface{}) {
	s.writerMutex.Lock()
	defer s.writerMutex.Unlock()

	notif := JSONRPCNotification{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}

	data, err := json.Marshal(notif)
	if err != nil {
		// Silently fail on notification marshal errors
		return
	}
	fmt.Fprintln(s.writer, string(data))
}

// sendProgress sends a progress notification to the MCP client.
func (s *Server) sendProgress(phase string, completed, total int, message string) {
	progress := ProgressNotification{
		Phase:     phase,
		Completed: completed,
		Total:     total,
		Message:   message,
	}
	s.sendNotification("notifications/progress", progress)
}

// sendError sends a JSON-RPC error response.
func (s *Server) sendError(id interface{}, code int, message string, data interface{}) {
	s.writerMutex.Lock()
	defer s.writerMutex.Unlock()

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
type ReconTool struct {
	server *Server
}

func (t *ReconTool) Name() string {
	return "wast_recon"
}

func (t *ReconTool) Description() string {
	return "Perform reconnaissance on a target domain. Includes DNS enumeration, subdomain discovery, and TLS certificate analysis. Progress notifications are sent during each phase of reconnaissance."
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

	// Validate and normalize domain
	validatedDomain, err := urlutil.ValidateDomain(args.Target)
	if err != nil {
		return nil, err
	}
	args.Target = validatedDomain

	// Parse timeout
	timeout := 10 * time.Second
	if args.Timeout != "" {
		var err error
		timeout, err = time.ParseDuration(args.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout: %w", err)
		}
	}

	// Create progress callback
	progressCallback := func(phase, message string) {
		t.server.sendProgress(phase, 0, 0, message)
	}

	// Execute recon command logic
	result := executeRecon(ctx, args.Target, timeout, args.IncludeSubdomains, t.server.tracer, progressCallback)

	return result, nil
}

// ScanTool implements the wast_scan MCP tool.
type ScanTool struct {
	server *Server
}

func (t *ScanTool) Name() string {
	return "wast_scan"
}

func (t *ScanTool) Description() string {
	return "Run security vulnerability scans on a target. Defaults to safe mode (passive checks only). Use active=true to enable active vulnerability testing (SQLi, XSS, CSRF, SSRF). Use discover=true to first crawl the target and discover forms/endpoints, then scan all discovered attack surfaces. Progress notifications are sent during discovery and scanning phases for long-running operations."
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
				"description": "Enable active vulnerability testing (SQLi, XSS, CSRF, SSRF). Defaults to false for safe mode.",
				"default":     false,
			},
			"verify": map[string]interface{}{
				"type":        "boolean",
				"description": "Enable finding verification to reduce false positives. Re-tests findings with payload variants.",
				"default":     false,
			},
			"discover": map[string]interface{}{
				"type":        "boolean",
				"description": "First crawl the target to discover forms and endpoints, then scan all discovered attack surfaces with their actual field names.",
				"default":     false,
			},
			"depth": map[string]interface{}{
				"type":        "integer",
				"description": "Maximum crawl depth for discovery mode (used with discover=true)",
				"default":     2,
			},
			"concurrency": map[string]interface{}{
				"type":        "integer",
				"description": "Number of concurrent workers for the crawl phase (used with discover=true)",
				"default":     5,
			},
			"scan_concurrency": map[string]interface{}{
				"type":        "integer",
				"description": "Number of concurrent workers for scanning discovered targets (used with discover=true)",
				"default":     5,
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
			"login_url": map[string]interface{}{
				"type":        "string",
				"description": "Login endpoint URL for automated authentication",
			},
			"login_user": map[string]interface{}{
				"type":        "string",
				"description": "Username for automated login",
			},
			"login_pass": map[string]interface{}{
				"type":        "string",
				"description": "Password for automated login (WARNING: will be visible in MCP logs. Consider using environment variables instead via CLI)",
			},
			"login_user_field": map[string]interface{}{
				"type":        "string",
				"description": "Form field name for username (default: 'username')",
				"default":     "username",
			},
			"login_pass_field": map[string]interface{}{
				"type":        "string",
				"description": "Form field name for password (default: 'password')",
				"default":     "password",
			},
			"requests_per_second": map[string]interface{}{
				"type":        "number",
				"description": "Rate limit for requests per second (0 for unlimited)",
				"default":     0,
			},
			"callback_url": map[string]interface{}{
				"type":        "string",
				"description": "Callback server base URL for out-of-band SSRF detection (e.g., http://callback.example.com:8888)",
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
		Discover          bool     `json:"discover"`
		Depth             int      `json:"depth"`
		Concurrency       int      `json:"concurrency"`
		ScanConcurrency   int      `json:"scan_concurrency"`
		BearerToken       string   `json:"bearer_token"`
		BasicAuth         string   `json:"basic_auth"`
		AuthHeader        string   `json:"auth_header"`
		Cookies           []string `json:"cookies"`
		LoginURL          string   `json:"login_url"`
		LoginUser         string   `json:"login_user"`
		LoginPass         string   `json:"login_pass"`
		LoginUserField    string   `json:"login_user_field"`
		LoginPassField    string   `json:"login_pass_field"`
		RequestsPerSecond float64  `json:"requests_per_second"`
		CallbackURL       string   `json:"callback_url"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if args.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	// Validate and normalize target URL
	validatedURL, err := urlutil.ValidateTargetURL(args.Target)
	if err != nil {
		return nil, err
	}
	args.Target = validatedURL

	if args.Timeout <= 0 {
		args.Timeout = 30
	}

	if args.Depth <= 0 {
		args.Depth = 2
	}

	if args.Concurrency <= 0 {
		args.Concurrency = 5
	}

	if args.ScanConcurrency <= 0 {
		args.ScanConcurrency = 5
	}

	// Construct auth config from arguments
	authConfig := &auth.AuthConfig{
		BearerToken: args.BearerToken,
		BasicAuth:   args.BasicAuth,
		AuthHeader:  args.AuthHeader,
		Cookies:     args.Cookies,
	}

	// Add login configuration if provided
	if args.LoginURL != "" {
		authConfig.Login = &auth.LoginConfig{
			LoginURL:      args.LoginURL,
			Username:      args.LoginUser,
			Password:      args.LoginPass,
			UsernameField: args.LoginUserField,
			PasswordField: args.LoginPassField,
		}
		// Perform login to capture session cookies
		if err := authConfig.PerformLogin(ctx); err != nil {
			return nil, fmt.Errorf("automated login failed: %w", err)
		}
	}

	rateLimitConfig := ratelimit.Config{RequestsPerSecond: args.RequestsPerSecond}

	// Create progress callback
	progressCallback := func(completed, total int, phase string) {
		message := fmt.Sprintf("%s: %d", phase, completed)
		if total > 0 {
			message = fmt.Sprintf("%s: %d/%d", phase, completed, total)
		}
		t.server.sendProgress(phase, completed, total, message)
	}

	// Execute scan command logic
	result := executeScan(ctx, args.Target, args.Timeout, !args.Active, args.Verify, args.Discover, args.Depth, args.Concurrency, args.ScanConcurrency, authConfig, rateLimitConfig, t.server.tracer, progressCallback, args.CallbackURL)

	return result, nil
}

// CrawlTool implements the wast_crawl MCP tool.
type CrawlTool struct {
	server *Server
}

func (t *CrawlTool) Name() string {
	return "wast_crawl"
}

func (t *CrawlTool) Description() string {
	return "Crawl a web application to discover URLs, endpoints, and content. Respects robots.txt by default. Progress notifications are sent as pages are visited during crawling."
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
			"concurrency": map[string]interface{}{
				"type":        "integer",
				"description": "Number of concurrent workers for crawling",
				"default":     5,
			},
			"compact": map[string]interface{}{
				"type":        "boolean",
				"description": "Return compact output with summarized resources and links to prevent output size overflow",
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
			"login_url": map[string]interface{}{
				"type":        "string",
				"description": "Login endpoint URL for automated authentication",
			},
			"login_user": map[string]interface{}{
				"type":        "string",
				"description": "Username for automated login",
			},
			"login_pass": map[string]interface{}{
				"type":        "string",
				"description": "Password for automated login (WARNING: will be visible in MCP logs. Consider using environment variables instead via CLI)",
			},
			"login_user_field": map[string]interface{}{
				"type":        "string",
				"description": "Form field name for username (default: 'username')",
				"default":     "username",
			},
			"login_pass_field": map[string]interface{}{
				"type":        "string",
				"description": "Form field name for password (default: 'password')",
				"default":     "password",
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
		Concurrency       int      `json:"concurrency"`
		Compact           *bool    `json:"compact"` // pointer to detect if set
		BearerToken       string   `json:"bearer_token"`
		BasicAuth         string   `json:"basic_auth"`
		AuthHeader        string   `json:"auth_header"`
		Cookies           []string `json:"cookies"`
		LoginURL          string   `json:"login_url"`
		LoginUser         string   `json:"login_user"`
		LoginPass         string   `json:"login_pass"`
		LoginUserField    string   `json:"login_user_field"`
		LoginPassField    string   `json:"login_pass_field"`
		RequestsPerSecond float64  `json:"requests_per_second"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if args.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	// Validate and normalize target URL
	validatedURL, err := urlutil.ValidateTargetURL(args.Target)
	if err != nil {
		return nil, err
	}
	args.Target = validatedURL

	if args.Depth == 0 {
		args.Depth = 3
	}

	if args.Concurrency == 0 {
		args.Concurrency = 5
	}

	// Default compact to true if not specified
	compact := true
	if args.Compact != nil {
		compact = *args.Compact
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

	// Add login configuration if provided
	if args.LoginURL != "" {
		authConfig.Login = &auth.LoginConfig{
			LoginURL:      args.LoginURL,
			Username:      args.LoginUser,
			Password:      args.LoginPass,
			UsernameField: args.LoginUserField,
			PasswordField: args.LoginPassField,
		}
		// Perform login to capture session cookies
		if err := authConfig.PerformLogin(ctx); err != nil {
			return nil, fmt.Errorf("automated login failed: %w", err)
		}
	}

	rateLimitConfig := ratelimit.Config{RequestsPerSecond: args.RequestsPerSecond}

	// Create progress callback
	progressCallback := func(visited, discovered int, phase string) {
		message := fmt.Sprintf("crawling: visited %d pages, discovered %d links", visited, discovered)
		t.server.sendProgress(phase, visited, 0, message)
	}

	// Execute crawl command logic
	result := executeCrawl(ctx, args.Target, args.Depth, timeout, args.RespectRobots, args.Concurrency, compact, authConfig, rateLimitConfig, t.server.tracer, progressCallback)

	return result, nil
}

// APITool implements the wast_api MCP tool.
type APITool struct {
	server *Server
}

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
			"login_url": map[string]interface{}{
				"type":        "string",
				"description": "Login endpoint URL for automated authentication",
			},
			"login_user": map[string]interface{}{
				"type":        "string",
				"description": "Username for automated login",
			},
			"login_pass": map[string]interface{}{
				"type":        "string",
				"description": "Password for automated login (WARNING: will be visible in MCP logs. Consider using environment variables instead via CLI)",
			},
			"login_user_field": map[string]interface{}{
				"type":        "string",
				"description": "Form field name for username (default: 'username')",
				"default":     "username",
			},
			"login_pass_field": map[string]interface{}{
				"type":        "string",
				"description": "Form field name for password (default: 'password')",
				"default":     "password",
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
		LoginURL          string   `json:"login_url"`
		LoginUser         string   `json:"login_user"`
		LoginPass         string   `json:"login_pass"`
		LoginUserField    string   `json:"login_user_field"`
		LoginPassField    string   `json:"login_pass_field"`
		RequestsPerSecond float64  `json:"requests_per_second"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if args.Target == "" && args.SpecFile == "" {
		return nil, fmt.Errorf("either target or spec_file is required")
	}

	// Validate and normalize target URL if provided
	if args.Target != "" {
		validatedURL, err := urlutil.ValidateTargetURL(args.Target)
		if err != nil {
			return nil, err
		}
		args.Target = validatedURL
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

	// Add login configuration if provided
	if args.LoginURL != "" {
		authConfig.Login = &auth.LoginConfig{
			LoginURL:      args.LoginURL,
			Username:      args.LoginUser,
			Password:      args.LoginPass,
			UsernameField: args.LoginUserField,
			PasswordField: args.LoginPassField,
		}
		// Perform login to capture session cookies
		if err := authConfig.PerformLogin(ctx); err != nil {
			return nil, fmt.Errorf("automated login failed: %w", err)
		}
	}

	rateLimitConfig := ratelimit.Config{RequestsPerSecond: args.RequestsPerSecond}

	// Execute API command logic
	result := executeAPI(ctx, args.Target, args.SpecFile, args.DryRun, args.Timeout, authConfig, rateLimitConfig, t.server.tracer)

	return result, nil
}

// InterceptTool implements the wast_intercept MCP tool.
type InterceptTool struct {
	server *Server
}

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
	result := executeIntercept(ctx, args.Port, duration, args.SaveFile, args.HTTPSInterception, args.MaxRequests, t.server.tracer)

	return result, nil
}

// HeadersTool implements the wast_headers MCP tool.
type HeadersTool struct {
	server *Server
}

func (t *HeadersTool) Name() string {
	return "wast_headers"
}

func (t *HeadersTool) Description() string {
	return "Perform passive-only security header analysis. Checks HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), cookie security attributes, and CORS policy configuration. This is a lightweight alternative to wast_scan when you only need header analysis."
}

func (t *HeadersTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target": map[string]interface{}{
				"type":        "string",
				"description": "Target URL to scan for security headers",
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
		"required": []string{"target"},
	}
}

func (t *HeadersTool) Execute(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var args struct {
		Target            string   `json:"target"`
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

	if args.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	// Validate and normalize target URL
	validatedURL, err := urlutil.ValidateTargetURL(args.Target)
	if err != nil {
		return nil, err
	}
	args.Target = validatedURL

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

	// Execute headers scan logic
	result := executeHeaders(ctx, args.Target, args.Timeout, authConfig, rateLimitConfig, t.server.tracer)

	return result, nil
}

// VerifyTool implements the wast_verify MCP tool.
type VerifyTool struct {
	server *Server
}

func (t *VerifyTool) Name() string {
	return "wast_verify"
}

func (t *VerifyTool) Description() string {
	return "Verify individual security findings before reporting them. Re-tests findings with payload variants to reduce false positives. Supports verification of SQLi, XSS, SSRF, CMDi, Path Traversal, Redirect, and CSRF findings."
}

func (t *VerifyTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"finding_type": map[string]interface{}{
				"type":        "string",
				"description": "Type of finding to verify",
				"enum":        []string{"sqli", "xss", "ssrf", "cmdi", "pathtraversal", "redirect", "csrf", "ssti"},
			},
			"finding_url": map[string]interface{}{
				"type":        "string",
				"description": "URL where the finding was detected",
			},
			"parameter": map[string]interface{}{
				"type":        "string",
				"description": "Vulnerable parameter name",
			},
			"payload": map[string]interface{}{
				"type":        "string",
				"description": "Original payload that triggered the finding",
			},
			"max_retries": map[string]interface{}{
				"type":        "integer",
				"description": "Maximum verification attempts",
				"default":     3,
			},
			"delay": map[string]interface{}{
				"type":        "string",
				"description": "Delay between verification attempts (e.g., '100ms', '1s')",
				"default":     "100ms",
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
			"login_url": map[string]interface{}{
				"type":        "string",
				"description": "Login endpoint URL for automated authentication",
			},
			"login_user": map[string]interface{}{
				"type":        "string",
				"description": "Username for automated login",
			},
			"login_pass": map[string]interface{}{
				"type":        "string",
				"description": "Password for automated login (WARNING: will be visible in MCP logs. Consider using environment variables instead via CLI)",
			},
			"login_user_field": map[string]interface{}{
				"type":        "string",
				"description": "Form field name for username (default: 'username')",
				"default":     "username",
			},
			"login_pass_field": map[string]interface{}{
				"type":        "string",
				"description": "Form field name for password (default: 'password')",
				"default":     "password",
			},
			"requests_per_second": map[string]interface{}{
				"type":        "number",
				"description": "Rate limit for requests per second (0 for unlimited)",
				"default":     0,
			},
		},
		"required": []string{"finding_type", "finding_url", "parameter", "payload"},
	}
}

func (t *VerifyTool) Execute(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var args struct {
		FindingType       string   `json:"finding_type"`
		FindingURL        string   `json:"finding_url"`
		Parameter         string   `json:"parameter"`
		Payload           string   `json:"payload"`
		MaxRetries        int      `json:"max_retries"`
		Delay             string   `json:"delay"`
		BearerToken       string   `json:"bearer_token"`
		BasicAuth         string   `json:"basic_auth"`
		AuthHeader        string   `json:"auth_header"`
		Cookies           []string `json:"cookies"`
		LoginURL          string   `json:"login_url"`
		LoginUser         string   `json:"login_user"`
		LoginPass         string   `json:"login_pass"`
		LoginUserField    string   `json:"login_user_field"`
		LoginPassField    string   `json:"login_pass_field"`
		RequestsPerSecond float64  `json:"requests_per_second"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	// Validate required fields
	if args.FindingType == "" {
		return nil, fmt.Errorf("finding_type is required")
	}
	if args.FindingURL == "" {
		return nil, fmt.Errorf("finding_url is required")
	}
	if args.Parameter == "" {
		return nil, fmt.Errorf("parameter is required")
	}
	if args.Payload == "" {
		return nil, fmt.Errorf("payload is required")
	}

	// Validate finding_type
	validTypes := map[string]bool{
		"sqli": true, "xss": true, "ssrf": true, "cmdi": true,
		"pathtraversal": true, "redirect": true, "csrf": true, "ssti": true,
	}
	if !validTypes[args.FindingType] {
		return nil, fmt.Errorf("invalid finding_type: %s (must be one of: sqli, xss, ssrf, cmdi, pathtraversal, redirect, csrf, ssti)", args.FindingType)
	}

	// Validate and normalize target URL
	validatedURL, err := urlutil.ValidateTargetURL(args.FindingURL)
	if err != nil {
		return nil, err
	}
	args.FindingURL = validatedURL

	// Set defaults
	if args.MaxRetries <= 0 {
		args.MaxRetries = 3
	}
	if args.Delay == "" {
		args.Delay = "100ms"
	}

	// Parse delay
	delay, err := time.ParseDuration(args.Delay)
	if err != nil {
		return nil, fmt.Errorf("invalid delay: %w", err)
	}

	// Construct auth config from arguments
	authConfig := &auth.AuthConfig{
		BearerToken: args.BearerToken,
		BasicAuth:   args.BasicAuth,
		AuthHeader:  args.AuthHeader,
		Cookies:     args.Cookies,
	}

	// Add login configuration if provided
	if args.LoginURL != "" {
		authConfig.Login = &auth.LoginConfig{
			LoginURL:      args.LoginURL,
			Username:      args.LoginUser,
			Password:      args.LoginPass,
			UsernameField: args.LoginUserField,
			PasswordField: args.LoginPassField,
		}
		// Perform login to capture session cookies
		if err := authConfig.PerformLogin(ctx); err != nil {
			return nil, fmt.Errorf("automated login failed: %w", err)
		}
	}

	rateLimitConfig := ratelimit.Config{RequestsPerSecond: args.RequestsPerSecond}

	// Execute verify logic
	result, err := executeVerify(ctx, args.FindingType, args.FindingURL, args.Parameter, args.Payload, args.MaxRetries, delay, authConfig, rateLimitConfig, t.server.tracer)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// WebSocketTool implements the wast_websocket MCP tool.
type WebSocketTool struct {
	server *Server
}

func (t *WebSocketTool) Name() string {
	return "wast_websocket"
}

func (t *WebSocketTool) Description() string {
	return "Perform WebSocket security scanning on a target. Detects WebSocket endpoints and scans for security issues including insecure protocols (ws:// vs wss://) and missing origin validation (CSWSH). Use active=true to enable active testing for Cross-Site WebSocket Hijacking vulnerabilities."
}

func (t *WebSocketTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target": map[string]interface{}{
				"type":        "string",
				"description": "Target URL to scan for WebSocket endpoints",
			},
			"active": map[string]interface{}{
				"type":        "boolean",
				"description": "Enable active testing for origin validation (CSWSH detection). Defaults to false for passive mode.",
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
		"required": []string{"target"},
	}
}

func (t *WebSocketTool) Execute(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var args struct {
		Target            string   `json:"target"`
		Active            bool     `json:"active"`
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

	if args.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	// Validate and normalize target URL
	validatedURL, err := urlutil.ValidateTargetURL(args.Target)
	if err != nil {
		return nil, err
	}
	args.Target = validatedURL

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

	// Execute WebSocket scan logic
	result := executeWebSocket(ctx, args.Target, args.Active, args.Timeout, authConfig, rateLimitConfig, t.server.tracer)

	return result, nil
}
