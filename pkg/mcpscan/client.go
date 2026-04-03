package mcpscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// maxBodyBytes limits HTTP/SSE response bodies to prevent memory exhaustion.
const maxBodyBytes = 1 << 20 // 1 MiB

// Retry / backoff defaults for HTTP 429 handling.
const (
	defaultMaxRetries   = 3
	retryInitialBackoff = 1 * time.Second
	retryMaxBackoff     = 60 * time.Second
)

// ErrMaxRetriesExceeded is returned by retryableDo when the server keeps
// responding with HTTP 429 after all retry attempts are exhausted.
type ErrMaxRetriesExceeded struct {
	// Retries is the number of retry attempts made (not counting the first try).
	Retries int
}

func (e *ErrMaxRetriesExceeded) Error() string {
	return fmt.Sprintf("rate limited: max retries (%d) exceeded after HTTP 429", e.Retries)
}

// Transport specifies how to connect to an MCP server.
type Transport string

const (
	TransportStdio Transport = "stdio"
	TransportSSE   Transport = "sse"
	TransportHTTP  Transport = "http"
)

// jsonrpcRequest is the wire format for JSON-RPC 2.0 requests.
type jsonrpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// jsonrpcResponse is the wire format for JSON-RPC 2.0 responses.
type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

// jsonrpcError is the wire format for a JSON-RPC 2.0 error object.
type jsonrpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (e *jsonrpcError) Error() string {
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

// ErrAuthRequired is returned when an MCP server responds with 401 or 403.
type ErrAuthRequired struct {
	StatusCode int
	Body       string
}

func (e *ErrAuthRequired) Error() string {
	return fmt.Sprintf("authentication required (HTTP %d)", e.StatusCode)
}

// stdioLine is a single line read from the subprocess stdout, or an error.
type stdioLine struct {
	line string
	err  error
}

// Client is an MCP JSON-RPC 2.0 client that supports stdio, SSE, and HTTP transports.
type Client struct {
	transport Transport
	target    string   // URL for SSE/HTTP, command for stdio
	args      []string // additional args for stdio
	env       []string // extra env vars for stdio (KEY=VALUE)
	timeout   time.Duration
	idCounter uint64

	// stdio fields
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader

	// linesCh receives lines from the dedicated stdio reader goroutine.
	// Using a buffered channel so the reader can proceed without blocking
	// when the consumer is busy with context selection.
	linesCh    chan stdioLine
	readerDone chan struct{}

	// http client (shared for SSE and HTTP transports)
	httpClient *http.Client

	// 429 retry configuration
	maxRetries          int           // max number of retry attempts on HTTP 429
	retryCount          int64         // total retries performed (accessed atomically)
	retryInitialBackoff time.Duration // initial backoff duration for exponential backoff
	retryMaxBackoff     time.Duration // cap for exponential backoff
}

// ClientOption is a functional option for configuring a Client.
type ClientOption func(*Client)

// WithTimeout sets the per-request timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) { c.timeout = d }
}

// WithEnv sets additional environment variables for stdio servers (KEY=VALUE format).
func WithEnv(env []string) ClientOption {
	return func(c *Client) { c.env = env }
}

// WithHTTPClient overrides the HTTP client used for SSE/HTTP transports.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = hc }
}

// WithMaxRetries sets the maximum number of retry attempts on HTTP 429 responses.
// The default is 3. Set to 0 to disable retries.
func WithMaxRetries(n int) ClientOption {
	return func(c *Client) { c.maxRetries = n }
}

// withRetryBackoff sets custom backoff parameters. This is intentionally
// unexported and intended for use in tests to avoid slow sleep durations.
func withRetryBackoff(initial, max time.Duration) ClientOption {
	return func(c *Client) {
		c.retryInitialBackoff = initial
		c.retryMaxBackoff = max
	}
}

// RetryCount returns the total number of HTTP 429 retries performed by this client.
func (c *Client) RetryCount() int {
	return int(atomic.LoadInt64(&c.retryCount))
}

// newClientDefaults fills retry-related fields with their default values.
// Call this before applying user options.
func newClientDefaults(c *Client) {
	c.maxRetries = defaultMaxRetries
	c.retryInitialBackoff = retryInitialBackoff
	c.retryMaxBackoff = retryMaxBackoff
}

// NewStdioClient creates a Client that communicates with a stdio-based MCP server.
// command is the executable; args are its arguments.
func NewStdioClient(command string, args []string, opts ...ClientOption) *Client {
	c := &Client{
		transport:  TransportStdio,
		target:     command,
		args:       args,
		timeout:    30 * time.Second,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	newClientDefaults(c)
	for _, o := range opts {
		o(c)
	}
	return c
}

// NewSSEClient creates a Client that communicates with an SSE-based MCP server.
func NewSSEClient(url string, opts ...ClientOption) *Client {
	c := &Client{
		transport:  TransportSSE,
		target:     url,
		timeout:    30 * time.Second,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
	newClientDefaults(c)
	for _, o := range opts {
		o(c)
	}
	return c
}

// NewHTTPClient creates a Client that communicates with an HTTP-based MCP server.
func NewHTTPClient(url string, opts ...ClientOption) *Client {
	c := &Client{
		transport:  TransportHTTP,
		target:     url,
		timeout:    30 * time.Second,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	newClientDefaults(c)
	for _, o := range opts {
		o(c)
	}
	return c
}

// Connect establishes the connection to the MCP server and performs the
// JSON-RPC initialize handshake. It returns the server info from the response.
func (c *Client) Connect(ctx context.Context) (*MCPServerInfo, error) {
	switch c.transport {
	case TransportStdio:
		if err := c.connectStdio(ctx); err != nil {
			return nil, fmt.Errorf("stdio connect: %w", err)
		}
	case TransportSSE, TransportHTTP:
		// HTTP/SSE transports are stateless; nothing to set up here.
	default:
		return nil, fmt.Errorf("unsupported transport: %s", c.transport)
	}

	return c.initialize(ctx)
}

// connectStdio starts the subprocess for stdio transport and launches a
// dedicated reader goroutine. All lines from the subprocess are forwarded
// through linesCh so that callStdio can select on context cancellation.
func (c *Client) connectStdio(ctx context.Context) error {
	c.cmd = exec.CommandContext(ctx, c.target, c.args...)
	if len(c.env) > 0 {
		c.cmd.Env = append(c.cmd.Environ(), c.env...)
	}

	var err error
	c.stdin, err = c.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	stdoutPipe, err := c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	c.stdout = bufio.NewReader(stdoutPipe)

	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("start command: %w", err)
	}

	// Start the dedicated reader goroutine. It forwards every line (or error)
	// from the subprocess stdout into linesCh. The channel is buffered so the
	// reader can write ahead while callStdio is in the select statement.
	c.linesCh = make(chan stdioLine, 32)
	c.readerDone = make(chan struct{})
	go func() {
		defer close(c.readerDone)
		for {
			line, err := c.stdout.ReadString('\n')
			c.linesCh <- stdioLine{line, err}
			if err != nil {
				return
			}
		}
	}()

	return nil
}

// Close shuts down the connection and cleans up resources.
func (c *Client) Close() error {
	if c.cmd != nil {
		if c.stdin != nil {
			_ = c.stdin.Close()
		}
		_ = c.cmd.Wait()
		// Wait for the reader goroutine to drain after the process exits.
		if c.readerDone != nil {
			<-c.readerDone
		}
	}
	return nil
}

// nextID returns a monotonically increasing request ID.
func (c *Client) nextID() uint64 {
	return atomic.AddUint64(&c.idCounter, 1)
}

// initialize sends the MCP initialize request and returns server info.
func (c *Client) initialize(ctx context.Context) (*MCPServerInfo, error) {
	params := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"clientInfo": map[string]interface{}{
			"name":    "wast-mcpscan",
			"version": "1.0.0",
		},
		"capabilities": map[string]interface{}{},
	}

	resp, err := c.call(ctx, "initialize", params)
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}

	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		// Non-fatal: return partial info.
		return &MCPServerInfo{
			Transport: string(c.transport),
			Target:    c.target,
		}, nil
	}

	// Send initialized notification.
	_ = c.notify(ctx, "notifications/initialized", map[string]interface{}{})

	return &MCPServerInfo{
		Transport:       string(c.transport),
		Target:          c.target,
		Name:            result.ServerInfo.Name,
		Version:         result.ServerInfo.Version,
		ProtocolVersion: result.ProtocolVersion,
	}, nil
}

// ListTools calls tools/list and returns all available tools.
func (c *Client) ListTools(ctx context.Context) ([]MCPToolInfo, error) {
	resp, err := c.call(ctx, "tools/list", map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}

	var result struct {
		Tools []struct {
			Name        string                 `json:"name"`
			Description string                 `json:"description"`
			InputSchema map[string]interface{} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("parse tools/list response: %w", err)
	}

	tools := make([]MCPToolInfo, 0, len(result.Tools))
	for _, t := range result.Tools {
		info := MCPToolInfo{
			Name:        t.Name,
			Description: t.Description,
			RawSchema:   t.InputSchema,
		}
		info.Parameters = extractParameters(t.InputSchema)
		tools = append(tools, info)
	}

	return tools, nil
}

// extractParameters parses a JSON Schema inputSchema into a flat list of parameter infos.
func extractParameters(schema map[string]interface{}) []MCPToolParameterInfo {
	if schema == nil {
		return nil
	}

	properties, _ := schema["properties"].(map[string]interface{})
	if properties == nil {
		return nil
	}

	// Collect required fields.
	requiredSet := map[string]bool{}
	if req, ok := schema["required"].([]interface{}); ok {
		for _, r := range req {
			if s, ok := r.(string); ok {
				requiredSet[s] = true
			}
		}
	}

	params := make([]MCPToolParameterInfo, 0, len(properties))
	for name, propRaw := range properties {
		prop, _ := propRaw.(map[string]interface{})
		p := MCPToolParameterInfo{
			Name:     name,
			Required: requiredSet[name],
		}
		if prop != nil {
			p.Type, _ = prop["type"].(string)
			p.Description, _ = prop["description"].(string)
			_, p.HasEnum = prop["enum"]
		}
		params = append(params, p)
	}

	return params
}

// CallTool invokes a tool and returns the raw response content.
func (c *Client) CallTool(ctx context.Context, toolName string, arguments map[string]interface{}) ([]byte, error) {
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": arguments,
	}

	resp, err := c.call(ctx, "tools/call", params)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// call performs a JSON-RPC 2.0 request and returns the raw result bytes.
func (c *Client) call(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	id := c.nextID()
	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	switch c.transport {
	case TransportStdio:
		return c.callStdio(ctx, req)
	case TransportHTTP:
		return c.callHTTP(ctx, req)
	case TransportSSE:
		return c.callSSE(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported transport: %s", c.transport)
	}
}

// notify sends a JSON-RPC notification (no response expected).
func (c *Client) notify(ctx context.Context, method string, params interface{}) error {
	notif := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}

	switch c.transport {
	case TransportStdio:
		data, err := json.Marshal(notif)
		if err != nil {
			return err
		}
		data = append(data, '\n')
		_, err = c.stdin.Write(data)
		return err
	case TransportHTTP, TransportSSE:
		// Notifications are fire-and-forget for HTTP/SSE; send and ignore response.
		notif["id"] = nil
		data, err := json.Marshal(notif)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.target, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.retryableDo(req, data)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}
	return nil
}

// callStdio sends a request over stdio and reads the matching response.
// It reads from linesCh (populated by the dedicated reader goroutine) and
// selects on context / per-request timeout so the function is never
// permanently blocked if the server hangs or stops responding.
func (c *Client) callStdio(ctx context.Context, req jsonrpcRequest) (json.RawMessage, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	data = append(data, '\n')

	if _, err := c.stdin.Write(data); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	// Apply a per-request timeout on top of whatever the caller's context says.
	timeoutCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// reqIDStr is the canonical string form of our request ID used for matching.
	reqIDStr := fmt.Sprintf("%v", req.ID)

	// Drain linesCh until we find the response whose ID matches our request.
	// The server may interleave JSON-RPC notifications before the actual reply.
	for {
		select {
		case <-timeoutCtx.Done():
			return nil, fmt.Errorf("timeout waiting for response to method %s", req.Method)

		case result, ok := <-c.linesCh:
			if !ok {
				// Reader goroutine closed the channel — process exited.
				return nil, fmt.Errorf("server closed connection")
			}
			if result.err != nil {
				if result.err == io.EOF {
					return nil, fmt.Errorf("server closed connection")
				}
				return nil, fmt.Errorf("read response: %w", result.err)
			}

			line := strings.TrimSpace(result.line)
			if line == "" {
				continue
			}

			var resp jsonrpcResponse
			if err := json.Unmarshal([]byte(line), &resp); err != nil {
				// May be a non-JSON log line; skip it.
				continue
			}

			// Skip JSON-RPC notifications (they have no ID).
			if resp.ID == nil {
				continue
			}

			// Skip responses whose ID does not match this request — they may
			// be stale responses from a previous timed-out request.
			if fmt.Sprintf("%v", resp.ID) != reqIDStr {
				continue
			}

			if resp.Error != nil {
				return nil, resp.Error
			}

			return resp.Result, nil
		}
	}
}

// parseRetryAfter parses the Retry-After response header per RFC 7231 §7.1.3.
// It accepts both delta-seconds ("Retry-After: 5") and HTTP-date formats.
// If the header is absent or cannot be parsed, fallback is returned.
func parseRetryAfter(header string, fallback time.Duration) time.Duration {
	if header == "" {
		return fallback
	}
	header = strings.TrimSpace(header)
	// Try delta-seconds first (most common).
	if secs, err := strconv.Atoi(header); err == nil {
		if secs < 0 {
			return fallback
		}
		return time.Duration(secs) * time.Second
	}
	// Try HTTP-date format (e.g. "Fri, 03 Apr 2026 12:00:00 GMT").
	if t, err := http.ParseTime(header); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
		return 0
	}
	return fallback
}

// retryableDo performs an HTTP request, retrying on HTTP 429 (Too Many Requests)
// up to c.maxRetries times. On each 429 response it inspects the Retry-After
// header (supporting both delta-seconds and HTTP-date formats per RFC 7231 §7.1.3).
// If no Retry-After header is present, exponential backoff is used starting at
// c.retryInitialBackoff, capped at c.retryMaxBackoff.
//
// The body parameter must be the raw request body bytes so the body can be
// replayed on each retry attempt (http.Request.Body is consumed by the first Do).
//
// When all retries are exhausted an *ErrMaxRetriesExceeded is returned.
func (c *Client) retryableDo(req *http.Request, body []byte) (*http.Response, error) {
	ctx := req.Context()
	backoff := c.retryInitialBackoff

	for attempt := 0; ; attempt++ {
		// (Re)set the request body for each attempt so the transport can read it.
		if len(body) > 0 {
			req.Body = io.NopCloser(bytes.NewReader(body))
			req.ContentLength = int64(len(body))
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		// Not rate-limited — return immediately.
		if resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}

		// Drain and close the 429 response body before retrying.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		// Check if retries are exhausted.
		if attempt >= c.maxRetries {
			return nil, &ErrMaxRetriesExceeded{Retries: attempt}
		}

		// Parse Retry-After header; fall back to current exponential backoff.
		wait := parseRetryAfter(resp.Header.Get("Retry-After"), backoff)

		// Increment per-client retry counter.
		atomic.AddInt64(&c.retryCount, 1)

		// Advance exponential backoff for next potential fallback.
		backoff = min(backoff*2, c.retryMaxBackoff)

		// Honour context cancellation during the wait.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// callHTTP sends a request over HTTP and reads the JSON response.
func (c *Client) callHTTP(ctx context.Context, req jsonrpcRequest) (json.RawMessage, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.target, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("build HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	httpResp, err := c.retryableDo(httpReq, data)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// Check for HTTP-level auth errors before parsing JSON-RPC.
	if httpResp.StatusCode == http.StatusUnauthorized || httpResp.StatusCode == http.StatusForbidden {
		return nil, &ErrAuthRequired{
			StatusCode: httpResp.StatusCode,
			Body:       string(body),
		}
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", httpResp.StatusCode, string(body))
	}

	// Streamable HTTP: server may respond with application/json or text/event-stream.
	contentType := httpResp.Header.Get("Content-Type")
	var jsonBody []byte
	if strings.Contains(contentType, "text/event-stream") {
		// Parse SSE: extract JSON from "data:" lines.
		jsonBody = extractJSONFromSSE(body)
		if jsonBody == nil {
			return nil, fmt.Errorf("no JSON-RPC message found in SSE response")
		}
	} else {
		jsonBody = body
	}

	var resp jsonrpcResponse
	if err := json.Unmarshal(jsonBody, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if resp.Error != nil {
		return nil, resp.Error
	}

	return resp.Result, nil
}

// extractJSONFromSSE extracts the last JSON-RPC message from an SSE stream.
// SSE format: lines prefixed with "data: " containing JSON payloads.
func extractJSONFromSSE(body []byte) []byte {
	var lastData []byte
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if data != "" {
				lastData = []byte(data)
			}
		}
	}
	return lastData
}

// callSSE sends a request to an SSE endpoint.
// MCP over SSE typically uses an HTTP POST endpoint alongside the SSE stream.
// Here we post the JSON-RPC request and wait for the streamed response.
func (c *Client) callSSE(ctx context.Context, req jsonrpcRequest) (json.RawMessage, error) {
	// Many SSE-based MCP implementations expose a separate POST endpoint
	// at the same base URL. We try HTTP POST first, falling back to treating
	// it as a plain HTTP endpoint.
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.target, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("build SSE request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	httpResp, err := c.retryableDo(httpReq, data)
	if err != nil {
		return nil, fmt.Errorf("SSE request: %w", err)
	}
	defer httpResp.Body.Close()

	contentType := httpResp.Header.Get("Content-Type")

	if strings.Contains(contentType, "text/event-stream") {
		// Parse the SSE stream for a matching response.
		return parseSSEResponse(httpResp.Body, req.ID)
	}

	// Treat as plain JSON response.
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read SSE response: %w", err)
	}

	var resp jsonrpcResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse SSE response: %w", err)
	}

	if resp.Error != nil {
		return nil, resp.Error
	}

	return resp.Result, nil
}

// parseSSEResponse reads an SSE stream looking for a JSON-RPC response with the given ID.
func parseSSEResponse(body io.Reader, id interface{}) (json.RawMessage, error) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}

		var resp jsonrpcResponse
		if err := json.Unmarshal([]byte(payload), &resp); err != nil {
			continue
		}

		// Match response ID (compare as strings for robustness).
		if fmt.Sprintf("%v", resp.ID) != fmt.Sprintf("%v", id) {
			continue
		}

		if resp.Error != nil {
			return nil, resp.Error
		}

		return resp.Result, nil
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("SSE stream error: %w", err)
	}

	return nil, fmt.Errorf("SSE stream ended without matching response")
}
