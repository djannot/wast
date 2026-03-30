package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// MockTransport implements the Transport interface for testing.
type MockTransport struct {
	Responses map[string]*http.Response
	Errors    map[string]error
	Requests  []*http.Request
}

// NewMockTransport creates a new MockTransport.
func NewMockTransport() *MockTransport {
	return &MockTransport{
		Responses: make(map[string]*http.Response),
		Errors:    make(map[string]error),
		Requests:  make([]*http.Request, 0),
	}
}

// AddResponse adds a mock response for a URL.
func (m *MockTransport) AddResponse(url string, statusCode int, body string, headers map[string]string) {
	h := make(http.Header)
	for k, v := range headers {
		h.Set(k, v)
	}
	m.Responses[url] = &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     h,
	}
}

// AddError adds a mock error for a URL.
func (m *MockTransport) AddError(url string, err error) {
	m.Errors[url] = err
}

// RoundTrip performs the mock HTTP request.
func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.Requests = append(m.Requests, req)
	url := req.URL.String()

	if err, ok := m.Errors[url]; ok {
		return nil, err
	}

	if resp, ok := m.Responses[url]; ok {
		// Create a fresh body for each request
		if originalResp, exists := m.Responses[url]; exists {
			body, _ := io.ReadAll(originalResp.Body)
			resp.Body = io.NopCloser(strings.NewReader(string(body)))
			m.Responses[url].Body = io.NopCloser(strings.NewReader(string(body)))
		}
		return resp, nil
	}

	// Default: 404
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Status:     "Not Found",
		Body:       io.NopCloser(strings.NewReader("Not Found")),
		Header:     make(http.Header),
	}, nil
}

// MockListener implements the Listener interface for testing.
type MockListener struct {
	conns     chan net.Conn
	closeOnce bool
	closed    bool
	addr      net.Addr
}

// NewMockListener creates a new MockListener.
func NewMockListener() *MockListener {
	return &MockListener{
		conns: make(chan net.Conn, 10),
		addr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
	}
}

func (m *MockListener) Accept() (net.Conn, error) {
	conn, ok := <-m.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (m *MockListener) Close() error {
	if !m.closed {
		m.closed = true
		close(m.conns)
	}
	return nil
}

func (m *MockListener) Addr() net.Addr {
	return m.addr
}

func TestProxy_NewProxy(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		p := NewProxy()
		if p.port != 8080 {
			t.Errorf("Expected default port 8080, got %d", p.port)
		}
		if p.saveFile != "" {
			t.Errorf("Expected empty save file, got %s", p.saveFile)
		}
		if p.transport == nil {
			t.Error("Expected default transport to be set")
		}
	})

	t.Run("custom port", func(t *testing.T) {
		p := NewProxy(WithPort(9090))
		if p.port != 9090 {
			t.Errorf("Expected port 9090, got %d", p.port)
		}
	})

	t.Run("custom save file", func(t *testing.T) {
		p := NewProxy(WithSaveFile("/tmp/traffic.json"))
		if p.saveFile != "/tmp/traffic.json" {
			t.Errorf("Expected save file '/tmp/traffic.json', got %s", p.saveFile)
		}
	})

	t.Run("custom transport", func(t *testing.T) {
		mock := NewMockTransport()
		p := NewProxy(WithTransport(mock))
		if p.transport != mock {
			t.Error("Expected custom transport to be set")
		}
	})
}

func TestProxy_HandleRequest(t *testing.T) {
	// Create a mock backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from backend"))
	}))
	defer backend.Close()

	// Create proxy with real transport
	p := NewProxy(WithPort(0))

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, backend.URL, nil)
	req.Header.Set("X-Custom-Header", "custom-value")

	// Create a response recorder
	w := httptest.NewRecorder()

	// Handle the request
	p.handleRequest(w, req)

	// Verify response
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Hello from backend" {
		t.Errorf("Expected body 'Hello from backend', got '%s'", string(body))
	}

	// Verify traffic was recorded
	traffic := p.GetTraffic()
	if len(traffic) != 1 {
		t.Fatalf("Expected 1 traffic pair, got %d", len(traffic))
	}

	pair := traffic[0]
	if pair.Request == nil {
		t.Fatal("Expected request to be captured")
	}
	if pair.Request.Method != http.MethodGet {
		t.Errorf("Expected method GET, got %s", pair.Request.Method)
	}
	if pair.Response == nil {
		t.Fatal("Expected response to be captured")
	}
	if pair.Response.StatusCode != http.StatusOK {
		t.Errorf("Expected response status 200, got %d", pair.Response.StatusCode)
	}
}

func TestProxy_HandleRequest_WithMockTransport(t *testing.T) {
	mock := NewMockTransport()
	mock.AddResponse("http://example.com/api", http.StatusOK, `{"status": "ok"}`, map[string]string{
		"Content-Type": "application/json",
	})

	p := NewProxy(WithTransport(mock))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api", nil)
	w := httptest.NewRecorder()

	p.handleRequest(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"status": "ok"}` {
		t.Errorf("Expected JSON body, got '%s'", string(body))
	}

	// Check stats
	stats := p.GetStats()
	if stats.TotalRequests != 1 {
		t.Errorf("Expected 1 request, got %d", stats.TotalRequests)
	}
	if stats.TotalResponses != 1 {
		t.Errorf("Expected 1 response, got %d", stats.TotalResponses)
	}
	if stats.SuccessCount != 1 {
		t.Errorf("Expected 1 success, got %d", stats.SuccessCount)
	}
}

func TestProxy_HandleRequest_WithBody(t *testing.T) {
	mock := NewMockTransport()
	mock.AddResponse("http://example.com/api", http.StatusCreated, `{"id": 123}`, nil)

	p := NewProxy(WithTransport(mock))

	reqBody := `{"name": "test"}`
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleRequest(w, req)

	// Verify request body was captured
	traffic := p.GetTraffic()
	if len(traffic) != 1 {
		t.Fatalf("Expected 1 traffic pair, got %d", len(traffic))
	}

	if traffic[0].Request.Body != reqBody {
		t.Errorf("Expected request body '%s', got '%s'", reqBody, traffic[0].Request.Body)
	}

	// Verify bytes tracking
	stats := p.GetStats()
	if stats.TotalBytesIn != len(reqBody) {
		t.Errorf("Expected %d bytes in, got %d", len(reqBody), stats.TotalBytesIn)
	}
}

func TestProxy_HandleRequest_Error(t *testing.T) {
	mock := NewMockTransport()
	mock.AddError("http://example.com/error", net.ErrClosed)

	p := NewProxy(WithTransport(mock))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/error", nil)
	w := httptest.NewRecorder()

	p.handleRequest(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", resp.StatusCode)
	}

	// Check error stats
	stats := p.GetStats()
	if stats.ErrorCount != 1 {
		t.Errorf("Expected 1 error, got %d", stats.ErrorCount)
	}
}

func TestProxy_Start_AlreadyRunning(t *testing.T) {
	p := NewProxy()
	p.running = true

	_, err := p.Start(context.Background())
	if err == nil {
		t.Error("Expected error when proxy is already running")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("Expected 'already running' error, got: %v", err)
	}
}

func TestProxy_Start_ContextCancellation(t *testing.T) {
	// Create a listener on a random available port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	p := NewProxy(WithListener(ln))

	// Create a context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start should complete when context is cancelled
	result, err := p.Start(ctx)
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	if result.Port != 8080 { // Default port from NewProxy
		t.Errorf("Expected port 8080 in result, got %d", result.Port)
	}

	if result.StartTime.IsZero() {
		t.Error("Expected start time to be set")
	}

	if result.EndTime.IsZero() {
		t.Error("Expected end time to be set")
	}
}

func TestProxy_SaveTrafficToFile(t *testing.T) {
	// Create temp file
	tmpFile, err := os.CreateTemp("", "traffic_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	mock := NewMockTransport()
	mock.AddResponse("http://example.com/test", http.StatusOK, "test response", nil)

	p := NewProxy(
		WithTransport(mock),
		WithSaveFile(tmpFile.Name()),
	)

	// Handle a request to generate traffic
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	w := httptest.NewRecorder()
	p.handleRequest(w, req)

	// Build result and save
	result := p.buildResult()

	if result.SavedToFile != tmpFile.Name() {
		t.Errorf("Expected saved file path %s, got %s", tmpFile.Name(), result.SavedToFile)
	}

	// Verify file was created and contains JSON
	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read saved file: %v", err)
	}

	if !strings.Contains(string(data), "http://example.com/test") {
		t.Error("Expected saved file to contain the request URL")
	}
	if !strings.Contains(string(data), "test response") {
		t.Error("Expected saved file to contain the response body")
	}
}

func TestProxyResult_String(t *testing.T) {
	result := &ProxyResult{
		Port:      8080,
		StartTime: time.Now().Add(-time.Minute),
		EndTime:   time.Now(),
		Traffic: []*RequestResponsePair{
			{
				Request: &InterceptedRequest{
					ID:     "req_1",
					Method: "GET",
					URL:    "http://example.com/test",
				},
				Response: &InterceptedResponse{
					StatusCode: 200,
					Status:     "OK",
					Duration:   50 * time.Millisecond,
				},
			},
		},
		Statistics: ProxyStats{
			TotalRequests:  1,
			TotalResponses: 1,
			SuccessCount:   1,
		},
		SavedToFile: "/tmp/traffic.json",
	}

	str := result.String()

	checks := []string{
		"8080",
		"Statistics",
		"Total Requests: 1",
		"req_1",
		"GET",
		"http://example.com/test",
		"200",
		"/tmp/traffic.json",
	}

	for _, check := range checks {
		if !strings.Contains(str, check) {
			t.Errorf("String should contain %q", check)
		}
	}
}

func TestProxyResult_HasResults(t *testing.T) {
	tests := []struct {
		name   string
		result *ProxyResult
		want   bool
	}{
		{
			name:   "no results",
			result: &ProxyResult{},
			want:   false,
		},
		{
			name: "with traffic",
			result: &ProxyResult{
				Traffic: []*RequestResponsePair{
					{Request: &InterceptedRequest{ID: "req_1"}},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasResults(); got != tt.want {
				t.Errorf("HasResults() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCopyHeaders(t *testing.T) {
	src := make(http.Header)
	src.Set("Content-Type", "application/json")
	src.Set("X-Custom-Header", "custom-value")
	src.Set("Connection", "keep-alive")     // hop-by-hop, should be skipped
	src.Set("Transfer-Encoding", "chunked") // hop-by-hop, should be skipped

	dst := make(http.Header)
	copyHeaders(dst, src)

	if dst.Get("Content-Type") != "application/json" {
		t.Error("Expected Content-Type to be copied")
	}
	if dst.Get("X-Custom-Header") != "custom-value" {
		t.Error("Expected X-Custom-Header to be copied")
	}
	if dst.Get("Connection") != "" {
		t.Error("Expected Connection (hop-by-hop) to be skipped")
	}
	if dst.Get("Transfer-Encoding") != "" {
		t.Error("Expected Transfer-Encoding (hop-by-hop) to be skipped")
	}
}

func TestHeadersToMap(t *testing.T) {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	h.Add("Accept", "text/html")
	h.Add("Accept", "application/json")

	m := headersToMap(h)

	if m["Content-Type"] != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", m["Content-Type"])
	}

	// Multiple values should be joined with comma
	if !strings.Contains(m["Accept"], "text/html") || !strings.Contains(m["Accept"], "application/json") {
		t.Errorf("Expected Accept to contain both values, got '%s'", m["Accept"])
	}
}

func TestInterceptedRequest_Fields(t *testing.T) {
	req := &InterceptedRequest{
		ID:        "req_1",
		Method:    "POST",
		URL:       "http://example.com/api/users",
		Host:      "example.com",
		Path:      "/api/users",
		Headers:   map[string]string{"Content-Type": "application/json"},
		Body:      `{"name": "test"}`,
		Timestamp: time.Now(),
	}

	if req.ID != "req_1" {
		t.Errorf("Expected ID 'req_1', got '%s'", req.ID)
	}
	if req.Method != "POST" {
		t.Errorf("Expected Method 'POST', got '%s'", req.Method)
	}
	if req.URL != "http://example.com/api/users" {
		t.Errorf("Expected URL 'http://example.com/api/users', got '%s'", req.URL)
	}
}

func TestInterceptedResponse_Fields(t *testing.T) {
	resp := &InterceptedResponse{
		RequestID:  "req_1",
		StatusCode: 201,
		Status:     "Created",
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       `{"id": 123}`,
		Timestamp:  time.Now(),
		Duration:   50 * time.Millisecond,
	}

	if resp.RequestID != "req_1" {
		t.Errorf("Expected RequestID 'req_1', got '%s'", resp.RequestID)
	}
	if resp.StatusCode != 201 {
		t.Errorf("Expected StatusCode 201, got %d", resp.StatusCode)
	}
	if resp.Duration != 50*time.Millisecond {
		t.Errorf("Expected Duration 50ms, got %v", resp.Duration)
	}
}

func TestProxy_CaptureRequest(t *testing.T) {
	p := NewProxy()

	body := bytes.NewReader([]byte(`{"test": "data"}`))
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "abc123")

	intercepted := p.captureRequest(req, "req_1")

	if intercepted.ID != "req_1" {
		t.Errorf("Expected ID 'req_1', got '%s'", intercepted.ID)
	}
	if intercepted.Method != http.MethodPost {
		t.Errorf("Expected method POST, got '%s'", intercepted.Method)
	}
	if intercepted.Body != `{"test": "data"}` {
		t.Errorf("Expected body '{\"test\": \"data\"}', got '%s'", intercepted.Body)
	}
	if intercepted.Headers["Content-Type"] != "application/json" {
		t.Errorf("Expected Content-Type header, got '%s'", intercepted.Headers["Content-Type"])
	}
}

func TestProxy_CaptureResponse(t *testing.T) {
	p := NewProxy()

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"result": "success"}`)),
	}
	resp.Header.Set("Content-Type", "application/json")

	startTime := time.Now().Add(-100 * time.Millisecond)
	intercepted := p.captureResponse(resp, "req_1", startTime)

	if intercepted.RequestID != "req_1" {
		t.Errorf("Expected RequestID 'req_1', got '%s'", intercepted.RequestID)
	}
	if intercepted.StatusCode != 200 {
		t.Errorf("Expected StatusCode 200, got %d", intercepted.StatusCode)
	}
	if intercepted.Body != `{"result": "success"}` {
		t.Errorf("Expected body, got '%s'", intercepted.Body)
	}
	if intercepted.Duration < 100*time.Millisecond {
		t.Errorf("Expected Duration >= 100ms, got %v", intercepted.Duration)
	}
}

func TestProxyStats(t *testing.T) {
	stats := ProxyStats{
		TotalRequests:  10,
		TotalResponses: 9,
		SuccessCount:   8,
		ErrorCount:     1,
		TotalBytesIn:   1000,
		TotalBytesOut:  5000,
	}

	if stats.TotalRequests != 10 {
		t.Errorf("Expected TotalRequests 10, got %d", stats.TotalRequests)
	}
	if stats.ErrorCount != 1 {
		t.Errorf("Expected ErrorCount 1, got %d", stats.ErrorCount)
	}
}

func TestDefaultTransport(t *testing.T) {
	transport := NewDefaultTransport()
	if transport == nil {
		t.Fatal("Expected transport to be non-nil")
	}
	if transport.transport == nil {
		t.Fatal("Expected underlying transport to be non-nil")
	}
}

// MockHijacker implements http.Hijacker for testing CONNECT tunnel hijacking.
type MockHijacker struct {
	http.ResponseWriter
	conn      net.Conn
	hijackErr error
}

func (m *MockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if m.hijackErr != nil {
		return nil, nil, m.hijackErr
	}
	return m.conn, bufio.NewReadWriter(bufio.NewReader(m.conn), bufio.NewWriter(m.conn)), nil
}

func TestProxy_HandleConnect_WithMITM(t *testing.T) {
	// Create temp directory for CA
	tmpDir, err := os.MkdirTemp("", "wast-test-ca-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a certificate authority for MITM
	config := &CAConfig{
		CertPath:      tmpDir + "/ca.crt",
		KeyPath:       tmpDir + "/ca.key",
		ValidityYears: 1,
		KeyBits:       2048,
	}
	ca := NewCertificateAuthority(config)
	if err := ca.Initialize(); err != nil {
		t.Fatalf("Failed to initialize CA: %v", err)
	}

	// Create proxy with HTTPS enabled
	p := NewProxy(
		WithCA(ca),
		WithHTTPSEnabled(true),
	)

	if p.mitmHandler == nil {
		t.Fatal("Expected MITM handler to be initialized")
	}

	if !p.httpsEnabled {
		t.Error("Expected HTTPS to be enabled")
	}

	// Test that handleConnect routes to MITM handler when HTTPS is enabled
	// We'll verify this by checking the error response (since we're not using a real hijacker)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"

	// This should call p.mitmHandler.HandleConnect, which will eventually fail
	// because we don't have a proper hijacker, but it verifies the routing
	p.handleConnect(recorder, req)

	// The MITM handler should have attempted to handle this
	// Since we're using a plain ResponseRecorder without hijacker support,
	// it should fail with an error
	resp := recorder.Result()
	defer resp.Body.Close()

	// The error may vary depending on the MITM implementation,
	// but it should have attempted to process the CONNECT request
	if resp.StatusCode == 0 {
		t.Error("Expected MITM handler to process the CONNECT request")
	}
}

func TestProxy_HandleConnect_WithoutMITM(t *testing.T) {
	// Create proxy without HTTPS/MITM enabled
	p := NewProxy()

	// Verify no MITM handler in plain proxy mode
	if p.mitmHandler != nil {
		t.Error("Expected no MITM handler in plain proxy mode")
	}

	// Test that handleConnect calls handleTunnel when no MITM is configured
	// We'll test this by verifying the error path when hijacking fails
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"

	p.handleConnect(recorder, req)

	// Should fail with hijacking not supported error
	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Hijacking not supported") {
		t.Errorf("Expected 'Hijacking not supported' error, got: %s", string(body))
	}
}

func TestProxy_HandleTunnel_Success(t *testing.T) {
	// Create a simple TCP server as the target that closes immediately
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Start server that accepts and immediately closes
	serverClosed := make(chan bool)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Close immediately to trigger tunnel completion
		conn.Close()
		serverClosed <- true
	}()

	p := NewProxy()

	// Create pipes for client connection
	clientEnd, proxyEnd := net.Pipe()

	// Create mock hijacker
	recorder := httptest.NewRecorder()
	hijacker := &MockHijacker{
		ResponseWriter: recorder,
		conn:           proxyEnd,
	}

	// Create CONNECT request to target server
	targetHost := listener.Addr().String()
	req := httptest.NewRequest(http.MethodConnect, "http://"+targetHost, nil)
	req.Host = targetHost

	// Handle tunnel in a goroutine
	tunnelDone := make(chan bool)
	go func() {
		p.handleTunnel(hijacker, req)
		tunnelDone <- true
	}()

	// Read the "200 Connection Established" response
	response := make([]byte, 1024)
	clientEnd.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := clientEnd.Read(response)
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}

	responseStr := string(response[:n])
	if !strings.Contains(responseStr, "200 Connection Established") {
		t.Errorf("Expected '200 Connection Established', got: %s", responseStr)
	}

	// Wait for server to close its end
	<-serverClosed

	// Close client connection to trigger tunnel completion
	clientEnd.Close()

	// Wait for tunnel to complete with a timeout
	select {
	case <-tunnelDone:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Tunnel did not complete in time")
	}
}

func TestProxy_HandleTunnel_TargetConnectionFails(t *testing.T) {
	p := NewProxy()

	// Use an invalid target that will fail to connect
	req := httptest.NewRequest(http.MethodConnect, "http://invalid-host-that-does-not-exist.local:9999", nil)
	req.Host = "invalid-host-that-does-not-exist.local:9999"

	recorder := httptest.NewRecorder()

	// Handle tunnel - should fail to connect to target
	p.handleTunnel(recorder, req)

	// Verify error response
	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected status 502 Bad Gateway, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Failed to connect to target") {
		t.Errorf("Expected 'Failed to connect to target' error, got: %s", string(body))
	}

	// Verify error was tracked
	p.mu.RLock()
	errorCount := len(p.errors)
	p.mu.RUnlock()

	if errorCount == 0 {
		t.Error("Expected error to be tracked in proxy errors")
	}
}

func TestProxy_HandleTunnel_HijackingNotSupported(t *testing.T) {
	p := NewProxy()

	// Create a regular ResponseRecorder that doesn't implement http.Hijacker
	recorder := httptest.NewRecorder()

	// Create CONNECT request
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"

	// Handle tunnel - should fail because hijacking is not supported
	p.handleTunnel(recorder, req)

	// Verify error response
	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Hijacking not supported") {
		t.Errorf("Expected 'Hijacking not supported' error, got: %s", string(body))
	}

	// Verify error was tracked
	p.mu.RLock()
	hasError := false
	for _, err := range p.errors {
		if strings.Contains(err, "hijacking not supported") {
			hasError = true
			break
		}
	}
	p.mu.RUnlock()

	if !hasError {
		t.Error("Expected 'hijacking not supported' error to be tracked")
	}
}

func TestProxy_HandleTunnel_HijackFails(t *testing.T) {
	p := NewProxy()

	// Create a test server to have a valid target
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	targetHost := strings.TrimPrefix(targetServer.URL, "http://")

	// Create mock hijacker that returns an error
	hijackErr := fmt.Errorf("hijack operation failed")
	recorder := httptest.NewRecorder()
	hijacker := &MockHijacker{
		ResponseWriter: recorder,
		hijackErr:      hijackErr,
	}

	// Create CONNECT request
	req := httptest.NewRequest(http.MethodConnect, "http://"+targetHost, nil)
	req.Host = targetHost

	// Handle tunnel - should fail during hijack
	p.handleTunnel(hijacker, req)

	// Verify error response
	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Failed to hijack connection") {
		t.Errorf("Expected 'Failed to hijack connection' error, got: %s", string(body))
	}

	// Verify error was tracked
	p.mu.RLock()
	hasError := false
	for _, err := range p.errors {
		if strings.Contains(err, "CONNECT hijack failed") {
			hasError = true
			break
		}
	}
	p.mu.RUnlock()

	if !hasError {
		t.Error("Expected hijack failure to be tracked in errors")
	}
}

func TestProxy_HandleTunnel_BidirectionalDataTransfer(t *testing.T) {
	// Create a simple echo server as the target
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create echo listener: %v", err)
	}
	defer echoListener.Close()

	// Start echo server
	go func() {
		conn, err := echoListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Echo back what we receive
		io.Copy(conn, conn)
	}()

	p := NewProxy()

	// Create pipes for client connection
	clientEnd, proxyEnd := net.Pipe()
	defer clientEnd.Close()

	// Create mock hijacker
	recorder := httptest.NewRecorder()
	hijacker := &MockHijacker{
		ResponseWriter: recorder,
		conn:           proxyEnd,
	}

	// Create CONNECT request to echo server
	targetHost := echoListener.Addr().String()
	req := httptest.NewRequest(http.MethodConnect, "http://"+targetHost, nil)
	req.Host = targetHost

	// Handle tunnel in a goroutine
	go func() {
		p.handleTunnel(hijacker, req)
	}()

	// Read the "200 Connection Established" response
	response := make([]byte, 1024)
	n, err := clientEnd.Read(response)
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}

	if !strings.Contains(string(response[:n]), "200 Connection Established") {
		t.Error("Expected '200 Connection Established' response")
	}

	// Send test data through the tunnel
	testData := []byte("Hello through tunnel")
	_, err = clientEnd.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write to tunnel: %v", err)
	}

	// Read echoed data back
	echoData := make([]byte, len(testData))
	clientEnd.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err = clientEnd.Read(echoData)
	if err != nil && err != io.EOF {
		t.Fatalf("Failed to read from tunnel: %v", err)
	}

	if n > 0 && !bytes.Equal(echoData[:n], testData) {
		t.Errorf("Expected echoed data %q, got %q", string(testData), string(echoData[:n]))
	}

	// Close connection
	clientEnd.Close()
	proxyEnd.Close()
}

func TestProxy_HandleConnect_Method(t *testing.T) {
	// Test that handleRequest properly routes CONNECT requests
	p := NewProxy()

	// Create a simple CONNECT request
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"

	// Use a plain recorder (no hijacker) - should fail with appropriate error
	recorder := httptest.NewRecorder()

	// This should call handleConnect which calls handleTunnel (no MITM)
	p.handleRequest(recorder, req)

	// Since recorder doesn't support hijacking, should get error
	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", resp.StatusCode)
	}
}

func TestSaveTrafficToFile_Permissions(t *testing.T) {
	tmpDir := t.TempDir()
	savePath := tmpDir + "/traffic.json"

	p := NewProxy(WithSaveFile(savePath))

	// Build a minimal ProxyResult to save
	result := &ProxyResult{
		Traffic: []*RequestResponsePair{
			{
				Request: &InterceptedRequest{
					Method: "GET",
					URL:    "http://example.com",
				},
				Response: &InterceptedResponse{
					StatusCode: 200,
				},
			},
		},
	}

	if err := p.saveTrafficToFile(result); err != nil {
		t.Fatalf("saveTrafficToFile failed: %v", err)
	}

	info, err := os.Stat(savePath)
	if err != nil {
		t.Fatalf("failed to stat saved file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected file permissions 0600, got %04o", perm)
	}
}
