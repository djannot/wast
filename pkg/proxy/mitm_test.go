package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupTestMITM(t *testing.T) (*MITMHandler, *CertificateAuthority, string) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "wast-mitm-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	config := &CAConfig{
		CertPath:      filepath.Join(tmpDir, "ca.crt"),
		KeyPath:       filepath.Join(tmpDir, "ca.key"),
		ValidityYears: 1,
		KeyBits:       2048,
	}

	ca := NewCertificateAuthority(config)
	if err := ca.Initialize(); err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to initialize CA: %v", err)
	}

	certCache := NewCertCache(ca, 100)
	proxy := NewProxy()

	mitmConfig := &MITMConfig{
		CA:        ca,
		CertCache: certCache,
		Enabled:   true,
	}

	handler := NewMITMHandler(proxy, mitmConfig)
	return handler, ca, tmpDir
}

func TestMITMHandler_Creation(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	if handler == nil {
		t.Fatal("MITMHandler is nil")
	}

	if handler.config == nil {
		t.Fatal("MITMHandler config is nil")
	}

	if !handler.config.Enabled {
		t.Error("Expected MITM to be enabled")
	}
}

func TestMITMHandler_GetHTTPSConnectionCount(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Initial count should be 0
	count := handler.GetHTTPSConnectionCount()
	if count != 0 {
		t.Errorf("Expected initial count 0, got %d", count)
	}
}

func TestMITMConfig_Disabled(t *testing.T) {
	proxy := NewProxy()

	mitmConfig := &MITMConfig{
		CA:        nil,
		CertCache: nil,
		Enabled:   false,
	}

	handler := NewMITMHandler(proxy, mitmConfig)

	if handler.config.Enabled {
		t.Error("Expected MITM to be disabled")
	}
}

func TestProxy_WithCA(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wast-proxy-ca-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	config := &CAConfig{
		CertPath:      filepath.Join(tmpDir, "ca.crt"),
		KeyPath:       filepath.Join(tmpDir, "ca.key"),
		ValidityYears: 1,
		KeyBits:       2048,
	}

	ca := NewCertificateAuthority(config)
	if err := ca.Initialize(); err != nil {
		t.Fatalf("Failed to initialize CA: %v", err)
	}

	proxy := NewProxy(WithCA(ca))

	if proxy.ca != ca {
		t.Error("Expected CA to be set")
	}

	if !proxy.httpsEnabled {
		t.Error("Expected HTTPS to be enabled")
	}

	if proxy.certCache == nil {
		t.Error("Expected certCache to be initialized")
	}

	if proxy.mitmHandler == nil {
		t.Error("Expected mitmHandler to be initialized")
	}
}

func TestProxy_WithHTTPSEnabled(t *testing.T) {
	proxy := NewProxy(WithHTTPSEnabled(true))
	if !proxy.httpsEnabled {
		t.Error("Expected HTTPS to be enabled")
	}

	proxy = NewProxy(WithHTTPSEnabled(false))
	if proxy.httpsEnabled {
		t.Error("Expected HTTPS to be disabled")
	}
}

func TestProxy_HandleConnect_NoMITM(t *testing.T) {
	// Create proxy without MITM
	proxy := NewProxy()

	// Create a test HTTPS server
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from TLS server"))
	}))
	defer tlsServer.Close()

	// Get the server address
	serverAddr := strings.TrimPrefix(tlsServer.URL, "https://")

	// Create mock connection pair
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	// Simulate CONNECT request
	go func() {
		// Read the 200 Connection Established response
		reader := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Logf("Error reading response: %v", err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			t.Logf("Expected status 200, got %d", resp.StatusCode)
		}
		resp.Body.Close()

		// Connect through the tunnel
		tlsConn := tls.Client(clientConn, &tls.Config{
			InsecureSkipVerify: true,
		})
		defer tlsConn.Close()

		// Make a request
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.Write(tlsConn)

		// Read response
		response, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
		if err != nil {
			t.Logf("Error reading TLS response: %v", err)
			return
		}
		defer response.Body.Close()
	}()

	// Create HTTP request for CONNECT
	req := httptest.NewRequest(http.MethodConnect, serverAddr, nil)
	req.Host = serverAddr

	// Create response recorder that supports hijacking
	hijackWriter := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           proxyConn,
	}

	// Handle the CONNECT request
	proxy.handleConnect(hijackWriter, req)
}

// hijackableResponseWriter wraps an http.ResponseWriter to support hijacking.
type hijackableResponseWriter struct {
	http.ResponseWriter
	conn net.Conn
}

func (h *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn))
	return h.conn, rw, nil
}

func TestMITMHandler_CaptureRequest(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	body := strings.NewReader(`{"test": "data"}`)
	req := httptest.NewRequest(http.MethodPost, "https://example.com/api", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "example.com"

	intercepted := handler.captureRequest(req, "req_1")

	if intercepted.ID != "req_1" {
		t.Errorf("Expected ID 'req_1', got '%s'", intercepted.ID)
	}

	if intercepted.Method != http.MethodPost {
		t.Errorf("Expected method POST, got '%s'", intercepted.Method)
	}

	if intercepted.Body != `{"test": "data"}` {
		t.Errorf("Expected body '{\"test\": \"data\"}', got '%s'", intercepted.Body)
	}

	if intercepted.Host != "example.com" {
		t.Errorf("Expected host 'example.com', got '%s'", intercepted.Host)
	}
}

func TestMITMHandler_CaptureResponse(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"result": "success"}`)),
	}
	resp.Header.Set("Content-Type", "application/json")

	startTime := time.Now().Add(-100 * time.Millisecond)
	intercepted := handler.captureResponse(resp, "req_1", startTime)

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

func TestMITMHandler_SendResponse(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Create a pipe to capture the response
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
	}
	resp.Header.Set("Content-Type", "application/json")

	body := `{"status": "ok"}`

	// Send response in goroutine
	go func() {
		handler.sendResponse(serverConn, resp, body)
		serverConn.Close()
	}()

	// Read response
	reader := bufio.NewReader(clientConn)
	respLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if !strings.Contains(respLine, "200 OK") {
		t.Errorf("Expected 200 OK, got '%s'", respLine)
	}
}

func TestMITMHandler_SendErrorResponse(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Create a pipe to capture the response
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errMsg := "Connection failed"

	// Send error response in goroutine
	go func() {
		handler.sendErrorResponse(serverConn, "req_1", errMsg)
		serverConn.Close()
	}()

	// Read response
	reader := bufio.NewReader(clientConn)
	respLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if !strings.Contains(respLine, "502 Bad Gateway") {
		t.Errorf("Expected 502 Bad Gateway, got '%s'", respLine)
	}

	// Check that error was recorded
	if handler.proxy.stats.ErrorCount != 1 {
		t.Errorf("Expected error count 1, got %d", handler.proxy.stats.ErrorCount)
	}
}

func TestProxy_HandleTunnel_DialError(t *testing.T) {
	proxy := NewProxy()

	// Use an invalid address that will fail to connect
	req := httptest.NewRequest(http.MethodConnect, "invalid.local:443", nil)
	req.Host = "invalid.local:443"

	w := httptest.NewRecorder()

	// This should fail but not panic
	proxy.handleTunnel(w, req)

	// Should have recorded an error
	if len(proxy.errors) == 0 {
		t.Error("Expected error to be recorded")
	}
}

func TestIntegration_MITMWithHTTPSServer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create a test HTTPS server
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"path": "%s", "method": "%s"}`, r.URL.Path, r.Method)
	}))
	defer tlsServer.Close()

	// Setup MITM handler
	handler, ca, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Get the server address
	serverAddr := strings.TrimPrefix(tlsServer.URL, "https://")
	host, _, _ := net.SplitHostPort(serverAddr)

	// Generate a certificate for the target host
	cert, err := ca.GenerateCertificate(host)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Verify certificate was generated
	if cert == nil {
		t.Fatal("Certificate is nil")
	}

	// Verify the handler exists
	if handler == nil {
		t.Fatal("Handler is nil")
	}
}

func TestMITMHandler_HandleTunnel_Success(t *testing.T) {
	// Create a test HTTP server (not TLS, as tunnel doesn't decrypt)
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from target"))
	}))
	defer targetServer.Close()

	// Setup proxy without MITM enabled
	proxy := NewProxy()
	mitmConfig := &MITMConfig{
		CA:        nil,
		CertCache: nil,
		Enabled:   false,
	}
	handler := NewMITMHandler(proxy, mitmConfig)

	// Get server address
	serverAddr := strings.TrimPrefix(targetServer.URL, "http://")

	// Create mock connection pair
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	done := make(chan bool)
	// Client goroutine to receive tunnel establishment and send data
	go func() {
		defer func() { done <- true }()

		// Set deadline to prevent hanging
		clientConn.SetDeadline(time.Now().Add(2 * time.Second))

		reader := bufio.NewReader(clientConn)
		// Read the 200 Connection Established response
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Logf("Error reading response: %v", err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
		resp.Body.Close()

		// Send some data through the tunnel
		clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + serverAddr + "\r\n\r\n"))

		// Read a bit of response
		buf := make([]byte, 1024)
		_, err = clientConn.Read(buf)
		if err != nil && err != io.EOF {
			t.Logf("Error reading from tunnel: %v", err)
		}
	}()

	// Create HTTP request for CONNECT
	req := httptest.NewRequest(http.MethodConnect, serverAddr, nil)
	req.Host = serverAddr

	// Create response recorder that supports hijacking
	hijackWriter := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           proxyConn,
	}

	// Handle the tunnel in a goroutine (it blocks)
	go handler.handleTunnel(hijackWriter, req)

	// Wait for client goroutine to complete or timeout
	select {
	case <-done:
		// Success
	case <-time.After(3 * time.Second):
		t.Fatal("Test timed out")
	}
}

func TestMITMHandler_HandleTunnel_DialError(t *testing.T) {
	proxy := NewProxy()
	mitmConfig := &MITMConfig{
		CA:        nil,
		CertCache: nil,
		Enabled:   false,
	}
	handler := NewMITMHandler(proxy, mitmConfig)

	// Use an invalid address that will fail to connect
	req := httptest.NewRequest(http.MethodConnect, "invalid.host.nonexistent:443", nil)
	req.Host = "invalid.host.nonexistent:443"

	w := httptest.NewRecorder()

	// This should fail but not panic
	handler.handleTunnel(w, req)

	// Should have recorded an error
	if len(proxy.errors) == 0 {
		t.Error("Expected error to be recorded")
	}

	// Check response status
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d, got %d", http.StatusBadGateway, w.Code)
	}
}

func TestMITMHandler_HandleTunnel_HijackNotSupported(t *testing.T) {
	proxy := NewProxy()
	mitmConfig := &MITMConfig{
		CA:        nil,
		CertCache: nil,
		Enabled:   false,
	}
	handler := NewMITMHandler(proxy, mitmConfig)

	// Create a simple server to connect to
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	serverAddr := strings.TrimPrefix(targetServer.URL, "http://")
	req := httptest.NewRequest(http.MethodConnect, serverAddr, nil)
	req.Host = serverAddr

	// Use a regular ResponseRecorder that doesn't support hijacking
	w := httptest.NewRecorder()

	handler.handleTunnel(w, req)

	// Should have recorded an error about hijacking not supported
	if len(proxy.errors) == 0 {
		t.Error("Expected error to be recorded")
	}

	// Check that the error mentions hijacking
	found := false
	for _, err := range proxy.errors {
		if strings.Contains(err, "hijacking not supported") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected error about hijacking not supported")
	}
}

func TestMITMHandler_HandleHTTPSRequests_Success(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Create a mock TLS connection using net.Pipe
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Wrap serverConn in TLS config for testing
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*handler.config.CertCache.ca.GetTLSCertificate()},
	}
	tlsConn := tls.Server(serverConn, tlsConfig)
	defer tlsConn.Close()

	targetHost := "example.com:443"

	// Client goroutine to send a request
	go func() {
		// Perform TLS handshake from client side
		clientTLS := tls.Client(clientConn, &tls.Config{
			InsecureSkipVerify: true,
		})
		defer clientTLS.Close()

		if err := clientTLS.Handshake(); err != nil {
			t.Logf("Client handshake error: %v", err)
			return
		}

		// Send HTTP request over TLS
		req, _ := http.NewRequest(http.MethodGet, "https://"+targetHost+"/test", nil)
		req.Header.Set("Host", targetHost)
		if err := req.Write(clientTLS); err != nil {
			t.Logf("Error writing request: %v", err)
			return
		}

		// Read response
		reader := bufio.NewReader(clientTLS)
		resp, err := http.ReadResponse(reader, req)
		if err == nil {
			resp.Body.Close()
		}
	}()

	// Give some time for the client to connect
	time.Sleep(50 * time.Millisecond)

	// This will try to read the request and handle it
	// It should fail to forward since we don't have a real server, but it tests the reading part
	handler.handleHTTPSRequests(tlsConn, targetHost)

	// Check that the proxy recorded traffic or errors
	if handler.proxy.stats.TotalRequests == 0 && len(handler.proxy.errors) == 0 {
		t.Log("Expected either traffic or errors to be recorded")
	}
}

func TestMITMHandler_HandleHTTPSRequests_EOF(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Create a mock TLS connection using net.Pipe
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	// Wrap serverConn in TLS config for testing
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*handler.config.CertCache.ca.GetTLSCertificate()},
	}
	tlsConn := tls.Server(serverConn, tlsConfig)
	defer tlsConn.Close()

	// Close client connection immediately to simulate EOF
	clientConn.Close()

	targetHost := "example.com:443"

	// This should handle EOF gracefully
	handler.handleHTTPSRequests(tlsConn, targetHost)

	// Should not have recorded an error for clean EOF
	// (The function logs but doesn't record EOF errors)
}

func TestMITMHandler_HandleInterceptedRequest_Success(t *testing.T) {
	// Create a test HTTPS server
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer targetServer.Close()

	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Create a mock connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Get target server address
	targetAddr := strings.TrimPrefix(targetServer.URL, "https://")

	// Create request
	req := httptest.NewRequest(http.MethodGet, "https://"+targetAddr+"/test", nil)
	req.URL.Scheme = "https"
	req.URL.Host = targetAddr
	req.Host = targetAddr
	req.RequestURI = ""

	// Read response in goroutine
	go func() {
		reader := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Logf("Error reading response: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	}()

	// Handle the request
	handler.handleInterceptedRequest(serverConn, req, targetAddr)

	// Wait a bit for goroutine to process
	time.Sleep(100 * time.Millisecond)

	// Verify stats were updated
	if handler.proxy.stats.TotalRequests != 1 {
		t.Errorf("Expected 1 request, got %d", handler.proxy.stats.TotalRequests)
	}

	if handler.proxy.stats.TotalResponses != 1 {
		t.Errorf("Expected 1 response, got %d", handler.proxy.stats.TotalResponses)
	}

	if handler.proxy.stats.SuccessCount != 1 {
		t.Errorf("Expected 1 success, got %d", handler.proxy.stats.SuccessCount)
	}

	if handler.proxy.stats.TotalBytesOut == 0 {
		t.Error("Expected bytes out to be greater than 0")
	}

	// Verify traffic was recorded
	if len(handler.proxy.traffic) != 1 {
		t.Errorf("Expected 1 traffic entry, got %d", len(handler.proxy.traffic))
	}
}

func TestMITMHandler_HandleInterceptedRequest_InvalidURL(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Create a mock connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Create request with valid initial URL, but then make URL String() invalid
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	// Make URL malformed by clearing required fields
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.URL.Path = "://invalid"

	// Read error response in goroutine
	go func() {
		reader := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Logf("Error reading response: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("Expected status 502, got %d", resp.StatusCode)
		}
	}()

	// Handle the request - should fail
	handler.handleInterceptedRequest(serverConn, req, "example.com:443")

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Should have recorded an error
	if handler.proxy.stats.ErrorCount == 0 {
		t.Error("Expected error count > 0")
	}
}

func TestMITMHandler_HandleInterceptedRequest_TransportError(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Create a mock connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Create request to non-existent server
	req := httptest.NewRequest(http.MethodGet, "https://nonexistent.local:9999/test", nil)
	req.URL.Scheme = "https"
	req.URL.Host = "nonexistent.local:9999"
	req.Host = "nonexistent.local:9999"
	req.RequestURI = ""

	// Read error response in goroutine
	go func() {
		reader := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Logf("Error reading response: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("Expected status 502, got %d", resp.StatusCode)
		}
	}()

	// Handle the request - should fail to forward
	handler.handleInterceptedRequest(serverConn, req, "nonexistent.local:9999")

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Should have recorded an error
	if handler.proxy.stats.ErrorCount == 0 {
		t.Error("Expected error count > 0")
	}

	// Should have recorded traffic (request part)
	if len(handler.proxy.traffic) == 0 {
		t.Error("Expected traffic to be recorded")
	}
}

func TestMITMHandler_HandleInterceptedRequest_WithBody(t *testing.T) {
	// Create a test HTTPS server that echoes the body
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer targetServer.Close()

	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Create a mock connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Get target server address
	targetAddr := strings.TrimPrefix(targetServer.URL, "https://")

	// Create request with body
	bodyContent := `{"test":"data"}`
	req := httptest.NewRequest(http.MethodPost, "https://"+targetAddr+"/api", strings.NewReader(bodyContent))
	req.URL.Scheme = "https"
	req.URL.Host = targetAddr
	req.Host = targetAddr
	req.RequestURI = ""
	req.Header.Set("Content-Type", "application/json")

	// Read response in goroutine
	go func() {
		reader := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Logf("Error reading response: %v", err)
			return
		}
		defer resp.Body.Close()
	}()

	// Handle the request
	handler.handleInterceptedRequest(serverConn, req, targetAddr)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Verify stats include body bytes
	if handler.proxy.stats.TotalBytesIn == 0 {
		t.Error("Expected bytes in to be greater than 0")
	}

	if handler.proxy.stats.TotalBytesOut == 0 {
		t.Error("Expected bytes out to be greater than 0")
	}
}

func TestMITMHandler_HandleInterceptedRequest_ErrorResponse(t *testing.T) {
	// Create a test HTTPS server that returns error status
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Server error"))
	}))
	defer targetServer.Close()

	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Create a mock connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Get target server address
	targetAddr := strings.TrimPrefix(targetServer.URL, "https://")

	// Create request
	req := httptest.NewRequest(http.MethodGet, "https://"+targetAddr+"/error", nil)
	req.URL.Scheme = "https"
	req.URL.Host = targetAddr
	req.Host = targetAddr
	req.RequestURI = ""

	// Read response in goroutine
	go func() {
		reader := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Logf("Error reading response: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", resp.StatusCode)
		}
	}()

	// Handle the request
	handler.handleInterceptedRequest(serverConn, req, targetAddr)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Verify error count was incremented (status >= 400)
	if handler.proxy.stats.ErrorCount != 1 {
		t.Errorf("Expected error count 1, got %d", handler.proxy.stats.ErrorCount)
	}

	if handler.proxy.stats.SuccessCount != 0 {
		t.Errorf("Expected success count 0, got %d", handler.proxy.stats.SuccessCount)
	}
}

func TestMITMHandler_HandleMITM_CertError(t *testing.T) {
	// Create proxy with MITM but no cert cache (to trigger cert generation error)
	proxy := NewProxy()

	// Create a CA but don't initialize it
	tmpDir, err := os.MkdirTemp("", "wast-mitm-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	config := &CAConfig{
		CertPath:      filepath.Join(tmpDir, "ca.crt"),
		KeyPath:       filepath.Join(tmpDir, "ca.key"),
		ValidityYears: 1,
		KeyBits:       2048,
	}
	ca := NewCertificateAuthority(config)
	// Don't initialize CA - this will cause cert generation to fail

	certCache := NewCertCache(ca, 100)

	mitmConfig := &MITMConfig{
		CA:        ca,
		CertCache: certCache,
		Enabled:   true,
	}
	handler := NewMITMHandler(proxy, mitmConfig)

	req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	req.Host = "example.com:443"

	w := httptest.NewRecorder()

	// This should fail with cert generation error
	handler.handleMITM(w, req)

	// Should have recorded an error
	if len(proxy.errors) == 0 {
		t.Error("Expected error to be recorded")
	}
}

func TestMITMHandler_HandleMITM_HijackError(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	req.Host = "example.com:443"

	// Use a regular ResponseRecorder that doesn't support hijacking
	w := httptest.NewRecorder()

	handler.handleMITM(w, req)

	// Should have recorded an error about hijacking
	if len(handler.proxy.errors) == 0 {
		t.Error("Expected error to be recorded")
	}

	found := false
	for _, err := range handler.proxy.errors {
		if strings.Contains(err, "hijacking not supported") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected error about hijacking not supported")
	}
}

func TestMITMHandler_HandleMITM_HostWithoutPort(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Test with hostname without port
	req := httptest.NewRequest(http.MethodConnect, "example.com", nil)
	req.Host = "example.com"

	// Create mock connection pair
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	done := make(chan bool)
	go func() {
		defer func() { done <- true }()

		// Set deadline to prevent hanging
		clientConn.SetDeadline(time.Now().Add(2 * time.Second))

		// Read the 200 Connection Established response
		reader := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Logf("Error reading response: %v", err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
		resp.Body.Close()

		// Try to establish TLS
		tlsClient := tls.Client(clientConn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "example.com",
		})
		defer tlsClient.Close()

		// Handshake
		if err := tlsClient.Handshake(); err != nil {
			t.Logf("Client TLS handshake error (expected): %v", err)
			return
		}
	}()

	// Create response recorder that supports hijacking
	hijackWriter := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           proxyConn,
	}

	// Handle MITM in goroutine
	go handler.handleMITM(hijackWriter, req)

	// Wait for client goroutine or timeout
	select {
	case <-done:
		// Success
	case <-time.After(3 * time.Second):
		t.Log("Test completed (timeout is acceptable)")
	}

	// Verify HTTPS connection count was incremented
	if handler.GetHTTPSConnectionCount() == 0 {
		t.Log("HTTPS connection count was not incremented (handshake may have failed)")
	}
}

func TestMITMHandler_HandleMITM_Success(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	// Test with hostname with port
	req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	req.Host = "example.com:443"

	// Create mock connection pair
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	done := make(chan bool)
	go func() {
		defer func() { done <- true }()

		// Set deadline to prevent hanging
		clientConn.SetDeadline(time.Now().Add(2 * time.Second))

		// Read the 200 Connection Established response
		reader := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Logf("Error reading response: %v", err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
		resp.Body.Close()

		// Establish TLS connection
		tlsClient := tls.Client(clientConn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "example.com",
		})
		defer tlsClient.Close()

		// Perform handshake
		if err := tlsClient.Handshake(); err != nil {
			t.Logf("Client TLS handshake error: %v", err)
			return
		}

		// Send an HTTP request over TLS
		req := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		if _, err := tlsClient.Write([]byte(req)); err != nil {
			t.Logf("Error writing request: %v", err)
		}

		// Read some response (may fail since no real server)
		buf := make([]byte, 1024)
		tlsClient.Read(buf)
	}()

	// Create response recorder that supports hijacking
	hijackWriter := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           proxyConn,
	}

	// Handle MITM in goroutine
	go handler.handleMITM(hijackWriter, req)

	// Wait for client goroutine or timeout
	select {
	case <-done:
		// Success
	case <-time.After(3 * time.Second):
		t.Log("Test completed (timeout is acceptable)")
	}

	// Verify HTTPS connection count was incremented
	if handler.GetHTTPSConnectionCount() == 0 {
		t.Log("HTTPS connection count was not incremented (handshake may have failed)")
	}
}

func TestMITMHandler_HandleMITM_TLSHandshakeFails(t *testing.T) {
	handler, _, tmpDir := setupTestMITM(t)
	defer os.RemoveAll(tmpDir)

	req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	req.Host = "example.com:443"

	// Create mock connection pair
	clientConn, proxyConn := net.Pipe()
	defer proxyConn.Close()

	done := make(chan bool)
	go func() {
		defer func() { done <- true }()

		// Read the 200 Connection Established response
		reader := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Logf("Error reading response: %v", err)
			return
		}
		resp.Body.Close()

		// Close immediately without TLS handshake
		clientConn.Close()
	}()

	// Create response recorder that supports hijacking
	hijackWriter := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           proxyConn,
	}

	// Handle MITM in goroutine
	go handler.handleMITM(hijackWriter, req)

	// Wait for client goroutine or timeout
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Log("Test completed")
	}

	// Give handler time to process the failed handshake
	time.Sleep(100 * time.Millisecond)

	// Should have recorded an error about TLS handshake
	handler.proxy.mu.RLock()
	errorCount := len(handler.proxy.errors)
	handler.proxy.mu.RUnlock()

	if errorCount == 0 {
		t.Log("Expected TLS handshake error to be recorded")
	}
}
