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
