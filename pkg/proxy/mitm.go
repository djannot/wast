// Package proxy provides HTTP traffic interception functionality for security testing.
package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// MITMConfig holds the configuration for MITM proxy.
type MITMConfig struct {
	// CA is the certificate authority for generating certificates.
	CA *CertificateAuthority
	// CertCache is the certificate cache.
	CertCache *CertCache
	// Enabled indicates if HTTPS interception is enabled.
	Enabled bool
}

// MITMHandler handles HTTPS CONNECT requests with man-in-the-middle interception.
type MITMHandler struct {
	config     *MITMConfig
	proxy      *Proxy
	mu         sync.RWMutex
	httpsConns int64
}

// NewMITMHandler creates a new MITM handler.
func NewMITMHandler(proxy *Proxy, config *MITMConfig) *MITMHandler {
	return &MITMHandler{
		config: config,
		proxy:  proxy,
	}
}

// HandleConnect handles HTTPS CONNECT requests.
func (m *MITMHandler) HandleConnect(w http.ResponseWriter, r *http.Request) {
	if !m.config.Enabled || m.config.CA == nil {
		// HTTPS interception not enabled, tunnel the connection
		m.handleTunnel(w, r)
		return
	}

	// Perform MITM interception
	m.handleMITM(w, r)
}

// handleTunnel creates a transparent tunnel without interception.
func (m *MITMHandler) handleTunnel(w http.ResponseWriter, r *http.Request) {
	// Connect to target server
	targetConn, err := net.DialTimeout("tcp", r.Host, 30*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to target: %v", err), http.StatusBadGateway)
		m.proxy.addError(fmt.Sprintf("CONNECT tunnel failed to %s: %v", r.Host, err))
		return
	}
	defer targetConn.Close()

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		m.proxy.addError("CONNECT failed: hijacking not supported")
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to hijack connection: %v", err), http.StatusInternalServerError)
		m.proxy.addError(fmt.Sprintf("CONNECT hijack failed: %v", err))
		return
	}
	defer clientConn.Close()

	// Send 200 Connection Established to client
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Create bidirectional tunnel
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
	}()

	wg.Wait()
}

// handleMITM performs MITM interception on HTTPS connections.
func (m *MITMHandler) handleMITM(w http.ResponseWriter, r *http.Request) {
	// Extract hostname from the CONNECT request
	hostname, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		// Host might not have a port, use as-is
		hostname = r.Host
	}

	// Get or generate certificate for this hostname
	cert, err := m.config.CertCache.GetOrGenerate(hostname)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate certificate: %v", err), http.StatusInternalServerError)
		m.proxy.addError(fmt.Sprintf("Certificate generation failed for %s: %v", hostname, err))
		return
	}

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		m.proxy.addError("MITM failed: hijacking not supported")
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to hijack connection: %v", err), http.StatusInternalServerError)
		m.proxy.addError(fmt.Sprintf("MITM hijack failed: %v", err))
		return
	}
	defer clientConn.Close()

	// Send 200 Connection Established to client
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Wrap client connection with TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		m.proxy.addError(fmt.Sprintf("TLS handshake failed for %s: %v", hostname, err))
		return
	}

	atomic.AddInt64(&m.httpsConns, 1)

	// Handle HTTP requests over the TLS connection
	m.handleHTTPSRequests(tlsConn, r.Host)
}

// handleHTTPSRequests handles HTTP requests over an established TLS connection.
func (m *MITMHandler) handleHTTPSRequests(conn *tls.Conn, targetHost string) {
	reader := bufio.NewReader(conn)

	for {
		// Set read deadline to detect connection close
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		// Read HTTP request from client
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				m.proxy.addError(fmt.Sprintf("Failed to read HTTPS request: %v", err))
			}
			return
		}

		// Build the full URL
		req.URL.Scheme = "https"
		req.URL.Host = targetHost
		req.RequestURI = ""

		// Handle the request
		m.handleInterceptedRequest(conn, req, targetHost)
	}
}

// handleInterceptedRequest handles a single intercepted HTTPS request.
func (m *MITMHandler) handleInterceptedRequest(conn net.Conn, req *http.Request, targetHost string) {
	startTime := time.Now()

	// Generate unique request ID
	reqID := fmt.Sprintf("req_%d", atomic.AddUint64(&m.proxy.reqCount, 1))

	// Capture the request
	interceptedReq := m.captureRequest(req, reqID)

	// Record the request
	m.proxy.mu.Lock()
	pair := &RequestResponsePair{Request: interceptedReq}
	m.proxy.traffic = append(m.proxy.traffic, pair)
	m.proxy.stats.TotalRequests++
	if len(interceptedReq.Body) > 0 {
		m.proxy.stats.TotalBytesIn += len(interceptedReq.Body)
	}
	pairIndex := len(m.proxy.traffic) - 1
	m.proxy.mu.Unlock()

	// Create TLS transport for connecting to the actual server
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // We're doing MITM, so we need to accept all certs
		},
		DisableKeepAlives: true,
	}

	// Create the outgoing request
	outReq, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader([]byte(interceptedReq.Body)))
	if err != nil {
		m.sendErrorResponse(conn, reqID, fmt.Sprintf("Failed to create request: %v", err))
		return
	}

	// Copy headers
	for key, values := range req.Header {
		for _, value := range values {
			outReq.Header.Add(key, value)
		}
	}
	outReq.Host = req.Host

	// Forward the request
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		m.sendErrorResponse(conn, reqID, fmt.Sprintf("Failed to forward request: %v", err))
		return
	}
	defer resp.Body.Close()

	// Capture the response
	interceptedResp := m.captureResponse(resp, reqID, startTime)

	// Update the pair with the response
	m.proxy.mu.Lock()
	m.proxy.traffic[pairIndex].Response = interceptedResp
	m.proxy.stats.TotalResponses++
	m.proxy.stats.TotalBytesOut += len(interceptedResp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		m.proxy.stats.SuccessCount++
	} else {
		m.proxy.stats.ErrorCount++
	}
	m.proxy.mu.Unlock()

	// Send response back to client
	m.sendResponse(conn, resp, interceptedResp.Body)
}

// captureRequest captures the details of an HTTPS request.
func (m *MITMHandler) captureRequest(r *http.Request, reqID string) *InterceptedRequest {
	var bodyStr string
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			bodyStr = string(body)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	return &InterceptedRequest{
		ID:        reqID,
		Method:    r.Method,
		URL:       r.URL.String(),
		Host:      r.Host,
		Path:      r.URL.Path,
		Headers:   headersToMap(r.Header),
		Body:      bodyStr,
		Timestamp: time.Now(),
	}
}

// captureResponse captures the details of an HTTPS response.
func (m *MITMHandler) captureResponse(resp *http.Response, reqID string, startTime time.Time) *InterceptedResponse {
	var bodyStr string
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			bodyStr = string(body)
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	return &InterceptedResponse{
		RequestID:  reqID,
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    headersToMap(resp.Header),
		Body:       bodyStr,
		Timestamp:  time.Now(),
		Duration:   time.Since(startTime),
	}
}

// sendResponse sends an HTTP response to the client over the TLS connection.
func (m *MITMHandler) sendResponse(conn net.Conn, resp *http.Response, body string) {
	// Write status line
	fmt.Fprintf(conn, "HTTP/1.1 %s\r\n", resp.Status)

	// Write headers
	for key, values := range resp.Header {
		for _, value := range values {
			fmt.Fprintf(conn, "%s: %s\r\n", key, value)
		}
	}

	// Write Content-Length if not present
	if resp.Header.Get("Content-Length") == "" {
		fmt.Fprintf(conn, "Content-Length: %d\r\n", len(body))
	}

	// End headers
	fmt.Fprintf(conn, "\r\n")

	// Write body
	conn.Write([]byte(body))
}

// sendErrorResponse sends an error response to the client.
func (m *MITMHandler) sendErrorResponse(conn net.Conn, reqID string, errMsg string) {
	m.proxy.addError(fmt.Sprintf("[%s] %s", reqID, errMsg))

	m.proxy.mu.Lock()
	m.proxy.stats.ErrorCount++
	m.proxy.mu.Unlock()

	resp := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(errMsg), errMsg)
	conn.Write([]byte(resp))
}

// GetHTTPSConnectionCount returns the number of HTTPS connections handled.
func (m *MITMHandler) GetHTTPSConnectionCount() int64 {
	return atomic.LoadInt64(&m.httpsConns)
}
