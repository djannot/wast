// Package proxy provides HTTP traffic interception functionality for security testing.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Listener defines the interface for network listeners, allowing for mock implementations in tests.
type Listener interface {
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

// Transport defines the interface for HTTP transport, allowing for mock implementations in tests.
type Transport interface {
	RoundTrip(req *http.Request) (*http.Response, error)
}

// DefaultTransport wraps the standard http.Transport.
type DefaultTransport struct {
	transport *http.Transport
}

// NewDefaultTransport creates a new DefaultTransport.
func NewDefaultTransport() *DefaultTransport {
	return &DefaultTransport{
		transport: &http.Transport{
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
			DisableKeepAlives:  false,
			DisableCompression: false,
		},
	}
}

// RoundTrip performs an HTTP request.
func (t *DefaultTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(req)
}

// Proxy represents an HTTP interception proxy.
type Proxy struct {
	port      int
	saveFile  string
	transport Transport
	listener  Listener
	server    *http.Server

	// HTTPS interception
	ca           *CertificateAuthority
	certCache    *CertCache
	mitmHandler  *MITMHandler
	httpsEnabled bool

	mu       sync.RWMutex
	traffic  []*RequestResponsePair
	stats    ProxyStats
	errors   []string
	reqCount uint64
	started  time.Time
	running  bool
}

// Option is a function that configures a Proxy.
type Option func(*Proxy)

// WithPort sets the listening port for the proxy.
func WithPort(port int) Option {
	return func(p *Proxy) {
		p.port = port
	}
}

// WithSaveFile sets the file path to save intercepted traffic.
func WithSaveFile(path string) Option {
	return func(p *Proxy) {
		p.saveFile = path
	}
}

// WithTransport sets a custom transport for the proxy (useful for testing).
func WithTransport(t Transport) Option {
	return func(p *Proxy) {
		p.transport = t
	}
}

// WithListener sets a custom listener for the proxy (useful for testing).
func WithListener(l Listener) Option {
	return func(p *Proxy) {
		p.listener = l
	}
}

// WithCA sets the certificate authority for HTTPS interception.
func WithCA(ca *CertificateAuthority) Option {
	return func(p *Proxy) {
		p.ca = ca
		p.httpsEnabled = true
	}
}

// WithHTTPSEnabled enables or disables HTTPS interception.
func WithHTTPSEnabled(enabled bool) Option {
	return func(p *Proxy) {
		p.httpsEnabled = enabled
	}
}

// NewProxy creates a new Proxy with the given options.
func NewProxy(opts ...Option) *Proxy {
	p := &Proxy{
		port:    8080,
		traffic: make([]*RequestResponsePair, 0),
		errors:  make([]string, 0),
	}

	for _, opt := range opts {
		opt(p)
	}

	// Create default transport if not set
	if p.transport == nil {
		p.transport = NewDefaultTransport()
	}

	// Initialize HTTPS interception components if CA is set
	if p.ca != nil && p.httpsEnabled {
		p.certCache = NewCertCache(p.ca, DefaultCacheSize)
		p.mitmHandler = NewMITMHandler(p, &MITMConfig{
			CA:        p.ca,
			CertCache: p.certCache,
			Enabled:   true,
		})
	}

	return p
}

// Start starts the proxy server and blocks until the context is cancelled.
func (p *Proxy) Start(ctx context.Context) (*ProxyResult, error) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil, fmt.Errorf("proxy is already running")
	}
	p.running = true
	p.started = time.Now()
	p.mu.Unlock()

	// Create listener if not provided (for testing)
	if p.listener == nil {
		addr := fmt.Sprintf(":%d", p.port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
		p.listener = ln
	}

	// Create HTTP server
	p.server = &http.Server{
		Handler: http.HandlerFunc(p.handleRequest),
	}

	// Start serving in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		err := p.server.Serve(p.listener)
		if err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		// Graceful shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p.server.Shutdown(shutdownCtx)
	case err := <-serverErr:
		if err != nil {
			p.addError(fmt.Sprintf("Server error: %v", err))
		}
	}

	return p.buildResult(), nil
}

// handleRequest handles incoming HTTP requests and proxies them.
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Handle CONNECT method for HTTPS tunneling
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	startTime := time.Now()

	// Generate unique request ID
	reqID := fmt.Sprintf("req_%d", atomic.AddUint64(&p.reqCount, 1))

	// Capture the request
	interceptedReq := p.captureRequest(r, reqID)

	// Record the request
	p.mu.Lock()
	pair := &RequestResponsePair{Request: interceptedReq}
	p.traffic = append(p.traffic, pair)
	p.stats.TotalRequests++
	if len(interceptedReq.Body) > 0 {
		p.stats.TotalBytesIn += len(interceptedReq.Body)
	}
	pairIndex := len(p.traffic) - 1
	p.mu.Unlock()

	// Create the outgoing request
	outReq, err := http.NewRequest(r.Method, r.URL.String(), bytes.NewReader([]byte(interceptedReq.Body)))
	if err != nil {
		p.handleError(w, reqID, fmt.Sprintf("Failed to create request: %v", err))
		return
	}

	// Copy headers (excluding hop-by-hop headers)
	copyHeaders(outReq.Header, r.Header)

	// Ensure Host is set correctly
	outReq.Host = r.Host

	// Forward the request
	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		p.handleError(w, reqID, fmt.Sprintf("Failed to forward request: %v", err))
		return
	}
	defer resp.Body.Close()

	// Capture the response
	interceptedResp := p.captureResponse(resp, reqID, startTime)

	// Update the pair with the response
	p.mu.Lock()
	p.traffic[pairIndex].Response = interceptedResp
	p.stats.TotalResponses++
	p.stats.TotalBytesOut += len(interceptedResp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		p.stats.SuccessCount++
	} else {
		p.stats.ErrorCount++
	}
	p.mu.Unlock()

	// Copy response headers to client
	copyHeaders(w.Header(), resp.Header)

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Write response body
	w.Write([]byte(interceptedResp.Body))
}

// captureRequest captures the details of an incoming HTTP request.
func (p *Proxy) captureRequest(r *http.Request, reqID string) *InterceptedRequest {
	// Read body
	var bodyStr string
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			bodyStr = string(body)
			// Reset the body for forwarding
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

// captureResponse captures the details of an HTTP response.
func (p *Proxy) captureResponse(resp *http.Response, reqID string, startTime time.Time) *InterceptedResponse {
	// Read body
	var bodyStr string
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			bodyStr = string(body)
			// Reset the body for returning to client
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

// handleConnect handles CONNECT requests for HTTPS proxying.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if p.mitmHandler != nil && p.httpsEnabled {
		// Use MITM handler for HTTPS interception
		p.mitmHandler.HandleConnect(w, r)
	} else {
		// Create a plain tunnel without interception
		p.handleTunnel(w, r)
	}
}

// handleTunnel creates a transparent tunnel for CONNECT requests without interception.
func (p *Proxy) handleTunnel(w http.ResponseWriter, r *http.Request) {
	// Connect to target server
	targetConn, err := net.DialTimeout("tcp", r.Host, 30*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to target: %v", err), http.StatusBadGateway)
		p.addError(fmt.Sprintf("CONNECT tunnel failed to %s: %v", r.Host, err))
		return
	}
	defer targetConn.Close()

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		p.addError("CONNECT failed: hijacking not supported")
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to hijack connection: %v", err), http.StatusInternalServerError)
		p.addError(fmt.Sprintf("CONNECT hijack failed: %v", err))
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

// handleError handles proxy errors and sends an error response to the client.
func (p *Proxy) handleError(w http.ResponseWriter, reqID string, errMsg string) {
	p.addError(fmt.Sprintf("[%s] %s", reqID, errMsg))

	p.mu.Lock()
	p.stats.ErrorCount++
	p.mu.Unlock()

	http.Error(w, errMsg, http.StatusBadGateway)
}

// addError adds an error message to the error list.
func (p *Proxy) addError(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.errors = append(p.errors, msg)
}

// buildResult builds the final proxy result.
func (p *Proxy) buildResult() *ProxyResult {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Update HTTPS connection count
	if p.mitmHandler != nil {
		p.stats.HTTPSConnections = int(p.mitmHandler.GetHTTPSConnectionCount())
	}

	result := &ProxyResult{
		Port:         p.port,
		StartTime:    p.started,
		EndTime:      time.Now(),
		Traffic:      p.traffic,
		Statistics:   p.stats,
		Errors:       p.errors,
		HTTPSEnabled: p.httpsEnabled,
	}

	// Include CA certificate path if HTTPS is enabled
	if p.ca != nil && p.httpsEnabled {
		result.CACertPath = p.ca.GetCertPath()
	}

	// Save to file if specified
	if p.saveFile != "" {
		if err := p.saveTrafficToFile(result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to save traffic: %v", err))
		} else {
			result.SavedToFile = p.saveFile
		}
	}

	return result
}

// saveTrafficToFile saves the intercepted traffic to a JSON file.
func (p *Proxy) saveTrafficToFile(result *ProxyResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal traffic: %w", err)
	}

	if err := os.WriteFile(p.saveFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// GetTraffic returns a copy of the intercepted traffic.
func (p *Proxy) GetTraffic() []*RequestResponsePair {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make([]*RequestResponsePair, len(p.traffic))
	copy(result, p.traffic)
	return result
}

// GetStats returns the current statistics.
func (p *Proxy) GetStats() ProxyStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stats
}

// copyHeaders copies headers from src to dst, excluding hop-by-hop headers.
func copyHeaders(dst, src http.Header) {
	// Hop-by-hop headers that should not be forwarded
	hopHeaders := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}

	for key, values := range src {
		if hopHeaders[key] {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
