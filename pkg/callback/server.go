// Package callback provides out-of-band callback server functionality
// for verifying SSRF and other vulnerabilities through HTTP and DNS callbacks.
package callback

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CallbackType represents the type of callback received.
type CallbackType string

const (
	// CallbackTypeHTTP indicates an HTTP callback was received.
	CallbackTypeHTTP CallbackType = "http"
	// CallbackTypeDNS indicates a DNS callback was received.
	CallbackTypeDNS CallbackType = "dns"
)

// CallbackEvent represents a received callback event.
type CallbackEvent struct {
	ID        string       `json:"id"`
	Type      CallbackType `json:"type"`
	Timestamp time.Time    `json:"timestamp"`
	SourceIP  string       `json:"source_ip"`
	Method    string       `json:"method,omitempty"`  // HTTP method
	Path      string       `json:"path,omitempty"`    // HTTP path
	Headers   http.Header  `json:"headers,omitempty"` // HTTP headers
	Query     string       `json:"query,omitempty"`   // DNS query
	UserAgent string       `json:"user_agent,omitempty"`
}

// PendingCallback represents a callback we're expecting.
type PendingCallback struct {
	ID          string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ScanContext interface{} // Additional context about the scan
	Notifier    chan<- CallbackEvent
}

// Server is the callback server that listens for HTTP and DNS callbacks.
type Server struct {
	httpAddr  string
	dnsAddr   string
	dnsDomain string
	baseURL   string

	mu              sync.RWMutex
	pending         map[string]*PendingCallback
	received        map[string][]CallbackEvent
	httpServer      *http.Server
	dnsServer       *dnsServer
	defaultTTL      time.Duration
	cleanupInterval time.Duration
	cleanupTicker   *time.Ticker
	cleanupDone     chan struct{}
}

// Config holds configuration for the callback server.
type Config struct {
	HTTPAddr        string        // Address to listen on for HTTP (e.g., ":8888")
	DNSAddr         string        // Address to listen on for DNS (e.g., ":53")
	DNSDomain       string        // Base domain for DNS callbacks (e.g., "cb.example.com")
	BaseURL         string        // Base URL for HTTP callbacks (e.g., "http://cb.example.com:8888")
	DefaultTTL      time.Duration // Default TTL for pending callbacks
	CleanupInterval time.Duration // How often to clean up expired callbacks
}

// NewServer creates a new callback server with the given configuration.
func NewServer(cfg Config) *Server {
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 1 * time.Minute
	}

	s := &Server{
		httpAddr:        cfg.HTTPAddr,
		dnsAddr:         cfg.DNSAddr,
		dnsDomain:       cfg.DNSDomain,
		baseURL:         cfg.BaseURL,
		pending:         make(map[string]*PendingCallback),
		received:        make(map[string][]CallbackEvent),
		defaultTTL:      cfg.DefaultTTL,
		cleanupInterval: cfg.CleanupInterval,
		cleanupDone:     make(chan struct{}),
	}

	return s
}

// Start starts the callback server.
func (s *Server) Start(ctx context.Context) error {
	// Start cleanup goroutine
	s.cleanupTicker = time.NewTicker(s.cleanupInterval)
	go s.cleanupLoop(ctx)

	// Start HTTP server if configured
	if s.httpAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleHTTPCallback)

		s.httpServer = &http.Server{
			Addr:    s.httpAddr,
			Handler: mux,
		}

		go func() {
			log.Printf("[callback] HTTP server listening on %s", s.httpAddr)
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[callback] HTTP server error: %v", err)
			}
		}()
	}

	// Start DNS server if configured
	if s.dnsAddr != "" && s.dnsDomain != "" {
		var err error
		s.dnsServer, err = newDNSServer(s.dnsAddr, s.dnsDomain, s)
		if err != nil {
			return fmt.Errorf("failed to create DNS server: %w", err)
		}

		go func() {
			log.Printf("[callback] DNS server listening on %s for domain %s", s.dnsAddr, s.dnsDomain)
			if err := s.dnsServer.Start(); err != nil {
				log.Printf("[callback] DNS server error: %v", err)
			}
		}()
	}

	return nil
}

// Stop stops the callback server.
func (s *Server) Stop(ctx context.Context) error {
	var errs []error

	// Stop HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("HTTP server shutdown error: %w", err))
		}
	}

	// Stop DNS server
	if s.dnsServer != nil {
		if err := s.dnsServer.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("DNS server shutdown error: %w", err))
		}
	}

	// Stop cleanup goroutine
	if s.cleanupTicker != nil {
		s.cleanupTicker.Stop()
	}
	close(s.cleanupDone)

	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}
	return nil
}

// GenerateCallbackID generates a unique callback ID.
func (s *Server) GenerateCallbackID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// RegisterCallback registers a pending callback with optional custom TTL.
func (s *Server) RegisterCallback(id string, ttl time.Duration, context interface{}, notifier chan<- CallbackEvent) {
	if ttl == 0 {
		ttl = s.defaultTTL
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.pending[id] = &PendingCallback{
		ID:          id,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		ScanContext: context,
		Notifier:    notifier,
	}
}

// UnregisterCallback removes a pending callback.
func (s *Server) UnregisterCallback(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, id)
}

// CheckCallback checks if a callback with the given ID has been received.
// Returns the callback events and true if received, nil and false otherwise.
func (s *Server) CheckCallback(id string) ([]CallbackEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	events, ok := s.received[id]
	return events, ok
}

// WaitForCallback waits for a callback with the given ID, up to the timeout.
// Returns the callback event and true if received, zero value and false if timeout.
func (s *Server) WaitForCallback(ctx context.Context, id string, timeout time.Duration) (CallbackEvent, bool) {
	// Create a channel for this specific callback
	notifier := make(chan CallbackEvent, 1)
	s.RegisterCallback(id, timeout, nil, notifier)
	defer s.UnregisterCallback(id)

	// Check if already received
	if events, ok := s.CheckCallback(id); ok && len(events) > 0 {
		return events[0], true
	}

	// Wait for callback or timeout
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case event := <-notifier:
		return event, true
	case <-timer.C:
		return CallbackEvent{}, false
	case <-ctx.Done():
		return CallbackEvent{}, false
	}
}

// GetHTTPCallbackURL returns the HTTP callback URL for the given ID.
func (s *Server) GetHTTPCallbackURL(id string) string {
	if s.baseURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/wast/%s", s.baseURL, id)
}

// GetDNSCallbackDomain returns the DNS callback domain for the given ID.
func (s *Server) GetDNSCallbackDomain(id string) string {
	if s.dnsDomain == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s", id, s.dnsDomain)
}

// handleHTTPCallback handles incoming HTTP callbacks.
func (s *Server) handleHTTPCallback(w http.ResponseWriter, r *http.Request) {
	// Extract callback ID from path
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.Split(path, "/")

	var callbackID string
	if len(parts) >= 2 && parts[0] == "wast" {
		callbackID = parts[1]
	}

	// Get source IP
	sourceIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		sourceIP = strings.Split(forwarded, ",")[0]
	}

	event := CallbackEvent{
		ID:        callbackID,
		Type:      CallbackTypeHTTP,
		Timestamp: time.Now(),
		SourceIP:  sourceIP,
		Method:    r.Method,
		Path:      r.URL.Path,
		Headers:   r.Header,
		UserAgent: r.Header.Get("User-Agent"),
	}

	log.Printf("[callback] HTTP callback received: ID=%s, IP=%s, Method=%s, Path=%s",
		callbackID, sourceIP, r.Method, r.URL.Path)

	s.recordCallback(callbackID, event)

	// Return a simple response
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// handleDNSCallback handles incoming DNS callbacks.
func (s *Server) handleDNSCallback(query string, sourceIP string) {
	// Extract callback ID from subdomain
	// Format: <callback-id>.cb.example.com
	query = strings.TrimSuffix(query, ".")
	if !strings.HasSuffix(query, s.dnsDomain) {
		return
	}

	subdomain := strings.TrimSuffix(query, "."+s.dnsDomain)
	parts := strings.Split(subdomain, ".")

	var callbackID string
	if len(parts) > 0 {
		callbackID = parts[len(parts)-1] // Last part is the callback ID
	}

	event := CallbackEvent{
		ID:        callbackID,
		Type:      CallbackTypeDNS,
		Timestamp: time.Now(),
		SourceIP:  sourceIP,
		Query:     query,
	}

	log.Printf("[callback] DNS callback received: ID=%s, IP=%s, Query=%s",
		callbackID, sourceIP, query)

	s.recordCallback(callbackID, event)
}

// recordCallback records a callback event and notifies waiting goroutines.
func (s *Server) recordCallback(id string, event CallbackEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store the event
	s.received[id] = append(s.received[id], event)

	// Notify if someone is waiting
	if pending, ok := s.pending[id]; ok && pending.Notifier != nil {
		select {
		case pending.Notifier <- event:
		default:
			// Channel full or closed, skip
		}
	}
}

// cleanupLoop periodically removes expired callbacks.
func (s *Server) cleanupLoop(ctx context.Context) {
	for {
		select {
		case <-s.cleanupTicker.C:
			s.cleanup()
		case <-ctx.Done():
			return
		case <-s.cleanupDone:
			return
		}
	}
}

// cleanup removes expired callbacks.
func (s *Server) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Clean up expired pending callbacks
	for id, pending := range s.pending {
		if now.After(pending.ExpiresAt) {
			delete(s.pending, id)
		}
	}

	// Clean up old received callbacks (keep for 10 minutes after expiry)
	maxAge := now.Add(-10 * time.Minute)
	for id, events := range s.received {
		if len(events) > 0 && events[0].Timestamp.Before(maxAge) {
			delete(s.received, id)
		}
	}
}

// dnsServer is a simple DNS server for handling callback queries.
type dnsServer struct {
	addr     string
	domain   string
	callback *Server
	conn     *net.UDPConn
}

// newDNSServer creates a new DNS server.
func newDNSServer(addr, domain string, callback *Server) (*dnsServer, error) {
	return &dnsServer{
		addr:     addr,
		domain:   domain,
		callback: callback,
	}, nil
}

// Start starts the DNS server.
func (s *dnsServer) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	s.conn = conn

	buf := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Connection closed
			return nil
		}

		go s.handleQuery(buf[:n], addr)
	}
}

// Stop stops the DNS server.
func (s *dnsServer) Stop() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// handleQuery handles a DNS query (simplified implementation).
func (s *dnsServer) handleQuery(data []byte, addr *net.UDPAddr) {
	// This is a very simplified DNS implementation
	// For production, consider using a proper DNS library like miekg/dns

	// Extract query name from DNS packet (very basic parsing)
	if len(data) < 12 {
		return
	}

	// Parse the query name (skip DNS header)
	query := parseDNSQuery(data[12:])
	if query != "" {
		s.callback.handleDNSCallback(query, addr.IP.String())
	}

	// Send a minimal DNS response
	s.sendDNSResponse(data, addr)
}

// parseDNSQuery extracts the query name from DNS packet.
func parseDNSQuery(data []byte) string {
	var parts []string
	i := 0
	for i < len(data) {
		length := int(data[i])
		if length == 0 {
			break
		}
		i++
		if i+length > len(data) {
			break
		}
		parts = append(parts, string(data[i:i+length]))
		i += length
	}
	return strings.Join(parts, ".")
}

// sendDNSResponse sends a minimal DNS response.
func (s *dnsServer) sendDNSResponse(query []byte, addr *net.UDPAddr) {
	if len(query) < 12 {
		return
	}

	// Create a minimal DNS response with NXDOMAIN
	response := make([]byte, len(query))
	copy(response, query)

	// Set QR bit (response) and RCODE to NXDOMAIN
	response[2] = 0x81 // QR=1, OPCODE=0, AA=0, TC=0, RD=1
	response[3] = 0x83 // RA=1, Z=0, RCODE=3 (NXDOMAIN)

	s.conn.WriteToUDP(response, addr)
}
