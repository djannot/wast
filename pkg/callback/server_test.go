package callback

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	cfg := Config{
		HTTPAddr:   ":8888",
		DNSDomain:  "cb.example.com",
		BaseURL:    "http://cb.example.com:8888",
		DefaultTTL: 5 * time.Minute,
	}

	server := NewServer(cfg)
	if server == nil {
		t.Fatal("expected server to be created")
	}

	if server.httpAddr != ":8888" {
		t.Errorf("expected httpAddr to be :8888, got %s", server.httpAddr)
	}

	if server.dnsDomain != "cb.example.com" {
		t.Errorf("expected dnsDomain to be cb.example.com, got %s", server.dnsDomain)
	}

	if server.baseURL != "http://cb.example.com:8888" {
		t.Errorf("expected baseURL to be http://cb.example.com:8888, got %s", server.baseURL)
	}

	if server.defaultTTL != 5*time.Minute {
		t.Errorf("expected defaultTTL to be 5m, got %v", server.defaultTTL)
	}
}

func TestGenerateCallbackID(t *testing.T) {
	server := NewServer(Config{})

	id1 := server.GenerateCallbackID()
	id2 := server.GenerateCallbackID()

	if id1 == "" {
		t.Error("expected non-empty callback ID")
	}

	if id1 == id2 {
		t.Error("expected unique callback IDs")
	}

	if len(id1) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("expected callback ID length of 32, got %d", len(id1))
	}
}

func TestRegisterUnregisterCallback(t *testing.T) {
	server := NewServer(Config{DefaultTTL: 5 * time.Minute})

	id := "test-callback-id"
	notifier := make(chan CallbackEvent, 1)

	// Register callback
	server.RegisterCallback(id, 0, nil, notifier)

	server.mu.RLock()
	pending, ok := server.pending[id]
	server.mu.RUnlock()

	if !ok {
		t.Fatal("expected callback to be registered")
	}

	if pending.ID != id {
		t.Errorf("expected pending ID to be %s, got %s", id, pending.ID)
	}

	// Unregister callback
	server.UnregisterCallback(id)

	server.mu.RLock()
	_, ok = server.pending[id]
	server.mu.RUnlock()

	if ok {
		t.Error("expected callback to be unregistered")
	}
}

func TestCheckCallback(t *testing.T) {
	server := NewServer(Config{})

	id := "test-callback-id"

	// Should not find callback initially
	events, ok := server.CheckCallback(id)
	if ok {
		t.Error("expected callback to not be found")
	}
	if len(events) != 0 {
		t.Error("expected no events")
	}

	// Record a callback event
	event := CallbackEvent{
		ID:        id,
		Type:      CallbackTypeHTTP,
		Timestamp: time.Now(),
		SourceIP:  "127.0.0.1",
		Method:    "GET",
		Path:      "/wast/" + id,
	}
	server.recordCallback(id, event)

	// Should find callback now
	events, ok = server.CheckCallback(id)
	if !ok {
		t.Error("expected callback to be found")
	}
	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}
	if events[0].ID != id {
		t.Errorf("expected event ID to be %s, got %s", id, events[0].ID)
	}
}

func TestGetHTTPCallbackURL(t *testing.T) {
	server := NewServer(Config{
		BaseURL: "http://cb.example.com:8888",
	})

	id := "abc123"
	url := server.GetHTTPCallbackURL(id)

	expected := "http://cb.example.com:8888/wast/abc123"
	if url != expected {
		t.Errorf("expected URL %s, got %s", expected, url)
	}
}

func TestGetDNSCallbackDomain(t *testing.T) {
	server := NewServer(Config{
		DNSDomain: "cb.example.com",
	})

	id := "abc123"
	domain := server.GetDNSCallbackDomain(id)

	expected := "abc123.cb.example.com"
	if domain != expected {
		t.Errorf("expected domain %s, got %s", expected, domain)
	}
}

func TestHTTPCallbackHandler(t *testing.T) {
	server := NewServer(Config{
		BaseURL: "http://localhost:9999",
	})

	// Start the server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server.httpAddr = ":9999"
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop(ctx)

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Send a callback request
	id := "test-http-callback"
	url := fmt.Sprintf("http://localhost:9999/wast/%s", id)

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("failed to send callback request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Wait a bit for the callback to be recorded
	time.Sleep(100 * time.Millisecond)

	// Check if callback was recorded
	events, ok := server.CheckCallback(id)
	if !ok {
		t.Fatal("expected callback to be recorded")
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.ID != id {
		t.Errorf("expected event ID %s, got %s", id, event.ID)
	}
	if event.Type != CallbackTypeHTTP {
		t.Errorf("expected event type HTTP, got %s", event.Type)
	}
	if event.Method != "GET" {
		t.Errorf("expected method GET, got %s", event.Method)
	}
}

func TestWaitForCallback(t *testing.T) {
	server := NewServer(Config{})

	id := "test-wait-callback"
	ctx := context.Background()

	// Test timeout when no callback received
	event, ok := server.WaitForCallback(ctx, id, 100*time.Millisecond)
	if ok {
		t.Error("expected timeout, got callback")
	}
	if event.ID != "" {
		t.Error("expected empty event on timeout")
	}

	// Test successful callback
	id2 := "test-wait-callback-2"
	go func() {
		time.Sleep(50 * time.Millisecond)
		server.recordCallback(id2, CallbackEvent{
			ID:        id2,
			Type:      CallbackTypeHTTP,
			Timestamp: time.Now(),
			SourceIP:  "127.0.0.1",
		})
	}()

	event, ok = server.WaitForCallback(ctx, id2, 200*time.Millisecond)
	if !ok {
		t.Error("expected callback to be received")
	}
	if event.ID != id2 {
		t.Errorf("expected event ID %s, got %s", id2, event.ID)
	}
}

func TestCleanup(t *testing.T) {
	server := NewServer(Config{
		DefaultTTL:      100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	})

	id := "test-cleanup"
	notifier := make(chan CallbackEvent, 1)

	// Register callback with short TTL
	server.RegisterCallback(id, 100*time.Millisecond, nil, notifier)

	// Verify it exists
	server.mu.RLock()
	_, ok := server.pending[id]
	server.mu.RUnlock()
	if !ok {
		t.Fatal("expected callback to be registered")
	}

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)
	server.cleanup()

	// Verify it's cleaned up
	server.mu.RLock()
	_, ok = server.pending[id]
	server.mu.RUnlock()
	if ok {
		t.Error("expected callback to be cleaned up")
	}
}

func TestParseDNSQuery(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "simple domain",
			input:    []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			expected: "www.example.com",
		},
		{
			name:     "callback subdomain",
			input:    []byte{6, 'a', 'b', 'c', '1', '2', '3', 2, 'c', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			expected: "abc123.cb.example.com",
		},
		{
			name:     "empty",
			input:    []byte{0},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDNSQuery(tt.input)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestDNSServerLifecycle tests DNS server Start() and Stop() methods
func TestDNSServerLifecycle(t *testing.T) {
	server := NewServer(Config{
		DNSDomain: "cb.example.com",
	})

	// Create a DNS server with a random port
	dnsServer, err := newDNSServer(":0", "cb.example.com", server)
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}

	// Start the DNS server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- dnsServer.Start()
	}()

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)

	// Verify the server is running (conn should be set)
	dnsServer.mu.RLock()
	conn := dnsServer.conn
	dnsServer.mu.RUnlock()

	if conn == nil {
		t.Fatal("expected DNS server connection to be established")
	}

	// Stop the server
	if err := dnsServer.Stop(); err != nil {
		t.Errorf("failed to stop DNS server: %v", err)
	}

	// Verify Start() returns after Stop()
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("expected nil error from Start() after Stop(), got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("Start() did not return after Stop()")
	}
}

// TestDNSServerMalformedPackets tests handleQuery with various malformed packets
func TestDNSServerMalformedPackets(t *testing.T) {
	server := NewServer(Config{
		DNSDomain: "cb.example.com",
	})

	dnsServer, err := newDNSServer(":0", "cb.example.com", server)
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}

	// Start the server to initialize the connection
	go dnsServer.Start()
	time.Sleep(50 * time.Millisecond)
	defer dnsServer.Stop()

	tests := []struct {
		name   string
		packet []byte
	}{
		{
			name:   "empty packet",
			packet: []byte{},
		},
		{
			name:   "packet less than 12 bytes",
			packet: []byte{0x00, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:   "exactly 11 bytes",
			packet: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
		},
		{
			name:   "12 bytes but corrupted query section",
			packet: []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// handleQuery should not panic with malformed data
			// We can't easily test the return value, but we can verify no panic occurs
			addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
			dnsServer.handleQuery(tt.packet, addr)
			// If we reach here, no panic occurred
		})
	}
}

// TestHandleDNSCallbackNonMatchingDomain tests DNS callback validation
func TestHandleDNSCallbackNonMatchingDomain(t *testing.T) {
	server := NewServer(Config{
		DNSDomain: "cb.example.com",
	})

	tests := []struct {
		name          string
		query         string
		shouldRecord  bool
		expectedID    string
		expectedQuery string // What query should be stored (after trimming trailing dot)
	}{
		{
			name:         "non-matching domain",
			query:        "abc123.wrong.example.com",
			shouldRecord: false,
		},
		{
			name:          "matching domain without trailing dot",
			query:         "abc123.cb.example.com",
			shouldRecord:  true,
			expectedID:    "abc123",
			expectedQuery: "abc123.cb.example.com",
		},
		{
			name:          "matching domain with trailing dot",
			query:         "abc123.cb.example.com.",
			shouldRecord:  true,
			expectedID:    "abc123",
			expectedQuery: "abc123.cb.example.com", // Trailing dot is trimmed
		},
		{
			name:          "multiple subdomains",
			query:         "foo.bar.abc123.cb.example.com",
			shouldRecord:  true,
			expectedID:    "abc123",
			expectedQuery: "foo.bar.abc123.cb.example.com",
		},
		{
			name:         "completely different domain",
			query:        "google.com",
			shouldRecord: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear received callbacks
			server.mu.Lock()
			server.received = make(map[string][]CallbackEvent)
			server.mu.Unlock()

			server.handleDNSCallback(tt.query, "127.0.0.1")

			if tt.shouldRecord {
				events, ok := server.CheckCallback(tt.expectedID)
				if !ok {
					t.Errorf("expected callback to be recorded for query %s", tt.query)
				}
				if len(events) != 1 {
					t.Errorf("expected 1 event, got %d", len(events))
				}
				if len(events) > 0 {
					if events[0].Query != tt.expectedQuery {
						t.Errorf("expected query %s, got %s", tt.expectedQuery, events[0].Query)
					}
					if events[0].Type != CallbackTypeDNS {
						t.Errorf("expected DNS callback type, got %s", events[0].Type)
					}
				}
			} else {
				// No callback should be recorded
				server.mu.RLock()
				totalEvents := len(server.received)
				server.mu.RUnlock()
				if totalEvents > 0 {
					t.Errorf("expected no callbacks to be recorded for query %s, got %d", tt.query, totalEvents)
				}
			}
		})
	}
}

// TestSendDNSResponseEdgeCases tests sendDNSResponse with various edge cases
func TestSendDNSResponseEdgeCases(t *testing.T) {
	server := NewServer(Config{
		DNSDomain: "cb.example.com",
	})

	// Create a DNS server with a random port
	dnsServer, err := newDNSServer(":0", "cb.example.com", server)
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}

	// Start the server to initialize the connection
	go dnsServer.Start()
	time.Sleep(50 * time.Millisecond)
	defer dnsServer.Stop()

	tests := []struct {
		name   string
		packet []byte
	}{
		{
			name:   "empty packet",
			packet: []byte{},
		},
		{
			name:   "packet less than 12 bytes",
			packet: []byte{0x00, 0x01, 0x02},
		},
		{
			name:   "exactly 11 bytes",
			packet: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
		},
		{
			name:   "valid 12 byte packet",
			packet: []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// sendDNSResponse should not panic with any packet size
			addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
			dnsServer.sendDNSResponse(tt.packet, addr)
			// If we reach here, no panic occurred
		})
	}
}

// TestConcurrentCallbackRegistration stress tests concurrent callback operations
func TestConcurrentCallbackRegistration(t *testing.T) {
	server := NewServer(Config{
		DefaultTTL: 5 * time.Minute,
	})

	const numGoroutines = 100
	const numOperations = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Stress test with concurrent registrations and unregistrations
	for i := 0; i < numGoroutines; i++ {
		go func(routineID int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				id := fmt.Sprintf("callback-%d-%d", routineID, j)
				notifier := make(chan CallbackEvent, 1)

				// Register
				server.RegisterCallback(id, 0, nil, notifier)

				// Check registration
				server.mu.RLock()
				_, exists := server.pending[id]
				server.mu.RUnlock()

				if !exists {
					t.Errorf("callback %s should exist after registration", id)
				}

				// Unregister
				server.UnregisterCallback(id)

				// Check unregistration
				server.mu.RLock()
				_, exists = server.pending[id]
				server.mu.RUnlock()

				if exists {
					t.Errorf("callback %s should not exist after unregistration", id)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify all callbacks are cleaned up
	server.mu.RLock()
	pendingCount := len(server.pending)
	server.mu.RUnlock()

	if pendingCount != 0 {
		t.Errorf("expected 0 pending callbacks after concurrent test, got %d", pendingCount)
	}
}

// TestCleanupLoopContextCancellation tests cleanup loop with context cancellation
func TestCleanupLoopContextCancellation(t *testing.T) {
	server := NewServer(Config{
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Start cleanup loop
	server.cleanupTicker = time.NewTicker(server.cleanupInterval)
	done := make(chan struct{})
	go func() {
		server.cleanupLoop(ctx)
		close(done)
	}()

	// Let it run for a bit
	time.Sleep(150 * time.Millisecond)

	// Cancel context
	cancel()

	// Verify cleanup loop exits
	select {
	case <-done:
		// Success - cleanup loop exited
	case <-time.After(500 * time.Millisecond):
		t.Error("cleanup loop did not exit after context cancellation")
	}
}

// TestCleanupLoopCleanupDone tests cleanup loop with cleanupDone channel
func TestCleanupLoopCleanupDone(t *testing.T) {
	server := NewServer(Config{
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: 100 * time.Millisecond,
	})

	ctx := context.Background()

	// Start cleanup loop
	server.cleanupTicker = time.NewTicker(server.cleanupInterval)
	done := make(chan struct{})
	go func() {
		server.cleanupLoop(ctx)
		close(done)
	}()

	// Let it run for a bit
	time.Sleep(150 * time.Millisecond)

	// Close cleanupDone channel
	close(server.cleanupDone)

	// Verify cleanup loop exits
	select {
	case <-done:
		// Success - cleanup loop exited
	case <-time.After(500 * time.Millisecond):
		t.Error("cleanup loop did not exit after cleanupDone channel closed")
	}
}

// buildDNSPacket constructs a minimal DNS query packet for testing
func buildDNSPacket(domain string) []byte {
	// DNS header (12 bytes)
	header := make([]byte, 12)
	header[0] = 0x00  // Transaction ID (high byte)
	header[1] = 0x01  // Transaction ID (low byte)
	header[2] = 0x01  // Flags: RD=1 (recursion desired)
	header[3] = 0x00  // Flags
	header[4] = 0x00  // QDCOUNT (high byte)
	header[5] = 0x01  // QDCOUNT (low byte) - 1 question
	header[6] = 0x00  // ANCOUNT (high byte)
	header[7] = 0x00  // ANCOUNT (low byte)
	header[8] = 0x00  // NSCOUNT (high byte)
	header[9] = 0x00  // NSCOUNT (low byte)
	header[10] = 0x00 // ARCOUNT (high byte)
	header[11] = 0x00 // ARCOUNT (low byte)

	// Encode domain name
	var querySection []byte
	parts := []byte(domain)
	labels := make([][]byte, 0)
	currentLabel := make([]byte, 0)

	for _, b := range parts {
		if b == '.' {
			if len(currentLabel) > 0 {
				labels = append(labels, currentLabel)
				currentLabel = make([]byte, 0)
			}
		} else {
			currentLabel = append(currentLabel, b)
		}
	}
	if len(currentLabel) > 0 {
		labels = append(labels, currentLabel)
	}

	for _, label := range labels {
		querySection = append(querySection, byte(len(label)))
		querySection = append(querySection, label...)
	}
	querySection = append(querySection, 0x00) // End of domain name

	// Query type (A record) and class (IN)
	querySection = append(querySection, 0x00, 0x01) // Type A
	querySection = append(querySection, 0x00, 0x01) // Class IN

	return append(header, querySection...)
}

// TestDNSServerIntegration tests DNS server with actual DNS packets
func TestDNSServerIntegration(t *testing.T) {
	server := NewServer(Config{
		DNSAddr:   ":0", // Random port
		DNSDomain: "cb.example.com",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the server
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop(ctx)

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Get the actual port the DNS server is listening on
	if server.dnsServer == nil {
		t.Fatal("DNS server not started")
	}

	server.dnsServer.mu.RLock()
	conn := server.dnsServer.conn
	server.dnsServer.mu.RUnlock()

	if conn == nil {
		t.Fatal("DNS server connection not established")
	}

	addr := conn.LocalAddr().(*net.UDPAddr)

	// Register a callback we expect to receive
	callbackID := "test123"
	notifier := make(chan CallbackEvent, 1)
	server.RegisterCallback(callbackID, 5*time.Second, nil, notifier)

	// Send a DNS query
	query := buildDNSPacket(fmt.Sprintf("%s.cb.example.com", callbackID))

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("failed to connect to DNS server: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(query); err != nil {
		t.Fatalf("failed to send DNS query: %v", err)
	}

	// Wait for callback
	select {
	case event := <-notifier:
		if event.ID != callbackID {
			t.Errorf("expected callback ID %s, got %s", callbackID, event.ID)
		}
		if event.Type != CallbackTypeDNS {
			t.Errorf("expected DNS callback type, got %s", event.Type)
		}
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for DNS callback")
	}
}

// TestNewDNSServerError tests error handling in newDNSServer
func TestNewDNSServerError(t *testing.T) {
	server := NewServer(Config{
		DNSDomain: "cb.example.com",
	})

	// newDNSServer currently doesn't return errors in its implementation
	// but we test it returns a valid server
	dnsServer, err := newDNSServer(":0", "cb.example.com", server)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if dnsServer == nil {
		t.Error("expected non-nil DNS server")
	}
	if dnsServer.addr != ":0" {
		t.Errorf("expected addr :0, got %s", dnsServer.addr)
	}
	if dnsServer.domain != "cb.example.com" {
		t.Errorf("expected domain cb.example.com, got %s", dnsServer.domain)
	}
}

// TestConcurrentCallbackRecording tests concurrent callback recording
func TestConcurrentCallbackRecording(t *testing.T) {
	server := NewServer(Config{})

	const numGoroutines = 50
	const eventsPerCallback = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Multiple goroutines recording events for the same callback ID
	callbackID := "concurrent-test"
	for i := 0; i < numGoroutines; i++ {
		go func(routineID int) {
			defer wg.Done()

			for j := 0; j < eventsPerCallback; j++ {
				event := CallbackEvent{
					ID:        callbackID,
					Type:      CallbackTypeHTTP,
					Timestamp: time.Now(),
					SourceIP:  fmt.Sprintf("192.168.1.%d", routineID),
				}
				server.recordCallback(callbackID, event)
			}
		}(i)
	}

	wg.Wait()

	// Verify all events were recorded
	events, ok := server.CheckCallback(callbackID)
	if !ok {
		t.Fatal("expected callback to be recorded")
	}

	expectedCount := numGoroutines * eventsPerCallback
	if len(events) != expectedCount {
		t.Errorf("expected %d events, got %d", expectedCount, len(events))
	}
}
