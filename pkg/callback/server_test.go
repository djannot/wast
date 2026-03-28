package callback

import (
	"context"
	"fmt"
	"net/http"
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
