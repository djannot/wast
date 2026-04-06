package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/ratelimit"
)

// ---------------------------------------------------------------------------
// rateLimitMiddleware tests
// ---------------------------------------------------------------------------

func TestRateLimitMiddleware_AllowsUnderLimit(t *testing.T) {
	limiter := ratelimit.NewLimiterWithBurst(100, 100) // generous limit
	called := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})

	handler := rateLimitMiddleware(inner, limiter)

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w := httptest.NewRecorder()
	handler(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if called != 1 {
		t.Errorf("expected inner handler called once, got %d", called)
	}
}

func TestRateLimitMiddleware_Returns429WhenExceeded(t *testing.T) {
	// Limiter with burst=1, rps=0.001 — effectively won't replenish during the test.
	limiter := ratelimit.NewLimiterWithBurst(0.001, 1)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rateLimitMiddleware(inner, limiter)

	// First request consumes the single token.
	r1 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w1 := httptest.NewRecorder()
	handler(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w1.Code)
	}

	// Second request should be rate-limited.
	r2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w2 := httptest.NewRecorder()
	handler(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", w2.Code)
	}
}

func TestRateLimitMiddleware_SetsRetryAfterHeader(t *testing.T) {
	limiter := ratelimit.NewLimiterWithBurst(0.001, 1)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rateLimitMiddleware(inner, limiter)

	// Exhaust the bucket.
	r1 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	handler(httptest.NewRecorder(), r1)

	r2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w2 := httptest.NewRecorder()
	handler(w2, r2)

	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w2.Code)
	}
	if ra := w2.Header().Get("Retry-After"); ra == "" {
		t.Error("expected Retry-After header to be set")
	}
}

// ---------------------------------------------------------------------------
// concurrencyLimitMiddleware tests
// ---------------------------------------------------------------------------

func TestConcurrencyLimitMiddleware_AllowsUnderLimit(t *testing.T) {
	sem := make(chan struct{}, 5)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := concurrencyLimitMiddleware(inner, sem)

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w := httptest.NewRecorder()
	handler(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestConcurrencyLimitMiddleware_Returns429WhenFull(t *testing.T) {
	sem := make(chan struct{}, 2)
	// Pre-fill the semaphore to simulate full capacity.
	sem <- struct{}{}
	sem <- struct{}{}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := concurrencyLimitMiddleware(inner, sem)

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w := httptest.NewRecorder()
	handler(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

func TestConcurrencyLimitMiddleware_SetsRetryAfterHeader(t *testing.T) {
	sem := make(chan struct{}, 1)
	sem <- struct{}{} // full

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := concurrencyLimitMiddleware(inner, sem)

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w := httptest.NewRecorder()
	handler(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("expected Retry-After header to be set")
	}
}

func TestConcurrencyLimitMiddleware_ReleasesSlotAfterRequest(t *testing.T) {
	sem := make(chan struct{}, 1)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := concurrencyLimitMiddleware(inner, sem)

	// First request succeeds and releases its slot.
	r1 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w1 := httptest.NewRecorder()
	handler(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w1.Code)
	}

	// Semaphore should be empty again; second request also succeeds.
	r2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w2 := httptest.NewRecorder()
	handler(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("second request: expected 200, got %d", w2.Code)
	}
}

func TestConcurrencyLimitMiddleware_ConcurrentRequests(t *testing.T) {
	const (
		maxConcurrent = 3
		totalRequests = 10
	)

	sem := make(chan struct{}, maxConcurrent)

	// Track the number of concurrent executions.
	var concurrent int32
	var peak int32
	var rejected int32

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&concurrent, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if cur <= old || atomic.CompareAndSwapInt32(&peak, old, cur) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&concurrent, -1)
		w.WriteHeader(http.StatusOK)
	})
	handler := concurrencyLimitMiddleware(inner, sem)

	var wg sync.WaitGroup
	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			w := httptest.NewRecorder()
			handler(w, r)
			if w.Code == http.StatusTooManyRequests {
				atomic.AddInt32(&rejected, 1)
			}
		}()
	}
	wg.Wait()

	if p := atomic.LoadInt32(&peak); p > maxConcurrent {
		t.Errorf("peak concurrent executions %d exceeded limit %d", p, maxConcurrent)
	}
	if atomic.LoadInt32(&rejected) == 0 {
		t.Log("no requests were rejected (all requests may have succeeded due to timing)")
	}
}

// ---------------------------------------------------------------------------
// Server-level integration: SetRateLimit / SetMaxConcurrent
// ---------------------------------------------------------------------------

func TestServer_SetRateLimit_WiresMiddleware(t *testing.T) {
	s := NewServer()
	s.SetRateLimit(0.001) // effectively never refills during test

	if s.rateLimiter == nil {
		t.Fatal("expected rateLimiter to be set")
	}
}

func TestServer_SetRateLimit_DisablesOnZero(t *testing.T) {
	s := NewServer()
	s.SetRateLimit(10)
	s.SetRateLimit(0)

	if s.rateLimiter != nil {
		t.Fatal("expected rateLimiter to be nil after setting 0")
	}
}

func TestServer_SetMaxConcurrent(t *testing.T) {
	s := NewServer()
	s.SetMaxConcurrent(3)

	if s.maxConcurrent != 3 {
		t.Errorf("expected maxConcurrent=3, got %d", s.maxConcurrent)
	}
}

// ---------------------------------------------------------------------------
// HTTP integration test via mcpHTTPHandler with rate limiting active
// ---------------------------------------------------------------------------

func TestHTTP_RateLimit_Returns429(t *testing.T) {
	s := NewServer()
	s.SetRateLimit(0.001) // burst=1, never replenishes

	// Build the same handler chain as ListenAndServe.
	handler := http.HandlerFunc(s.mcpHTTPHandler)
	handler = rateLimitMiddleware(handler, s.rateLimiter)

	initBody, _ := json.Marshal(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}`),
	})

	// First request — should pass (consumes the single burst token).
	r1 := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(initBody))
	r1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	handler(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w1.Code)
	}

	// Second request — should be rate-limited.
	r2 := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(initBody))
	r2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", w2.Code)
	}
	if ra := w2.Header().Get("Retry-After"); ra == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}
