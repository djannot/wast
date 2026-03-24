package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestNewLimiter(t *testing.T) {
	tests := []struct {
		name              string
		requestsPerSecond float64
		wantNoop          bool
	}{
		{
			name:              "zero rate returns noop",
			requestsPerSecond: 0,
			wantNoop:          true,
		},
		{
			name:              "negative rate returns noop",
			requestsPerSecond: -1,
			wantNoop:          true,
		},
		{
			name:              "positive rate returns token bucket",
			requestsPerSecond: 5,
			wantNoop:          false,
		},
		{
			name:              "fractional rate returns token bucket",
			requestsPerSecond: 0.5,
			wantNoop:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewLimiter(tt.requestsPerSecond)
			_, isNoop := limiter.(*NoopLimiter)
			if isNoop != tt.wantNoop {
				t.Errorf("NewLimiter(%v) noop = %v, want %v", tt.requestsPerSecond, isNoop, tt.wantNoop)
			}
		})
	}
}

func TestNewDelayLimiter(t *testing.T) {
	tests := []struct {
		name     string
		delayMs  int
		wantNoop bool
	}{
		{
			name:     "zero delay returns noop",
			delayMs:  0,
			wantNoop: true,
		},
		{
			name:     "negative delay returns noop",
			delayMs:  -100,
			wantNoop: true,
		},
		{
			name:     "positive delay returns delay limiter",
			delayMs:  100,
			wantNoop: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewDelayLimiter(tt.delayMs)
			_, isNoop := limiter.(*NoopLimiter)
			if isNoop != tt.wantNoop {
				t.Errorf("NewDelayLimiter(%v) noop = %v, want %v", tt.delayMs, isNoop, tt.wantNoop)
			}
		})
	}
}

func TestNoopLimiter(t *testing.T) {
	limiter := &NoopLimiter{}

	// Wait should return immediately
	ctx := context.Background()
	start := time.Now()
	err := limiter.Wait(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("NoopLimiter.Wait() error = %v, want nil", err)
	}
	if elapsed > 10*time.Millisecond {
		t.Errorf("NoopLimiter.Wait() took %v, expected immediate return", elapsed)
	}

	// Allow should always return true
	if !limiter.Allow() {
		t.Error("NoopLimiter.Allow() = false, want true")
	}
}

func TestDelayLimiter_Wait(t *testing.T) {
	delayMs := 100
	limiter := NewDelayLimiter(delayMs).(*DelayLimiter)

	ctx := context.Background()

	// First call should not wait
	start := time.Now()
	err := limiter.Wait(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("DelayLimiter.Wait() first call error = %v, want nil", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("DelayLimiter.Wait() first call took %v, expected < 50ms", elapsed)
	}

	// Second call should wait approximately delayMs
	start = time.Now()
	err = limiter.Wait(ctx)
	elapsed = time.Since(start)

	if err != nil {
		t.Errorf("DelayLimiter.Wait() second call error = %v, want nil", err)
	}
	// Allow some tolerance
	expectedMin := time.Duration(delayMs-20) * time.Millisecond
	expectedMax := time.Duration(delayMs+50) * time.Millisecond
	if elapsed < expectedMin || elapsed > expectedMax {
		t.Errorf("DelayLimiter.Wait() second call took %v, expected between %v and %v", elapsed, expectedMin, expectedMax)
	}
}

func TestDelayLimiter_WaitContextCancelled(t *testing.T) {
	delayMs := 1000
	limiter := NewDelayLimiter(delayMs).(*DelayLimiter)

	ctx, cancel := context.WithCancel(context.Background())

	// First call to start tracking
	_ = limiter.Wait(ctx)

	// Cancel context immediately
	cancel()

	// Second call should fail immediately due to cancelled context
	err := limiter.Wait(ctx)
	if err != context.Canceled {
		t.Errorf("DelayLimiter.Wait() with cancelled context error = %v, want context.Canceled", err)
	}
}

func TestDelayLimiter_Allow(t *testing.T) {
	delayMs := 100
	limiter := NewDelayLimiter(delayMs).(*DelayLimiter)

	// First call should be allowed
	if !limiter.Allow() {
		t.Error("DelayLimiter.Allow() first call = false, want true")
	}

	// Immediate second call should not be allowed
	if limiter.Allow() {
		t.Error("DelayLimiter.Allow() immediate second call = true, want false")
	}

	// Wait for delay and try again
	time.Sleep(time.Duration(delayMs+10) * time.Millisecond)
	if !limiter.Allow() {
		t.Error("DelayLimiter.Allow() after delay = false, want true")
	}
}

func TestTokenBucketLimiter_Wait(t *testing.T) {
	// 10 requests per second = 100ms between requests
	limiter := NewLimiter(10).(*TokenBucketLimiter)
	ctx := context.Background()

	// Should allow burst of initial requests
	start := time.Now()
	for i := 0; i < 10; i++ {
		err := limiter.Wait(ctx)
		if err != nil {
			t.Errorf("TokenBucketLimiter.Wait() call %d error = %v, want nil", i, err)
		}
	}
	burstElapsed := time.Since(start)

	// Burst should be fast (all tokens available)
	if burstElapsed > 200*time.Millisecond {
		t.Errorf("TokenBucketLimiter burst took %v, expected < 200ms", burstElapsed)
	}

	// Next request should wait for token refill
	start = time.Now()
	err := limiter.Wait(ctx)
	waitElapsed := time.Since(start)

	if err != nil {
		t.Errorf("TokenBucketLimiter.Wait() after burst error = %v, want nil", err)
	}
	// Should wait at least ~100ms for one token to refill
	if waitElapsed < 50*time.Millisecond {
		t.Errorf("TokenBucketLimiter.Wait() after burst took %v, expected >= 50ms", waitElapsed)
	}
}

func TestTokenBucketLimiter_WaitContextCancelled(t *testing.T) {
	// Very slow rate to ensure we need to wait
	limiter := NewLimiterWithBurst(0.5, 1).(*TokenBucketLimiter)

	ctx, cancel := context.WithCancel(context.Background())

	// Use the one token
	_ = limiter.Wait(ctx)

	// Cancel context
	cancel()

	// Next call should fail immediately
	err := limiter.Wait(ctx)
	if err != context.Canceled {
		t.Errorf("TokenBucketLimiter.Wait() with cancelled context error = %v, want context.Canceled", err)
	}
}

func TestTokenBucketLimiter_Allow(t *testing.T) {
	// 1 request per second with burst of 1
	limiter := NewLimiterWithBurst(1, 1).(*TokenBucketLimiter)

	// First request should be allowed
	if !limiter.Allow() {
		t.Error("TokenBucketLimiter.Allow() first call = false, want true")
	}

	// Immediate second request should not be allowed
	if limiter.Allow() {
		t.Error("TokenBucketLimiter.Allow() immediate second call = true, want false")
	}

	// Wait for token refill
	time.Sleep(1100 * time.Millisecond)
	if !limiter.Allow() {
		t.Error("TokenBucketLimiter.Allow() after refill = false, want true")
	}
}

func TestNewLimiterFromConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     Config
		wantNoop   bool
		wantDelay  bool
		wantBucket bool
	}{
		{
			name:     "empty config returns noop",
			config:   Config{},
			wantNoop: true,
		},
		{
			name:       "delay takes precedence",
			config:     Config{DelayMs: 100, RequestsPerSecond: 5},
			wantDelay:  true,
			wantBucket: false,
		},
		{
			name:       "requests per second creates bucket",
			config:     Config{RequestsPerSecond: 5},
			wantBucket: true,
		},
		{
			name:      "only delay creates delay limiter",
			config:    Config{DelayMs: 100},
			wantDelay: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewLimiterFromConfig(tt.config)

			_, isNoop := limiter.(*NoopLimiter)
			_, isDelay := limiter.(*DelayLimiter)
			_, isBucket := limiter.(*TokenBucketLimiter)

			if tt.wantNoop && !isNoop {
				t.Errorf("NewLimiterFromConfig() got %T, want *NoopLimiter", limiter)
			}
			if tt.wantDelay && !isDelay {
				t.Errorf("NewLimiterFromConfig() got %T, want *DelayLimiter", limiter)
			}
			if tt.wantBucket && !isBucket {
				t.Errorf("NewLimiterFromConfig() got %T, want *TokenBucketLimiter", limiter)
			}
		})
	}
}

func TestConfig_IsEnabled(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   bool
	}{
		{
			name:   "empty config is disabled",
			config: Config{},
			want:   false,
		},
		{
			name:   "zero values is disabled",
			config: Config{RequestsPerSecond: 0, DelayMs: 0},
			want:   false,
		},
		{
			name:   "rate limit enables",
			config: Config{RequestsPerSecond: 5},
			want:   true,
		},
		{
			name:   "delay enables",
			config: Config{DelayMs: 100},
			want:   true,
		},
		{
			name:   "both enables",
			config: Config{RequestsPerSecond: 5, DelayMs: 100},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.IsEnabled(); got != tt.want {
				t.Errorf("Config.IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewLimiterWithBurst(t *testing.T) {
	tests := []struct {
		name              string
		requestsPerSecond float64
		burst             int
		wantNoop          bool
	}{
		{
			name:              "zero rate returns noop",
			requestsPerSecond: 0,
			burst:             5,
			wantNoop:          true,
		},
		{
			name:              "zero burst returns noop",
			requestsPerSecond: 5,
			burst:             0,
			wantNoop:          true,
		},
		{
			name:              "negative burst returns noop",
			requestsPerSecond: 5,
			burst:             -1,
			wantNoop:          true,
		},
		{
			name:              "valid params returns bucket",
			requestsPerSecond: 5,
			burst:             10,
			wantNoop:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewLimiterWithBurst(tt.requestsPerSecond, tt.burst)
			_, isNoop := limiter.(*NoopLimiter)
			if isNoop != tt.wantNoop {
				t.Errorf("NewLimiterWithBurst(%v, %v) noop = %v, want %v", tt.requestsPerSecond, tt.burst, isNoop, tt.wantNoop)
			}
		})
	}
}
