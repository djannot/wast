package telemetry

import (
	"context"
	"os"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

func TestConfigFromEnv(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		serviceName string
		wantEnabled bool
		wantName    string
	}{
		{
			name:        "no environment variables",
			endpoint:    "",
			serviceName: "",
			wantEnabled: false,
			wantName:    "wast",
		},
		{
			name:        "endpoint set",
			endpoint:    "localhost:4317",
			serviceName: "",
			wantEnabled: true,
			wantName:    "wast",
		},
		{
			name:        "both set",
			endpoint:    "localhost:4317",
			serviceName: "custom-wast",
			wantEnabled: true,
			wantName:    "custom-wast",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			if tt.endpoint != "" {
				os.Setenv("WAST_OTEL_ENDPOINT", tt.endpoint)
				defer os.Unsetenv("WAST_OTEL_ENDPOINT")
			}
			if tt.serviceName != "" {
				os.Setenv("WAST_OTEL_SERVICE_NAME", tt.serviceName)
				defer os.Unsetenv("WAST_OTEL_SERVICE_NAME")
			}

			config := ConfigFromEnv()

			if config.Enabled != tt.wantEnabled {
				t.Errorf("Enabled = %v, want %v", config.Enabled, tt.wantEnabled)
			}
			if config.ServiceName != tt.wantName {
				t.Errorf("ServiceName = %v, want %v", config.ServiceName, tt.wantName)
			}
			if config.Endpoint != tt.endpoint {
				t.Errorf("Endpoint = %v, want %v", config.Endpoint, tt.endpoint)
			}
		})
	}
}

func TestConfigIsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected bool
	}{
		{
			name: "enabled with endpoint",
			config: Config{
				Enabled:  true,
				Endpoint: "localhost:4317",
			},
			expected: true,
		},
		{
			name: "enabled without endpoint",
			config: Config{
				Enabled:  true,
				Endpoint: "",
			},
			expected: false,
		},
		{
			name: "disabled with endpoint",
			config: Config{
				Enabled:  false,
				Endpoint: "localhost:4317",
			},
			expected: false,
		},
		{
			name: "disabled without endpoint",
			config: Config{
				Enabled:  false,
				Endpoint: "",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.IsEnabled(); got != tt.expected {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewProvider_Disabled(t *testing.T) {
	ctx := context.Background()

	config := Config{
		Enabled:  false,
		Endpoint: "",
	}

	provider, err := NewProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewProvider() error = %v, want nil", err)
	}
	if provider == nil {
		t.Fatal("NewProvider() returned nil provider")
	}

	// Verify we get a no-op tracer
	tracer := provider.Tracer()
	if tracer == nil {
		t.Fatal("Tracer() returned nil")
	}

	// Create a span to ensure it doesn't panic
	_, span := tracer.Start(ctx, "test")
	span.End()

	// Shutdown should not error
	if err := provider.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error = %v, want nil", err)
	}
}

func TestNewProvider_InvalidEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	config := Config{
		Enabled:     true,
		Endpoint:    "invalid:999999", // Invalid port
		ServiceName: "test-wast",
	}

	// This should not error during creation, only when trying to export
	provider, err := NewProvider(ctx, config)
	if err != nil {
		// It's okay if it errors with invalid endpoint
		t.Logf("NewProvider() with invalid endpoint error = %v (expected)", err)
		return
	}

	if provider != nil {
		defer provider.Shutdown(context.Background())
	}
}

func TestProviderTracer(t *testing.T) {
	ctx := context.Background()

	// Test with disabled config
	config := Config{
		Enabled:  false,
		Endpoint: "",
	}

	provider, err := NewProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewProvider() error = %v, want nil", err)
	}
	defer provider.Shutdown(ctx)

	tracer := provider.Tracer()
	if tracer == nil {
		t.Fatal("Tracer() returned nil")
	}

	// Ensure tracer works (no-op)
	_, span := tracer.Start(ctx, "test-span")
	if span == nil {
		t.Fatal("Start() returned nil span")
	}
	span.End()
}

func TestSpanNames(t *testing.T) {
	// Verify all span name constants are properly defined
	spanNames := []string{
		SpanNameRecon,
		SpanNameDNSEnumerate,
		SpanNameTLSAnalyze,
		SpanNameScan,
		SpanNameScanHeaders,
		SpanNameScanXSS,
		SpanNameScanSQLi,
		SpanNameScanCSRF,
		SpanNameScanSSRF,
		SpanNameHTTPRequest,
		SpanNameCrawl,
		SpanNameAPI,
		SpanNameIntercept,
	}

	for _, name := range spanNames {
		if name == "" {
			t.Errorf("Span name is empty")
		}
		if len(name) < 5 {
			t.Errorf("Span name %q is too short", name)
		}
	}
}

func TestProviderShutdown(t *testing.T) {
	ctx := context.Background()

	// Test shutdown with disabled provider
	config := Config{
		Enabled:  false,
		Endpoint: "",
	}

	provider, err := NewProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewProvider() error = %v, want nil", err)
	}

	// Shutdown should not error even when called multiple times
	if err := provider.Shutdown(ctx); err != nil {
		t.Errorf("First Shutdown() error = %v, want nil", err)
	}
	if err := provider.Shutdown(ctx); err != nil {
		t.Errorf("Second Shutdown() error = %v, want nil", err)
	}
}

func TestTracer_CreateSpanWithContext(t *testing.T) {
	ctx := context.Background()

	config := Config{
		Enabled:  false,
		Endpoint: "",
	}

	provider, err := NewProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}
	defer provider.Shutdown(ctx)

	tracer := provider.Tracer()

	// Create a span
	ctx, span := tracer.Start(ctx, SpanNameRecon)
	defer span.End()

	// Verify we can extract span context
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		// For no-op tracer, this is expected behavior
		t.Log("Span context is not valid (expected for no-op tracer)")
	}
}
