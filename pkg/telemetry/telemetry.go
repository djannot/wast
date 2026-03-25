// Package telemetry provides OpenTelemetry tracing and metrics support for WAST operations.
package telemetry

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// SpanNameRecon is the span name for reconnaissance operations
	SpanNameRecon = "wast.recon"
	// SpanNameDNSEnumerate is the span name for DNS enumeration
	SpanNameDNSEnumerate = "wast.dns.enumerate"
	// SpanNameTLSAnalyze is the span name for TLS analysis
	SpanNameTLSAnalyze = "wast.tls.analyze"
	// SpanNameScan is the span name for security scanning
	SpanNameScan = "wast.scan"
	// SpanNameScanHeaders is the span name for header scanning
	SpanNameScanHeaders = "wast.scanner.headers"
	// SpanNameScanXSS is the span name for XSS scanning
	SpanNameScanXSS = "wast.scanner.xss"
	// SpanNameScanSQLi is the span name for SQL injection scanning
	SpanNameScanSQLi = "wast.scanner.sqli"
	// SpanNameScanCSRF is the span name for CSRF scanning
	SpanNameScanCSRF = "wast.scanner.csrf"
	// SpanNameScanSSRF is the span name for SSRF scanning
	SpanNameScanSSRF = "wast.scanner.ssrf"
	// SpanNameHTTPRequest is the span name for individual HTTP requests
	SpanNameHTTPRequest = "wast.http.request"
	// SpanNameCrawl is the span name for crawling operations
	SpanNameCrawl = "wast.crawl"
	// SpanNameAPI is the span name for API operations
	SpanNameAPI = "wast.api"
	// SpanNameIntercept is the span name for traffic interception
	SpanNameIntercept = "wast.intercept"
)

// Config holds the configuration for OpenTelemetry tracing.
type Config struct {
	// Enabled indicates whether telemetry is enabled
	Enabled bool
	// Endpoint is the OTLP gRPC endpoint (e.g., "localhost:4317")
	Endpoint string
	// ServiceName is the name of the service (default: "wast")
	ServiceName string
	// ServiceVersion is the version of the service
	ServiceVersion string
	// Insecure disables TLS for the gRPC connection (for local development only)
	Insecure bool
}

// Provider wraps the OpenTelemetry tracer provider and provides cleanup.
type Provider struct {
	tracerProvider *sdktrace.TracerProvider
	tracer         trace.Tracer
}

// NewProvider creates and initializes a new OpenTelemetry tracer provider.
// If config.Enabled is false, it returns a no-op provider with zero overhead.
func NewProvider(ctx context.Context, config Config) (*Provider, error) {
	if !config.Enabled || config.Endpoint == "" {
		// Return a no-op provider when telemetry is disabled
		return &Provider{
			tracerProvider: nil,
			tracer:         trace.NewNoopTracerProvider().Tracer("wast"),
		}, nil
	}

	// Set defaults
	if config.ServiceName == "" {
		config.ServiceName = "wast"
	}

	// Create OTLP exporter
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Configure transport credentials (default to TLS)
	var transportCreds credentials.TransportCredentials
	if config.Insecure {
		transportCreds = insecure.NewCredentials()
	} else {
		transportCreds = credentials.NewTLS(&tls.Config{})
	}

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(config.Endpoint),
		otlptracegrpc.WithDialOption(grpc.WithTransportCredentials(transportCreds)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource with service information
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(config.ServiceName),
			semconv.ServiceVersionKey.String(config.ServiceVersion),
		),
		resource.WithHost(),
		resource.WithOS(),
		resource.WithProcess(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tp)

	return &Provider{
		tracerProvider: tp,
		tracer:         tp.Tracer("wast"),
	}, nil
}

// Tracer returns the trace.Tracer for creating spans.
func (p *Provider) Tracer() trace.Tracer {
	return p.tracer
}

// Shutdown gracefully shuts down the tracer provider, flushing any remaining spans.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.tracerProvider == nil {
		return nil
	}
	return p.tracerProvider.Shutdown(ctx)
}

// ConfigFromEnv creates a Config from environment variables.
// It reads WAST_OTEL_ENDPOINT, WAST_OTEL_SERVICE_NAME, and WAST_OTEL_INSECURE.
func ConfigFromEnv() Config {
	endpoint := os.Getenv("WAST_OTEL_ENDPOINT")
	serviceName := os.Getenv("WAST_OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "wast"
	}

	// Check if insecure mode is enabled (for local development)
	insecure := os.Getenv("WAST_OTEL_INSECURE") == "true"

	return Config{
		Enabled:     endpoint != "",
		Endpoint:    endpoint,
		ServiceName: serviceName,
		Insecure:    insecure,
	}
}

// IsEnabled returns true if telemetry is enabled.
func (c Config) IsEnabled() bool {
	return c.Enabled && c.Endpoint != ""
}
