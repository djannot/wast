// Package proxy provides HTTP traffic interception functionality for security testing.
package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// InterceptedRequest represents a captured HTTP request.
type InterceptedRequest struct {
	ID        string            `json:"id" yaml:"id"`
	Method    string            `json:"method" yaml:"method"`
	URL       string            `json:"url" yaml:"url"`
	Host      string            `json:"host" yaml:"host"`
	Path      string            `json:"path" yaml:"path"`
	Headers   map[string]string `json:"headers" yaml:"headers"`
	Body      string            `json:"body,omitempty" yaml:"body,omitempty"`
	Timestamp time.Time         `json:"timestamp" yaml:"timestamp"`
}

// InterceptedResponse represents a captured HTTP response.
type InterceptedResponse struct {
	RequestID  string            `json:"request_id" yaml:"request_id"`
	StatusCode int               `json:"status_code" yaml:"status_code"`
	Status     string            `json:"status" yaml:"status"`
	Headers    map[string]string `json:"headers" yaml:"headers"`
	Body       string            `json:"body,omitempty" yaml:"body,omitempty"`
	Timestamp  time.Time         `json:"timestamp" yaml:"timestamp"`
	Duration   time.Duration     `json:"duration_ns" yaml:"duration_ns"`
}

// RequestResponsePair represents a matched request and response pair.
type RequestResponsePair struct {
	Request  *InterceptedRequest  `json:"request" yaml:"request"`
	Response *InterceptedResponse `json:"response,omitempty" yaml:"response,omitempty"`
}

// ProxyResult represents the result of a proxy session.
type ProxyResult struct {
	Port         int                    `json:"port" yaml:"port"`
	StartTime    time.Time              `json:"start_time" yaml:"start_time"`
	EndTime      time.Time              `json:"end_time,omitempty" yaml:"end_time,omitempty"`
	Traffic      []*RequestResponsePair `json:"traffic,omitempty" yaml:"traffic,omitempty"`
	Statistics   ProxyStats             `json:"statistics" yaml:"statistics"`
	Errors       []string               `json:"errors,omitempty" yaml:"errors,omitempty"`
	SavedToFile  string                 `json:"saved_to_file,omitempty" yaml:"saved_to_file,omitempty"`
}

// ProxyStats contains statistics about the proxy session.
type ProxyStats struct {
	TotalRequests   int `json:"total_requests" yaml:"total_requests"`
	TotalResponses  int `json:"total_responses" yaml:"total_responses"`
	SuccessCount    int `json:"success_count" yaml:"success_count"`
	ErrorCount      int `json:"error_count" yaml:"error_count"`
	TotalBytesIn    int `json:"total_bytes_in" yaml:"total_bytes_in"`
	TotalBytesOut   int `json:"total_bytes_out" yaml:"total_bytes_out"`
}

// String returns a human-readable representation of the proxy result.
func (r *ProxyResult) String() string {
	var sb strings.Builder

	sb.WriteString("HTTP Proxy Session Results\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n")

	sb.WriteString(fmt.Sprintf("\nProxy Port: %d\n", r.Port))
	sb.WriteString(fmt.Sprintf("Session Start: %s\n", r.StartTime.Format(time.RFC3339)))
	if !r.EndTime.IsZero() {
		sb.WriteString(fmt.Sprintf("Session End: %s\n", r.EndTime.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Duration: %s\n", r.EndTime.Sub(r.StartTime)))
	}

	sb.WriteString(fmt.Sprintf("\nStatistics:\n"))
	sb.WriteString(fmt.Sprintf("  Total Requests: %d\n", r.Statistics.TotalRequests))
	sb.WriteString(fmt.Sprintf("  Total Responses: %d\n", r.Statistics.TotalResponses))
	sb.WriteString(fmt.Sprintf("  Success Count: %d\n", r.Statistics.SuccessCount))
	sb.WriteString(fmt.Sprintf("  Error Count: %d\n", r.Statistics.ErrorCount))
	sb.WriteString(fmt.Sprintf("  Bytes In: %d\n", r.Statistics.TotalBytesIn))
	sb.WriteString(fmt.Sprintf("  Bytes Out: %d\n", r.Statistics.TotalBytesOut))

	if len(r.Traffic) > 0 {
		sb.WriteString("\nIntercepted Traffic:\n")
		for _, pair := range r.Traffic {
			req := pair.Request
			sb.WriteString(fmt.Sprintf("  [%s] %s %s\n", req.ID, req.Method, req.URL))
			if pair.Response != nil {
				sb.WriteString(fmt.Sprintf("    -> %d %s (%.3fms)\n",
					pair.Response.StatusCode,
					pair.Response.Status,
					float64(pair.Response.Duration.Microseconds())/1000.0))
			}
		}
	}

	if r.SavedToFile != "" {
		sb.WriteString(fmt.Sprintf("\nTraffic saved to: %s\n", r.SavedToFile))
	}

	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, err := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	return sb.String()
}

// HasResults returns true if any traffic was intercepted.
func (r *ProxyResult) HasResults() bool {
	return len(r.Traffic) > 0
}

// headersToMap converts http.Header to a simple map.
func headersToMap(h http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range h {
		result[key] = strings.Join(values, ", ")
	}
	return result
}
