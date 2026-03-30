// Package scanner provides security scanning functionality for web applications.
package scanner

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"go.opentelemetry.io/otel/trace"
)

// BaseScanner holds the common fields shared by all scanner implementations.
// It is designed to be embedded in scanner structs to eliminate field and
// option-function duplication.
type BaseScanner struct {
	client      HTTPClient
	userAgent   string
	timeout     time.Duration
	authConfig  *auth.AuthConfig
	rateLimiter ratelimit.Limiter
	tracer      trace.Tracer
}

// newBaseScanner returns a BaseScanner with sensible defaults.
// Embed this in scanner-specific New* constructors to avoid repeating default
// values across every scanner.
func newBaseScanner() BaseScanner {
	return BaseScanner{
		userAgent: "WAST/1.0 (Web Application Security Testing)",
		timeout:   30 * time.Second,
	}
}

// baselineResponse stores information about a baseline request for comparison.
type baselineResponse struct {
	StatusCode    int
	BodyLength    int
	BodyHash      string
	ContainsKey   string
	DataWordCount int    // Number of words in data-bearing elements (td, th, pre)
	DataContent   string // Text extracted from data-bearing elements
	DataRowCount  int    // Number of table rows with data cells
}

// responseCharacteristics holds response data for comparison.
type responseCharacteristics struct {
	StatusCode         int
	BodyLength         int
	Body               string
	ContentHash        string // MD5 hash of extracted body content
	WordCount          int    // Number of words in the response
	StructuralElements int    // Count of structural HTML elements (tr, li, etc.)
	DataContent        string // Text extracted from data-bearing elements (td, th, pre)
	DataWordCount      int    // Number of words in data content
	DataRowCount       int    // Number of table rows in data regions (for DVWA-style detection)
}

// makeRequest is a helper to make a GET request with a specific payload value
// injected into the named query parameter.
func (b *BaseScanner) makeRequest(ctx context.Context, baseURL *url.URL, paramName string, payloadValue string) (*responseCharacteristics, error) {
	testURL := *baseURL
	q := testURL.Query()
	q.Set(paramName, payloadValue)
	testURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", b.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if b.authConfig != nil {
		b.authConfig.ApplyToRequest(req)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bodyStr := string(body)
	contentHash, wordCount, structuralElements, dataContent, dataWordCount, dataRowCount := analyzeResponse(bodyStr)

	return &responseCharacteristics{
		StatusCode:         resp.StatusCode,
		BodyLength:         len(body),
		Body:               bodyStr,
		ContentHash:        contentHash,
		WordCount:          wordCount,
		StructuralElements: structuralElements,
		DataContent:        dataContent,
		DataWordCount:      dataWordCount,
		DataRowCount:       dataRowCount,
	}, nil
}

// makeRequestPOST is a helper to make a POST request with a specific payload value
// injected into the named form parameter. allParameters provides the full set of
// form fields; paramName is overridden with payloadValue.
func (b *BaseScanner) makeRequestPOST(ctx context.Context, baseURL *url.URL, paramName string, payloadValue string, allParameters map[string]string) (*responseCharacteristics, error) {
	// Build form data from all parameters, then override the target parameter.
	formData := url.Values{}
	for k, v := range allParameters {
		formData.Set(k, v)
	}
	formData.Set(paramName, payloadValue)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", b.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if b.authConfig != nil {
		b.authConfig.ApplyToRequest(req)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bodyStr := string(body)
	contentHash, wordCount, structuralElements, dataContent, dataWordCount, dataRowCount := analyzeResponse(bodyStr)

	return &responseCharacteristics{
		StatusCode:         resp.StatusCode,
		BodyLength:         len(body),
		Body:               bodyStr,
		ContentHash:        contentHash,
		WordCount:          wordCount,
		StructuralElements: structuralElements,
		DataContent:        dataContent,
		DataWordCount:      dataWordCount,
		DataRowCount:       dataRowCount,
	}, nil
}

// getBaselineWithTiming makes a GET request using the original parameter value (or
// defaultValue when the URL carries no value for paramName) and returns a baseline
// snapshot together with the measured request duration.
//
// defaultValue controls what placeholder is used when the parameter is absent from
// the URL – pass "1" for numeric contexts (e.g. SQLi) or "test" for string contexts
// (e.g. CMDi).
func (b *BaseScanner) getBaselineWithTiming(ctx context.Context, baseURL *url.URL, paramName, defaultValue string) (*baselineResponse, time.Duration) {
	testURL := *baseURL
	q := testURL.Query()

	originalValue := q.Get(paramName)
	if originalValue == "" {
		originalValue = defaultValue
		q.Set(paramName, originalValue)
	}
	testURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return nil, 0
	}

	req.Header.Set("User-Agent", b.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if b.authConfig != nil {
		b.authConfig.ApplyToRequest(req)
	}

	startTime := time.Now()
	resp, err := b.client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0
	}

	bodyStr := string(body)
	_, _, _, dataContent, dataWordCount, dataRowCount := analyzeResponse(bodyStr)

	baseline := &baselineResponse{
		StatusCode:    resp.StatusCode,
		BodyLength:    len(body),
		BodyHash:      fmt.Sprintf("%x", len(body)), // Simple length-based fingerprint for GET baseline
		ContainsKey:   bodyStr,
		DataWordCount: dataWordCount,
		DataContent:   dataContent,
		DataRowCount:  dataRowCount,
	}

	return baseline, duration
}

// getBaselineWithTimingPOST makes a POST request using the supplied parameters to
// establish a baseline and measures the request duration for time-based detection.
//
// defaultParamValue, when non-empty, is substituted for any parameter whose value
// is the empty string – this prevents apps that require a valid prefix from
// returning an unrepresentative baseline. Pass "" to disable the substitution
// (e.g. for SQLi where parameter values are always non-empty).
func (b *BaseScanner) getBaselineWithTimingPOST(ctx context.Context, baseURL *url.URL, paramName string, allParameters map[string]string, defaultParamValue string) (*baselineResponse, time.Duration) {
	formData := url.Values{}
	for k, v := range allParameters {
		if v == "" && defaultParamValue != "" {
			v = defaultParamValue
		}
		formData.Set(k, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, 0
	}

	req.Header.Set("User-Agent", b.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if b.authConfig != nil {
		b.authConfig.ApplyToRequest(req)
	}

	startTime := time.Now()
	resp, err := b.client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0
	}

	hash := md5.Sum(body)

	baseline := &baselineResponse{
		StatusCode:  resp.StatusCode,
		BodyLength:  len(body),
		BodyHash:    fmt.Sprintf("%x", hash),
		ContainsKey: string(body),
	}

	return baseline, duration
}
