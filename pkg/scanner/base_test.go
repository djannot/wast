package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/ratelimit"
	"go.opentelemetry.io/otel/trace"
)

// mockBaseHTTPClient is a simple mock HTTP client used to exercise BaseScanner methods.
type mockBaseHTTPClient struct {
	statusCode  int
	body        string
	err         error
	lastRequest *http.Request
}

func (m *mockBaseHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.lastRequest = req
	if m.err != nil {
		return nil, m.err
	}
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(strings.NewReader(m.body)),
		Header:     make(http.Header),
	}, nil
}

// TestNewBaseScanner verifies that newBaseScanner returns expected defaults.
func TestNewBaseScanner(t *testing.T) {
	b := newBaseScanner()

	if b.userAgent != "WAST/1.0 (Web Application Security Testing)" {
		t.Errorf("expected default userAgent, got %q", b.userAgent)
	}
	if b.timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", b.timeout)
	}
	if b.client != nil {
		t.Error("expected nil client before initialization")
	}
	if b.authConfig != nil {
		t.Error("expected nil authConfig")
	}
	if b.rateLimiter != nil {
		t.Error("expected nil rateLimiter")
	}
	if b.tracer != nil {
		t.Error("expected nil tracer")
	}
}

// TestBaseScanner_MakeRequest verifies that makeRequest builds a correct GET request
// with the payload injected into the named parameter.
func TestBaseScanner_MakeRequest(t *testing.T) {
	mock := &mockBaseHTTPClient{
		statusCode: 200,
		body:       "<html><body>hello world</body></html>",
	}
	b := newBaseScanner()
	b.client = mock

	parsedURL, _ := url.Parse("http://example.com/page?id=1")
	result, err := b.makeRequest(context.Background(), parsedURL, "id", "injected")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}

	// Verify the payload was injected into the URL
	if mock.lastRequest == nil {
		t.Fatal("no request was made")
	}
	gotParam := mock.lastRequest.URL.Query().Get("id")
	if gotParam != "injected" {
		t.Errorf("expected id=injected, got id=%q", gotParam)
	}
	if mock.lastRequest.Method != http.MethodGet {
		t.Errorf("expected GET, got %s", mock.lastRequest.Method)
	}
}

// TestBaseScanner_MakeRequest_RateLimit verifies that a 429 response is returned as an error.
func TestBaseScanner_MakeRequest_RateLimit(t *testing.T) {
	mock := &mockBaseHTTPClient{statusCode: http.StatusTooManyRequests, body: ""}
	b := newBaseScanner()
	b.client = mock

	parsedURL, _ := url.Parse("http://example.com/page?id=1")
	result, err := b.makeRequest(context.Background(), parsedURL, "id", "payload")
	if err == nil {
		t.Fatal("expected rate-limit error, got nil")
	}
	if result != nil {
		t.Error("expected nil result on rate-limit error")
	}
}

// TestBaseScanner_MakeRequestPOST verifies that makeRequestPOST sends a POST with
// the correct form-encoded body.
func TestBaseScanner_MakeRequestPOST(t *testing.T) {
	mock := &mockBaseHTTPClient{
		statusCode: 200,
		body:       "<html><body>post response</body></html>",
	}
	b := newBaseScanner()
	b.client = mock

	parsedURL, _ := url.Parse("http://example.com/login")
	allParams := map[string]string{"username": "admin", "password": "secret"}
	result, err := b.makeRequestPOST(context.Background(), parsedURL, "password", "injected", allParams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if mock.lastRequest.Method != http.MethodPost {
		t.Errorf("expected POST, got %s", mock.lastRequest.Method)
	}

	// Read and verify the request body
	bodyBytes, _ := io.ReadAll(mock.lastRequest.Body)
	bodyStr := string(bodyBytes)
	if !strings.Contains(bodyStr, "password=injected") {
		t.Errorf("expected password=injected in body, got %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "username=admin") {
		t.Errorf("expected username=admin in body, got %q", bodyStr)
	}
}

// TestBaseScanner_GetBaselineWithTiming verifies the GET baseline method.
func TestBaseScanner_GetBaselineWithTiming(t *testing.T) {
	mock := &mockBaseHTTPClient{
		statusCode: 200,
		body:       "<html><body>baseline content</body></html>",
	}
	b := newBaseScanner()
	b.client = mock

	parsedURL, _ := url.Parse("http://example.com/page?id=1")
	baseline, duration := b.getBaselineWithTiming(context.Background(), parsedURL, "id", "1")
	if baseline == nil {
		t.Fatal("expected non-nil baseline")
	}
	if baseline.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", baseline.StatusCode)
	}
	if baseline.BodyLength == 0 {
		t.Error("expected non-zero body length")
	}
	if baseline.ContainsKey == "" {
		t.Error("expected non-empty ContainsKey")
	}
	if duration < 0 {
		t.Error("expected non-negative duration")
	}
}

// TestBaseScanner_GetBaselineWithTiming_DefaultValue verifies that the defaultValue is
// used when the parameter has no value in the URL.
func TestBaseScanner_GetBaselineWithTiming_DefaultValue(t *testing.T) {
	mock := &mockBaseHTTPClient{statusCode: 200, body: "ok"}
	b := newBaseScanner()
	b.client = mock

	// URL with no query parameters – the default value should be injected.
	parsedURL, _ := url.Parse("http://example.com/page")
	b.getBaselineWithTiming(context.Background(), parsedURL, "cmd", "test")

	if mock.lastRequest == nil {
		t.Fatal("no request was made")
	}
	gotParam := mock.lastRequest.URL.Query().Get("cmd")
	if gotParam != "test" {
		t.Errorf("expected cmd=test (default), got cmd=%q", gotParam)
	}
}

// TestBaseScanner_GetBaselineWithTimingPOST verifies the POST baseline method.
func TestBaseScanner_GetBaselineWithTimingPOST(t *testing.T) {
	mock := &mockBaseHTTPClient{statusCode: 200, body: "post baseline"}
	b := newBaseScanner()
	b.client = mock

	parsedURL, _ := url.Parse("http://example.com/submit")
	allParams := map[string]string{"ip": "127.0.0.1", "submit": "Submit"}
	baseline, _ := b.getBaselineWithTimingPOST(context.Background(), parsedURL, allParams, "test")
	if baseline == nil {
		t.Fatal("expected non-nil baseline")
	}
	if mock.lastRequest.Method != http.MethodPost {
		t.Errorf("expected POST, got %s", mock.lastRequest.Method)
	}
}

// TestBaseScanner_GetBaselineWithTimingPOST_DefaultParamValue verifies that empty
// parameter values are replaced with the supplied defaultParamValue.
func TestBaseScanner_GetBaselineWithTimingPOST_DefaultParamValue(t *testing.T) {
	mock := &mockBaseHTTPClient{statusCode: 200, body: "ok"}
	b := newBaseScanner()
	b.client = mock

	parsedURL, _ := url.Parse("http://example.com/cmd")
	// The "cmd" parameter starts empty; the default "test" should be used.
	allParams := map[string]string{"cmd": "", "submit": "Submit"}
	b.getBaselineWithTimingPOST(context.Background(), parsedURL, allParams, "test")

	if mock.lastRequest == nil {
		t.Fatal("no request was made")
	}
	bodyBytes, _ := io.ReadAll(mock.lastRequest.Body)
	bodyStr := string(bodyBytes)
	if !strings.Contains(bodyStr, "cmd=test") {
		t.Errorf("expected cmd=test in body (empty replaced by default), got %q", bodyStr)
	}
}

// TestBaseScanner_GetBaselineWithTimingPOST_AllEmptyParamsReplaced verifies that ALL
// empty parameter values (not just the target parameter) are replaced with the default.
// This documents the intentional scope expansion vs. the original CMDi implementation
// that only substituted the target parameter.
func TestBaseScanner_GetBaselineWithTimingPOST_AllEmptyParamsReplaced(t *testing.T) {
	mock := &mockBaseHTTPClient{statusCode: 200, body: "ok"}
	b := newBaseScanner()
	b.client = mock

	parsedURL, _ := url.Parse("http://example.com/cmd")
	// "cmd" is the scan target; "extra" is an unrelated optional field — both empty.
	allParams := map[string]string{"cmd": "", "extra": "", "submit": "Submit"}
	b.getBaselineWithTimingPOST(context.Background(), parsedURL, allParams, "test")

	if mock.lastRequest == nil {
		t.Fatal("no request was made")
	}
	bodyBytes, _ := io.ReadAll(mock.lastRequest.Body)
	bodyStr := string(bodyBytes)
	// Both empty parameters should be replaced, not just the target.
	if !strings.Contains(bodyStr, "cmd=test") {
		t.Errorf("expected cmd=test in body, got %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "extra=test") {
		t.Errorf("expected extra=test in body (non-target empty param also replaced), got %q", bodyStr)
	}
}

// TestBaseScanner_GetBaselineWithTimingPOST_PopulatesDataFields verifies that the POST
// baseline populates DataWordCount, DataContent, and DataRowCount via analyzeResponse.
// This is a regression test for the behavioral fix that restores parity with the
// original SQLiScanner.getBaselineWithTimingPOST implementation.
func TestBaseScanner_GetBaselineWithTimingPOST_PopulatesDataFields(t *testing.T) {
	// Use a body that will produce non-zero DataWordCount via analyzeResponse.
	// A simple HTML table gives us table rows with data cells.
	tableBody := `<html><body><table>
		<tr><td>user1</td><td>password1</td></tr>
		<tr><td>user2</td><td>password2</td></tr>
	</table></body></html>`
	mock := &mockBaseHTTPClient{statusCode: 200, body: tableBody}
	b := newBaseScanner()
	b.client = mock

	parsedURL, _ := url.Parse("http://example.com/submit")
	allParams := map[string]string{"id": "1"}
	baseline, _ := b.getBaselineWithTimingPOST(context.Background(), parsedURL, allParams, "")
	if baseline == nil {
		t.Fatal("expected non-nil baseline")
	}
	if baseline.DataWordCount == 0 {
		t.Error("expected non-zero DataWordCount in POST baseline (regression: analyzeResponse must be called)")
	}
	if baseline.DataContent == "" {
		t.Error("expected non-empty DataContent in POST baseline")
	}
}

// TestBaseScanner_GetBaselineWithTimingPOST_NoDefaultParamValue verifies that empty
// parameter values are NOT replaced when defaultParamValue is "".
func TestBaseScanner_GetBaselineWithTimingPOST_NoDefaultParamValue(t *testing.T) {
	mock := &mockBaseHTTPClient{statusCode: 200, body: "ok"}
	b := newBaseScanner()
	b.client = mock

	parsedURL, _ := url.Parse("http://example.com/form")
	allParams := map[string]string{"field": ""}
	b.getBaselineWithTimingPOST(context.Background(), parsedURL, allParams, "")

	bodyBytes, _ := io.ReadAll(mock.lastRequest.Body)
	bodyStr := string(bodyBytes)
	// With no default, empty value stays empty ("field=" in form-encoded body).
	if !strings.Contains(bodyStr, "field=") {
		t.Errorf("expected field= in body, got %q", bodyStr)
	}
	// It should NOT be replaced with anything non-empty.
	if strings.Contains(bodyStr, "field=test") {
		t.Errorf("did not expect field=test, got %q", bodyStr)
	}
}

// TestBaseScanner_AuthConfig verifies that the auth config is applied to requests.
func TestBaseScanner_AuthConfig(t *testing.T) {
	mock := &mockBaseHTTPClient{statusCode: 200, body: "ok"}
	b := newBaseScanner()
	b.client = mock
	b.authConfig = &auth.AuthConfig{
		BasicAuth: "user:pass",
	}

	parsedURL, _ := url.Parse("http://example.com/page?id=1")
	_, err := b.makeRequest(context.Background(), parsedURL, "id", "val")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Authorization header was set
	authHeader := mock.lastRequest.Header.Get("Authorization")
	if authHeader == "" {
		t.Error("expected Authorization header to be set by authConfig")
	}
}

// TestBaseScanner_UserAgent verifies the User-Agent header is sent correctly.
func TestBaseScanner_UserAgent(t *testing.T) {
	customUA := "MyCustomAgent/1.0"
	mock := &mockBaseHTTPClient{statusCode: 200, body: "ok"}
	b := newBaseScanner()
	b.client = mock
	b.userAgent = customUA

	parsedURL, _ := url.Parse("http://example.com/page?id=1")
	b.makeRequest(context.Background(), parsedURL, "id", "val") //nolint:errcheck

	if mock.lastRequest.Header.Get("User-Agent") != customUA {
		t.Errorf("expected User-Agent %q, got %q", customUA, mock.lastRequest.Header.Get("User-Agent"))
	}
}

// TestBaseScanner_EmbeddedInSQLiScanner verifies that SQLiScanner correctly embeds
// BaseScanner and that field promotion works as expected.
func TestBaseScanner_EmbeddedInSQLiScanner(t *testing.T) {
	mock := &mockBaseHTTPClient{statusCode: 200, body: "ok"}
	scanner := NewSQLiScanner(WithSQLiHTTPClient(mock))

	// The promoted fields should be accessible via the scanner directly.
	if scanner.userAgent == "" {
		t.Error("expected non-empty userAgent via embedded BaseScanner")
	}
	if scanner.timeout == 0 {
		t.Error("expected non-zero timeout via embedded BaseScanner")
	}
	if scanner.client == nil {
		t.Error("expected non-nil client via embedded BaseScanner")
	}
}

// TestBaseScanner_EmbeddedInCMDiScanner verifies that CMDiScanner correctly embeds
// BaseScanner and that field promotion works as expected.
func TestBaseScanner_EmbeddedInCMDiScanner(t *testing.T) {
	mock := &mockBaseHTTPClient{statusCode: 200, body: "ok"}
	scanner := NewCMDiScanner(WithCMDiHTTPClient(mock))

	if scanner.userAgent == "" {
		t.Error("expected non-empty userAgent via embedded BaseScanner")
	}
	if scanner.timeout == 0 {
		t.Error("expected non-zero timeout via embedded BaseScanner")
	}
	if scanner.client == nil {
		t.Error("expected non-nil client via embedded BaseScanner")
	}
}

// TestBaseScanner_OptionFunctions verifies that all shared option functions correctly
// update the embedded BaseScanner fields.
func TestBaseScanner_OptionFunctions(t *testing.T) {
	customUA := "TestAgent/2.0"
	customTimeout := 45 * time.Second
	mockClient := &mockBaseHTTPClient{statusCode: 200, body: "ok"}
	authCfg := &auth.AuthConfig{
		BasicAuth: "user:pass",
	}
	limiter := ratelimit.NewLimiter(5)
	var nilTracer trace.Tracer // nil is a valid tracer (no-op)

	scanner := NewSQLiScanner(
		WithSQLiHTTPClient(mockClient),
		WithSQLiUserAgent(customUA),
		WithSQLiTimeout(customTimeout),
		WithSQLiAuth(authCfg),
		WithSQLiRateLimiter(limiter),
		WithSQLiTracer(nilTracer),
	)

	if scanner.userAgent != customUA {
		t.Errorf("expected userAgent %q, got %q", customUA, scanner.userAgent)
	}
	if scanner.timeout != customTimeout {
		t.Errorf("expected timeout %v, got %v", customTimeout, scanner.timeout)
	}
	if scanner.client != mockClient {
		t.Error("expected client to be mockClient")
	}
	if scanner.authConfig != authCfg {
		t.Error("expected authConfig to be set")
	}
	if scanner.rateLimiter != limiter {
		t.Error("expected rateLimiter to be set")
	}
}

// TestBaseScanner_RateLimitConfig verifies that WithSQLiRateLimitConfig creates a limiter.
func TestBaseScanner_RateLimitConfig(t *testing.T) {
	scanner := NewSQLiScanner(
		WithSQLiRateLimitConfig(ratelimit.Config{RequestsPerSecond: 10}),
	)
	if scanner.rateLimiter == nil {
		t.Error("expected non-nil rateLimiter after WithSQLiRateLimitConfig")
	}
}

// TestBaseScanner_MakeRequest_ClientError verifies that client errors are propagated.
func TestBaseScanner_MakeRequest_ClientError(t *testing.T) {
	mock := &mockBaseHTTPClient{err: fmt.Errorf("connection refused")}
	b := newBaseScanner()
	b.client = mock

	parsedURL, _ := url.Parse("http://example.com/page?id=1")
	result, err := b.makeRequest(context.Background(), parsedURL, "id", "payload")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if result != nil {
		t.Error("expected nil result on client error")
	}
}
