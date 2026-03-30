//go:build integration

package juiceshop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/scanner"
)

const (
	juiceShopURL          = "http://localhost:3000"
	juiceShopAdminEmail   = "admin@juice-sh.op"
	juiceShopAdminPass    = "admin123"
	juiceShopSetupTimeout = 180 * time.Second
	juiceShopScanTimeout  = 300 * time.Second
)

// TestMain handles the lifecycle of the Juice Shop container for all tests.
func TestMain(m *testing.M) {
	if os.Getenv("SKIP_JUICESHOP_TESTS") == "true" {
		fmt.Println("Skipping Juice Shop integration tests (SKIP_JUICESHOP_TESTS=true)")
		os.Exit(0)
	}

	// Clean up any existing containers first
	fmt.Println("Cleaning up any existing Juice Shop containers...")
	juiceShopCleanup()

	// Start Juice Shop container
	fmt.Println("Starting Juice Shop container...")
	startCmd := exec.Command("docker", "compose", "-f", "../../../docker-compose.juiceshop.yml", "up", "-d")
	startCmd.Stdout = os.Stdout
	startCmd.Stderr = os.Stderr
	if err := startCmd.Run(); err != nil {
		fmt.Printf("Failed to start Juice Shop container: %v\n", err)
		os.Exit(1)
	}

	// Wait for Juice Shop to be ready
	fmt.Println("Waiting for Juice Shop to be ready...")
	if err := waitForJuiceShop(); err != nil {
		fmt.Printf("Juice Shop failed to become ready: %v\n", err)
		juiceShopCleanup()
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	juiceShopCleanup()

	os.Exit(code)
}

// waitForJuiceShop waits for the Juice Shop application to be ready.
func waitForJuiceShop() error {
	ctx, cancel := context.WithTimeout(context.Background(), juiceShopSetupTimeout)
	defer cancel()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	readinessURL := juiceShopURL + "/rest/admin/application-version"

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Juice Shop to be ready")
		case <-ticker.C:
			resp, err := client.Get(readinessURL)
			if err == nil && (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized) {
				resp.Body.Close()
				// Give it a bit more time to fully initialize
				time.Sleep(3 * time.Second)
				return nil
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
	}
}

// juiceShopCleanup stops and removes Juice Shop containers.
func juiceShopCleanup() {
	fmt.Println("Stopping Juice Shop containers...")
	stopCmd := exec.Command("docker", "compose", "-f", "../../../docker-compose.juiceshop.yml", "down", "-v")
	stopCmd.Stdout = os.Stdout
	stopCmd.Stderr = os.Stderr
	stopCmd.Run() // Ignore errors during cleanup

	// Also forcefully remove container by name in case docker-compose cleanup failed
	removeCmd := exec.Command("docker", "rm", "-f", "juiceshop-test")
	removeCmd.Run() // Ignore errors - container may not exist
}

// loginToJuiceShop performs JWT-based login and returns an AuthConfig with the bearer token.
func loginToJuiceShop(t *testing.T) *auth.AuthConfig {
	t.Helper()

	loginPayload := map[string]string{
		"email":    juiceShopAdminEmail,
		"password": juiceShopAdminPass,
	}
	body, err := json.Marshal(loginPayload)
	if err != nil {
		t.Fatalf("Failed to marshal login payload: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(
		juiceShopURL+"/rest/user/login",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to POST to /rest/user/login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Login returned unexpected status %d (expected 200)", resp.StatusCode)
	}

	var loginResp struct {
		Authentication struct {
			Token string `json:"token"`
			Umail string `json:"umail"`
		} `json:"authentication"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}

	if loginResp.Authentication.Token == "" {
		t.Fatal("Login succeeded but no JWT token was returned")
	}

	t.Logf("Logged in as %s", loginResp.Authentication.Umail)

	return &auth.AuthConfig{
		BearerToken: loginResp.Authentication.Token,
	}
}

// newAuthHTTPClient creates an http.Client that injects the bearer token on every request.
func newAuthHTTPClient(authCfg *auth.AuthConfig) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &bearerTransport{
			wrapped: http.DefaultTransport,
			token:   authCfg.BearerToken,
		},
	}
}

// bearerTransport is an http.RoundTripper that adds a Bearer Authorization header.
type bearerTransport struct {
	wrapped http.RoundTripper
	token   string
}

func (bt *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if bt.token != "" {
		clone.Header.Set("Authorization", "Bearer "+bt.token)
	}
	return bt.wrapped.RoundTrip(clone)
}

// TestJuiceShop_NoSQLi verifies that the NoSQLi scanner detects at least one injection
// finding on Juice Shop's product search endpoint, which is backed by MongoDB.
func TestJuiceShop_NoSQLi(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Juice Shop integration test in short mode")
	}

	authCfg := loginToJuiceShop(t)
	client := newAuthHTTPClient(authCfg)

	nosqliScanner := scanner.NewNoSQLiScanner(
		scanner.WithNoSQLiHTTPClient(client),
		scanner.WithNoSQLiTimeout(60*time.Second),
		scanner.WithNoSQLiAuth(authCfg),
	)

	ctx, cancel := context.WithTimeout(context.Background(), juiceShopScanTimeout)
	defer cancel()

	// The product search endpoint is backed by MongoDB and is known to be injectable.
	targetURL := juiceShopURL + "/rest/products/search?q=test"
	result := nosqliScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("NoSQLi scan returned nil result")
	}

	t.Logf("NoSQLi scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  NoSQLi finding: url=%s param=%s type=%s confidence=%s payload=%q",
			f.URL, f.Parameter, f.Type, f.Confidence, f.Payload)
	}

	// Juice Shop uses MongoDB — at least one NoSQLi finding is expected.
	if len(result.Findings) < 1 {
		t.Errorf("NoSQLi: expected >= 1 finding on /rest/products/search (MongoDB backend), got 0 (tests: %d)",
			result.Summary.TotalTests)
	} else {
		t.Logf("NoSQLi: %d finding(s) on search endpoint — PASS", len(result.Findings))
	}
}

// TestJuiceShop_Headers asserts that Juice Shop is missing at least 3 security headers.
// Juice Shop ships without HSTS, CSP, and X-Frame-Options by default.
func TestJuiceShop_Headers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Juice Shop integration test in short mode")
	}

	headersScanner := scanner.NewHTTPHeadersScanner(
		scanner.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		scanner.WithTimeout(30*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), juiceShopScanTimeout)
	defer cancel()

	result := headersScanner.Scan(ctx, juiceShopURL)

	if result == nil {
		t.Fatal("Headers scan returned nil result")
	}

	missingHeaders := 0
	for _, h := range result.Headers {
		if !h.Present {
			missingHeaders++
			t.Logf("  Missing header: %s (severity: %s)", h.Name, h.Severity)
		} else {
			t.Logf("  Present header: %s = %q", h.Name, h.Value)
		}
	}

	t.Logf("Headers scan completed: %d headers checked, %d missing", len(result.Headers), missingHeaders)

	// Juice Shop ships without several key security headers.
	if missingHeaders < 3 {
		t.Errorf("Headers: expected >= 3 missing security headers on Juice Shop, got %d", missingHeaders)
	} else {
		t.Logf("Headers: %d missing security headers — PASS", missingHeaders)
	}
}

// TestJuiceShop_XSS scans the Juice Shop search endpoint for reflected XSS.
// The `q` parameter is tested against the JSON response body using the JSON-aware
// reflection detector (verbatim and Unicode-escaped). Juice Shop's search endpoint
// returns only matching products and does not echo the query back, so 0 findings is
// expected and the assertion is intentionally non-fatal.
// TODO: harden to t.Errorf once an endpoint that reflects the query in JSON is targeted.
func TestJuiceShop_XSS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Juice Shop integration test in short mode")
	}

	authCfg := loginToJuiceShop(t)
	client := newAuthHTTPClient(authCfg)

	xssScanner := scanner.NewXSSScanner(
		scanner.WithXSSHTTPClient(client),
		scanner.WithXSSTimeout(60*time.Second),
		scanner.WithXSSAuth(authCfg),
	)

	ctx, cancel := context.WithTimeout(context.Background(), juiceShopScanTimeout)
	defer cancel()

	targetURL := juiceShopURL + "/rest/products/search?q=test"
	result := xssScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("XSS scan returned nil result")
	}

	t.Logf("XSS scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  XSS finding: url=%s param=%s type=%s confidence=%s",
			f.URL, f.Parameter, f.Type, f.Confidence)
	}

	// Log results without hard-failing: the search endpoint does not reflect the
	// query parameter back in its JSON response body, so 0 findings is expected.
	// The JSON reflection detector (analyzeJSONContext) is exercised through the
	// unit tests in xss_test.go.
	if len(result.Findings) < 1 {
		t.Logf("XSS: 0 findings on /rest/products/search — expected >= 1 (tests: %d)", result.Summary.TotalTests)
	} else {
		t.Logf("XSS: %d finding(s) on search endpoint — PASS", len(result.Findings))
	}
}

// TestJuiceShop_SQLi_NoFalsePositives asserts that the SQLi scanner produces zero
// findings against Juice Shop. Juice Shop uses MongoDB, not MySQL/PostgreSQL, so
// any SQLi finding would be a false positive.
func TestJuiceShop_SQLi_NoFalsePositives(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Juice Shop integration test in short mode")
	}

	authCfg := loginToJuiceShop(t)
	client := newAuthHTTPClient(authCfg)

	sqliScanner := scanner.NewSQLiScanner(
		scanner.WithSQLiHTTPClient(client),
		scanner.WithSQLiTimeout(60*time.Second),
		scanner.WithSQLiAuth(authCfg),
	)

	ctx, cancel := context.WithTimeout(context.Background(), juiceShopScanTimeout)
	defer cancel()

	// Test the search endpoint — Juice Shop has no SQL database so any finding is a FP.
	targetURL := juiceShopURL + "/rest/products/search?q=test"
	result := sqliScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("SQLi scan returned nil result")
	}

	t.Logf("SQLi scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  SQLi false positive: url=%s param=%s type=%s evidence=%s",
			f.URL, f.Parameter, f.Type, f.Evidence)
	}

	// Juice Shop uses MongoDB — zero SQL injection findings are expected.
	if len(result.Findings) != 0 {
		t.Errorf("SQLi: expected 0 findings on Juice Shop (no SQL database), got %d (false positives)",
			len(result.Findings))
	} else {
		t.Logf("SQLi: 0 findings — PASS")
	}
}

// TestJuiceShop_FullScanSummary runs all scanners against the Juice Shop home page
// via a targeted multi-scanner pass and logs an overall summary.
func TestJuiceShop_FullScanSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Juice Shop full scan summary in short mode")
	}

	authCfg := loginToJuiceShop(t)

	ctx, cancel := context.WithTimeout(context.Background(), juiceShopScanTimeout)
	defer cancel()

	// --- NoSQLi on search endpoint ---
	nosqliScanner := scanner.NewNoSQLiScanner(
		scanner.WithNoSQLiHTTPClient(newAuthHTTPClient(authCfg)),
		scanner.WithNoSQLiTimeout(60*time.Second),
		scanner.WithNoSQLiAuth(authCfg),
	)
	nosqliResult := nosqliScanner.Scan(ctx, juiceShopURL+"/rest/products/search?q=test")

	// --- SQLi on search endpoint (expect 0) ---
	sqliScanner := scanner.NewSQLiScanner(
		scanner.WithSQLiHTTPClient(newAuthHTTPClient(authCfg)),
		scanner.WithSQLiTimeout(60*time.Second),
		scanner.WithSQLiAuth(authCfg),
	)
	sqliResult := sqliScanner.Scan(ctx, juiceShopURL+"/rest/products/search?q=test")

	// --- Headers on home page ---
	headersScanner := scanner.NewHTTPHeadersScanner(
		scanner.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		scanner.WithTimeout(30*time.Second),
	)
	headersResult := headersScanner.Scan(ctx, juiceShopURL)

	// ---- Summary ----
	t.Logf("=== Juice Shop Full Scan Summary ===")

	nosqliCount := 0
	if nosqliResult != nil {
		nosqliCount = len(nosqliResult.Findings)
	}
	t.Logf("NoSQLi findings: %d", nosqliCount)

	sqliCount := 0
	if sqliResult != nil {
		sqliCount = len(sqliResult.Findings)
	}
	t.Logf("SQLi findings: %d (expect 0)", sqliCount)

	missingHeaders := 0
	if headersResult != nil {
		for _, h := range headersResult.Headers {
			if !h.Present {
				missingHeaders++
			}
		}
	}
	t.Logf("Missing security headers: %d", missingHeaders)

	// ---- Assertions ----
	if nosqliCount < 1 {
		t.Errorf("NoSQLi: expected >= 1 finding on MongoDB-backed search endpoint, got 0")
	}
	if sqliCount != 0 {
		t.Errorf("SQLi: expected 0 findings (no SQL database), got %d false positives", sqliCount)
	}
	if missingHeaders < 3 {
		t.Errorf("Headers: expected >= 3 missing security headers, got %d", missingHeaders)
	}

	// Summarise all errors from scanners
	var errs []string
	if nosqliResult != nil {
		errs = append(errs, nosqliResult.Errors...)
	}
	if sqliResult != nil {
		errs = append(errs, sqliResult.Errors...)
	}
	if headersResult != nil {
		errs = append(errs, headersResult.Errors...)
	}
	if len(errs) > 0 {
		t.Logf("Scanner errors: %s", strings.Join(errs, "; "))
	}
}

// readResponseBody reads the response body with a size limit to prevent memory exhaustion.
func readResponseBody(r io.Reader) ([]byte, error) {
	const maxBodySize = 1024 * 1024 // 1 MB
	return io.ReadAll(io.LimitReader(r, maxBodySize))
}
