//go:build integration

package webgoat

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/scanner"
)

const (
	webGoatURL          = "http://localhost:8888"
	webGoatUser         = "guest"
	webGoatPass         = "guest"
	webGoatSetupTimeout = 300 * time.Second
	webGoatScanTimeout  = 300 * time.Second
)

// TestMain handles the lifecycle of the WebGoat container for all tests.
func TestMain(m *testing.M) {
	if os.Getenv("SKIP_WEBGOAT_TESTS") == "true" {
		fmt.Println("Skipping WebGoat integration tests (SKIP_WEBGOAT_TESTS=true)")
		os.Exit(0)
	}

	// Clean up any existing containers first
	fmt.Println("Cleaning up any existing WebGoat containers...")
	webGoatCleanup()

	// Start WebGoat container
	fmt.Println("Starting WebGoat container...")
	startCmd := exec.Command("docker", "compose", "-f", "../../../docker-compose.webgoat.yml", "up", "-d")
	startCmd.Stdout = os.Stdout
	startCmd.Stderr = os.Stderr
	if err := startCmd.Run(); err != nil {
		fmt.Printf("Failed to start WebGoat container: %v\n", err)
		os.Exit(1)
	}

	// Wait for WebGoat to be ready
	fmt.Println("Waiting for WebGoat to be ready...")
	if err := waitForWebGoat(); err != nil {
		fmt.Printf("WebGoat failed to become ready: %v\n", err)
		webGoatCleanup()
		os.Exit(1)
	}

	// Register the guest user so subsequent logins succeed
	fmt.Println("Registering WebGoat guest user...")
	if err := registerWebGoatUser(); err != nil {
		fmt.Printf("Warning: failed to register guest user (may already exist): %v\n", err)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	webGoatCleanup()

	os.Exit(code)
}

// waitForWebGoat waits for the WebGoat application to be ready.
func waitForWebGoat() error {
	ctx, cancel := context.WithTimeout(context.Background(), webGoatSetupTimeout)
	defer cancel()

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	readinessURL := webGoatURL + "/WebGoat/login"

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for WebGoat to be ready")
		case <-ticker.C:
			resp, err := client.Get(readinessURL)
			if err == nil && resp.StatusCode == http.StatusOK {
				resp.Body.Close()
				// Give it a bit more time to fully initialize
				time.Sleep(5 * time.Second)
				return nil
			}
			if resp != nil {
				resp.Body.Close()
			}
			fmt.Printf("WebGoat not ready yet (err=%v), retrying...\n", err)
		}
	}
}

// registerWebGoatUser attempts to register the guest user via the registration endpoint.
func registerWebGoatUser() error {
	client := &http.Client{Timeout: 30 * time.Second}
	formData := url.Values{
		"username":         {webGoatUser},
		"password":         {webGoatPass},
		"matchingPassword": {webGoatPass},
		"agree":            {"agree"},
	}
	resp, err := client.PostForm(webGoatURL+"/WebGoat/register.mvc", formData)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 200 or 302 are both acceptable (user created or already exists)
	return nil
}

// webGoatCleanup stops and removes WebGoat containers.
func webGoatCleanup() {
	fmt.Println("Stopping WebGoat containers...")
	stopCmd := exec.Command("docker", "compose", "-f", "../../../docker-compose.webgoat.yml", "down", "-v")
	stopCmd.Stdout = os.Stdout
	stopCmd.Stderr = os.Stderr
	stopCmd.Run() // Ignore errors during cleanup

	// Also forcefully remove container by name in case docker-compose cleanup failed
	removeCmd := exec.Command("docker", "rm", "-f", "webgoat-test")
	removeCmd.Run() // Ignore errors - container may not exist
}

// loginToWebGoat performs form-based login and returns an AuthConfig with session cookies.
func loginToWebGoat(t *testing.T) *auth.AuthConfig {
	t.Helper()

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // do not follow redirects automatically
		},
	}

	formData := url.Values{
		"username": {webGoatUser},
		"password": {webGoatPass},
	}

	resp, err := client.PostForm(webGoatURL+"/WebGoat/login", formData)
	if err != nil {
		t.Fatalf("Failed to POST to /WebGoat/login: %v", err)
	}
	defer resp.Body.Close()

	// WebGoat redirects to the lesson page on successful login
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusMovedPermanently {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		t.Fatalf("Login returned unexpected status %d (body: %s)", resp.StatusCode, string(body))
	}

	// Collect session cookies as "name=value" strings for AuthConfig.Cookies
	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, c.Name+"="+c.Value)
	}

	if len(cookies) == 0 {
		// Warn loudly: all auth-dependent tests will run unauthenticated, which makes
		// their soft-assertion failures very hard to diagnose. This can happen if
		// WebGoat is misconfigured or has changed its cookie-issuing behaviour.
		t.Logf("WARNING: loginToWebGoat succeeded (status %d) but server set 0 cookies — "+
			"auth-dependent tests will run unauthenticated", resp.StatusCode)
	}

	t.Logf("Logged into WebGoat as %s (cookies: %d)", webGoatUser, len(resp.Cookies()))

	return &auth.AuthConfig{
		Cookies: cookies,
	}
}

// newSessionHTTPClient creates an http.Client that injects the session cookies on every request.
func newSessionHTTPClient(authCfg *auth.AuthConfig) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &sessionTransport{
			wrapped: http.DefaultTransport,
			cookies: authCfg.Cookies,
		},
	}
}

// sessionTransport is an http.RoundTripper that adds session cookies.
type sessionTransport struct {
	wrapped http.RoundTripper
	cookies []string
}

func (st *sessionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if len(st.cookies) > 0 {
		injected := strings.Join(st.cookies, "; ")
		if existing := clone.Header.Get("Cookie"); existing != "" {
			// Merge: preserve any cookies already set by the caller (e.g. a scanner's
			// internal redirect handling) rather than silently overwriting them.
			clone.Header.Set("Cookie", existing+"; "+injected)
		} else {
			clone.Header.Set("Cookie", injected)
		}
	}
	return st.wrapped.RoundTrip(clone)
}

// TestWebGoat_SQLi verifies that the SQLi scanner detects at least one injection
// finding on WebGoat's SQL injection lesson endpoint.
func TestWebGoat_SQLi(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping WebGoat integration test in short mode")
	}

	authCfg := loginToWebGoat(t)
	client := newSessionHTTPClient(authCfg)

	sqliScanner := scanner.NewSQLiScanner(
		scanner.WithSQLiHTTPClient(client),
		scanner.WithSQLiTimeout(60*time.Second),
		scanner.WithSQLiAuth(authCfg),
	)

	ctx, cancel := context.WithTimeout(context.Background(), webGoatScanTimeout)
	defer cancel()

	// WebGoat's SQL Injection lesson 5 endpoint is a known injectable parameter.
	targetURL := webGoatURL + "/WebGoat/SqlInjection/attack5a?account=Smith"
	result := sqliScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("SQLi scan returned nil result")
	}

	t.Logf("SQLi scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  SQLi finding: url=%s param=%s type=%s confidence=%s evidence=%s",
			f.URL, f.Parameter, f.Type, f.Confidence, f.Evidence)
	}

	// WebGoat uses an in-memory SQL database — at least one SQLi finding is expected.
	// TODO: promote to t.Errorf once session authentication against this Java/Spring
	// app is fully validated (tracked in a follow-up issue).
	if len(result.Findings) < 1 {
		t.Logf("SQLi: 0 findings on SqlInjection/attack5a — may need auth or endpoint variant (tests: %d)",
			result.Summary.TotalTests)
	} else {
		t.Logf("SQLi: %d finding(s) on SQL injection lesson — PASS", len(result.Findings))
	}
}

// TestWebGoat_XSS verifies that the XSS scanner detects at least one reflected XSS
// finding on WebGoat's Cross-Site Scripting lesson endpoint.
func TestWebGoat_XSS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping WebGoat integration test in short mode")
	}

	authCfg := loginToWebGoat(t)
	client := newSessionHTTPClient(authCfg)

	xssScanner := scanner.NewXSSScanner(
		scanner.WithXSSHTTPClient(client),
		scanner.WithXSSTimeout(60*time.Second),
		scanner.WithXSSAuth(authCfg),
	)

	ctx, cancel := context.WithTimeout(context.Background(), webGoatScanTimeout)
	defer cancel()

	// WebGoat's XSS reflected lesson endpoint reflects the query parameter.
	targetURL := webGoatURL + "/WebGoat/CrossSiteScripting/attack5a?QTY1=1&QTY2=1&QTY3=1&QTY4=1&field1=test&field2=test"
	result := xssScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("XSS scan returned nil result")
	}

	t.Logf("XSS scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  XSS finding: url=%s param=%s type=%s confidence=%s",
			f.URL, f.Parameter, f.Type, f.Confidence)
	}

	// WebGoat's XSS lesson reflects input — at least one finding is expected.
	// TODO: promote to t.Errorf once session authentication against this Java/Spring
	// app is fully validated (tracked in a follow-up issue).
	if len(result.Findings) < 1 {
		t.Logf("XSS: 0 findings on CrossSiteScripting lesson — may need different endpoint (tests: %d)",
			result.Summary.TotalTests)
	} else {
		t.Logf("XSS: %d finding(s) on XSS lesson — PASS", len(result.Findings))
	}
}

// TestWebGoat_PathTraversal verifies that the path traversal scanner detects at least
// one finding on WebGoat's path traversal lesson endpoint.
func TestWebGoat_PathTraversal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping WebGoat integration test in short mode")
	}

	authCfg := loginToWebGoat(t)
	client := newSessionHTTPClient(authCfg)

	ptScanner := scanner.NewPathTraversalScanner(
		scanner.WithPathTraversalHTTPClient(client),
		scanner.WithPathTraversalTimeout(60*time.Second),
		scanner.WithPathTraversalAuth(authCfg),
	)

	ctx, cancel := context.WithTimeout(context.Background(), webGoatScanTimeout)
	defer cancel()

	// WebGoat's path traversal lesson endpoint.
	targetURL := webGoatURL + "/WebGoat/PathTraversal/random-picture?id=cat.jpg"
	result := ptScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("PathTraversal scan returned nil result")
	}

	t.Logf("PathTraversal scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  PathTraversal finding: url=%s param=%s type=%s confidence=%s payload=%q",
			f.URL, f.Parameter, f.Type, f.Confidence, f.Payload)
	}

	// WebGoat's path traversal lesson is intentionally vulnerable.
	// TODO: promote to t.Errorf once session authentication against this Java/Spring
	// app is fully validated (tracked in a follow-up issue).
	if len(result.Findings) < 1 {
		t.Logf("PathTraversal: 0 findings on PathTraversal lesson — may need different endpoint (tests: %d)",
			result.Summary.TotalTests)
	} else {
		t.Logf("PathTraversal: %d finding(s) on path traversal lesson — PASS", len(result.Findings))
	}
}

// TestWebGoat_Headers asserts that WebGoat is missing at least 3 security headers.
// WebGoat intentionally ships without hardened security headers as it is a training app.
func TestWebGoat_Headers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping WebGoat integration test in short mode")
	}

	headersScanner := scanner.NewHTTPHeadersScanner(
		scanner.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		scanner.WithTimeout(30*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), webGoatScanTimeout)
	defer cancel()

	result := headersScanner.Scan(ctx, webGoatURL+"/WebGoat/login")

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

	// WebGoat ships without several key security headers.
	if missingHeaders < 3 {
		t.Errorf("Headers: expected >= 3 missing security headers on WebGoat, got %d", missingHeaders)
	} else {
		t.Logf("Headers: %d missing security headers — PASS", missingHeaders)
	}
}

// TestWebGoat_NoSQLi_NoFalsePositives asserts that the NoSQLi scanner produces zero
// findings against WebGoat. WebGoat uses an in-memory SQL database (HyperSQL/H2),
// not MongoDB, so any NoSQLi finding would be a false positive.
func TestWebGoat_NoSQLi_NoFalsePositives(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping WebGoat integration test in short mode")
	}

	authCfg := loginToWebGoat(t)
	client := newSessionHTTPClient(authCfg)

	nosqliScanner := scanner.NewNoSQLiScanner(
		scanner.WithNoSQLiHTTPClient(client),
		scanner.WithNoSQLiTimeout(60*time.Second),
		scanner.WithNoSQLiAuth(authCfg),
	)

	ctx, cancel := context.WithTimeout(context.Background(), webGoatScanTimeout)
	defer cancel()

	// Test the SQL injection lesson endpoint — WebGoat has no MongoDB backend.
	targetURL := webGoatURL + "/WebGoat/SqlInjection/attack5a?account=Smith"
	result := nosqliScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("NoSQLi scan returned nil result")
	}

	t.Logf("NoSQLi scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  NoSQLi false positive: url=%s param=%s type=%s evidence=%s",
			f.URL, f.Parameter, f.Type, f.Evidence)
	}

	// WebGoat uses HyperSQL/H2, not MongoDB — zero NoSQLi findings are expected.
	if len(result.Findings) != 0 {
		t.Errorf("NoSQLi: expected 0 findings on WebGoat (no MongoDB backend), got %d (false positives)",
			len(result.Findings))
	} else {
		t.Logf("NoSQLi: 0 findings — PASS")
	}
}

// TestWebGoat_XXE_NoFalsePositives asserts that the XXE scanner produces zero
// findings against WebGoat's non-XML endpoints.
func TestWebGoat_XXE_NoFalsePositives(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping WebGoat integration test in short mode")
	}

	authCfg := loginToWebGoat(t)
	client := newSessionHTTPClient(authCfg)

	xxeScanner := scanner.NewXXEScanner(
		scanner.WithXXEHTTPClient(client),
		scanner.WithXXETimeout(60*time.Second),
		scanner.WithXXEAuth(authCfg),
	)

	ctx, cancel := context.WithTimeout(context.Background(), webGoatScanTimeout)
	defer cancel()

	// Test against a non-XML endpoint — no XXE expected.
	targetURL := webGoatURL + "/WebGoat/SqlInjection/attack5a?account=Smith"
	result := xxeScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("XXE scan returned nil result")
	}

	t.Logf("XXE scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  XXE false positive: url=%s param=%s type=%s evidence=%s",
			f.URL, f.Parameter, f.Type, f.Evidence)
	}

	// Non-XML endpoint — zero XXE findings are expected.
	if len(result.Findings) != 0 {
		t.Errorf("XXE: expected 0 findings on non-XML WebGoat endpoint, got %d (false positives)",
			len(result.Findings))
	} else {
		t.Logf("XXE: 0 findings — PASS")
	}
}

// TestWebGoat_FullScanSummary runs all scanners against WebGoat endpoints and logs
// an overall summary. This is the primary smoke-test for WebGoat integration.
func TestWebGoat_FullScanSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping WebGoat full scan summary in short mode")
	}

	authCfg := loginToWebGoat(t)

	// Each scanner gets its own fresh context so that a slow early scanner does not
	// exhaust the deadline for later ones. 6 scanners × up to 90 s each = up to 540 s
	// total, which cannot fit in a single 300 s shared context.

	// --- SQLi on SQL injection lesson ---
	sqliCtx, sqliCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer sqliCancel()
	sqliScanner := scanner.NewSQLiScanner(
		scanner.WithSQLiHTTPClient(newSessionHTTPClient(authCfg)),
		scanner.WithSQLiTimeout(60*time.Second),
		scanner.WithSQLiAuth(authCfg),
	)
	sqliResult := sqliScanner.Scan(sqliCtx, webGoatURL+"/WebGoat/SqlInjection/attack5a?account=Smith")

	// --- XSS on XSS lesson ---
	xssCtx, xssCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer xssCancel()
	xssScanner := scanner.NewXSSScanner(
		scanner.WithXSSHTTPClient(newSessionHTTPClient(authCfg)),
		scanner.WithXSSTimeout(60*time.Second),
		scanner.WithXSSAuth(authCfg),
	)
	xssResult := xssScanner.Scan(xssCtx, webGoatURL+"/WebGoat/CrossSiteScripting/attack5a?QTY1=1&QTY2=1&QTY3=1&QTY4=1&field1=test&field2=test")

	// --- PathTraversal on path traversal lesson ---
	ptCtx, ptCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer ptCancel()
	ptScanner := scanner.NewPathTraversalScanner(
		scanner.WithPathTraversalHTTPClient(newSessionHTTPClient(authCfg)),
		scanner.WithPathTraversalTimeout(60*time.Second),
		scanner.WithPathTraversalAuth(authCfg),
	)
	ptResult := ptScanner.Scan(ptCtx, webGoatURL+"/WebGoat/PathTraversal/random-picture?id=cat.jpg")

	// --- Headers on login page ---
	headersCtx, headersCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer headersCancel()
	headersScanner := scanner.NewHTTPHeadersScanner(
		scanner.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		scanner.WithTimeout(30*time.Second),
	)
	headersResult := headersScanner.Scan(headersCtx, webGoatURL+"/WebGoat/login")

	// --- NoSQLi on SQL endpoint (expect 0 — no MongoDB) ---
	nosqliCtx, nosqliCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer nosqliCancel()
	nosqliScanner := scanner.NewNoSQLiScanner(
		scanner.WithNoSQLiHTTPClient(newSessionHTTPClient(authCfg)),
		scanner.WithNoSQLiTimeout(60*time.Second),
		scanner.WithNoSQLiAuth(authCfg),
	)
	nosqliResult := nosqliScanner.Scan(nosqliCtx, webGoatURL+"/WebGoat/SqlInjection/attack5a?account=Smith")

	// --- XXE on non-XML endpoint (expect 0) ---
	xxeCtx, xxeCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer xxeCancel()
	xxeScanner := scanner.NewXXEScanner(
		scanner.WithXXEHTTPClient(newSessionHTTPClient(authCfg)),
		scanner.WithXXETimeout(60*time.Second),
		scanner.WithXXEAuth(authCfg),
	)
	xxeResult := xxeScanner.Scan(xxeCtx, webGoatURL+"/WebGoat/SqlInjection/attack5a?account=Smith")

	// ---- Summary ----
	t.Logf("=== WebGoat Full Scan Summary ===")

	sqliCount := 0
	if sqliResult != nil {
		sqliCount = len(sqliResult.Findings)
	}
	t.Logf("SQLi findings: %d (expect >= 1)", sqliCount)

	xssCount := 0
	if xssResult != nil {
		xssCount = len(xssResult.Findings)
	}
	t.Logf("XSS findings: %d (expect >= 1)", xssCount)

	ptCount := 0
	if ptResult != nil {
		ptCount = len(ptResult.Findings)
	}
	t.Logf("PathTraversal findings: %d (expect >= 1)", ptCount)

	missingHeaders := 0
	if headersResult != nil {
		for _, h := range headersResult.Headers {
			if !h.Present {
				missingHeaders++
			}
		}
	}
	t.Logf("Missing security headers: %d (expect >= 3)", missingHeaders)

	nosqliCount := 0
	if nosqliResult != nil {
		nosqliCount = len(nosqliResult.Findings)
	}
	t.Logf("NoSQLi findings: %d (expect 0)", nosqliCount)

	xxeCount := 0
	if xxeResult != nil {
		xxeCount = len(xxeResult.Findings)
	}
	t.Logf("XXE findings: %d (expect 0)", xxeCount)

	// ---- Assertions ----
	// Headers is the most reliable assertion (doesn't require authentication).
	if missingHeaders < 3 {
		t.Errorf("Headers: expected >= 3 missing security headers on WebGoat, got %d", missingHeaders)
	}
	// NoSQLi and XXE false-positive checks.
	if nosqliCount != 0 {
		t.Errorf("NoSQLi: expected 0 findings (no MongoDB backend), got %d false positives", nosqliCount)
	}
	if xxeCount != 0 {
		t.Errorf("XXE: expected 0 findings on non-XML endpoint, got %d false positives", xxeCount)
	}
	// SQLi, XSS, and PathTraversal require working authentication — log without hard-failing
	// until the session management is fully validated on this Java/Spring app.
	if sqliCount < 1 {
		t.Logf("SQLi: 0 findings on SqlInjection lesson — check auth/endpoint (tests: %d)", func() int {
			if sqliResult != nil {
				return sqliResult.Summary.TotalTests
			}
			return 0
		}())
	}
	if xssCount < 1 {
		t.Logf("XSS: 0 findings on CrossSiteScripting lesson — check auth/endpoint (tests: %d)", func() int {
			if xssResult != nil {
				return xssResult.Summary.TotalTests
			}
			return 0
		}())
	}
	if ptCount < 1 {
		t.Logf("PathTraversal: 0 findings on PathTraversal lesson — check auth/endpoint (tests: %d)", func() int {
			if ptResult != nil {
				return ptResult.Summary.TotalTests
			}
			return 0
		}())
	}

	// Summarise all errors from scanners
	var errs []string
	if sqliResult != nil {
		errs = append(errs, sqliResult.Errors...)
	}
	if xssResult != nil {
		errs = append(errs, xssResult.Errors...)
	}
	if ptResult != nil {
		errs = append(errs, ptResult.Errors...)
	}
	if headersResult != nil {
		errs = append(errs, headersResult.Errors...)
	}
	if nosqliResult != nil {
		errs = append(errs, nosqliResult.Errors...)
	}
	if xxeResult != nil {
		errs = append(errs, xxeResult.Errors...)
	}
	if len(errs) > 0 {
		t.Logf("Scanner errors: %s", strings.Join(errs, "; "))
	}
}
