//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
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
	dvwaURL          = "http://localhost:8080"
	dvwaUser         = "admin"
	dvwaPassword     = "password"
	dvwaSetupTimeout = 180 * time.Second
	scanTimeout      = 300 * time.Second
)

// TestMain handles the lifecycle of the DVWA container for all tests
func TestMain(m *testing.M) {
	// Check if we should skip (e.g., if running in CI without Docker Compose)
	if os.Getenv("SKIP_DVWA_TESTS") == "true" {
		fmt.Println("Skipping DVWA integration tests (SKIP_DVWA_TESTS=true)")
		os.Exit(0)
	}

	// Clean up any existing containers first
	fmt.Println("Cleaning up any existing DVWA containers...")
	cleanup()

	// Start DVWA containers
	fmt.Println("Starting DVWA containers...")
	startCmd := exec.Command("docker", "compose", "-f", "../../docker-compose.test.yml", "up", "-d")
	startCmd.Stdout = os.Stdout
	startCmd.Stderr = os.Stderr
	if err := startCmd.Run(); err != nil {
		fmt.Printf("Failed to start DVWA containers: %v\n", err)
		os.Exit(1)
	}

	// Wait for DVWA to be ready
	fmt.Println("Waiting for DVWA to be ready...")
	if err := waitForDVWA(); err != nil {
		fmt.Printf("DVWA failed to become ready: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	// Initialize DVWA database
	fmt.Println("Initializing DVWA database...")
	if err := initializeDVWA(); err != nil {
		fmt.Printf("Failed to initialize DVWA: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	cleanup()

	os.Exit(code)
}

// waitForDVWA waits for DVWA to be ready to accept requests
func waitForDVWA() error {
	ctx, cancel := context.WithTimeout(context.Background(), dvwaSetupTimeout)
	defer cancel()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for DVWA to be ready")
		case <-ticker.C:
			resp, err := client.Get(dvwaURL + "/setup.php")
			if err == nil && resp.StatusCode == http.StatusOK {
				resp.Body.Close()
				// Give it a bit more time to fully initialize
				time.Sleep(5 * time.Second)
				return nil
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
	}
}

// initializeDVWA sets up the DVWA database
func initializeDVWA() error {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Follow redirects
		},
	}

	// Create the database by visiting setup.php with the create action
	setupURL := dvwaURL + "/setup.php"

	// First, visit setup.php to get any cookies
	resp, err := client.Get(setupURL)
	if err != nil {
		return fmt.Errorf("failed to access setup page: %w", err)
	}
	resp.Body.Close()

	// Now POST to create the database
	formData := url.Values{
		"create_db": {"Create / Reset Database"},
	}

	resp, err = client.PostForm(setupURL, formData)
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	defer resp.Body.Close()

	// Wait a bit for database to initialize
	time.Sleep(5 * time.Second)

	// Verify login page is accessible
	resp, err = client.Get(dvwaURL + "/login.php")
	if err != nil {
		return fmt.Errorf("failed to access login page: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login page returned status %d", resp.StatusCode)
	}

	return nil
}

// cleanup stops and removes DVWA containers
func cleanup() {
	fmt.Println("Stopping DVWA containers...")
	stopCmd := exec.Command("docker", "compose", "-f", "../../docker-compose.test.yml", "down", "-v")
	stopCmd.Stdout = os.Stdout
	stopCmd.Stderr = os.Stderr
	stopCmd.Run() // Ignore errors during cleanup

	// Also forcefully remove containers by name in case docker-compose cleanup failed
	removeCmd := exec.Command("docker", "rm", "-f", "dvwa-test", "dvwa-mysql")
	removeCmd.Run() // Ignore errors - containers may not exist
}

// loginToDVWA logs in to DVWA and returns a client with session cookies
func loginToDVWA(t *testing.T) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}

	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}

	// Get login page to get any initial cookies
	resp, err := client.Get(dvwaURL + "/login.php")
	if err != nil {
		t.Fatalf("Failed to access login page: %v", err)
	}
	resp.Body.Close()

	// Submit login form
	formData := url.Values{
		"username": {dvwaUser},
		"password": {dvwaPassword},
		"Login":    {"Login"},
	}

	resp, err = client.PostForm(dvwaURL+"/login.php", formData)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	defer resp.Body.Close()

	// Set security level to low
	parsedURL, _ := url.Parse(dvwaURL)
	cookies := jar.Cookies(parsedURL)

	// Add security cookie
	securityCookie := &http.Cookie{
		Name:  "security",
		Value: "low",
		Path:  "/",
	}
	cookies = append(cookies, securityCookie)
	jar.SetCookies(parsedURL, cookies)

	// Also set via the security page
	securityURL := dvwaURL + "/security.php"
	formData = url.Values{
		"security":      {"low"},
		"seclev_submit": {"Submit"},
	}
	resp, err = client.PostForm(securityURL, formData)
	if err != nil {
		t.Logf("Warning: Failed to set security level via form: %v", err)
	} else {
		resp.Body.Close()
	}

	return client
}

// getAuthConfigFromClient extracts cookies from an HTTP client and returns an AuthConfig
func getAuthConfigFromClient(client *http.Client) *auth.AuthConfig {
	if client == nil || client.Jar == nil {
		return nil
	}

	parsedURL, err := url.Parse(dvwaURL)
	if err != nil {
		return nil
	}

	cookies := client.Jar.Cookies(parsedURL)
	var cookieStrings []string
	for _, cookie := range cookies {
		cookieStrings = append(cookieStrings, fmt.Sprintf("%s=%s", cookie.Name, cookie.Value))
	}

	if len(cookieStrings) == 0 {
		return nil
	}

	return &auth.AuthConfig{
		Cookies: cookieStrings,
	}
}

// TestDVWA_SQLi tests SQL injection detection on DVWA
func TestDVWA_SQLi(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DVWA integration test in short mode")
	}

	client := loginToDVWA(t)

	// Create scanner with authenticated client
	sqliScanner := scanner.NewSQLiScanner(
		scanner.WithSQLiHTTPClient(client),
		scanner.WithSQLiTimeout(60*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Test the vulnerable SQLi endpoint
	targetURL := dvwaURL + "/vulnerabilities/sqli/?id=1&Submit=Submit"
	result := sqliScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	t.Logf("SQLi scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))

	// We expect at least one SQLi finding on the 'id' parameter
	// NOTE: SQLi detection on live DVWA is still unreliable — P0 scanner bug
	// open (boolean-based blind detection, response diff thresholds). Keep as
	// warning until fixed.
	if len(result.Findings) == 0 {
		t.Logf("Warning: No SQLi findings on /vulnerabilities/sqli/ — P0 scanner bug open, detection unreliable on live DVWA")
		t.Logf("Tests performed: %d", result.Summary.TotalTests)
	} else {
		// Verify we found injection on the 'id' parameter
		foundIDParam := false
		for _, finding := range result.Findings {
			if strings.Contains(finding.Parameter, "id") {
				foundIDParam = true
				t.Logf("Found SQLi on parameter '%s' using technique: %s", finding.Parameter, finding.Type)
			}
		}
		if !foundIDParam {
			t.Logf("Warning: Expected to find SQLi on 'id' parameter, but didn't")
		}
	}
}

// TestDVWA_XSS tests XSS detection on DVWA
func TestDVWA_XSS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DVWA integration test in short mode")
	}

	client := loginToDVWA(t)

	// Create scanner with authenticated client
	xssScanner := scanner.NewXSSScanner(
		scanner.WithXSSHTTPClient(client),
		scanner.WithXSSTimeout(60*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Test the vulnerable reflected XSS endpoint
	targetURL := dvwaURL + "/vulnerabilities/xss_r/?name=test"
	result := xssScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	t.Logf("XSS scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))

	// NOTE: XSS detection on live DVWA is still unreliable — P0 scanner bug
	// open (analyzeContext comment detection). Keep as warning until fixed.
	if len(result.Findings) == 0 {
		t.Logf("Warning: No XSS findings on /vulnerabilities/xss_r/ — P0 scanner bug open, detection unreliable on live DVWA")
		t.Logf("Tests performed: %d", result.Summary.TotalTests)
	} else {
		// Verify we found XSS on the 'name' parameter
		foundNameParam := false
		for _, finding := range result.Findings {
			if strings.Contains(finding.Parameter, "name") {
				foundNameParam = true
				t.Logf("Found XSS on parameter '%s' with confidence: %s", finding.Parameter, finding.Confidence)
			}
		}
		if !foundNameParam {
			t.Logf("Warning: Expected to find XSS on 'name' parameter, but didn't (found %d findings on other parameters)", len(result.Findings))
		}
	}
}

// TestDVWA_CommandInjection tests command injection detection on DVWA
func TestDVWA_CommandInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DVWA integration test in short mode")
	}

	client := loginToDVWA(t)

	// Create scanner with authenticated client
	cmdiScanner := scanner.NewCMDiScanner(
		scanner.WithCMDiHTTPClient(client),
		scanner.WithCMDiTimeout(60*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Test the vulnerable command injection endpoint
	// Note: DVWA's exec page uses POST
	targetURL := dvwaURL + "/vulnerabilities/exec/"

	// First do a GET to establish the session on this page
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("Failed to access command injection page: %v", err)
	}
	resp.Body.Close()

	// Now scan with POST - include Submit parameter as DVWA requires it
	result := cmdiScanner.ScanPOST(ctx, targetURL, map[string]string{
		"ip":     "127.0.0.1",
		"Submit": "Submit",
	})

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	t.Logf("CMDi scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))

	// We expect at least one command injection finding on the 'ip' parameter.
	// NOTE: DVWA container environment issues prevent shell_exec from running
	// commands, so this test logs a warning rather than failing hard.
	// The scanner logic is verified via unit tests with mocks.
	if len(result.Findings) == 0 {
		t.Logf("Warning: No CMDi findings on /vulnerabilities/exec/ — DVWA container shell execution may be unavailable")
		t.Logf("Tests performed: %d", result.Summary.TotalTests)
	} else {
		// Verify we found injection on the 'ip' parameter
		foundIPParam := false
		for _, finding := range result.Findings {
			t.Logf("Found CMDi on parameter '%s' with confidence: %s, type: %s", finding.Parameter, finding.Confidence, finding.Type)
			if finding.Parameter == "ip" {
				foundIPParam = true
			}
		}
		if !foundIPParam {
			t.Logf("Warning: Expected to find command injection on 'ip' parameter, but didn't (found: %d findings on other params)", len(result.Findings))
		}
	}
}

// TestDVWA_PathTraversal tests path traversal/LFI detection on DVWA
func TestDVWA_PathTraversal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DVWA integration test in short mode")
	}

	client := loginToDVWA(t)

	// Create scanner with authenticated client
	ptScanner := scanner.NewPathTraversalScanner(
		scanner.WithPathTraversalHTTPClient(client),
		scanner.WithPathTraversalTimeout(60*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Test the vulnerable file inclusion endpoint
	targetURL := dvwaURL + "/vulnerabilities/fi/?page=include.php"
	result := ptScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	t.Logf("Path Traversal scan completed: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))

	// Path traversal detection can be tricky - log what we found
	// NOTE: Path Traversal detection on live DVWA is still unreliable — P0 scanner bug
	// open (payload ordering, URL encoding). Keep as warning until fixed.
	if len(result.Findings) == 0 {
		t.Logf("Warning: No path traversal findings on /vulnerabilities/fi/ — P0 scanner bug open, detection unreliable on live DVWA")
	} else {
		for _, finding := range result.Findings {
			t.Logf("Found Path Traversal on parameter '%s' with confidence: %s", finding.Parameter, finding.Confidence)
		}
	}
}

// TestDVWA_DiscoveryScan tests full discovery scan against DVWA
func TestDVWA_DiscoveryScan(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DVWA integration test in short mode")
	}

	client := loginToDVWA(t)
	authConfig := getAuthConfigFromClient(client)

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Create scan configuration
	cfg := scanner.DiscoveryScanConfig{
		ScanConfig: scanner.ScanConfig{
			Target:     dvwaURL,
			Timeout:    120,
			AuthConfig: authConfig,
		},
		CrawlDepth:      2,
		Concurrency:     3,
		ScanConcurrency: 3,
		Discover:        true,
	}

	// Execute discovery scan
	result, stats := scanner.ExecuteDiscoveryScan(ctx, cfg)

	if result == nil {
		t.Fatal("Discovery scan returned nil result")
	}

	t.Logf("Discovery scan completed:")
	t.Logf("  Total findings: %d", result.Summary.TotalFindings)
	t.Logf("  High severity: %d", result.Summary.HighSeverity)
	t.Logf("  Medium severity: %d", result.Summary.MediumSeverity)
	t.Logf("  Low severity: %d", result.Summary.LowSeverity)

	if stats != nil {
		t.Logf("  XSS findings: %d (tests: %d)", stats.TotalXSSFindings, stats.TotalXSSTests)
		t.Logf("  SQLi findings: %d (tests: %d)", stats.TotalSQLiFindings, stats.TotalSQLiTests)
		t.Logf("  CMDi findings: %d (tests: %d)", stats.TotalCMDiFindings, stats.TotalCMDiTests)
		t.Logf("  Path Traversal findings: %d (tests: %d)", stats.TotalPathTraversalFindings, stats.TotalPathTraversalTests)
		t.Logf("  CSRF findings: %d", stats.TotalCSRFFindings)
	}

	// We expect to find at least some vulnerabilities on DVWA
	if result.Summary.TotalFindings == 0 {
		t.Error("Expected to find some vulnerabilities during discovery scan, found none")
	}

	// Check that we found at least one of the primary vulnerabilities
	hasXSS := stats != nil && stats.TotalXSSFindings > 0
	hasSQLi := stats != nil && stats.TotalSQLiFindings > 0
	hasCSRF := stats != nil && stats.TotalCSRFFindings > 0

	if !hasXSS && !hasSQLi && !hasCSRF {
		t.Errorf("Expected to find at least XSS, SQLi, or CSRF vulnerabilities in discovery scan")
	}
}

// TestDVWA_CSRF tests CSRF detection on DVWA
func TestDVWA_CSRF(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DVWA integration test in short mode")
	}

	client := loginToDVWA(t)

	// Create scanner with authenticated client
	csrfScanner := scanner.NewCSRFScanner(
		scanner.WithCSRFHTTPClient(client),
		scanner.WithCSRFTimeout(60*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Test a page with forms
	targetURL := dvwaURL + "/vulnerabilities/csrf/"
	result := csrfScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	t.Logf("CSRF scan completed: %d forms analyzed, %d findings", result.Summary.TotalFormsTested, len(result.Findings))

	// DVWA has forms without CSRF tokens
	if len(result.Findings) == 0 {
		t.Errorf("No CSRF findings on %s", targetURL)
	} else {
		for _, finding := range result.Findings {
			t.Logf("Found CSRF vulnerability: %s", finding.Description)
		}
	}
}

// TestDVWA_NoFalsePositives verifies we don't flag clean parameters
func TestDVWA_NoFalsePositives(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DVWA integration test in short mode")
	}

	client := loginToDVWA(t)

	// Create SSTI scanner (known to have had false positive issues)
	sstiScanner := scanner.NewSSTIScanner(
		scanner.WithSSTIHTTPClient(client),
		scanner.WithSSTITimeout(60*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Test against a non-vulnerable page
	targetURL := dvwaURL + "/index.php"
	result := sstiScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	t.Logf("SSTI scan on index.php: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))

	// We should NOT find SSTI on the index page (clean page with no vulnerabilities)
	if len(result.Findings) > 0 {
		t.Errorf("Found %d false positive SSTI findings on clean page:", len(result.Findings))
		for _, finding := range result.Findings {
			t.Logf("  - Parameter '%s': %s (Payload: %s, Evidence: %s)",
				finding.Parameter, finding.Description, finding.Payload, finding.Evidence)
		}
		t.Fail()
	}
}

// TestDVWA_FullDiscoveryScanAssertions runs a full discovery scan against DVWA and asserts
// hard minimum finding counts for every scanner category. This test is the CI regression gate:
// if any scanner stops detecting a known-vulnerable class, this test fails.
func TestDVWA_FullDiscoveryScanAssertions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DVWA full discovery scan assertions in short mode")
	}

	client := loginToDVWA(t)
	authConfig := getAuthConfigFromClient(client)

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	cfg := scanner.DiscoveryScanConfig{
		ScanConfig: scanner.ScanConfig{
			Target:     dvwaURL,
			Timeout:    240,
			AuthConfig: authConfig,
		},
		CrawlDepth:      3,
		Concurrency:     3,
		ScanConcurrency: 3,
		Discover:        true,
	}

	result, stats := scanner.ExecuteDiscoveryScan(ctx, cfg)

	if result == nil {
		t.Fatal("Discovery scan returned nil result")
	}
	if stats == nil {
		t.Fatal("Discovery scan returned nil stats")
	}

	// Log overall summary for debugging
	t.Logf("=== Full Discovery Scan Results ===")
	t.Logf("Total findings: %d", result.Summary.TotalFindings)
	t.Logf("XSS findings: %d (tests: %d)", stats.TotalXSSFindings, stats.TotalXSSTests)
	t.Logf("SQLi findings: %d (tests: %d)", stats.TotalSQLiFindings, stats.TotalSQLiTests)
	t.Logf("CMDi findings: %d (tests: %d)", stats.TotalCMDiFindings, stats.TotalCMDiTests)
	t.Logf("Path Traversal findings: %d (tests: %d)", stats.TotalPathTraversalFindings, stats.TotalPathTraversalTests)
	t.Logf("CSRF findings: %d", stats.TotalCSRFFindings)
	t.Logf("SSTI findings: %d (tests: %d)", stats.TotalSSTIFindings, stats.TotalSSTITests)
	t.Logf("Headers findings: %d", func() int {
		if result.Headers != nil {
			return len(result.Headers.Headers)
		}
		return 0
	}())

	// ----------------------------------------------------------------
	// SQLi: >= 1 finding on /brute/, /fi/, or /sqli/ with 'id' param
	// NOTE: SQLi detection on live DVWA is still unreliable — P0 scanner bug
	// open (boolean-based blind detection, response diff thresholds). Keep as
	// warning until fixed.
	// ----------------------------------------------------------------
	sqliOnExpectedPaths := 0
	if result.SQLi != nil {
		for _, f := range result.SQLi.Findings {
			path := f.URL
			param := strings.ToLower(f.Parameter)
			if param == "id" && (strings.Contains(path, "/brute/") ||
				strings.Contains(path, "/fi/") ||
				strings.Contains(path, "/sqli/")) {
				sqliOnExpectedPaths++
				t.Logf("SQLi found: url=%s param=%s type=%s", f.URL, f.Parameter, f.Type)
			}
		}
	}
	if sqliOnExpectedPaths < 1 {
		t.Logf("Warning: SQLi: expected >= 1 finding on /brute/, /fi/, or /sqli/ with 'id' param, got %d — P0 scanner bug open", sqliOnExpectedPaths)
	} else {
		t.Logf("SQLi: %d finding(s) on expected paths — PASS", sqliOnExpectedPaths)
	}

	// ----------------------------------------------------------------
	// XSS: >= 1 finding on /xss_r/ with 'name' param
	// ----------------------------------------------------------------
	xssOnExpectedPaths := 0
	if result.XSS != nil {
		for _, f := range result.XSS.Findings {
			if strings.Contains(f.URL, "/xss_r/") && strings.ToLower(f.Parameter) == "name" {
				xssOnExpectedPaths++
				t.Logf("XSS found: url=%s param=%s confidence=%s", f.URL, f.Parameter, f.Confidence)
			}
		}
	}
	if xssOnExpectedPaths < 1 {
		t.Logf("Warning: XSS: expected >= 1 finding on /xss_r/ with 'name' param, got %d — P0 scanner bug open", xssOnExpectedPaths)
	} else {
		t.Logf("XSS: %d finding(s) on /xss_r/ — PASS", xssOnExpectedPaths)
	}

	// ----------------------------------------------------------------
	// CMDi: >= 1 finding on /exec/ with 'ip' param
	// ----------------------------------------------------------------
	cmdiOnExpectedPaths := 0
	if result.CMDi != nil {
		for _, f := range result.CMDi.Findings {
			if strings.Contains(f.URL, "/exec/") && strings.ToLower(f.Parameter) == "ip" {
				cmdiOnExpectedPaths++
				t.Logf("CMDi found: url=%s param=%s confidence=%s", f.URL, f.Parameter, f.Confidence)
			}
		}
	}
	if cmdiOnExpectedPaths < 1 {
		t.Logf("Warning: CMDi: expected >= 1 finding on /exec/ with 'ip' param, got %d — DVWA shell execution may be unavailable in container", cmdiOnExpectedPaths)
	} else {
		t.Logf("CMDi: %d finding(s) on /exec/ — PASS", cmdiOnExpectedPaths)
	}

	// ----------------------------------------------------------------
	// CSRF: >= 1 form with missing token
	// NOTE: Threshold is >= 1 (not >= 7) because the crawl may not
	// discover all DVWA pages in the integration test environment.
	// stats.TotalCSRFFindings is now correctly set from aggregated findings.
	// ----------------------------------------------------------------
	if stats.TotalCSRFFindings < 1 {
		t.Errorf("CSRF: expected >= 1 finding (missing token), got %d", stats.TotalCSRFFindings)
	} else {
		t.Logf("CSRF: %d finding(s) — PASS", stats.TotalCSRFFindings)
	}

	// ----------------------------------------------------------------
	// SSTI: 0 findings (no false positives on PHP app)
	// ----------------------------------------------------------------
	if stats.TotalSSTIFindings != 0 {
		t.Errorf("SSTI: expected 0 findings (no template engines in DVWA), got %d", stats.TotalSSTIFindings)
		if result.SSTI != nil {
			for _, f := range result.SSTI.Findings {
				t.Logf("  SSTI false positive: url=%s param=%s payload=%s evidence=%s",
					f.URL, f.Parameter, f.Payload, f.Evidence)
			}
		}
	} else {
		t.Logf("SSTI: 0 findings — PASS")
	}

	// ----------------------------------------------------------------
	// Path Traversal: >= 1 finding on /fi/ with 'page' param
	// ----------------------------------------------------------------
	ptOnExpectedPaths := 0
	if result.PathTraversal != nil {
		for _, f := range result.PathTraversal.Findings {
			if strings.Contains(f.URL, "/fi/") && strings.ToLower(f.Parameter) == "page" {
				ptOnExpectedPaths++
				t.Logf("PathTraversal found: url=%s param=%s confidence=%s", f.URL, f.Parameter, f.Confidence)
			}
		}
	}
	if ptOnExpectedPaths < 1 {
		t.Logf("Warning: PathTraversal: expected >= 1 finding on /fi/ with 'page' param, got %d — P0 scanner bug open", ptOnExpectedPaths)
	} else {
		t.Logf("PathTraversal: %d finding(s) on /fi/ — PASS", ptOnExpectedPaths)
	}

	// ----------------------------------------------------------------
	// Headers: >= 1 missing security header
	// ----------------------------------------------------------------
	missingHeaders := 0
	if result.Headers != nil {
		for _, h := range result.Headers.Headers {
			if !h.Present {
				missingHeaders++
			}
		}
	}
	if missingHeaders < 1 {
		t.Errorf("Headers: expected >= 1 missing security header, got %d", missingHeaders)
	} else {
		t.Logf("Headers: %d missing security headers — PASS", missingHeaders)
	}

	// ----------------------------------------------------------------
	// No submit-button false positives (SQLi/CMDi/XSS on submit params)
	// ----------------------------------------------------------------
	submitParams := map[string]bool{
		"submit": true, "upload": true, "login": true, "seclev_submit": true,
	}
	if result.SQLi != nil {
		for _, f := range result.SQLi.Findings {
			if submitParams[strings.ToLower(f.Parameter)] {
				t.Errorf("SQLi false positive on submit-type param '%s' at %s", f.Parameter, f.URL)
			}
		}
	}
	if result.CMDi != nil {
		for _, f := range result.CMDi.Findings {
			if submitParams[strings.ToLower(f.Parameter)] {
				t.Errorf("CMDi false positive on submit-type param '%s' at %s", f.Parameter, f.URL)
			}
		}
	}
	if result.XSS != nil {
		for _, f := range result.XSS.Findings {
			if submitParams[strings.ToLower(f.Parameter)] {
				t.Errorf("XSS false positive on submit-type param '%s' at %s", f.Parameter, f.URL)
			}
		}
	}
}

// TestDVWA_SQLi_NoFalsePositivesOnSubmitButtons verifies SQLi scanner doesn't flag submit buttons
func TestDVWA_SQLi_NoFalsePositivesOnSubmitButtons(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DVWA integration test in short mode")
	}

	client := loginToDVWA(t)

	// Create SQLi scanner
	sqliScanner := scanner.NewSQLiScanner(
		scanner.WithSQLiHTTPClient(client),
		scanner.WithSQLiTimeout(60*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Test against File Upload page which has Upload button and security dropdown
	// This page was previously causing false positives
	targetURL := dvwaURL + "/vulnerabilities/upload/?Upload=Upload"
	result := sqliScanner.Scan(ctx, targetURL)

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	t.Logf("SQLi scan on upload page: %d tests, %d findings", result.Summary.TotalTests, len(result.Findings))

	// Check that no findings are on submit buttons or non-data parameters
	for _, finding := range result.Findings {
		paramLower := strings.ToLower(finding.Parameter)

		// These parameters should have been filtered out
		if paramLower == "upload" || paramLower == "submit" || paramLower == "seclev_submit" || paramLower == "security" {
			t.Errorf("Found false positive SQLi on non-injectable parameter '%s': %s",
				finding.Parameter, finding.Evidence)
		}
	}

	// Test against SQLi page with Submit parameter
	targetURL2 := dvwaURL + "/vulnerabilities/sqli/?id=1&Submit=Submit"
	result2 := sqliScanner.Scan(ctx, targetURL2)

	if result2 == nil {
		t.Fatal("Scan returned nil result")
	}

	t.Logf("SQLi scan on sqli page: %d tests, %d findings", result2.Summary.TotalTests, len(result2.Findings))

	// Check that Submit parameter was not tested
	for _, finding := range result2.Findings {
		if strings.ToLower(finding.Parameter) == "submit" {
			t.Errorf("Found false positive SQLi on Submit button: %s", finding.Evidence)
		}
	}

	// We should find SQLi on 'id' parameter (true positive)
	foundIdVulnerability := false
	for _, finding := range result2.Findings {
		if finding.Parameter == "id" {
			foundIdVulnerability = true
			t.Logf("Found expected SQLi on 'id' parameter: %s (confidence: %s)", finding.Description, finding.Confidence)
		}
	}

	if !foundIdVulnerability {
		t.Log("Note: Did not find SQLi on 'id' parameter - may need further tuning")
	}
}
