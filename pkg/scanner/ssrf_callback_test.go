package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/djannot/wast/pkg/callback"
)

// TestSSRFCallbackDetection tests SSRF detection using out-of-band callbacks.
func TestSSRFCallbackDetection(t *testing.T) {
	// Start a callback server
	callbackServer := callback.NewServer(callback.Config{
		HTTPAddr: ":0", // Use random port
		BaseURL:  "http://localhost:9999",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := callbackServer.Start(ctx); err != nil {
		t.Fatalf("Failed to start callback server: %v", err)
	}
	defer callbackServer.Stop(ctx)

	// Create a vulnerable test server that makes HTTP requests to parameters
	vulnerableServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the URL parameter and make a request to it (simulating SSRF)
		targetURL := r.URL.Query().Get("url")
		if targetURL != "" {
			// Make HTTP request to the target URL (SSRF vulnerability)
			go func() {
				client := &http.Client{Timeout: 2 * time.Second}
				client.Get(targetURL)
			}()
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer vulnerableServer.Close()

	// Update callback server's base URL to point to the actual server
	// In a real scenario, this would be a publicly accessible domain
	callbackServer = callback.NewServer(callback.Config{
		HTTPAddr: ":9999",
		BaseURL:  "http://localhost:9999",
	})
	if err := callbackServer.Start(ctx); err != nil {
		t.Fatalf("Failed to start callback server on port 9999: %v", err)
	}

	// Wait for callback server to start
	time.Sleep(100 * time.Millisecond)

	// Create SSRF scanner with callback server
	scanner := NewSSRFScanner(
		WithSSRFCallbackServer(callbackServer),
		WithSSRFTimeout(5*time.Second),
	)

	// Scan the vulnerable endpoint
	result := scanner.Scan(ctx, vulnerableServer.URL+"?url=test")

	// We should find at least one vulnerability via callback
	if len(result.Findings) == 0 {
		t.Error("Expected to find SSRF vulnerability via callback, but found none")
	}

	// Check if any finding is verified via callback
	foundCallback := false
	for _, finding := range result.Findings {
		if finding.Type == "callback" && finding.Verified {
			foundCallback = true
			t.Logf("Found verified SSRF via callback: %s", finding.Evidence)
			break
		}
	}

	if !foundCallback {
		t.Error("Expected to find verified callback-based SSRF finding")
	}
}

// TestSSRFCallbackDetectionPOST tests SSRF detection using POST with callbacks.
func TestSSRFCallbackDetectionPOST(t *testing.T) {
	// Start a callback server
	callbackServer := callback.NewServer(callback.Config{
		HTTPAddr: ":9998",
		BaseURL:  "http://localhost:9998",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := callbackServer.Start(ctx); err != nil {
		t.Fatalf("Failed to start callback server: %v", err)
	}
	defer callbackServer.Stop(ctx)

	// Wait for callback server to start
	time.Sleep(100 * time.Millisecond)

	// Create a vulnerable test server that makes HTTP requests from POST data
	vulnerableServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			targetURL := r.FormValue("url")
			if targetURL != "" {
				// Make HTTP request to the target URL (SSRF vulnerability)
				go func() {
					client := &http.Client{Timeout: 2 * time.Second}
					client.Get(targetURL)
				}()
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer vulnerableServer.Close()

	// Create SSRF scanner with callback server
	scanner := NewSSRFScanner(
		WithSSRFCallbackServer(callbackServer),
		WithSSRFTimeout(5*time.Second),
	)

	// Scan the vulnerable endpoint with POST
	params := map[string]string{
		"url": "https://example.com",
	}
	result := scanner.ScanPOST(ctx, vulnerableServer.URL, params)

	// We should find at least one vulnerability via callback
	if len(result.Findings) == 0 {
		t.Error("Expected to find SSRF vulnerability via callback, but found none")
	}

	// Check if any finding is verified via callback
	foundCallback := false
	for _, finding := range result.Findings {
		if finding.Type == "callback" && finding.Verified {
			foundCallback = true
			t.Logf("Found verified SSRF via callback (POST): %s", finding.Evidence)
			break
		}
	}

	if !foundCallback {
		t.Error("Expected to find verified callback-based SSRF finding (POST)")
	}
}

// TestSSRFNoCallbackWhenNotVulnerable tests that no false positives occur.
func TestSSRFNoCallbackWhenNotVulnerable(t *testing.T) {
	// Start a callback server
	callbackServer := callback.NewServer(callback.Config{
		HTTPAddr: ":9997",
		BaseURL:  "http://localhost:9997",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := callbackServer.Start(ctx); err != nil {
		t.Fatalf("Failed to start callback server: %v", err)
	}
	defer callbackServer.Stop(ctx)

	// Wait for callback server to start
	time.Sleep(100 * time.Millisecond)

	// Create a non-vulnerable test server that ignores URL parameters
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This server does NOT make requests to the URL parameter
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Safe server - no SSRF here"))
	}))
	defer safeServer.Close()

	// Create SSRF scanner with callback server
	scanner := NewSSRFScanner(
		WithSSRFCallbackServer(callbackServer),
		WithSSRFTimeout(2*time.Second),
	)

	// Scan the safe endpoint
	result := scanner.Scan(ctx, safeServer.URL+"?url=test")

	// Check that we don't get false positives from callbacks
	for _, finding := range result.Findings {
		if finding.Type == "callback" && finding.Verified {
			t.Errorf("False positive: Found callback-based SSRF finding on safe server: %s", finding.Evidence)
		}
	}
}

// TestCallbackURLGeneration tests that callback URLs are properly generated.
func TestCallbackURLGeneration(t *testing.T) {
	callbackServer := callback.NewServer(callback.Config{
		BaseURL: "http://callback.example.com:8888",
	})

	id := callbackServer.GenerateCallbackID()
	if id == "" {
		t.Error("Expected non-empty callback ID")
	}

	url := callbackServer.GetHTTPCallbackURL(id)
	expectedPrefix := "http://callback.example.com:8888/wast/"
	if len(url) <= len(expectedPrefix) {
		t.Errorf("Expected URL to start with %s, got %s", expectedPrefix, url)
	}

	if url[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("Expected URL to start with %s, got %s", expectedPrefix, url)
	}
}

// TestSSRFWithCallbackServerIntegration is a full integration test.
func TestSSRFWithCallbackServerIntegration(t *testing.T) {
	// This test simulates a real-world scenario with callback server

	// 1. Start callback server
	callbackServer := callback.NewServer(callback.Config{
		HTTPAddr: ":9996",
		BaseURL:  "http://localhost:9996",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := callbackServer.Start(ctx); err != nil {
		t.Fatalf("Failed to start callback server: %v", err)
	}
	defer callbackServer.Stop(ctx)

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// 2. Create vulnerable application
	vulnerableApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse URL parameter
		urlParam := r.URL.Query().Get("fetch")
		if urlParam == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Missing fetch parameter")
			return
		}

		// Vulnerable: Make request to user-controlled URL
		// In a real app, this might be fetching a webhook, RSS feed, etc.
		go func() {
			parsedURL, err := url.Parse(urlParam)
			if err != nil {
				return
			}

			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Get(parsedURL.String())
			if err == nil {
				resp.Body.Close()
			}
		}()

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Processing request...")
	}))
	defer vulnerableApp.Close()

	// 3. Run SSRF scan with callback detection
	scanner := NewSSRFScanner(
		WithSSRFCallbackServer(callbackServer),
		WithSSRFTimeout(5*time.Second),
	)

	targetURL := vulnerableApp.URL + "?fetch=https://example.com"
	result := scanner.Scan(ctx, targetURL)

	// 4. Verify results
	t.Logf("Scan completed. Total tests: %d, Vulnerabilities: %d",
		result.Summary.TotalTests, result.Summary.VulnerabilitiesFound)

	if len(result.Findings) == 0 {
		t.Fatal("Expected to find SSRF vulnerability, but found none")
	}

	// Look for callback-based findings
	var callbackFinding *SSRFFinding
	for i := range result.Findings {
		if result.Findings[i].Type == "callback" {
			callbackFinding = &result.Findings[i]
			break
		}
	}

	if callbackFinding == nil {
		t.Error("Expected to find callback-based SSRF finding")
		for _, f := range result.Findings {
			t.Logf("Found: Type=%s, Verified=%v, Payload=%s", f.Type, f.Verified, f.Payload)
		}
	} else {
		if !callbackFinding.Verified {
			t.Error("Callback finding should be marked as verified")
		}
		if callbackFinding.Confidence != "high" {
			t.Errorf("Expected high confidence for callback finding, got %s", callbackFinding.Confidence)
		}
		if callbackFinding.Severity != SeverityHigh {
			t.Errorf("Expected high severity for callback finding, got %s", callbackFinding.Severity)
		}
		t.Logf("✓ Successfully detected SSRF via callback: %s", callbackFinding.Evidence)
	}
}
