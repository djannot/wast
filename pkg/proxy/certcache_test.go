package proxy

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func createTestCA(t *testing.T) (*CertificateAuthority, string) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "wast-certcache-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	config := &CAConfig{
		CertPath:      filepath.Join(tmpDir, "ca.crt"),
		KeyPath:       filepath.Join(tmpDir, "ca.key"),
		ValidityYears: 1,
		KeyBits:       2048,
	}

	ca := NewCertificateAuthority(config)
	if err := ca.Initialize(); err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to initialize CA: %v", err)
	}

	return ca, tmpDir
}

func TestCertCache_GetOrGenerate(t *testing.T) {
	ca, tmpDir := createTestCA(t)
	defer os.RemoveAll(tmpDir)

	cache := NewCertCache(ca, 10)

	// First call should generate
	cert1, err := cache.GetOrGenerate("example.com")
	if err != nil {
		t.Fatalf("Failed to get or generate certificate: %v", err)
	}

	if cert1 == nil {
		t.Fatal("Certificate is nil")
	}

	// Second call should return cached
	cert2, err := cache.GetOrGenerate("example.com")
	if err != nil {
		t.Fatalf("Failed to get cached certificate: %v", err)
	}

	// Should be the same certificate
	if cert1 != cert2 {
		t.Error("Expected same certificate instance from cache")
	}

	// Cache should have size 1
	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", cache.Size())
	}
}

func TestCertCache_Get(t *testing.T) {
	ca, tmpDir := createTestCA(t)
	defer os.RemoveAll(tmpDir)

	cache := NewCertCache(ca, 10)

	// Get before generating should return nil
	cert, found := cache.Get("example.com")
	if found {
		t.Error("Expected not found for non-existent entry")
	}
	if cert != nil {
		t.Error("Expected nil certificate")
	}

	// Generate certificate
	_, err := cache.GetOrGenerate("example.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Now Get should return it
	cert, found = cache.Get("example.com")
	if !found {
		t.Error("Expected to find cached certificate")
	}
	if cert == nil {
		t.Error("Expected non-nil certificate")
	}
}

func TestCertCache_Put(t *testing.T) {
	ca, tmpDir := createTestCA(t)
	defer os.RemoveAll(tmpDir)

	cache := NewCertCache(ca, 10)

	// Create a certificate manually
	cert, err := ca.GenerateCertificate("manual.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Put it in cache
	cache.Put("manual.com", cert)

	// Should be retrievable
	cached, found := cache.Get("manual.com")
	if !found {
		t.Error("Expected to find cached certificate")
	}
	if cached != cert {
		t.Error("Expected same certificate instance")
	}
}

func TestCertCache_Remove(t *testing.T) {
	ca, tmpDir := createTestCA(t)
	defer os.RemoveAll(tmpDir)

	cache := NewCertCache(ca, 10)

	// Generate certificate
	_, err := cache.GetOrGenerate("example.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", cache.Size())
	}

	// Remove it
	cache.Remove("example.com")

	if cache.Size() != 0 {
		t.Errorf("Expected cache size 0, got %d", cache.Size())
	}

	// Should not be found
	_, found := cache.Get("example.com")
	if found {
		t.Error("Expected not found after removal")
	}
}

func TestCertCache_Clear(t *testing.T) {
	ca, tmpDir := createTestCA(t)
	defer os.RemoveAll(tmpDir)

	cache := NewCertCache(ca, 10)

	// Generate multiple certificates
	hostnames := []string{"a.com", "b.com", "c.com"}
	for _, hostname := range hostnames {
		_, err := cache.GetOrGenerate(hostname)
		if err != nil {
			t.Fatalf("Failed to generate certificate for %s: %v", hostname, err)
		}
	}

	if cache.Size() != len(hostnames) {
		t.Errorf("Expected cache size %d, got %d", len(hostnames), cache.Size())
	}

	// Clear all
	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected cache size 0 after clear, got %d", cache.Size())
	}
}

func TestCertCache_LRUEviction(t *testing.T) {
	ca, tmpDir := createTestCA(t)
	defer os.RemoveAll(tmpDir)

	// Create cache with max size 3
	cache := NewCertCache(ca, 3)

	// Generate 3 certificates
	for _, hostname := range []string{"a.com", "b.com", "c.com"} {
		_, err := cache.GetOrGenerate(hostname)
		if err != nil {
			t.Fatalf("Failed to generate certificate for %s: %v", hostname, err)
		}
	}

	if cache.Size() != 3 {
		t.Errorf("Expected cache size 3, got %d", cache.Size())
	}

	// Access a.com to make it most recently used
	cache.Get("a.com")

	// Add a 4th certificate - should evict b.com (oldest)
	_, err := cache.GetOrGenerate("d.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate for d.com: %v", err)
	}

	if cache.Size() != 3 {
		t.Errorf("Expected cache size 3 after eviction, got %d", cache.Size())
	}

	// b.com should be evicted
	_, found := cache.Get("b.com")
	if found {
		t.Error("Expected b.com to be evicted")
	}

	// a.com, c.com, d.com should still be present
	for _, hostname := range []string{"a.com", "c.com", "d.com"} {
		_, found := cache.Get(hostname)
		if !found {
			t.Errorf("Expected %s to be in cache", hostname)
		}
	}
}

func TestCertCache_ConcurrentAccess(t *testing.T) {
	ca, tmpDir := createTestCA(t)
	defer os.RemoveAll(tmpDir)

	cache := NewCertCache(ca, 100)

	// Concurrent access from multiple goroutines
	var wg sync.WaitGroup
	hostnames := []string{"a.com", "b.com", "c.com", "d.com", "e.com"}

	for i := 0; i < 10; i++ {
		for _, hostname := range hostnames {
			wg.Add(1)
			go func(h string) {
				defer wg.Done()
				_, err := cache.GetOrGenerate(h)
				if err != nil {
					t.Errorf("Failed to get or generate certificate for %s: %v", h, err)
				}
			}(hostname)
		}
	}

	wg.Wait()

	// Should have 5 unique certificates
	if cache.Size() != len(hostnames) {
		t.Errorf("Expected cache size %d, got %d", len(hostnames), cache.Size())
	}
}

func TestCertCache_DefaultSize(t *testing.T) {
	ca, tmpDir := createTestCA(t)
	defer os.RemoveAll(tmpDir)

	// Pass 0 or negative size should use default
	cache := NewCertCache(ca, 0)
	if cache.maxSize != DefaultCacheSize {
		t.Errorf("Expected default cache size %d, got %d", DefaultCacheSize, cache.maxSize)
	}

	cache = NewCertCache(ca, -1)
	if cache.maxSize != DefaultCacheSize {
		t.Errorf("Expected default cache size %d, got %d", DefaultCacheSize, cache.maxSize)
	}
}

func TestCertCache_PutUpdatesExisting(t *testing.T) {
	ca, tmpDir := createTestCA(t)
	defer os.RemoveAll(tmpDir)

	cache := NewCertCache(ca, 10)

	// Put first certificate
	cert1, _ := ca.GenerateCertificate("example.com")
	cache.Put("example.com", cert1)

	// Put second certificate for same hostname
	cert2, _ := ca.GenerateCertificate("example.com")
	cache.Put("example.com", cert2)

	// Should have same size
	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", cache.Size())
	}

	// Should return the new certificate
	cached, found := cache.Get("example.com")
	if !found {
		t.Error("Expected to find certificate")
	}
	if cached != cert2 {
		t.Error("Expected the updated certificate")
	}
}

func TestCertCache_RemoveNonExistent(t *testing.T) {
	ca, tmpDir := createTestCA(t)
	defer os.RemoveAll(tmpDir)

	cache := NewCertCache(ca, 10)

	// Should not panic when removing non-existent
	cache.Remove("nonexistent.com")

	if cache.Size() != 0 {
		t.Errorf("Expected cache size 0, got %d", cache.Size())
	}
}

func TestCertCache_GeneratedCertificateUsable(t *testing.T) {
	ca, tmpDir := createTestCA(t)
	defer os.RemoveAll(tmpDir)

	cache := NewCertCache(ca, 10)

	cert, err := cache.GetOrGenerate("example.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Verify it can be used in TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Error("Expected 1 certificate in TLS config")
	}
}
