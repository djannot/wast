package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestCertificateAuthority_DefaultConfig(t *testing.T) {
	config := DefaultCAConfig()

	if config.ValidityYears != DefaultCAValidityYears {
		t.Errorf("Expected validity years %d, got %d", DefaultCAValidityYears, config.ValidityYears)
	}

	if config.KeyBits != DefaultKeyBits {
		t.Errorf("Expected key bits %d, got %d", DefaultKeyBits, config.KeyBits)
	}

	// Should contain default CA directory
	homeDir, _ := os.UserHomeDir()
	expectedDir := filepath.Join(homeDir, DefaultCADir)
	if !filepath.HasPrefix(config.CertPath, expectedDir) {
		t.Errorf("Expected cert path to be in %s, got %s", expectedDir, config.CertPath)
	}
}

func TestCertificateAuthority_Initialize(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "wast-ca-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	config := &CAConfig{
		CertPath:      filepath.Join(tmpDir, "ca.crt"),
		KeyPath:       filepath.Join(tmpDir, "ca.key"),
		ValidityYears: 1,
		KeyBits:       2048,
	}

	ca := NewCertificateAuthority(config)

	// Should not be initialized yet
	if ca.IsInitialized() {
		t.Error("CA should not be initialized yet")
	}

	// Initialize CA
	if err := ca.Initialize(); err != nil {
		t.Fatalf("Failed to initialize CA: %v", err)
	}

	// Should be initialized now
	if !ca.IsInitialized() {
		t.Error("CA should be initialized")
	}

	// Verify files were created
	if _, err := os.Stat(config.CertPath); os.IsNotExist(err) {
		t.Error("Certificate file was not created")
	}
	if _, err := os.Stat(config.KeyPath); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}

	// Verify certificate is valid
	cert := ca.GetCertificate()
	if cert == nil {
		t.Fatal("GetCertificate returned nil")
	}

	if !cert.IsCA {
		t.Error("Certificate should be a CA")
	}

	if cert.Subject.CommonName != "WAST Root CA" {
		t.Errorf("Expected common name 'WAST Root CA', got '%s'", cert.Subject.CommonName)
	}
}

func TestCertificateAuthority_Load(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "wast-ca-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	config := &CAConfig{
		CertPath:      filepath.Join(tmpDir, "ca.crt"),
		KeyPath:       filepath.Join(tmpDir, "ca.key"),
		ValidityYears: 1,
		KeyBits:       2048,
	}

	// Initialize first
	ca1 := NewCertificateAuthority(config)
	if err := ca1.Initialize(); err != nil {
		t.Fatalf("Failed to initialize CA: %v", err)
	}

	// Create a new CA instance and load
	ca2 := NewCertificateAuthority(config)
	if err := ca2.Load(); err != nil {
		t.Fatalf("Failed to load CA: %v", err)
	}

	// Verify loaded certificate matches
	if ca1.GetCertificate().SerialNumber.Cmp(ca2.GetCertificate().SerialNumber) != 0 {
		t.Error("Loaded certificate serial number doesn't match")
	}
}

func TestCertificateAuthority_LoadOrInitialize(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "wast-ca-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	config := &CAConfig{
		CertPath:      filepath.Join(tmpDir, "ca.crt"),
		KeyPath:       filepath.Join(tmpDir, "ca.key"),
		ValidityYears: 1,
		KeyBits:       2048,
	}

	// First call should initialize
	ca1 := NewCertificateAuthority(config)
	if err := ca1.LoadOrInitialize(); err != nil {
		t.Fatalf("Failed to load or initialize CA: %v", err)
	}

	// Second call should load existing
	ca2 := NewCertificateAuthority(config)
	if err := ca2.LoadOrInitialize(); err != nil {
		t.Fatalf("Failed to load or initialize CA: %v", err)
	}

	// Should have same serial number
	if ca1.GetCertificate().SerialNumber.Cmp(ca2.GetCertificate().SerialNumber) != 0 {
		t.Error("Serial numbers should match")
	}
}

func TestCertificateAuthority_GenerateCertificate(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "wast-ca-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	config := &CAConfig{
		CertPath:      filepath.Join(tmpDir, "ca.crt"),
		KeyPath:       filepath.Join(tmpDir, "ca.key"),
		ValidityYears: 1,
		KeyBits:       2048,
	}

	ca := NewCertificateAuthority(config)
	if err := ca.Initialize(); err != nil {
		t.Fatalf("Failed to initialize CA: %v", err)
	}

	// Generate certificate for hostname
	hostname := "example.com"
	cert, err := ca.GenerateCertificate(hostname)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if cert == nil {
		t.Fatal("Generated certificate is nil")
	}

	// Verify the certificate
	if cert.Leaf == nil {
		t.Fatal("Certificate Leaf is nil")
	}

	if cert.Leaf.Subject.CommonName != hostname {
		t.Errorf("Expected common name '%s', got '%s'", hostname, cert.Leaf.Subject.CommonName)
	}

	// Verify DNS names
	found := false
	for _, name := range cert.Leaf.DNSNames {
		if name == hostname {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected DNS name '%s' not found", hostname)
	}

	// Verify certificate is signed by CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.GetCertificate())

	opts := x509.VerifyOptions{
		DNSName: hostname,
		Roots:   roots,
	}

	if _, err := cert.Leaf.Verify(opts); err != nil {
		t.Errorf("Certificate verification failed: %v", err)
	}
}

func TestCertificateAuthority_GenerateCertificate_NotInitialized(t *testing.T) {
	config := &CAConfig{
		CertPath:      "/nonexistent/ca.crt",
		KeyPath:       "/nonexistent/ca.key",
		ValidityYears: 1,
		KeyBits:       2048,
	}

	ca := NewCertificateAuthority(config)

	// Should fail because CA is not initialized
	_, err := ca.GenerateCertificate("example.com")
	if err == nil {
		t.Error("Expected error when CA is not initialized")
	}
}

func TestCertificateAuthority_TLSCertificate(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "wast-ca-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	config := &CAConfig{
		CertPath:      filepath.Join(tmpDir, "ca.crt"),
		KeyPath:       filepath.Join(tmpDir, "ca.key"),
		ValidityYears: 1,
		KeyBits:       2048,
	}

	ca := NewCertificateAuthority(config)
	if err := ca.Initialize(); err != nil {
		t.Fatalf("Failed to initialize CA: %v", err)
	}

	tlsCert := ca.GetTLSCertificate()
	if tlsCert == nil {
		t.Fatal("GetTLSCertificate returned nil")
	}

	// Verify it can be used in TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Error("Expected 1 certificate in TLS config")
	}
}

func TestCertificateAuthority_GetPaths(t *testing.T) {
	config := &CAConfig{
		CertPath:      "/custom/path/ca.crt",
		KeyPath:       "/custom/path/ca.key",
		ValidityYears: 1,
		KeyBits:       2048,
	}

	ca := NewCertificateAuthority(config)

	if ca.GetCertPath() != config.CertPath {
		t.Errorf("Expected cert path '%s', got '%s'", config.CertPath, ca.GetCertPath())
	}

	if ca.GetKeyPath() != config.KeyPath {
		t.Errorf("Expected key path '%s', got '%s'", config.KeyPath, ca.GetKeyPath())
	}
}

func TestCertificateAuthority_GetPrivateKey(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "wast-ca-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	config := &CAConfig{
		CertPath:      filepath.Join(tmpDir, "ca.crt"),
		KeyPath:       filepath.Join(tmpDir, "ca.key"),
		ValidityYears: 1,
		KeyBits:       2048,
	}

	ca := NewCertificateAuthority(config)

	// Before initialization, private key should be nil
	if ca.GetPrivateKey() != nil {
		t.Error("Expected private key to be nil before initialization")
	}

	// Initialize CA
	if err := ca.Initialize(); err != nil {
		t.Fatalf("Failed to initialize CA: %v", err)
	}

	// After initialization, private key should exist
	privateKey := ca.GetPrivateKey()
	if privateKey == nil {
		t.Fatal("Expected private key to be non-nil after initialization")
	}

	// Verify the private key is valid
	if privateKey.N == nil {
		t.Error("Private key N is nil")
	}

	// Verify key size
	if privateKey.N.BitLen() != config.KeyBits {
		t.Errorf("Expected key size %d bits, got %d bits", config.KeyBits, privateKey.N.BitLen())
	}
}
