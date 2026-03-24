// Package proxy provides HTTP traffic interception functionality for security testing.
package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultCADir is the default directory for storing CA certificates.
	DefaultCADir = ".wast/ca"
	// DefaultCAValidityYears is the default validity period for CA certificates.
	DefaultCAValidityYears = 10
	// DefaultCertValidityHours is the default validity period for generated certificates.
	DefaultCertValidityHours = 24
	// DefaultKeyBits is the default RSA key size.
	DefaultKeyBits = 2048
)

// CAConfig holds the configuration for the Certificate Authority.
type CAConfig struct {
	// CertPath is the path to the CA certificate file.
	CertPath string
	// KeyPath is the path to the CA private key file.
	KeyPath string
	// ValidityYears is the validity period for the CA certificate.
	ValidityYears int
	// KeyBits is the RSA key size for the CA.
	KeyBits int
}

// CertificateAuthority manages CA certificate operations.
type CertificateAuthority struct {
	config      *CAConfig
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	tlsCert     tls.Certificate
}

// NewCertificateAuthority creates a new CertificateAuthority with the given configuration.
func NewCertificateAuthority(config *CAConfig) *CertificateAuthority {
	if config == nil {
		config = DefaultCAConfig()
	}
	return &CertificateAuthority{
		config: config,
	}
}

// DefaultCAConfig returns the default CA configuration.
func DefaultCAConfig() *CAConfig {
	homeDir, _ := os.UserHomeDir()
	caDir := filepath.Join(homeDir, DefaultCADir)
	return &CAConfig{
		CertPath:      filepath.Join(caDir, "ca.crt"),
		KeyPath:       filepath.Join(caDir, "ca.key"),
		ValidityYears: DefaultCAValidityYears,
		KeyBits:       DefaultKeyBits,
	}
}

// GetCertPath returns the path to the CA certificate file.
func (ca *CertificateAuthority) GetCertPath() string {
	return ca.config.CertPath
}

// GetKeyPath returns the path to the CA private key file.
func (ca *CertificateAuthority) GetKeyPath() string {
	return ca.config.KeyPath
}

// IsInitialized checks if the CA certificate and key files exist.
func (ca *CertificateAuthority) IsInitialized() bool {
	_, certErr := os.Stat(ca.config.CertPath)
	_, keyErr := os.Stat(ca.config.KeyPath)
	return certErr == nil && keyErr == nil
}

// Initialize generates a new CA certificate and key pair.
func (ca *CertificateAuthority) Initialize() error {
	// Ensure directory exists
	dir := filepath.Dir(ca.config.CertPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create CA directory: %w", err)
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, ca.config.KeyBits)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.AddDate(ca.config.ValidityYears, 0, 0)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"WAST Security Testing"},
			OrganizationalUnit: []string{"MITM Proxy"},
			CommonName:         "WAST Root CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Save certificate to file
	certFile, err := os.OpenFile(ca.config.CertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key to file
	keyFile, err := os.OpenFile(ca.config.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Parse and store the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	ca.certificate = cert
	ca.privateKey = privateKey
	ca.tlsCert = tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	return nil
}

// Load loads an existing CA certificate and key from files.
func (ca *CertificateAuthority) Load() error {
	// Load certificate
	certPEM, err := os.ReadFile(ca.config.CertPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(ca.config.KeyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	ca.certificate = cert
	ca.privateKey = privateKey
	ca.tlsCert = tls.Certificate{
		Certificate: [][]byte{certBlock.Bytes},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	return nil
}

// LoadOrInitialize loads an existing CA or initializes a new one if it doesn't exist.
func (ca *CertificateAuthority) LoadOrInitialize() error {
	if ca.IsInitialized() {
		return ca.Load()
	}
	return ca.Initialize()
}

// GenerateCertificate generates a certificate for the given hostname signed by this CA.
func (ca *CertificateAuthority) GenerateCertificate(hostname string) (*tls.Certificate, error) {
	if ca.certificate == nil || ca.privateKey == nil {
		return nil, fmt.Errorf("CA not loaded or initialized")
	}

	// Generate private key for the certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, DefaultKeyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(DefaultCertValidityHours) * time.Hour)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"WAST Security Testing"},
			CommonName:   hostname,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	// Sign certificate with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &privateKey.PublicKey, ca.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate for the Leaf field
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER, ca.tlsCert.Certificate[0]},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	return tlsCert, nil
}

// GetCertificate returns the CA certificate.
func (ca *CertificateAuthority) GetCertificate() *x509.Certificate {
	return ca.certificate
}

// GetPrivateKey returns the CA private key.
func (ca *CertificateAuthority) GetPrivateKey() *rsa.PrivateKey {
	return ca.privateKey
}

// GetTLSCertificate returns the CA TLS certificate.
func (ca *CertificateAuthority) GetTLSCertificate() *tls.Certificate {
	return &ca.tlsCert
}
