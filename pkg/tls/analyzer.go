// Package tls provides TLS/SSL certificate analysis functionality for reconnaissance operations.
package tls

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// DefaultPort is the default HTTPS port used for TLS connections.
const DefaultPort = 443

// TLSDialer defines the interface for TLS connections, allowing for mock implementations in tests.
type TLSDialer interface {
	Dial(network, addr string, config *tls.Config) (TLSConn, error)
}

// TLSConn defines the interface for a TLS connection.
type TLSConn interface {
	ConnectionState() tls.ConnectionState
	Close() error
}

// DefaultDialer wraps the standard tls.Dial function.
type DefaultDialer struct {
	timeout time.Duration
}

// NewDefaultDialer creates a new DefaultDialer with the specified timeout.
func NewDefaultDialer(timeout time.Duration) *DefaultDialer {
	return &DefaultDialer{timeout: timeout}
}

// Dial establishes a TLS connection.
func (d *DefaultDialer) Dial(network, addr string, config *tls.Config) (TLSConn, error) {
	dialer := &net.Dialer{
		Timeout: d.timeout,
	}
	return tls.DialWithDialer(dialer, network, addr, config)
}

// CertAnalyzer performs TLS certificate analysis for a host.
type CertAnalyzer struct {
	dialer  TLSDialer
	timeout time.Duration
	port    int
}

// Option is a function that configures a CertAnalyzer.
type Option func(*CertAnalyzer)

// WithDialer sets a custom TLS dialer for the analyzer.
func WithDialer(d TLSDialer) Option {
	return func(a *CertAnalyzer) {
		a.dialer = d
	}
}

// WithTimeout sets the timeout for TLS connections.
func WithTimeout(d time.Duration) Option {
	return func(a *CertAnalyzer) {
		a.timeout = d
	}
}

// WithPort sets the port to connect to for TLS analysis.
func WithPort(port int) Option {
	return func(a *CertAnalyzer) {
		a.port = port
	}
}

// NewCertAnalyzer creates a new TLS certificate analyzer with the given options.
func NewCertAnalyzer(opts ...Option) *CertAnalyzer {
	a := &CertAnalyzer{
		timeout: 10 * time.Second,
		port:    DefaultPort,
	}

	for _, opt := range opts {
		opt(a)
	}

	// Set default dialer if not provided
	if a.dialer == nil {
		a.dialer = NewDefaultDialer(a.timeout)
	}

	return a
}

// Analyze performs TLS certificate analysis for the given host.
func (a *CertAnalyzer) Analyze(host string) *TLSResult {
	result := &TLSResult{
		Host: host,
		Port: a.port,
	}

	// Validate and clean host
	host = strings.TrimSpace(host)
	if host == "" {
		result.Errors = append(result.Errors, "host cannot be empty")
		return result
	}

	// Strip protocol if present
	host = stripProtocol(host)
	result.Host = host

	// Connect with TLS
	addr := fmt.Sprintf("%s:%d", host, a.port)
	config := &tls.Config{
		InsecureSkipVerify: true, // We want to analyze all certs, even invalid ones
		MinVersion:         tls.VersionTLS10,
	}

	conn, err := a.dialer.Dial("tcp", addr, config)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("TLS connection failed: %v", err))
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Extract TLS version
	result.TLSVersion = tlsVersionString(state.Version)

	// Extract cipher suite
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// Process peer certificates
	if len(state.PeerCertificates) > 0 {
		// Primary certificate
		cert := state.PeerCertificates[0]
		result.Certificate = extractCertificateInfo(cert)

		// Certificate chain (skip the first one as it's the primary)
		if len(state.PeerCertificates) > 1 {
			for _, chainCert := range state.PeerCertificates[1:] {
				result.Chain = append(result.Chain, *extractCertificateInfo(chainCert))
			}
		}

		// Check for security issues
		result.SecurityIssues = analyzeSecurityIssues(cert, state, host)
	}

	return result
}

// extractCertificateInfo extracts relevant information from an X.509 certificate.
func extractCertificateInfo(cert *x509.Certificate) *CertificateInfo {
	info := &CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysUntilExpiry:    int(time.Until(cert.NotAfter).Hours() / 24),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		IsCA:               cert.IsCA,
		IsSelfSigned:       cert.Subject.String() == cert.Issuer.String(),
	}

	// Extract public key size
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.PublicKeyBits = pub.Curve.Params().BitSize
	}

	// Copy DNS names
	info.DNSNames = make([]string, len(cert.DNSNames))
	copy(info.DNSNames, cert.DNSNames)

	// Convert IP addresses to strings
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	return info
}

// analyzeSecurityIssues checks for common security issues with the certificate.
func analyzeSecurityIssues(cert *x509.Certificate, state tls.ConnectionState, host string) []string {
	var issues []string

	// Check if certificate is expired
	now := time.Now()
	if now.After(cert.NotAfter) {
		issues = append(issues, fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC3339)))
	}

	// Check if certificate is not yet valid
	if now.Before(cert.NotBefore) {
		issues = append(issues, fmt.Sprintf("Certificate not valid until %s", cert.NotBefore.Format(time.RFC3339)))
	}

	// Check for expiring soon (within 30 days)
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysUntilExpiry > 0 && daysUntilExpiry <= 30 {
		issues = append(issues, fmt.Sprintf("Certificate expires in %d days", daysUntilExpiry))
	}

	// Check if self-signed
	if cert.Subject.String() == cert.Issuer.String() {
		issues = append(issues, "Certificate is self-signed")
	}

	// Check for weak signature algorithms
	weakAlgorithms := map[x509.SignatureAlgorithm]string{
		x509.MD2WithRSA:  "MD2WithRSA (weak)",
		x509.MD5WithRSA:  "MD5WithRSA (weak)",
		x509.SHA1WithRSA: "SHA1WithRSA (deprecated)",
		x509.DSAWithSHA1: "DSAWithSHA1 (deprecated)",
	}
	if weakName, isWeak := weakAlgorithms[cert.SignatureAlgorithm]; isWeak {
		issues = append(issues, fmt.Sprintf("Weak signature algorithm: %s", weakName))
	}

	// Check RSA key size
	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		keyBits := rsaKey.N.BitLen()
		if keyBits < 2048 {
			issues = append(issues, fmt.Sprintf("RSA key too small: %d bits (minimum 2048 recommended)", keyBits))
		}
	}

	// Check TLS version
	if state.Version < tls.VersionTLS12 {
		issues = append(issues, fmt.Sprintf("Insecure TLS version: %s (TLS 1.2+ recommended)", tlsVersionString(state.Version)))
	}

	// Check hostname match
	if err := cert.VerifyHostname(host); err != nil {
		issues = append(issues, fmt.Sprintf("Hostname mismatch: %v", err))
	}

	return issues
}

// tlsVersionString returns a human-readable string for a TLS version.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// stripProtocol removes common URL protocol prefixes from a host string.
func stripProtocol(host string) string {
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	// Remove any path or query string
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	// Remove port if present (we use our own port setting)
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Make sure this is a port, not part of an IPv6 address
		potentialPort := host[idx+1:]
		if !strings.Contains(potentialPort, ":") {
			host = host[:idx]
		}
	}
	return host
}
