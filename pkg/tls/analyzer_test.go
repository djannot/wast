package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// MockTLSConn implements the TLSConn interface for testing.
type MockTLSConn struct {
	state tls.ConnectionState
}

func (m *MockTLSConn) ConnectionState() tls.ConnectionState {
	return m.state
}

func (m *MockTLSConn) Close() error {
	return nil
}

// MockDialer implements the TLSDialer interface for testing.
type MockDialer struct {
	ConnState *tls.ConnectionState
	Error     error
}

func (m *MockDialer) Dial(network, addr string, config *tls.Config) (TLSConn, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return &MockTLSConn{state: *m.ConnState}, nil
}

// generateTestCertificate creates a test certificate for testing purposes.
func generateTestCertificate(t *testing.T, opts certOptions) *x509.Certificate {
	t.Helper()

	// Generate a key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, opts.keyBits)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   opts.commonName,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
		DNSNames:              opts.dnsNames,
		IPAddresses:           opts.ipAddresses,
		SignatureAlgorithm:    opts.signatureAlgorithm,
	}

	// Determine issuer template (self-signed or use provided issuer)
	issuerTemplate := template
	issuerKey := privateKey
	if opts.issuer != nil {
		issuerTemplate = opts.issuer
		issuerKey = opts.issuerKey
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerTemplate, &privateKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

type certOptions struct {
	commonName         string
	notBefore          time.Time
	notAfter           time.Time
	keyBits            int
	isCA               bool
	dnsNames           []string
	ipAddresses        []net.IP
	signatureAlgorithm x509.SignatureAlgorithm
	issuer             *x509.Certificate
	issuerKey          *rsa.PrivateKey
}

func defaultCertOptions() certOptions {
	return certOptions{
		commonName:         "test.example.com",
		notBefore:          time.Now().Add(-24 * time.Hour),
		notAfter:           time.Now().Add(365 * 24 * time.Hour),
		keyBits:            2048,
		isCA:               false,
		dnsNames:           []string{"test.example.com"},
		signatureAlgorithm: x509.SHA256WithRSA,
	}
}

func TestCertAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name               string
		host               string
		mockState          *tls.ConnectionState
		mockError          error
		wantCert           bool
		wantSecurityIssues int
		wantErrors         int
	}{
		{
			name: "successful analysis with valid certificate",
			host: "test.example.com",
			mockState: &tls.ConnectionState{
				Version:     tls.VersionTLS12,
				CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				PeerCertificates: []*x509.Certificate{
					generateTestCertificateHelper(t, defaultCertOptions()),
				},
			},
			wantCert:           true,
			wantSecurityIssues: 1, // Self-signed (test certs are always self-signed)
			wantErrors:         0,
		},
		{
			name: "expired certificate",
			host: "expired.example.com",
			mockState: &tls.ConnectionState{
				Version:     tls.VersionTLS12,
				CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				PeerCertificates: []*x509.Certificate{
					generateTestCertificateHelper(t, certOptions{
						commonName: "expired.example.com",
						notBefore:  time.Now().Add(-365 * 24 * time.Hour),
						notAfter:   time.Now().Add(-24 * time.Hour), // Expired yesterday
						keyBits:    2048,
						dnsNames:   []string{"expired.example.com"},
					}),
				},
			},
			wantCert:           true,
			wantSecurityIssues: 2, // Expired + Self-signed
			wantErrors:         0,
		},
		{
			name: "certificate expiring soon",
			host: "expiring.example.com",
			mockState: &tls.ConnectionState{
				Version:     tls.VersionTLS12,
				CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				PeerCertificates: []*x509.Certificate{
					generateTestCertificateHelper(t, certOptions{
						commonName: "expiring.example.com",
						notBefore:  time.Now().Add(-30 * 24 * time.Hour),
						notAfter:   time.Now().Add(15 * 24 * time.Hour), // Expires in 15 days
						keyBits:    2048,
						dnsNames:   []string{"expiring.example.com"},
					}),
				},
			},
			wantCert:           true,
			wantSecurityIssues: 2, // Expiring soon + Self-signed
			wantErrors:         0,
		},
		{
			name: "self-signed certificate",
			host: "selfsigned.example.com",
			mockState: &tls.ConnectionState{
				Version:     tls.VersionTLS12,
				CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				PeerCertificates: []*x509.Certificate{
					generateTestCertificateHelper(t, certOptions{
						commonName: "selfsigned.example.com",
						notBefore:  time.Now().Add(-24 * time.Hour),
						notAfter:   time.Now().Add(365 * 24 * time.Hour),
						keyBits:    2048,
						dnsNames:   []string{"selfsigned.example.com"},
					}),
				},
			},
			wantCert:           true,
			wantSecurityIssues: 1, // Self-signed
			wantErrors:         0,
		},
		{
			name: "hostname mismatch",
			host: "wrong.example.com",
			mockState: &tls.ConnectionState{
				Version:     tls.VersionTLS12,
				CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				PeerCertificates: []*x509.Certificate{
					generateTestCertificateHelper(t, certOptions{
						commonName: "correct.example.com",
						notBefore:  time.Now().Add(-24 * time.Hour),
						notAfter:   time.Now().Add(365 * 24 * time.Hour),
						keyBits:    2048,
						dnsNames:   []string{"correct.example.com"},
					}),
				},
			},
			wantCert:           true,
			wantSecurityIssues: 2, // Self-signed + hostname mismatch
			wantErrors:         0,
		},
		{
			name: "weak TLS version",
			host: "oldtls.example.com",
			mockState: &tls.ConnectionState{
				Version:     tls.VersionTLS10,
				CipherSuite: tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				PeerCertificates: []*x509.Certificate{
					generateTestCertificateHelper(t, certOptions{
						commonName: "oldtls.example.com",
						notBefore:  time.Now().Add(-24 * time.Hour),
						notAfter:   time.Now().Add(365 * 24 * time.Hour),
						keyBits:    2048,
						dnsNames:   []string{"oldtls.example.com"},
					}),
				},
			},
			wantCert:           true,
			wantSecurityIssues: 2, // Self-signed + weak TLS
			wantErrors:         0,
		},
		{
			name:       "connection error",
			host:       "unreachable.example.com",
			mockError:  net.ErrClosed,
			wantCert:   false,
			wantErrors: 1,
		},
		{
			name:       "empty host",
			host:       "",
			wantCert:   false,
			wantErrors: 1,
		},
		{
			name:       "whitespace host",
			host:       "   ",
			wantCert:   false,
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mockDialer *MockDialer
			if tt.mockState != nil || tt.mockError != nil {
				mockDialer = &MockDialer{
					ConnState: tt.mockState,
					Error:     tt.mockError,
				}
			}

			var opts []Option
			if mockDialer != nil {
				opts = append(opts, WithDialer(mockDialer))
			}

			analyzer := NewCertAnalyzer(opts...)
			result := analyzer.Analyze(tt.host)

			// Check certificate presence
			if (result.Certificate != nil) != tt.wantCert {
				t.Errorf("Certificate presence: got %v, want %v", result.Certificate != nil, tt.wantCert)
			}

			// Check security issues count
			if len(result.SecurityIssues) != tt.wantSecurityIssues {
				t.Errorf("SecurityIssues: got %d (%v), want %d", len(result.SecurityIssues), result.SecurityIssues, tt.wantSecurityIssues)
			}

			// Check errors count
			if len(result.Errors) != tt.wantErrors {
				t.Errorf("Errors: got %d (%v), want %d", len(result.Errors), result.Errors, tt.wantErrors)
			}
		})
	}
}

// generateTestCertificateHelper wraps generateTestCertificate with default values.
func generateTestCertificateHelper(t *testing.T, opts certOptions) *x509.Certificate {
	t.Helper()

	if opts.keyBits == 0 {
		opts.keyBits = 2048
	}
	if opts.signatureAlgorithm == 0 {
		opts.signatureAlgorithm = x509.SHA256WithRSA
	}

	return generateTestCertificate(t, opts)
}

func TestCertAnalyzer_WithOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		a := NewCertAnalyzer()
		if a.dialer == nil {
			t.Error("Expected default dialer to be set")
		}
		if a.timeout != 10*time.Second {
			t.Errorf("Expected default timeout of 10s, got %v", a.timeout)
		}
		if a.port != 443 {
			t.Errorf("Expected default port of 443, got %d", a.port)
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		a := NewCertAnalyzer(WithTimeout(30 * time.Second))
		if a.timeout != 30*time.Second {
			t.Errorf("Expected timeout of 30s, got %v", a.timeout)
		}
	})

	t.Run("custom port", func(t *testing.T) {
		a := NewCertAnalyzer(WithPort(8443))
		if a.port != 8443 {
			t.Errorf("Expected port 8443, got %d", a.port)
		}
	})

	t.Run("custom dialer", func(t *testing.T) {
		mock := &MockDialer{}
		a := NewCertAnalyzer(WithDialer(mock))
		if a.dialer != mock {
			t.Error("Expected custom dialer to be set")
		}
	})
}

func TestTLSResult_String(t *testing.T) {
	result := &TLSResult{
		Host: "example.com",
		Port: 443,
		Certificate: &CertificateInfo{
			Subject:            "CN=example.com,O=Test",
			Issuer:             "CN=Test CA,O=Test",
			SerialNumber:       "1234567890",
			NotBefore:          time.Now().Add(-24 * time.Hour),
			NotAfter:           time.Now().Add(365 * 24 * time.Hour),
			DaysUntilExpiry:    365,
			SignatureAlgorithm: "SHA256-RSA",
			PublicKeyAlgorithm: "RSA",
			PublicKeyBits:      2048,
			DNSNames:           []string{"example.com", "www.example.com"},
			IPAddresses:        []string{"93.184.216.34"},
			IsCA:               false,
			IsSelfSigned:       false,
		},
		Chain: []CertificateInfo{
			{
				Subject: "CN=Test CA,O=Test",
				Issuer:  "CN=Root CA,O=Test",
			},
		},
		TLSVersion:     "TLS 1.2",
		CipherSuite:    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		SecurityIssues: []string{"test issue"},
		Errors:         []string{"test error"},
	}

	str := result.String()

	// Check that all sections are present
	checks := []string{
		"example.com",
		"443",
		"CN=example.com",
		"CN=Test CA",
		"SHA256-RSA",
		"RSA",
		"2048",
		"TLS 1.2",
		"test issue",
		"test error",
	}

	for _, check := range checks {
		if !containsStr(str, check) {
			t.Errorf("String should contain %q", check)
		}
	}
}

func TestTLSResult_HasCertificate(t *testing.T) {
	tests := []struct {
		name   string
		result *TLSResult
		want   bool
	}{
		{
			name:   "no certificate",
			result: &TLSResult{Host: "example.com"},
			want:   false,
		},
		{
			name: "with certificate",
			result: &TLSResult{
				Host:        "example.com",
				Certificate: &CertificateInfo{Subject: "CN=example.com"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasCertificate(); got != tt.want {
				t.Errorf("HasCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTLSResult_HasSecurityIssues(t *testing.T) {
	tests := []struct {
		name   string
		result *TLSResult
		want   bool
	}{
		{
			name:   "no security issues",
			result: &TLSResult{Host: "example.com"},
			want:   false,
		},
		{
			name: "with security issues",
			result: &TLSResult{
				Host:           "example.com",
				SecurityIssues: []string{"Certificate expired"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasSecurityIssues(); got != tt.want {
				t.Errorf("HasSecurityIssues() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStripProtocol(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com", "example.com"},
		{"https://example.com/path", "example.com"},
		{"https://example.com:443", "example.com"},
		{"https://example.com:8443/path", "example.com"},
		{"http://example.com/path?query=1", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := stripProtocol(tt.input); got != tt.want {
				t.Errorf("stripProtocol(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0200, "Unknown (0x0200)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tlsVersionString(tt.version); got != tt.want {
				t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestExtractCertificateInfo(t *testing.T) {
	// Test with RSA certificate
	t.Run("RSA certificate", func(t *testing.T) {
		cert := generateTestCertificateHelper(t, certOptions{
			commonName: "rsa.example.com",
			notBefore:  time.Now().Add(-24 * time.Hour),
			notAfter:   time.Now().Add(365 * 24 * time.Hour),
			keyBits:    2048,
			dnsNames:   []string{"rsa.example.com", "www.rsa.example.com"},
			ipAddresses: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
		})

		info := extractCertificateInfo(cert)

		if info.PublicKeyBits != 2048 {
			t.Errorf("Expected PublicKeyBits 2048, got %d", info.PublicKeyBits)
		}
		if len(info.DNSNames) != 2 {
			t.Errorf("Expected 2 DNS names, got %d", len(info.DNSNames))
		}
		if len(info.IPAddresses) != 1 {
			t.Errorf("Expected 1 IP address, got %d", len(info.IPAddresses))
		}
	})

	// Test with ECDSA certificate
	t.Run("ECDSA certificate", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "ecdsa.example.com",
			},
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			DNSNames:              []string{"ecdsa.example.com"},
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		info := extractCertificateInfo(cert)

		if info.PublicKeyBits != 256 {
			t.Errorf("Expected PublicKeyBits 256, got %d", info.PublicKeyBits)
		}
		if info.PublicKeyAlgorithm != "ECDSA" {
			t.Errorf("Expected PublicKeyAlgorithm ECDSA, got %s", info.PublicKeyAlgorithm)
		}
	})
}

func TestCertificateChain(t *testing.T) {
	opts := defaultCertOptions()
	cert1 := generateTestCertificateHelper(t, opts)

	opts2 := certOptions{
		commonName: "Intermediate CA",
		notBefore:  time.Now().Add(-365 * 24 * time.Hour),
		notAfter:   time.Now().Add(5 * 365 * 24 * time.Hour),
		keyBits:    2048,
		isCA:       true,
	}
	cert2 := generateTestCertificateHelper(t, opts2)

	mockState := &tls.ConnectionState{
		Version:          tls.VersionTLS12,
		CipherSuite:      tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{cert1, cert2},
	}

	mockDialer := &MockDialer{
		ConnState: mockState,
	}

	analyzer := NewCertAnalyzer(WithDialer(mockDialer))
	result := analyzer.Analyze("example.com")

	if result.Certificate == nil {
		t.Error("Expected certificate to be set")
	}

	if len(result.Chain) != 1 {
		t.Errorf("Expected 1 chain certificate, got %d", len(result.Chain))
	}

	if result.Chain[0].Subject != cert2.Subject.String() {
		t.Errorf("Expected chain cert subject %q, got %q", cert2.Subject.String(), result.Chain[0].Subject)
	}
}

// Integration test that performs a real TLS connection.
func TestCertAnalyzer_IntegrationTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	analyzer := NewCertAnalyzer(WithTimeout(30 * time.Second))
	result := analyzer.Analyze("example.com")

	// example.com should have a certificate
	if result.Certificate == nil {
		if len(result.Errors) > 0 {
			t.Logf("Connection errors: %v", result.Errors)
		}
		t.Error("Expected certificate for example.com")
	}

	// Log the results for manual verification
	t.Logf("TLS Results for example.com:\n%s", result.String())
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
