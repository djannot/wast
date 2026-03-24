// Package tls provides TLS/SSL certificate analysis functionality for reconnaissance operations.
package tls

import (
	"fmt"
	"strings"
	"time"
)

// CertificateInfo contains details about an X.509 certificate.
type CertificateInfo struct {
	Subject            string    `json:"subject" yaml:"subject"`
	Issuer             string    `json:"issuer" yaml:"issuer"`
	SerialNumber       string    `json:"serial_number" yaml:"serial_number"`
	NotBefore          time.Time `json:"not_before" yaml:"not_before"`
	NotAfter           time.Time `json:"not_after" yaml:"not_after"`
	DaysUntilExpiry    int       `json:"days_until_expiry" yaml:"days_until_expiry"`
	SignatureAlgorithm string    `json:"signature_algorithm" yaml:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm" yaml:"public_key_algorithm"`
	PublicKeyBits      int       `json:"public_key_bits,omitempty" yaml:"public_key_bits,omitempty"`
	DNSNames           []string  `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty" yaml:"ip_addresses,omitempty"`
	IsCA               bool      `json:"is_ca" yaml:"is_ca"`
	IsSelfSigned       bool      `json:"is_self_signed" yaml:"is_self_signed"`
}

// TLSResult contains the results of TLS certificate analysis for a host.
type TLSResult struct {
	Host           string            `json:"host" yaml:"host"`
	Port           int               `json:"port" yaml:"port"`
	Certificate    *CertificateInfo  `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	Chain          []CertificateInfo `json:"chain,omitempty" yaml:"chain,omitempty"`
	TLSVersion     string            `json:"tls_version,omitempty" yaml:"tls_version,omitempty"`
	CipherSuite    string            `json:"cipher_suite,omitempty" yaml:"cipher_suite,omitempty"`
	SecurityIssues []string          `json:"security_issues,omitempty" yaml:"security_issues,omitempty"`
	Errors         []string          `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// String returns a human-readable representation of the TLS result.
func (r *TLSResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("TLS Certificate Analysis for: %s:%d\n", r.Host, r.Port))
	sb.WriteString(strings.Repeat("=", 50) + "\n")

	if r.Certificate != nil {
		sb.WriteString("\nCertificate Details:\n")
		sb.WriteString(fmt.Sprintf("  Subject: %s\n", r.Certificate.Subject))
		sb.WriteString(fmt.Sprintf("  Issuer: %s\n", r.Certificate.Issuer))
		sb.WriteString(fmt.Sprintf("  Serial Number: %s\n", r.Certificate.SerialNumber))
		sb.WriteString(fmt.Sprintf("  Valid From: %s\n", r.Certificate.NotBefore.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("  Valid Until: %s\n", r.Certificate.NotAfter.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("  Days Until Expiry: %d\n", r.Certificate.DaysUntilExpiry))
		sb.WriteString(fmt.Sprintf("  Signature Algorithm: %s\n", r.Certificate.SignatureAlgorithm))
		sb.WriteString(fmt.Sprintf("  Public Key Algorithm: %s\n", r.Certificate.PublicKeyAlgorithm))
		if r.Certificate.PublicKeyBits > 0 {
			sb.WriteString(fmt.Sprintf("  Public Key Bits: %d\n", r.Certificate.PublicKeyBits))
		}
		sb.WriteString(fmt.Sprintf("  Is CA: %t\n", r.Certificate.IsCA))
		sb.WriteString(fmt.Sprintf("  Is Self-Signed: %t\n", r.Certificate.IsSelfSigned))

		if len(r.Certificate.DNSNames) > 0 {
			sb.WriteString("  DNS Names:\n")
			for _, name := range r.Certificate.DNSNames {
				sb.WriteString(fmt.Sprintf("    - %s\n", name))
			}
		}

		if len(r.Certificate.IPAddresses) > 0 {
			sb.WriteString("  IP Addresses:\n")
			for _, ip := range r.Certificate.IPAddresses {
				sb.WriteString(fmt.Sprintf("    - %s\n", ip))
			}
		}
	}

	if r.TLSVersion != "" {
		sb.WriteString(fmt.Sprintf("\nTLS Version: %s\n", r.TLSVersion))
	}

	if r.CipherSuite != "" {
		sb.WriteString(fmt.Sprintf("Cipher Suite: %s\n", r.CipherSuite))
	}

	if len(r.Chain) > 0 {
		sb.WriteString(fmt.Sprintf("\nCertificate Chain (%d certificates):\n", len(r.Chain)))
		for i, cert := range r.Chain {
			sb.WriteString(fmt.Sprintf("  [%d] %s (issued by: %s)\n", i, cert.Subject, cert.Issuer))
		}
	}

	if len(r.SecurityIssues) > 0 {
		sb.WriteString("\nSecurity Issues:\n")
		for _, issue := range r.SecurityIssues {
			sb.WriteString(fmt.Sprintf("  - %s\n", issue))
		}
	}

	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors encountered:\n")
		for _, err := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	return sb.String()
}

// HasCertificate returns true if certificate information was retrieved.
func (r *TLSResult) HasCertificate() bool {
	return r.Certificate != nil
}

// HasSecurityIssues returns true if any security issues were found.
func (r *TLSResult) HasSecurityIssues() bool {
	return len(r.SecurityIssues) > 0
}
