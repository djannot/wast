// Package dns provides DNS enumeration functionality for reconnaissance operations.
package dns

import (
	"fmt"
	"strings"
)

// MXRecord represents a mail exchange record with host and priority.
type MXRecord struct {
	Host     string `json:"host" yaml:"host"`
	Priority uint16 `json:"priority" yaml:"priority"`
}

// DNSResult contains the results of DNS enumeration for a domain.
type DNSResult struct {
	Domain string     `json:"domain" yaml:"domain"`
	A      []string   `json:"a_records,omitempty" yaml:"a_records,omitempty"`
	AAAA   []string   `json:"aaaa_records,omitempty" yaml:"aaaa_records,omitempty"`
	MX     []MXRecord `json:"mx_records,omitempty" yaml:"mx_records,omitempty"`
	NS     []string   `json:"ns_records,omitempty" yaml:"ns_records,omitempty"`
	TXT    []string   `json:"txt_records,omitempty" yaml:"txt_records,omitempty"`
	CNAME  string     `json:"cname,omitempty" yaml:"cname,omitempty"`
	Errors []string   `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// String returns a human-readable representation of the DNS result.
func (r *DNSResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("DNS Enumeration Results for: %s\n", r.Domain))
	sb.WriteString(strings.Repeat("=", 50) + "\n")

	if len(r.A) > 0 {
		sb.WriteString("\nA Records (IPv4):\n")
		for _, ip := range r.A {
			sb.WriteString(fmt.Sprintf("  - %s\n", ip))
		}
	}

	if len(r.AAAA) > 0 {
		sb.WriteString("\nAAAA Records (IPv6):\n")
		for _, ip := range r.AAAA {
			sb.WriteString(fmt.Sprintf("  - %s\n", ip))
		}
	}

	if len(r.MX) > 0 {
		sb.WriteString("\nMX Records (Mail Servers):\n")
		for _, mx := range r.MX {
			sb.WriteString(fmt.Sprintf("  - %s (priority: %d)\n", mx.Host, mx.Priority))
		}
	}

	if len(r.NS) > 0 {
		sb.WriteString("\nNS Records (Name Servers):\n")
		for _, ns := range r.NS {
			sb.WriteString(fmt.Sprintf("  - %s\n", ns))
		}
	}

	if len(r.TXT) > 0 {
		sb.WriteString("\nTXT Records:\n")
		for _, txt := range r.TXT {
			sb.WriteString(fmt.Sprintf("  - %s\n", txt))
		}
	}

	if r.CNAME != "" {
		sb.WriteString(fmt.Sprintf("\nCNAME Record: %s\n", r.CNAME))
	}

	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors encountered:\n")
		for _, err := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	return sb.String()
}

// HasRecords returns true if any DNS records were found.
func (r *DNSResult) HasRecords() bool {
	return len(r.A) > 0 || len(r.AAAA) > 0 || len(r.MX) > 0 ||
		len(r.NS) > 0 || len(r.TXT) > 0 || r.CNAME != ""
}
