// Package dns provides DNS enumeration functionality for reconnaissance operations.
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Resolver defines the interface for DNS lookups, allowing for mock implementations in tests.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// DefaultResolver wraps the standard net.Resolver.
type DefaultResolver struct {
	resolver *net.Resolver
}

// NewDefaultResolver creates a new DefaultResolver.
func NewDefaultResolver() *DefaultResolver {
	return &DefaultResolver{
		resolver: net.DefaultResolver,
	}
}

// LookupHost performs a host lookup.
func (r *DefaultResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return r.resolver.LookupHost(ctx, host)
}

// LookupIP performs an IP lookup.
func (r *DefaultResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return r.resolver.LookupIP(ctx, network, host)
}

// LookupMX performs an MX record lookup.
func (r *DefaultResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return r.resolver.LookupMX(ctx, name)
}

// LookupNS performs an NS record lookup.
func (r *DefaultResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return r.resolver.LookupNS(ctx, name)
}

// LookupTXT performs a TXT record lookup.
func (r *DefaultResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.resolver.LookupTXT(ctx, name)
}

// LookupCNAME performs a CNAME record lookup.
func (r *DefaultResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return r.resolver.LookupCNAME(ctx, host)
}

// Enumerator performs DNS enumeration for a domain.
type Enumerator struct {
	resolver Resolver
	timeout  time.Duration
}

// Option is a function that configures an Enumerator.
type Option func(*Enumerator)

// WithResolver sets a custom resolver for the enumerator.
func WithResolver(r Resolver) Option {
	return func(e *Enumerator) {
		e.resolver = r
	}
}

// WithTimeout sets the timeout for DNS queries.
func WithTimeout(d time.Duration) Option {
	return func(e *Enumerator) {
		e.timeout = d
	}
}

// NewEnumerator creates a new DNS enumerator with the given options.
func NewEnumerator(opts ...Option) *Enumerator {
	e := &Enumerator{
		resolver: NewDefaultResolver(),
		timeout:  10 * time.Second,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

// Enumerate performs DNS enumeration for the given domain.
func (e *Enumerator) Enumerate(domain string) *DNSResult {
	result := &DNSResult{
		Domain: domain,
	}

	// Validate domain
	domain = strings.TrimSpace(domain)
	if domain == "" {
		result.Errors = append(result.Errors, "domain cannot be empty")
		return result
	}

	// Strip protocol if present
	domain = stripProtocol(domain)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	// Perform all DNS lookups
	e.lookupA(ctx, domain, result)
	e.lookupAAAA(ctx, domain, result)
	e.lookupMX(ctx, domain, result)
	e.lookupNS(ctx, domain, result)
	e.lookupTXT(ctx, domain, result)
	e.lookupCNAME(ctx, domain, result)

	return result
}

// lookupA retrieves A records (IPv4 addresses) for the domain.
func (e *Enumerator) lookupA(ctx context.Context, domain string, result *DNSResult) {
	ips, err := e.resolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		if !isNotFoundError(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("A record lookup failed: %v", err))
		}
		return
	}

	for _, ip := range ips {
		result.A = append(result.A, ip.String())
	}
}

// lookupAAAA retrieves AAAA records (IPv6 addresses) for the domain.
func (e *Enumerator) lookupAAAA(ctx context.Context, domain string, result *DNSResult) {
	ips, err := e.resolver.LookupIP(ctx, "ip6", domain)
	if err != nil {
		if !isNotFoundError(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("AAAA record lookup failed: %v", err))
		}
		return
	}

	for _, ip := range ips {
		result.AAAA = append(result.AAAA, ip.String())
	}
}

// lookupMX retrieves MX records (mail servers) for the domain.
func (e *Enumerator) lookupMX(ctx context.Context, domain string, result *DNSResult) {
	mxRecords, err := e.resolver.LookupMX(ctx, domain)
	if err != nil {
		if !isNotFoundError(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("MX record lookup failed: %v", err))
		}
		return
	}

	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		// Skip null MX records (RFC 7505) which have an empty host or just "."
		if host == "" {
			continue
		}
		result.MX = append(result.MX, MXRecord{
			Host:     host,
			Priority: mx.Pref,
		})
	}
}

// lookupNS retrieves NS records (name servers) for the domain.
func (e *Enumerator) lookupNS(ctx context.Context, domain string, result *DNSResult) {
	nsRecords, err := e.resolver.LookupNS(ctx, domain)
	if err != nil {
		if !isNotFoundError(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("NS record lookup failed: %v", err))
		}
		return
	}

	for _, ns := range nsRecords {
		result.NS = append(result.NS, strings.TrimSuffix(ns.Host, "."))
	}
}

// lookupTXT retrieves TXT records for the domain.
func (e *Enumerator) lookupTXT(ctx context.Context, domain string, result *DNSResult) {
	txtRecords, err := e.resolver.LookupTXT(ctx, domain)
	if err != nil {
		if !isNotFoundError(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("TXT record lookup failed: %v", err))
		}
		return
	}

	result.TXT = txtRecords
}

// lookupCNAME retrieves the CNAME record for the domain.
func (e *Enumerator) lookupCNAME(ctx context.Context, domain string, result *DNSResult) {
	cname, err := e.resolver.LookupCNAME(ctx, domain)
	if err != nil {
		if !isNotFoundError(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("CNAME record lookup failed: %v", err))
		}
		return
	}

	// Trim trailing dot and only set if different from domain
	cname = strings.TrimSuffix(cname, ".")
	if cname != domain {
		result.CNAME = cname
	}
}

// stripProtocol removes common URL protocol prefixes from a domain string.
func stripProtocol(domain string) string {
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	// Remove any path or query string
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}

// isNotFoundError checks if the error is a "no such host" or similar error
// that should not be reported as an error (just means no records of that type).
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	var dnsErr *net.DNSError
	if ok := (err != nil) && (err.Error() != ""); ok {
		// Check for DNSError
		if dnsError, isDNSError := err.(*net.DNSError); isDNSError {
			dnsErr = dnsError
		}
	}

	if dnsErr != nil {
		// IsNotFound indicates that the name does not exist
		return dnsErr.IsNotFound
	}

	// Check for common error messages indicating no records
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "nxdomain") ||
		strings.Contains(errStr, "no answer")
}
