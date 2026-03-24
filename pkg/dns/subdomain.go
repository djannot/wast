// Package dns provides DNS enumeration functionality for reconnaissance operations.
package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// HTTPClient defines the interface for HTTP operations, allowing for mock implementations in tests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DNSClient defines the interface for low-level DNS operations (e.g., zone transfers).
type DNSClient interface {
	Transfer(m *dns.Msg, address string) (chan *dns.Envelope, error)
}

// DefaultHTTPClient wraps the standard http.Client.
type DefaultHTTPClient struct {
	client *http.Client
}

// NewDefaultHTTPClient creates a new DefaultHTTPClient with the given timeout.
func NewDefaultHTTPClient(timeout time.Duration) *DefaultHTTPClient {
	return &DefaultHTTPClient{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Do performs an HTTP request.
func (c *DefaultHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// DefaultDNSClient wraps the miekg/dns Transfer functionality.
type DefaultDNSClient struct {
	timeout time.Duration
}

// NewDefaultDNSClient creates a new DefaultDNSClient with the given timeout.
func NewDefaultDNSClient(timeout time.Duration) *DefaultDNSClient {
	return &DefaultDNSClient{
		timeout: timeout,
	}
}

// Transfer performs a DNS zone transfer (AXFR).
func (c *DefaultDNSClient) Transfer(m *dns.Msg, address string) (chan *dns.Envelope, error) {
	t := &dns.Transfer{
		DialTimeout:  c.timeout,
		ReadTimeout:  c.timeout,
		WriteTimeout: c.timeout,
	}
	return t.In(m, address)
}

// SubdomainDiscoverer performs subdomain discovery using various techniques.
type SubdomainDiscoverer struct {
	httpClient HTTPClient
	dnsClient  DNSClient
	resolver   Resolver
	timeout    time.Duration
}

// SubdomainOption is a function that configures a SubdomainDiscoverer.
type SubdomainOption func(*SubdomainDiscoverer)

// WithHTTPClient sets a custom HTTP client for the discoverer.
func WithHTTPClient(c HTTPClient) SubdomainOption {
	return func(d *SubdomainDiscoverer) {
		d.httpClient = c
	}
}

// WithDNSClient sets a custom DNS client for the discoverer.
func WithDNSClient(c DNSClient) SubdomainOption {
	return func(d *SubdomainDiscoverer) {
		d.dnsClient = c
	}
}

// WithSubdomainResolver sets a custom resolver for the discoverer.
func WithSubdomainResolver(r Resolver) SubdomainOption {
	return func(d *SubdomainDiscoverer) {
		d.resolver = r
	}
}

// WithSubdomainTimeout sets the timeout for discovery operations.
func WithSubdomainTimeout(t time.Duration) SubdomainOption {
	return func(d *SubdomainDiscoverer) {
		d.timeout = t
	}
}

// NewSubdomainDiscoverer creates a new SubdomainDiscoverer with the given options.
func NewSubdomainDiscoverer(opts ...SubdomainOption) *SubdomainDiscoverer {
	d := &SubdomainDiscoverer{
		timeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(d)
	}

	// Set default clients if not provided
	if d.httpClient == nil {
		d.httpClient = NewDefaultHTTPClient(d.timeout)
	}
	if d.dnsClient == nil {
		d.dnsClient = NewDefaultDNSClient(d.timeout)
	}
	if d.resolver == nil {
		d.resolver = NewDefaultResolver()
	}

	return d
}

// Discover performs subdomain discovery for the given domain using passive techniques.
// It combines results from Certificate Transparency logs and DNS zone transfer attempts.
func (d *SubdomainDiscoverer) Discover(ctx context.Context, domain string) ([]string, []string) {
	subdomains := make(map[string]struct{})
	var errors []string

	// Certificate Transparency lookup
	ctSubdomains, ctErr := d.discoverFromCT(ctx, domain)
	if ctErr != nil {
		errors = append(errors, fmt.Sprintf("CT lookup: %v", ctErr))
	} else {
		for _, sub := range ctSubdomains {
			subdomains[sub] = struct{}{}
		}
	}

	// DNS Zone Transfer attempt
	axfrSubdomains, axfrErr := d.discoverFromZoneTransfer(ctx, domain)
	if axfrErr != nil {
		// Zone transfer failures are common and expected, don't report as error
		// unless it's not a "refused" or "not allowed" type error
		errStr := strings.ToLower(axfrErr.Error())
		if !strings.Contains(errStr, "refused") &&
			!strings.Contains(errStr, "not allowed") &&
			!strings.Contains(errStr, "notauth") &&
			!strings.Contains(errStr, "servfail") {
			errors = append(errors, fmt.Sprintf("Zone transfer: %v", axfrErr))
		}
	} else {
		for _, sub := range axfrSubdomains {
			subdomains[sub] = struct{}{}
		}
	}

	// Convert map to sorted slice
	result := make([]string, 0, len(subdomains))
	for sub := range subdomains {
		result = append(result, sub)
	}
	sort.Strings(result)

	return result, errors
}

// CTLogEntry represents an entry from crt.sh Certificate Transparency logs.
type CTLogEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

// discoverFromCT queries Certificate Transparency logs via crt.sh API.
func (d *SubdomainDiscoverer) discoverFromCT(ctx context.Context, domain string) ([]string, error) {
	// Build the crt.sh URL
	ctURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", ctURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "WAST-Security-Scanner/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CT logs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CT log server returned status %d", resp.StatusCode)
	}

	// Read and parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Handle empty response (no certificates found)
	if len(body) == 0 || string(body) == "null" || string(body) == "[]" {
		return []string{}, nil
	}

	var entries []CTLogEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse CT log response: %w", err)
	}

	// Extract unique subdomains
	seen := make(map[string]struct{})
	var subdomains []string

	for _, entry := range entries {
		// Process both name_value and common_name fields
		names := []string{entry.NameValue, entry.CommonName}
		for _, name := range names {
			// Split on newlines (crt.sh sometimes returns multiple names)
			for _, n := range strings.Split(name, "\n") {
				n = strings.TrimSpace(n)
				n = strings.ToLower(n)

				// Skip empty, wildcard-only entries, and non-matching domains
				if n == "" || n == "*" {
					continue
				}

				// Remove wildcard prefix if present
				n = strings.TrimPrefix(n, "*.")

				// Verify it's a subdomain of the target domain
				if !isSubdomainOf(n, domain) {
					continue
				}

				// Skip if it's exactly the domain itself
				if n == strings.ToLower(domain) {
					continue
				}

				if _, exists := seen[n]; !exists {
					seen[n] = struct{}{}
					subdomains = append(subdomains, n)
				}
			}
		}
	}

	return subdomains, nil
}

// discoverFromZoneTransfer attempts a DNS zone transfer (AXFR) to discover subdomains.
func (d *SubdomainDiscoverer) discoverFromZoneTransfer(ctx context.Context, domain string) ([]string, error) {
	// First, lookup the NS records for the domain
	nsRecords, err := d.resolver.LookupNS(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup NS records: %w", err)
	}

	if len(nsRecords) == 0 {
		return nil, fmt.Errorf("no NS records found for domain")
	}

	var subdomains []string
	var lastErr error

	// Try zone transfer against each nameserver
	for _, ns := range nsRecords {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		subs, err := d.attemptZoneTransfer(domain, nsHost)
		if err != nil {
			lastErr = err
			continue
		}
		subdomains = append(subdomains, subs...)
		// If we got results, no need to try other nameservers
		if len(subs) > 0 {
			break
		}
	}

	if len(subdomains) == 0 && lastErr != nil {
		return nil, lastErr
	}

	return subdomains, nil
}

// attemptZoneTransfer performs an AXFR query against a specific nameserver.
func (d *SubdomainDiscoverer) attemptZoneTransfer(domain, nameserver string) ([]string, error) {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	// Try port 53 for zone transfer
	address := fmt.Sprintf("%s:53", nameserver)

	env, err := d.dnsClient.Transfer(m, address)
	if err != nil {
		return nil, fmt.Errorf("zone transfer failed: %w", err)
	}

	seen := make(map[string]struct{})
	var subdomains []string
	domainLower := strings.ToLower(domain)

	for e := range env {
		if e.Error != nil {
			return nil, fmt.Errorf("zone transfer error: %w", e.Error)
		}

		for _, rr := range e.RR {
			name := strings.TrimSuffix(strings.ToLower(rr.Header().Name), ".")

			// Skip if it's the domain itself or not a subdomain
			if name == domainLower || !isSubdomainOf(name, domain) {
				continue
			}

			if _, exists := seen[name]; !exists {
				seen[name] = struct{}{}
				subdomains = append(subdomains, name)
			}
		}
	}

	return subdomains, nil
}

// isSubdomainOf checks if name is a subdomain of domain.
func isSubdomainOf(name, domain string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	if name == domain {
		return true
	}

	return strings.HasSuffix(name, "."+domain)
}
