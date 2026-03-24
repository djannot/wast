package dns

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// MockHTTPClient implements the HTTPClient interface for testing.
type MockHTTPClient struct {
	Response *http.Response
	Error    error
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.Response, m.Error
}

// MockDNSClient implements the DNSClient interface for testing.
type MockDNSClient struct {
	Envelopes []dns.Envelope
	Error     error
}

func (m *MockDNSClient) Transfer(msg *dns.Msg, address string) (chan *dns.Envelope, error) {
	if m.Error != nil {
		return nil, m.Error
	}

	ch := make(chan *dns.Envelope)
	go func() {
		for _, env := range m.Envelopes {
			envCopy := env
			ch <- &envCopy
		}
		close(ch)
	}()
	return ch, nil
}

func TestSubdomainDiscoverer_DiscoverFromCT(t *testing.T) {
	tests := []struct {
		name           string
		domain         string
		httpResponse   string
		httpStatusCode int
		httpError      error
		wantSubdomains []string
		wantError      bool
	}{
		{
			name:   "successful CT lookup with subdomains",
			domain: "example.com",
			httpResponse: `[
				{"name_value": "www.example.com", "common_name": "www.example.com"},
				{"name_value": "api.example.com", "common_name": "api.example.com"},
				{"name_value": "mail.example.com", "common_name": "mail.example.com"}
			]`,
			httpStatusCode: http.StatusOK,
			wantSubdomains: []string{"www.example.com", "api.example.com", "mail.example.com"},
			wantError:      false,
		},
		{
			name:   "CT lookup with wildcard entries",
			domain: "example.com",
			httpResponse: `[
				{"name_value": "*.example.com", "common_name": "*.example.com"},
				{"name_value": "www.example.com", "common_name": "www.example.com"}
			]`,
			httpStatusCode: http.StatusOK,
			wantSubdomains: []string{"www.example.com"},
			wantError:      false,
		},
		{
			name:   "CT lookup with newline-separated names",
			domain: "example.com",
			httpResponse: `[
				{"name_value": "www.example.com\napi.example.com", "common_name": ""}
			]`,
			httpStatusCode: http.StatusOK,
			wantSubdomains: []string{"www.example.com", "api.example.com"},
			wantError:      false,
		},
		{
			name:           "CT lookup with empty response",
			domain:         "example.com",
			httpResponse:   "[]",
			httpStatusCode: http.StatusOK,
			wantSubdomains: []string{},
			wantError:      false,
		},
		{
			name:           "CT lookup with null response",
			domain:         "example.com",
			httpResponse:   "null",
			httpStatusCode: http.StatusOK,
			wantSubdomains: []string{},
			wantError:      false,
		},
		{
			name:           "CT lookup HTTP error",
			domain:         "example.com",
			httpError:      errors.New("connection refused"),
			wantSubdomains: nil,
			wantError:      true,
		},
		{
			name:           "CT lookup non-200 status",
			domain:         "example.com",
			httpResponse:   "",
			httpStatusCode: http.StatusInternalServerError,
			wantSubdomains: nil,
			wantError:      true,
		},
		{
			name:   "CT lookup filters out domain itself",
			domain: "example.com",
			httpResponse: `[
				{"name_value": "example.com", "common_name": "example.com"},
				{"name_value": "www.example.com", "common_name": "www.example.com"}
			]`,
			httpStatusCode: http.StatusOK,
			wantSubdomains: []string{"www.example.com"},
			wantError:      false,
		},
		{
			name:   "CT lookup filters out non-matching domains",
			domain: "example.com",
			httpResponse: `[
				{"name_value": "www.example.com", "common_name": "www.example.com"},
				{"name_value": "www.otherdomain.com", "common_name": "www.otherdomain.com"}
			]`,
			httpStatusCode: http.StatusOK,
			wantSubdomains: []string{"www.example.com"},
			wantError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mockHTTP *MockHTTPClient
			if tt.httpError != nil {
				mockHTTP = &MockHTTPClient{Error: tt.httpError}
			} else {
				mockHTTP = &MockHTTPClient{
					Response: &http.Response{
						StatusCode: tt.httpStatusCode,
						Body:       io.NopCloser(bytes.NewBufferString(tt.httpResponse)),
					},
				}
			}

			d := NewSubdomainDiscoverer(
				WithHTTPClient(mockHTTP),
				WithSubdomainTimeout(5*time.Second),
			)

			ctx := context.Background()
			subdomains, err := d.discoverFromCT(ctx, tt.domain)

			if tt.wantError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(subdomains) != len(tt.wantSubdomains) {
				t.Errorf("Subdomains count: got %d, want %d", len(subdomains), len(tt.wantSubdomains))
				t.Errorf("Got: %v, Want: %v", subdomains, tt.wantSubdomains)
				return
			}

			for i, want := range tt.wantSubdomains {
				if i < len(subdomains) && subdomains[i] != want {
					t.Errorf("Subdomain[%d]: got %s, want %s", i, subdomains[i], want)
				}
			}
		})
	}
}

func TestSubdomainDiscoverer_DiscoverFromZoneTransfer(t *testing.T) {
	tests := []struct {
		name           string
		domain         string
		nsRecords      []*net.NS
		nsError        error
		dnsEnvelopes   []dns.Envelope
		dnsError       error
		wantSubdomains []string
		wantError      bool
	}{
		{
			name:   "successful zone transfer",
			domain: "example.com",
			nsRecords: []*net.NS{
				{Host: "ns1.example.com."},
			},
			dnsEnvelopes: []dns.Envelope{
				{
					RR: []dns.RR{
						&dns.A{Hdr: dns.RR_Header{Name: "www.example.com."}},
						&dns.A{Hdr: dns.RR_Header{Name: "api.example.com."}},
						&dns.A{Hdr: dns.RR_Header{Name: "example.com."}}, // Should be filtered
					},
				},
			},
			wantSubdomains: []string{"api.example.com", "www.example.com"},
			wantError:      false,
		},
		{
			name:      "no NS records",
			domain:    "example.com",
			nsRecords: []*net.NS{},
			wantError: true,
		},
		{
			name:      "NS lookup error",
			domain:    "example.com",
			nsError:   errors.New("lookup failed"),
			wantError: true,
		},
		{
			name:   "zone transfer refused",
			domain: "example.com",
			nsRecords: []*net.NS{
				{Host: "ns1.example.com."},
			},
			dnsError:       errors.New("zone transfer refused"),
			wantSubdomains: nil,
			wantError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockResolver := &MockResolver{
				NSResult: tt.nsRecords,
				NSError:  tt.nsError,
			}

			mockDNS := &MockDNSClient{
				Envelopes: tt.dnsEnvelopes,
				Error:     tt.dnsError,
			}

			d := NewSubdomainDiscoverer(
				WithSubdomainResolver(mockResolver),
				WithDNSClient(mockDNS),
				WithSubdomainTimeout(5*time.Second),
			)

			ctx := context.Background()
			subdomains, err := d.discoverFromZoneTransfer(ctx, tt.domain)

			if tt.wantError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(subdomains) != len(tt.wantSubdomains) {
				t.Errorf("Subdomains count: got %d, want %d", len(subdomains), len(tt.wantSubdomains))
				return
			}

			// Sort both for comparison (order might differ)
			for _, want := range tt.wantSubdomains {
				found := false
				for _, got := range subdomains {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected subdomain %s not found in results: %v", want, subdomains)
				}
			}
		})
	}
}

func TestSubdomainDiscoverer_Discover(t *testing.T) {
	t.Run("combines results from CT and zone transfer", func(t *testing.T) {
		mockHTTP := &MockHTTPClient{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewBufferString(`[
					{"name_value": "www.example.com", "common_name": "www.example.com"},
					{"name_value": "api.example.com", "common_name": "api.example.com"}
				]`)),
			},
		}

		mockResolver := &MockResolver{
			NSResult: []*net.NS{
				{Host: "ns1.example.com."},
			},
		}

		mockDNS := &MockDNSClient{
			Envelopes: []dns.Envelope{
				{
					RR: []dns.RR{
						&dns.A{Hdr: dns.RR_Header{Name: "mail.example.com."}},
						&dns.A{Hdr: dns.RR_Header{Name: "www.example.com."}}, // Duplicate
					},
				},
			},
		}

		d := NewSubdomainDiscoverer(
			WithHTTPClient(mockHTTP),
			WithSubdomainResolver(mockResolver),
			WithDNSClient(mockDNS),
			WithSubdomainTimeout(5*time.Second),
		)

		ctx := context.Background()
		subdomains, errs := d.Discover(ctx, "example.com")

		// Should have 3 unique subdomains (www, api, mail)
		if len(subdomains) != 3 {
			t.Errorf("Expected 3 subdomains, got %d: %v", len(subdomains), subdomains)
		}

		// Results should be sorted
		expected := []string{"api.example.com", "mail.example.com", "www.example.com"}
		for i, want := range expected {
			if i < len(subdomains) && subdomains[i] != want {
				t.Errorf("Subdomain[%d]: got %s, want %s", i, subdomains[i], want)
			}
		}

		// Should have no errors
		if len(errs) != 0 {
			t.Errorf("Expected no errors, got %v", errs)
		}
	})

	t.Run("handles CT error gracefully", func(t *testing.T) {
		mockHTTP := &MockHTTPClient{
			Error: errors.New("connection refused"),
		}

		mockResolver := &MockResolver{
			NSResult: []*net.NS{
				{Host: "ns1.example.com."},
			},
		}

		mockDNS := &MockDNSClient{
			Envelopes: []dns.Envelope{
				{
					RR: []dns.RR{
						&dns.A{Hdr: dns.RR_Header{Name: "www.example.com."}},
					},
				},
			},
		}

		d := NewSubdomainDiscoverer(
			WithHTTPClient(mockHTTP),
			WithSubdomainResolver(mockResolver),
			WithDNSClient(mockDNS),
			WithSubdomainTimeout(5*time.Second),
		)

		ctx := context.Background()
		subdomains, errs := d.Discover(ctx, "example.com")

		// Should still have results from zone transfer
		if len(subdomains) != 1 {
			t.Errorf("Expected 1 subdomain from zone transfer, got %d", len(subdomains))
		}

		// Should have error from CT lookup
		if len(errs) != 1 {
			t.Errorf("Expected 1 error, got %d: %v", len(errs), errs)
		}
	})
}

func TestIsSubdomainOf(t *testing.T) {
	tests := []struct {
		name   string
		sub    string
		domain string
		want   bool
	}{
		{"exact match", "example.com", "example.com", true},
		{"subdomain", "www.example.com", "example.com", true},
		{"nested subdomain", "api.v1.example.com", "example.com", true},
		{"different domain", "www.other.com", "example.com", false},
		{"partial match", "notexample.com", "example.com", false},
		{"with trailing dots", "www.example.com.", "example.com.", true},
		{"case insensitive", "WWW.EXAMPLE.COM", "example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSubdomainOf(tt.sub, tt.domain); got != tt.want {
				t.Errorf("isSubdomainOf(%q, %q) = %v, want %v", tt.sub, tt.domain, got, tt.want)
			}
		})
	}
}

func TestNewSubdomainDiscoverer(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		d := NewSubdomainDiscoverer()
		if d.httpClient == nil {
			t.Error("Expected default HTTP client to be set")
		}
		if d.dnsClient == nil {
			t.Error("Expected default DNS client to be set")
		}
		if d.resolver == nil {
			t.Error("Expected default resolver to be set")
		}
		if d.timeout != 30*time.Second {
			t.Errorf("Expected default timeout of 30s, got %v", d.timeout)
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		d := NewSubdomainDiscoverer(WithSubdomainTimeout(60 * time.Second))
		if d.timeout != 60*time.Second {
			t.Errorf("Expected timeout of 60s, got %v", d.timeout)
		}
	})

	t.Run("custom HTTP client", func(t *testing.T) {
		mock := &MockHTTPClient{}
		d := NewSubdomainDiscoverer(WithHTTPClient(mock))
		if d.httpClient != mock {
			t.Error("Expected custom HTTP client to be set")
		}
	})

	t.Run("custom DNS client", func(t *testing.T) {
		mock := &MockDNSClient{}
		d := NewSubdomainDiscoverer(WithDNSClient(mock))
		if d.dnsClient != mock {
			t.Error("Expected custom DNS client to be set")
		}
	})

	t.Run("custom resolver", func(t *testing.T) {
		mock := &MockResolver{}
		d := NewSubdomainDiscoverer(WithSubdomainResolver(mock))
		if d.resolver != mock {
			t.Error("Expected custom resolver to be set")
		}
	})
}

func TestDNSResult_WithSubdomains(t *testing.T) {
	t.Run("HasRecords with subdomains", func(t *testing.T) {
		result := &DNSResult{
			Domain:     "example.com",
			Subdomains: []string{"www.example.com"},
		}
		if !result.HasRecords() {
			t.Error("HasRecords() should return true when subdomains are present")
		}
	})

	t.Run("String includes subdomains", func(t *testing.T) {
		result := &DNSResult{
			Domain:     "example.com",
			Subdomains: []string{"www.example.com", "api.example.com"},
		}
		str := result.String()
		if !contains(str, "Subdomains Discovered") {
			t.Error("String should contain 'Subdomains Discovered'")
		}
		if !contains(str, "www.example.com") {
			t.Error("String should contain subdomain www.example.com")
		}
		if !contains(str, "api.example.com") {
			t.Error("String should contain subdomain api.example.com")
		}
	})
}
