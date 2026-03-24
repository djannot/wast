package dns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// MockResolver implements the Resolver interface for testing.
type MockResolver struct {
	HostResult  []string
	HostError   error
	IP4Result   []net.IP
	IP4Error    error
	IP6Result   []net.IP
	IP6Error    error
	MXResult    []*net.MX
	MXError     error
	NSResult    []*net.NS
	NSError     error
	TXTResult   []string
	TXTError    error
	CNAMEResult string
	CNAMEError  error
}

func (m *MockResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return m.HostResult, m.HostError
}

func (m *MockResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if network == "ip4" {
		return m.IP4Result, m.IP4Error
	}
	return m.IP6Result, m.IP6Error
}

func (m *MockResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return m.MXResult, m.MXError
}

func (m *MockResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return m.NSResult, m.NSError
}

func (m *MockResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return m.TXTResult, m.TXTError
}

func (m *MockResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return m.CNAMEResult, m.CNAMEError
}

func TestEnumerator_Enumerate(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		mock     *MockResolver
		wantA    []string
		wantAAAA []string
		wantMX   []MXRecord
		wantNS   []string
		wantTXT  []string
		wantCNAME string
		wantErrs int
	}{
		{
			name:   "successful enumeration with all record types",
			domain: "example.com",
			mock: &MockResolver{
				IP4Result: []net.IP{net.ParseIP("93.184.216.34")},
				IP6Result: []net.IP{net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")},
				MXResult: []*net.MX{
					{Host: "mail.example.com.", Pref: 10},
					{Host: "mail2.example.com.", Pref: 20},
				},
				NSResult: []*net.NS{
					{Host: "a.iana-servers.net."},
					{Host: "b.iana-servers.net."},
				},
				TXTResult:   []string{"v=spf1 -all"},
				CNAMEResult: "example.com.",
			},
			wantA:    []string{"93.184.216.34"},
			wantAAAA: []string{"2606:2800:220:1:248:1893:25c8:1946"},
			wantMX: []MXRecord{
				{Host: "mail.example.com", Priority: 10},
				{Host: "mail2.example.com", Priority: 20},
			},
			wantNS:  []string{"a.iana-servers.net", "b.iana-servers.net"},
			wantTXT: []string{"v=spf1 -all"},
			wantCNAME: "", // Same as domain, so not set
			wantErrs: 0,
		},
		{
			name:   "domain with CNAME pointing elsewhere",
			domain: "www.example.com",
			mock: &MockResolver{
				IP4Result:   []net.IP{net.ParseIP("93.184.216.34")},
				CNAMEResult: "example.com.",
			},
			wantA:     []string{"93.184.216.34"},
			wantCNAME: "example.com",
			wantErrs:  0,
		},
		{
			name:   "empty domain",
			domain: "",
			mock:   &MockResolver{},
			wantErrs: 1,
		},
		{
			name:   "whitespace only domain",
			domain: "   ",
			mock:   &MockResolver{},
			wantErrs: 1,
		},
		{
			name:   "domain with protocol prefix",
			domain: "https://example.com",
			mock: &MockResolver{
				IP4Result: []net.IP{net.ParseIP("93.184.216.34")},
			},
			wantA:    []string{"93.184.216.34"},
			wantErrs: 0,
		},
		{
			name:   "domain with path",
			domain: "https://example.com/path/to/resource",
			mock: &MockResolver{
				IP4Result: []net.IP{net.ParseIP("93.184.216.34")},
			},
			wantA:    []string{"93.184.216.34"},
			wantErrs: 0,
		},
		{
			name:   "lookup errors are recorded",
			domain: "example.com",
			mock: &MockResolver{
				IP4Error: errors.New("connection refused"),
				MXError:  errors.New("timeout"),
			},
			wantErrs: 2,
		},
		{
			name:   "no such host errors are not recorded",
			domain: "nonexistent.example.com",
			mock: &MockResolver{
				IP4Error: &net.DNSError{
					Err:        "no such host",
					Name:       "nonexistent.example.com",
					IsNotFound: true,
				},
			},
			wantErrs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEnumerator(
				WithResolver(tt.mock),
				WithTimeout(5*time.Second),
			)

			result := e.Enumerate(tt.domain)

			// Check A records
			if len(result.A) != len(tt.wantA) {
				t.Errorf("A records: got %d, want %d", len(result.A), len(tt.wantA))
			}
			for i, want := range tt.wantA {
				if i < len(result.A) && result.A[i] != want {
					t.Errorf("A[%d]: got %s, want %s", i, result.A[i], want)
				}
			}

			// Check AAAA records
			if len(result.AAAA) != len(tt.wantAAAA) {
				t.Errorf("AAAA records: got %d, want %d", len(result.AAAA), len(tt.wantAAAA))
			}

			// Check MX records
			if len(result.MX) != len(tt.wantMX) {
				t.Errorf("MX records: got %d, want %d", len(result.MX), len(tt.wantMX))
			}
			for i, want := range tt.wantMX {
				if i < len(result.MX) {
					if result.MX[i].Host != want.Host {
						t.Errorf("MX[%d].Host: got %s, want %s", i, result.MX[i].Host, want.Host)
					}
					if result.MX[i].Priority != want.Priority {
						t.Errorf("MX[%d].Priority: got %d, want %d", i, result.MX[i].Priority, want.Priority)
					}
				}
			}

			// Check NS records
			if len(result.NS) != len(tt.wantNS) {
				t.Errorf("NS records: got %d, want %d", len(result.NS), len(tt.wantNS))
			}

			// Check TXT records
			if len(result.TXT) != len(tt.wantTXT) {
				t.Errorf("TXT records: got %d, want %d", len(result.TXT), len(tt.wantTXT))
			}

			// Check CNAME
			if result.CNAME != tt.wantCNAME {
				t.Errorf("CNAME: got %s, want %s", result.CNAME, tt.wantCNAME)
			}

			// Check errors
			if len(result.Errors) != tt.wantErrs {
				t.Errorf("Errors: got %d (%v), want %d", len(result.Errors), result.Errors, tt.wantErrs)
			}
		})
	}
}

func TestEnumerator_WithOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		e := NewEnumerator()
		if e.resolver == nil {
			t.Error("Expected default resolver to be set")
		}
		if e.timeout != 10*time.Second {
			t.Errorf("Expected default timeout of 10s, got %v", e.timeout)
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		e := NewEnumerator(WithTimeout(30 * time.Second))
		if e.timeout != 30*time.Second {
			t.Errorf("Expected timeout of 30s, got %v", e.timeout)
		}
	})

	t.Run("custom resolver", func(t *testing.T) {
		mock := &MockResolver{}
		e := NewEnumerator(WithResolver(mock))
		if e.resolver != mock {
			t.Error("Expected custom resolver to be set")
		}
	})
}

func TestDNSResult_String(t *testing.T) {
	result := &DNSResult{
		Domain: "example.com",
		A:      []string{"93.184.216.34"},
		AAAA:   []string{"2606:2800:220:1:248:1893:25c8:1946"},
		MX:     []MXRecord{{Host: "mail.example.com", Priority: 10}},
		NS:     []string{"a.iana-servers.net"},
		TXT:    []string{"v=spf1 -all"},
		CNAME:  "www.example.com",
		Errors: []string{"test error"},
	}

	str := result.String()

	// Check that all sections are present
	if !contains(str, "example.com") {
		t.Error("String should contain domain")
	}
	if !contains(str, "93.184.216.34") {
		t.Error("String should contain A record")
	}
	if !contains(str, "2606:2800:220:1:248:1893:25c8:1946") {
		t.Error("String should contain AAAA record")
	}
	if !contains(str, "mail.example.com") {
		t.Error("String should contain MX record")
	}
	if !contains(str, "a.iana-servers.net") {
		t.Error("String should contain NS record")
	}
	if !contains(str, "v=spf1 -all") {
		t.Error("String should contain TXT record")
	}
	if !contains(str, "www.example.com") {
		t.Error("String should contain CNAME record")
	}
	if !contains(str, "test error") {
		t.Error("String should contain error")
	}
}

func TestDNSResult_HasRecords(t *testing.T) {
	tests := []struct {
		name   string
		result *DNSResult
		want   bool
	}{
		{
			name:   "no records",
			result: &DNSResult{Domain: "example.com"},
			want:   false,
		},
		{
			name:   "with A record",
			result: &DNSResult{Domain: "example.com", A: []string{"1.2.3.4"}},
			want:   true,
		},
		{
			name:   "with AAAA record",
			result: &DNSResult{Domain: "example.com", AAAA: []string{"::1"}},
			want:   true,
		},
		{
			name:   "with MX record",
			result: &DNSResult{Domain: "example.com", MX: []MXRecord{{Host: "mail.example.com"}}},
			want:   true,
		},
		{
			name:   "with NS record",
			result: &DNSResult{Domain: "example.com", NS: []string{"ns1.example.com"}},
			want:   true,
		},
		{
			name:   "with TXT record",
			result: &DNSResult{Domain: "example.com", TXT: []string{"v=spf1"}},
			want:   true,
		},
		{
			name:   "with CNAME record",
			result: &DNSResult{Domain: "example.com", CNAME: "www.example.com"},
			want:   true,
		},
		{
			name:   "only errors",
			result: &DNSResult{Domain: "example.com", Errors: []string{"error"}},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasRecords(); got != tt.want {
				t.Errorf("HasRecords() = %v, want %v", got, tt.want)
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
		{"https://example.com/path/to/resource", "example.com"},
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

// Integration test that performs a real DNS lookup.
// This test uses example.com which is a well-known domain maintained by IANA.
func TestEnumerator_IntegrationTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	e := NewEnumerator(WithTimeout(30 * time.Second))
	result := e.Enumerate("example.com")

	// example.com should have at least an A record
	if len(result.A) == 0 {
		t.Error("Expected at least one A record for example.com")
	}

	// example.com should have NS records
	if len(result.NS) == 0 {
		t.Error("Expected at least one NS record for example.com")
	}

	// Domain should be set correctly
	if result.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got %s", result.Domain)
	}

	// Log the results for manual verification
	t.Logf("DNS Results for example.com:\n%s", result.String())
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
