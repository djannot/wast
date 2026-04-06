package scanner

import (
	"bytes"
	"testing"
)

// TestReadResponseBody_Limit verifies that readResponseBody truncates responses
// that exceed maxResponseBodySize, preventing memory exhaustion from oversized
// server responses.
func TestReadResponseBody_Limit(t *testing.T) {
	oversizeLen := maxResponseBodySize + 1024 // slightly over the limit
	oversized := bytes.Repeat([]byte("A"), oversizeLen)

	got, err := readResponseBody(bytes.NewReader(oversized))
	if err != nil {
		t.Fatalf("readResponseBody returned unexpected error: %v", err)
	}
	if len(got) != maxResponseBodySize {
		t.Errorf("expected body truncated to %d bytes, got %d", maxResponseBodySize, len(got))
	}
}

// TestReadResponseBody_UnderLimit verifies that small responses are returned
// in full without truncation.
func TestReadResponseBody_UnderLimit(t *testing.T) {
	data := []byte("hello, world")

	got, err := readResponseBody(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("readResponseBody returned unexpected error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("expected body %q, got %q", data, got)
	}
}

func TestTitleCase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"reflected", "Reflected"},
		{"stored", "Stored"},
		{"blind", "Blind"},
		{"unix", "Unix"},
		{"windows", "Windows"},
		{"error-based", "Error-Based"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := titleCase(tt.input)
			if got != tt.want {
				t.Errorf("titleCase(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
