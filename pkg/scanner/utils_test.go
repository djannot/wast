package scanner

import "testing"

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
