package httputil

import (
	"bytes"
	"testing"
)

func TestReadResponseBody_Limit(t *testing.T) {
	oversizeLen := MaxResponseBodySize + 1024
	oversized := bytes.Repeat([]byte("B"), oversizeLen)

	got, err := ReadResponseBody(bytes.NewReader(oversized))
	if err != nil {
		t.Fatalf("ReadResponseBody returned unexpected error: %v", err)
	}
	if len(got) != MaxResponseBodySize {
		t.Errorf("expected body truncated to %d bytes, got %d", MaxResponseBodySize, len(got))
	}
}

func TestReadResponseBody_UnderLimit(t *testing.T) {
	data := []byte("small response body")

	got, err := ReadResponseBody(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadResponseBody returned unexpected error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("expected body %q, got %q", data, got)
	}
}
