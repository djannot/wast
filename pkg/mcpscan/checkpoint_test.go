package mcpscan

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckpointWriter_CreatesFileAndWritesRecord verifies that Write creates
// the checkpoint file when it does not exist and produces a non-empty JSONL
// file after a single record is written.
func TestCheckpointWriter_CreatesFileAndWritesRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.ckpt")

	w := NewCheckpointWriter(path)
	rec := BulkScanRecord{
		Name:   "server-a",
		Target: "https://a.example.com/mcp",
	}
	if err := w.Write(rec); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("checkpoint file not created: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("checkpoint file is empty after Write")
	}
	// Must end with newline (JSONL format).
	if data[len(data)-1] != '\n' {
		t.Errorf("checkpoint file must end with newline, got: %q", data)
	}
}

// TestCheckpointWriter_MultipleRecords verifies that successive Write calls
// append records as separate lines in the checkpoint file.
func TestCheckpointWriter_MultipleRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.ckpt")

	w := NewCheckpointWriter(path)
	recs := []BulkScanRecord{
		{Name: "a", Target: "https://a.example.com/mcp"},
		{Name: "b", Target: "https://b.example.com/mcp", Errored: true, Unreachable: true},
		{Name: "c", Target: "https://c.example.com/mcp", Skipped: true},
	}
	for _, r := range recs {
		if err := w.Write(r); err != nil {
			t.Fatalf("Write(%s) error: %v", r.Target, err)
		}
	}

	// Load and verify three records are present.
	reader := NewCheckpointReader(path)
	completed, loaded, err := reader.Load()
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if len(loaded) != len(recs) {
		t.Errorf("expected %d records, got %d", len(recs), len(loaded))
	}
	for _, r := range recs {
		if !completed[r.Target] {
			t.Errorf("target %q missing from completed set", r.Target)
		}
	}
}

// TestCheckpointReader_NonExistentFile verifies that loading a non-existent
// file returns nil/empty results without error (fresh start case).
func TestCheckpointReader_NonExistentFile(t *testing.T) {
	reader := NewCheckpointReader("/tmp/this-file-does-not-exist-wast-test.ckpt")
	completed, records, err := reader.Load()
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if completed != nil {
		t.Errorf("expected nil completed map for missing file, got: %v", completed)
	}
	if records != nil {
		t.Errorf("expected nil records for missing file, got: %v", records)
	}
}

// TestCheckpointReader_EmptyFile verifies that an empty checkpoint file
// returns an empty (not nil) completed map and empty records.
func TestCheckpointReader_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.ckpt")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	reader := NewCheckpointReader(path)
	completed, records, err := reader.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(completed) != 0 {
		t.Errorf("expected empty completed set, got %d entries", len(completed))
	}
	if len(records) != 0 {
		t.Errorf("expected empty records, got %d entries", len(records))
	}
}

// TestCheckpointReader_CorruptedLastLine verifies that a partially-written
// final line (simulating an interrupted write) is silently discarded and the
// valid preceding records are still returned.
func TestCheckpointReader_CorruptedLastLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.ckpt")

	// Write two valid records.
	w := NewCheckpointWriter(path)
	valid := []BulkScanRecord{
		{Name: "a", Target: "https://a.example.com/mcp"},
		{Name: "b", Target: "https://b.example.com/mcp"},
	}
	for _, r := range valid {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}

	// Append a corrupted partial line.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"Name":"c","Target":"https://c.exa`) // truncated
	f.Close()

	reader := NewCheckpointReader(path)
	completed, records, err := reader.Load()
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	// Only the two valid records should be returned.
	if len(records) != 2 {
		t.Errorf("expected 2 valid records, got %d", len(records))
	}
	for _, r := range valid {
		if !completed[r.Target] {
			t.Errorf("valid target %q missing from completed set", r.Target)
		}
	}
	// Corrupted target must NOT be in completed set.
	if completed["https://c.exa"] || completed["https://c.example.com/mcp"] {
		t.Error("corrupted partial target should not be in completed set")
	}
}

// TestCheckpointRoundTrip verifies that a BulkScanRecord written by
// CheckpointWriter can be faithfully recovered by CheckpointReader, including
// the Errored/Unreachable/Skipped flags.
func TestCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roundtrip.ckpt")

	original := BulkScanRecord{
		Name:        "my-server",
		Target:      "https://my.server.com/mcp",
		Errored:     true,
		Unreachable: true,
		Skipped:     false,
	}

	w := NewCheckpointWriter(path)
	if err := w.Write(original); err != nil {
		t.Fatalf("Write: %v", err)
	}

	reader := NewCheckpointReader(path)
	_, records, err := reader.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	got := records[0]
	if got.Name != original.Name {
		t.Errorf("Name: got %q, want %q", got.Name, original.Name)
	}
	if got.Target != original.Target {
		t.Errorf("Target: got %q, want %q", got.Target, original.Target)
	}
	if got.Errored != original.Errored {
		t.Errorf("Errored: got %v, want %v", got.Errored, original.Errored)
	}
	if got.Unreachable != original.Unreachable {
		t.Errorf("Unreachable: got %v, want %v", got.Unreachable, original.Unreachable)
	}
	if got.Skipped != original.Skipped {
		t.Errorf("Skipped: got %v, want %v", got.Skipped, original.Skipped)
	}
}

// TestCheckpointWriter_ConcurrentWrites verifies that concurrent Write calls
// do not corrupt the checkpoint file (no interleaved JSON lines).
func TestCheckpointWriter_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.ckpt")
	w := NewCheckpointWriter(path)

	const n = 20
	done := make(chan error, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			done <- w.Write(BulkScanRecord{
				Name:   "server",
				Target: "https://example.com/mcp/" + string(rune('a'+i)),
			})
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent Write error: %v", err)
		}
	}

	reader := NewCheckpointReader(path)
	_, records, err := reader.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(records) != n {
		t.Errorf("expected %d records after concurrent writes, got %d", n, len(records))
	}
}
