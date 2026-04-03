package mcpscan

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
)

// CheckpointWriter appends BulkScanRecord entries to a JSONL checkpoint file
// after each server scan completes. Each record is written as a single JSON
// line followed by a newline, and Sync is called for crash safety.
// A mutex ensures concurrent goroutines do not interleave writes.
type CheckpointWriter struct {
	path string
	mu   sync.Mutex
}

// NewCheckpointWriter returns a CheckpointWriter that writes to path.
func NewCheckpointWriter(path string) *CheckpointWriter {
	return &CheckpointWriter{path: path}
}

// Write serializes rec as a JSON line and appends it to the checkpoint file.
// The file is created if it does not exist. Each call opens, writes, syncs,
// and closes the file so that a crash after any completed server leaves the
// file in a valid (albeit partial) state.
func (w *CheckpointWriter) Write(rec BulkScanRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// CheckpointReader loads an existing JSONL checkpoint file produced by
// CheckpointWriter and returns the set of already-completed target URLs and
// the parsed records so they can be merged back into a resumed scan.
type CheckpointReader struct {
	path string
}

// NewCheckpointReader returns a CheckpointReader that reads from path.
func NewCheckpointReader(path string) *CheckpointReader {
	return &CheckpointReader{path: path}
}

// Load reads the checkpoint file and returns:
//   - completed: a set of target URLs that have already been scanned.
//   - records:   the parsed BulkScanRecord slice for result merging.
//
// If the file does not exist both return values are nil/empty (not an error).
// A corrupted final line (from an interrupted write) is silently discarded so
// that the target is re-scanned on resume.
func (r *CheckpointReader) Load() (completed map[string]bool, records []BulkScanRecord, err error) {
	f, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	defer f.Close()

	completed = make(map[string]bool)

	scanner := bufio.NewScanner(f)
	// Allow lines up to 16 MB to accommodate large scan results.
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var rec BulkScanRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			// Skip corrupted / partial last line — it will be re-scanned.
			continue
		}
		if rec.Target != "" {
			completed[rec.Target] = true
			records = append(records, rec)
		}
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return nil, nil, scanErr
	}
	return completed, records, nil
}
