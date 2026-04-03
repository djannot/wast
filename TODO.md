# WAST - TODO

## MCP Discovery & Scanning Improvements

### P0: Fix noise and usability

- [x] **Permission checker false positives** — Switched from `strings.Contains` substring matching to pre-compiled `\b` whole-word regexp patterns, and added context-aware co-occurrence guard for ambiguous keywords like `"token"`. False positives from "refresh"/"push"/"publish" (sh), "relevant"/"evaluation" (eval), and blockchain token descriptions are eliminated.
- [x] **Aggregated summary for bulk scans** — Added `BulkScanSummary` type and `BuildBulkScanSummary` aggregation logic. The `scan` subcommand now prints a concise summary block after per-server results and supports `--summary-only` to suppress per-server detail. JSON output wraps all results in a `BulkScanResult` with a `bulk_summary` field.
- [x] **Concurrency for bulk scanning** — Scanning 10 servers took ~2 minutes (sequential). 1,760 would take ~6 hours. Add `--concurrency N` flag to scan multiple servers in parallel.

### P1: New detection capabilities

- [x] **Tool invocation data exposure** — On open servers, call each tool with benign args and scan responses for leaked API keys, internal IPs, database connection strings, stack traces, environment variables. Servers like agentrapay (payments) and aarna.ai (crypto) are prime candidates. Added `benignArgStrategy` to `ExposureChecker` that generates up to 3 semantically-realistic argument sets per tool using param-name heuristics, enum extraction from descriptions, and wildcard variants for query/search params.
- [x] **SSRF through tool parameters** — Response-based probes (cloud metadata, file://) were already implemented. Added OOB (out-of-band) callback detection for blind SSRF via `pkg/callback` server integration. Use `--ssrf-callback-host <url>` with `--active` to enable. Integration test `TestBlindSSRFDetected` validates the full OOB path against the vulnerable server's `fetch_url_blind` tool.
- [x] **Registry as a discovery source** — `wast mcpscan discover --registry` that pulls directly from the MCP registry API instead of needing the Python script + converter. Makes the workflow seamless.

### P2: Operational polish

- [x] **Rate limiting for bulk scans** — Added `--rate-limit` flag for token-bucket throttling of bulk scans. Automatic backoff on 429 responses implemented: `retryableDo` wrapper in `pkg/mcpscan/client.go` detects HTTP 429, honours `Retry-After` header (delta-seconds or HTTP-date per RFC 7231 §7.1.3), and falls back to exponential backoff (1 s → 60 s). Max retries default is 3, configurable via `WithMaxRetries`. `BulkScanSummary.RateLimited` and `BulkScanRecord.Retries` track 429 events; per-server log lines surface `retried N× after 429`.
- [x] **Resume/checkpoint for long scans** — For bulk scans across 1,760 servers, save progress so you can resume after interruption instead of starting over. Added `--checkpoint <file>` flag to `wast mcpscan scan` that writes a JSONL checkpoint after each server and resumes from completed entries on re-run.
- [x] **Filter by auth status** — `wast mcpscan scan --targets targets.json --open-only` to skip auth-required servers and focus on the ones you can actually test.
- [x] **SARIF output for MCP findings** — Integrate mcpscan results into the existing SARIF format for CI/CD pipelines and GitHub Code Scanning integration.
