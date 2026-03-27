# WAST - Remaining Issues

## Fixed

- **Form action resolution** (`pkg/crawler/crawler.go:415-428`) — `action="#"` was resolved relative to the root target URL instead of the current page. Now resolves correctly.
- **robots.txt blocking discovery** (`pkg/scanner/discovery.go:56`) — Discovery mode hardcoded `WithRespectRobots(true)`, blocking crawling on sites with `Disallow: /`. Changed to `false` since active scanning implies authorization.
- **Discovered parameters discarded** (`pkg/scanner/discovery.go:671-729`) — `scanTargetFor*` functions passed only the URL, ignoring discovered form parameters. Added `buildURLWithParams()` to embed them as query params.
- **SSRF false positives on invented parameters** — Added `WithSSRFOnlyProvidedParams(true)` in discovery mode so the SSRF scanner only tests parameters actually found during crawling, not invented ones. Eliminated all SSRF false positives.
- **POST form scanning** — Added `ScanPOST()` routing in `scanTargetFor*` functions so POST forms are tested with payloads in the request body instead of GET query params.
- **SQLi detection improved** — Boolean-based SQLi now detects real injection on DVWA (`/vulnerabilities/brute/` username param, `/vulnerabilities/fi/` page param). 4 high-confidence findings.
- **SSTI scanner added** — New scanner for Server-Side Template Injection.

## Retest results (2026-03-27)

Tested against DVWA (security=low) with `active=true, discover=true, depth=3`.

| Scanner | Findings | Notes |
|---------|----------|-------|
| SQLi | 4 | Boolean-based on `/brute/` and `/fi/` — real positives |
| CSRF | 9 | Real missing CSRF tokens |
| SSRF | 0 | No false positives (fixed) |
| XSS | 0 | Reflected XSS on `/xss_r/` not detected |
| CMDi | 0 | POST injection on `/exec/` not detected |
| Path Traversal | 0 | LFI on `/fi/?page=` not detected |
| Headers | 7 missing | Expected for DVWA |

## Fixed (Phase 2)

- **XSS reflected detection improved** — Added check for URL-encoded payload reflection to handle edge cases where applications reflect parameters without decoding. Made the detection logic more robust and explicit. The scanner now properly detects DVWA-style reflected XSS where `<script>alert(1)</script>` is echoed unescaped in the response.
- **CMDi POST detection improved** — Enhanced `cmdOutputPatterns` to detect simple usernames from `whoami` command (e.g., `www-data`, `root`, `apache`, `nginx`, etc.). The scanner now properly detects DVWA's `/vulnerabilities/exec/` endpoint where injecting `; whoami` or `; id` appends command output to the ping response. Added comprehensive test case simulating DVWA behavior.
- **SQLi scanner now detects DVWA `/vulnerabilities/sqli/?id=` injection** (Issue #188) — Fixed the scanner to detect classic DVWA SQLi endpoint. Root cause was that DVWA requires a `Submit` parameter to process form submissions. When the crawler discovers URLs with only data parameters (e.g., `id=1`), DVWA returns just the form without executing queries, causing all responses (baseline, true, false) to be identical. Added fallback mechanism: when no vulnerabilities are found and responses look like empty forms, the scanner automatically retries with `Submit=Submit` parameter added. This fixes the P0 issue where the scanner detected SQLi on `/brute/` and `/fi/` but missed the primary `/sqli/` test page.

## Still broken

### P1: Path traversal scanner misses LFI on `/vulnerabilities/fi/?page=`

**Impact:** DVWA's file inclusion page accepts `page=../../etc/passwd` and returns the file contents. The scanner doesn't detect it.

**Root cause:** The path traversal scanner likely sends payloads like `../../../../etc/passwd` and checks for specific strings (e.g., `root:`) in the response. Either the payloads don't match what DVWA expects, or the response content check is too strict/wrong.

**Files:** `pkg/scanner/pathtraversal.go` — detection heuristics

### P2: Summary aggregation incorrect in discovery mode

**Impact:** `total_tests` shows 0 for all scanners that ran in discovery mode, even though they clearly executed tests (SQLi ran tests and found 4 vulns but reports `total_tests: 0`). Per-target scan results don't accumulate into the aggregate summary.

**Files:** `pkg/scanner/discovery.go` — summary aggregation logic. Individual target results overwrite rather than accumulate into the aggregate summary structs.

### P3: Crawl output too large for MCP

**Impact:** `wast_crawl` output exceeded 465K characters due to 1,766 resource entries. Gets dumped to disk instead of returned via MCP.

**Fix approach:** Add a compact mode for MCP that omits or summarizes the resources list. Or add pagination/filtering to the crawl output.
