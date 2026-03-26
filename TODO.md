# WAST - Remaining Issues

## Fixed in this session

- **Form action resolution** (`pkg/crawler/crawler.go:415-428`) — `action="#"` was resolved relative to the root target URL instead of the current page. Now resolves correctly.
- **robots.txt blocking discovery** (`pkg/scanner/discovery.go:56`) — Discovery mode hardcoded `WithRespectRobots(true)`, blocking crawling on sites with `Disallow: /`. Changed to `false` since active scanning implies authorization.
- **Discovered parameters discarded** (`pkg/scanner/discovery.go:671-729`) — `scanTargetFor*` functions passed only the URL, ignoring discovered form parameters. Added `buildURLWithParams()` to embed them as query params.

## Still broken

### P0: SQLi scanner doesn't detect trivial SQL injection

**Impact:** DVWA at security=low has `1' OR '1'='1` injectable `id` param. WAST runs 26 tests against it and finds nothing.

**Root cause:** The detection heuristics (error-based, boolean-based, time-based) likely fail because:
- Error-based: DVWA may not return SQL error strings in the response body
- Boolean-based: Baseline comparison may not detect the difference between normal and injected responses
- Time-based: `SLEEP()` payloads may work but the timing threshold could be miscalibrated

**Files:** `pkg/scanner/sqli.go` — `testErrorBased()`, `testBooleanBased()`, `testTimeBased()`

### P0: XSS scanner doesn't detect reflected XSS

**Impact:** DVWA `/vulnerabilities/xss_r/?name=<script>alert(1)</script>` reflects input directly. WAST runs 12 tests and finds nothing.

**Root cause:** Likely the response body analysis doesn't check if the payload appears unescaped in the response HTML.

**Files:** `pkg/scanner/xss.go` — `testParameter()`

### P0: CMDi scanner doesn't detect command injection

**Impact:** DVWA `/vulnerabilities/exec/` accepts `ip` param and passes it to `shell_exec()`. WAST runs 42 tests (via discovery) and finds nothing.

**Root cause:** The scanner sends payloads via GET query params, but the DVWA form uses POST. The `buildURLWithParams` approach only works for GET — POST form parameters need to be sent in the request body.

**Files:** `pkg/scanner/cmdi.go`, `pkg/scanner/discovery.go`

### P1: SSRF scanner produces false positives on invented parameters

**Impact:** When no query params exist, the scanner invents parameters (`url`, `uri`, `path`, etc.) and reports SSRF when it gets a 200 response. Any application that ignores unknown query params triggers this.

**Root cause:** Detection logic at `pkg/scanner/ssrf.go:423-487` treats any 200 OK from a private IP payload as evidence of SSRF, without comparing to a baseline response.

**Fix approach:** Get a baseline response first (no SSRF payload). Only flag if the response differs meaningfully from baseline when the payload is injected.

### P1: SSRF scanner still tests invented parameters when real ones exist

**Impact:** Even with `buildURLWithParams`, the SSRF scanner sees real params in the URL but also adds invented ones via its fallback. Discovery mode should skip the invented-params fallback entirely.

**Fix approach:** Add a `ScanWithParams` method or a flag that tells scanners "only test these specific parameters, don't invent more."

### P2: POST form scanning not supported

**Impact:** Many web forms use POST. Currently all scanners only test via GET query parameters. POST forms like DVWA's command injection (`ip` field), stored XSS (`txtName`, `mtxMessage`), and file upload are never tested.

**Fix approach:** Each scanner needs a `testPOSTParameter()` method that sends payloads as form-encoded POST body. `scanTargetFor*` in `discovery.go` should check `target.Method` and call the appropriate method.

### P2: Summary aggregation incorrect in discovery mode

**Impact:** `total_tests` shows 0 for scanners that did run in discovery mode. The per-target scan results don't accumulate into the aggregate summary correctly.

**Files:** `pkg/scanner/discovery.go:392-453` — Summary structs are initialized with zero values, and individual target results overwrite rather than accumulate.

### P3: Crawl output too large for MCP

**Impact:** `wast_crawl` output exceeded 465K characters due to 1,766 resource entries. Gets dumped to disk instead of returned via MCP.

**Fix approach:** Add a compact mode for MCP that omits or summarizes the resources list. Or add pagination/filtering to the crawl output.
