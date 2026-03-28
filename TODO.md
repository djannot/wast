# WAST - TODO

## Live DVWA Retest Results (2026-03-28)

Tested against DVWA (security=low) with `wast_scan active=true, discover=true, depth=3`.

All vulnerabilities confirmed exploitable via curl:
- `curl "http://dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E"` → payload reflected verbatim
- `curl -X POST http://dvwa/vulnerabilities/exec/ -d "ip=127.0.0.1;id&Submit=Submit"` → `uid=33(www-data)`
- `curl "http://dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd"` → `root:x:0:0:root:/root:/bin/bash`

| Scanner | Tests | Findings | Expected | Verdict |
|---------|-------|----------|----------|---------|
| SQLi | 391 | 6 | SQLi on `/sqli/`, `/brute/` | Mixed — real positives on `/brute/`, `/fi/` but FPs on `Change`, `doc` |
| CSRF | — | 9 | 9 missing tokens | **PASS** |
| SSTI | 370 | 0 | 0 (PHP app) | **PASS** |
| SSRF | 629 | 0 | 0 | **PASS** |
| XSS | 259 | 0 | Reflected XSS on `/xss_r/?name=` | **FAIL** |
| CMDi | 1,184 | 0 | CMDi on POST `/exec/` `ip` param | **FAIL** |
| Path Traversal | 666 | 0 | LFI on `/fi/?page=` | **FAIL** |
| Headers | — | 7 | 7 missing | **PASS** |

---

## P0: XSS — not detecting reflected XSS on live DVWA

Unit tests pass with simulated DVWA responses but the live scan finds nothing.

**Root cause:** `analyzeContext()` examines a context snippet around the payload to determine if it's in an executable position. The function checks for HTML comments (`<!--`) before the payload. DVWA pages contain HTML comments in the page structure (e.g., `<!-- You used a wrong captcha -->`, source code comments). If any `<!--` appears before the payload position in the extracted snippet, and the corresponding `-->` appears after the payload, the function classifies the payload as inside a comment and skips it — even though the payload is actually in the HTML body, not inside that comment. The comment detection uses `strings.Index()` on the full body rather than checking the specific DOM context around the injection point.

**Files:** `pkg/scanner/xss.go` — `analyzeContext()` comment detection logic

---

## P0: CMDi — not detecting command injection on live DVWA

Unit tests pass with simulated DVWA responses but the live scan finds nothing.

**Root cause:** Two issues:

1. **Empty baseline value:** The discovery pipeline extracts the form with `ip=""` (empty default value). The CMDi scanner sends a baseline request with `ip=""`, which DVWA doesn't process (no ping output). When injection payloads like `; id` are sent (without a leading valid IP), DVWA may also not process them. The payloads need a valid prefix like `127.0.0.1; id` but the scanner may be sending just `; id` as a replacement for the empty `ip` value rather than prepending to a valid value.

2. **Submit button injection waste:** The scanner tests all parameters including `Submit`. When it injects into `Submit` while keeping `ip=""`, DVWA doesn't process the form at all. This wastes test budget and produces noise. Submit-type params should be excluded from injection testing.

**Files:** `pkg/scanner/cmdi.go` — `ScanPOST()`, `testOutputBasedPOST()`, baseline value handling

---

## P0: Path Traversal — not detecting LFI on live DVWA

Unit tests pass with simulated DVWA responses but the live scan finds nothing.

**Root cause:** Two issues:

1. **Wrapper payload takes priority over direct replacement:** When the parameter has an existing value (`page=include.php`), the scanner first tries `page=include.php/../../../etc/passwd`. This fails because `include.php` is not a real directory. The direct replacement payload (`page=../../../../../../etc/passwd`) works, but it may not be tried first, or the wrapper result may mask it.

2. **URL encoding of slashes:** The scanner manually constructs `RawQuery` to avoid Go's `url.Values.Encode()` encoding `/` as `%2F`. However, the manual construction may still have edge cases where slashes get encoded by the HTTP client, breaking the traversal for PHP's `include()` which needs literal `../` sequences.

**Files:** `pkg/scanner/pathtraversal.go` — `testParameter()`, `testPayloadVariant()`, payload ordering

---

## P1: SQLi — boolean-based false positives from CSRF tokens

**Root cause:** `ContentHash` is computed from `extractBodyContent()` which does NOT normalize CSRF tokens. DVWA's `user_token` hidden field changes every request, so `contentHashDiffers` is always `true`. Combined with small word count diffs (~4 words from different token values), this exceeds the `minWordCountDifference=2` threshold.

`extractDataContent()` already normalizes via `normalizeResponseContent()`, but `extractBodyContent()` (used for ContentHash) does not. The normalization exists but isn't applied to the right function.

**Affected:** `Change` on `/csrf/`, `doc` param, `Login` button — all non-injectable.

**Fix:** Normalize content before computing ContentHash in `analyzeResponse()`.

**Files:** `pkg/scanner/sqli.go` — `analyzeResponse()`, `extractBodyContent()`

---

## P1: CI integration test assertions are soft (warnings, not failures) — ✅ PARTIALLY DONE

**Done (PR #259):** `t.Logf("Warning: ...")` assertions converted to `t.Errorf(...)` hard failures for:
- SQLi: `TestDVWA_SQLi` and `TestDVWA_FullDiscoveryScanAssertions` — **HARD FAILURE** (scanner reliably detects)
- CSRF: `TestDVWA_CSRF` and `TestDVWA_FullDiscoveryScanAssertions` — **HARD FAILURE** (scanner reliably detects)
- Discovery scan combined check: `TestDVWA_DiscoveryScan` — **HARD FAILURE** (SQLi/CSRF always present)

**Pending (blocked by P0 bugs above):** XSS, CMDi, and Path Traversal remain as `t.Logf("Warning: ...")` in both individual tests and `TestDVWA_FullDiscoveryScanAssertions` until their P0 scanner detection bugs are resolved. Live DVWA retesting on 2026-03-28 confirmed 0 findings for all three.

**What still needs to change once P0 bugs are fixed:** Convert remaining warnings to `t.Errorf(...)` for XSS, CMDi, and Path Traversal in `TestDVWA_XSS`, `TestDVWA_CommandInjection`, `TestDVWA_PathTraversal`, and `TestDVWA_FullDiscoveryScanAssertions`.
