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
| XSS | 259 | 0 | Reflected XSS on `/xss_r/?name=` | **FIXED** |
| CMDi | 1,184 | 0 | CMDi on POST `/exec/` `ip` param | **FAIL** |
| Path Traversal | 666 | 0 | LFI on `/fi/?page=` | **FAIL** |
| Headers | — | 7 | 7 missing | **PASS** |

---

## ~~P0: XSS — not detecting reflected XSS on live DVWA~~ ✅ FIXED (PR #262)

**Root cause (resolved):** `analyzeContext()` used `strings.LastIndex` to detect HTML comments, which incorrectly treated `<!--`/`-->` sequences inside `<script>` blocks as HTML comment boundaries. If a JS string literal in a `<script>` block contained `-->` at a lower offset than `<!--`, the function classified the payload as inside an HTML comment and skipped it.

**Fix:** Replaced with `isInsideHTMLComment()` — a left-to-right state machine that properly skips content inside `<script>` and `<style>` blocks and only counts `<!--`/`-->` as HTML comment boundaries in regular HTML body content.

**Files:** `pkg/scanner/xss.go` — added `isInsideHTMLComment()`, replaced three `strings.LastIndex` calls in `analyzeContext()`

**Integration tests hardened:** Converted `t.Logf("Warning: ...")` to `t.Errorf(...)` for XSS in `TestDVWA_XSS` and `TestDVWA_FullDiscoveryScanAssertions`.

---

## ~~P0: CMDi — not detecting command injection on live DVWA~~ ✅ FIXED (PR #264)

**Root cause (resolved):** Two issues, both fixed:

1. **Empty baseline value / missing prefix:** The discovery pipeline extracts the form with `ip=""` (empty default value). Payloads like `; id` were sent as direct replacements, giving `ip=; id`. Many real-world apps (including DVWA) require a valid prefix (e.g. `127.0.0.1`) before the shell separator. The scanner now also tries prepended variants: `127.0.0.1;sleep 5`, `test;sleep 5`, etc., via `buildPrependedPayloads()`. When the original value is non-empty, it is prepended to the payload as well.

2. **Submit button injection waste:** Already fixed via `isSubmitButton()` — the `Submit` parameter is now correctly skipped during scanning.

**Fix:** Added `buildPrependedPayloads(originalValue, payload string) []string` helper in `pkg/scanner/cmdi.go`. All 6 test functions (`testErrorBased`, `testOutputBased`, `testTimeBased` and their POST variants) now iterate over prepended payload variants.

**Integration tests hardened:** Converted `t.Logf("Warning: ...")` to `t.Errorf(...)` for CMDi in `TestDVWA_CommandInjection` and `TestDVWA_FullDiscoveryScanAssertions`.

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

**CMDi done (PR #264):** Converted `t.Logf("Warning: ...")` to `t.Errorf(...)` for CMDi in `TestDVWA_CommandInjection` and `TestDVWA_FullDiscoveryScanAssertions`.

**XSS done (PR #262):** Converted `t.Logf("Warning: ...")` to `t.Errorf(...)` for XSS in `TestDVWA_XSS` and `TestDVWA_FullDiscoveryScanAssertions`.

**Pending (blocked by Path Traversal P0 bug):** Path Traversal remains as `t.Logf("Warning: ...")` in `TestDVWA_PathTraversal` and `TestDVWA_FullDiscoveryScanAssertions` until the P0 scanner detection bug is resolved.

**What still needs to change once remaining P0 bugs are fixed:** Convert Path Traversal warnings to `t.Errorf(...)` in `TestDVWA_PathTraversal` and `TestDVWA_FullDiscoveryScanAssertions`.
