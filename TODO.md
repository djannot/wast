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

## ~~P0: Path Traversal — not detecting LFI on live DVWA~~ ✅ FIXED (PR #267)

Unit tests pass with simulated DVWA responses but the live scan finds nothing.

**Root cause (resolved):** Three issues, all fixed:

1. **Non-deterministic `RawQuery` construction:** `testPayloadVariant()` iterated over `url.Values` (a `map[string][]string`) with Go's non-deterministic map iteration order when building the manual query string. For multi-parameter URLs this produced an unpredictable parameter order. Fixed by sorting keys before building the query string.

2. **POST form encoding destroys path separators:** `testParameterPOST()` used `formData.Encode()` which encodes `/` as `%2F`. PHP's `include()` needs literal `../` sequences. Fixed by replacing `formData.Encode()` with a new `buildPathTraversalFormBody()` helper that preserves `/` and `\` characters while still encoding other special characters.

3. **Direct replacement (Test 1) correctly tried first:** The direct replacement (`page=../../../../../../etc/passwd`) is already tried first in `testParameter()`. The GET path preserves literal slashes via manual `RawQuery` construction, which is now also stabilised with sorted keys.

**Files:** `pkg/scanner/pathtraversal.go` — added `"sort"` import, sorted keys in `testPayloadVariant()`, added `buildPathTraversalFormBody()` helper, refactored `testParameterPOST()` to use it.

**Integration tests hardened:** Converted `t.Logf("Warning: ...")` to `t.Errorf(...)` for Path Traversal in `TestDVWA_PathTraversal` and `TestDVWA_FullDiscoveryScanAssertions`.

---

## ~~P1: SQLi — boolean-based false positives from CSRF tokens~~ ✅ FIXED (PR #268)

**Root cause (resolved):** `ContentHash` was computed from `extractBodyContent()` which did NOT normalize CSRF tokens. DVWA's `user_token` hidden field changes every request, so `contentHashDiffers` was always `true`. Combined with small word count diffs (~4 words from different token values), this exceeded the `minWordCountDifference=2` threshold.

`extractDataContent()` already normalized via `normalizeResponseContent()`, but `extractBodyContent()` (used for ContentHash) did not. The normalization existed but wasn't applied to the right function.

**Affected:** `Change` on `/csrf/`, `doc` param, `Login` button — all non-injectable (now no longer false-positived).

**Fix:** `analyzeResponse()` now calls `normalizeResponseContent()` before `extractBodyContent()` so both `ContentHash` and `WordCount` are computed from normalized HTML.

**Files:** `pkg/scanner/sqli.go` — `analyzeResponse()`, `pkg/scanner/sqli_test.go` — added `TestAnalyzeResponse_CSRFTokenNormalization`, `test/integration/dvwa_test.go` — added `TestDVWA_SQLi_NoFalsePositivesOnCSRFPage`

---

## ~~P1: CI integration test assertions are soft (warnings, not failures)~~ ✅ FIXED (PR #272)

All integration test assertions are now hard `t.Errorf` failures. No soft `t.Logf("Warning: ...")` remain for scanner-result assertions.

Hard failures (`t.Errorf`) are in place for:
- **PR #259:** SQLi (false-positive count), CSRF, SSTI, Headers, submit-button false-positives.
- **PR #262:** XSS `name` param check (individual scan test).
- **PR #264:** CMDi `ip` param check (individual scan test).
- **PR #267:** Path Traversal `page` param check (individual scan test).
- **PR #272:** SQLi, XSS, CMDi, Path Traversal 0-finding cases in `TestDVWA_SQLi`, `TestDVWA_XSS`, `TestDVWA_CommandInjection`, `TestDVWA_PathTraversal`, and `TestDVWA_FullDiscoveryScanAssertions`.

All blocking scanner bugs are resolved (PRs #262, #264, #267, #268), so CI will now correctly fail on any regression.
