# WAST - TODO

## Goal: Pass DVWA benchmark with zero false positives

The CI runs a full discovery scan against DVWA (security=low) via `TestDVWA_FullDiscoveryScanAssertions`. Every scanner must hit its target score **and** produce no false positives. Once all targets are met, convert the soft warnings (`t.Logf`) to hard failures (`t.Errorf`) so regressions break the build.

### Target scores

| Scanner | Target | Current | Gap |
|---------|--------|---------|-----|
| XSS | >= 1 finding on `/xss_r/` `name` param | 0 | Payload reflected verbatim but `analyzeContext()` still rejects it |
| CMDi | >= 1 finding on `/exec/` `ip` param (POST) | 0 | 1,120 tests run, prepended payloads added, still no detection |
| Path Traversal | >= 1 finding on `/fi/` `page` param | 0 | 666 tests run, raw slashes preserved, still no detection |
| SQLi | >= 1 finding on `/sqli/` or `/brute/` `id`/`username` param | 4 (but 0 on `id`) | Detects on `username`/`page` but misses the primary `/sqli/?id=` endpoint |
| CSRF | >= 7 forms with missing tokens | 9 | **PASS** |
| SSTI | 0 findings (no template engines in DVWA) | 0 | **PASS** |
| SSRF | 0 findings | 0 | **PASS** |
| NoSQLi | 0 false positives on non-MongoDB app | 14 FPs | All on `doc` param — DVWA uses MySQL, not MongoDB |
| Headers | >= 5 missing security headers | 7 | **PASS** |

### False positive targets

| Scanner | Target | Current | Gap |
|---------|--------|---------|-----|
| SQLi | 0 findings on `Change`, `doc`, `Login`, submit buttons | 4 FPs | CSRF token normalization not fully effective |
| NoSQLi | 0 findings on DVWA (MySQL app) | 14 FPs | `doc` param loads different pages — response size change is not injection |
| SSTI | 0 findings | 0 | **PASS** |
| SSRF | 0 findings | 0 | **PASS** |

### When all targets are met

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
