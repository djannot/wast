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
| CMDi | 1,184 | 0 | CMDi on POST `/exec/` `ip` param | **FIXED** |
| Path Traversal | 666 | 0 | LFI on `/fi/?page=` | **FAIL** |
| Headers | — | 7 | 7 missing | **PASS** |

---

## P0: XSS — not detecting reflected XSS on live DVWA

Unit tests pass with simulated DVWA responses but the live scan finds nothing.

**Root cause:** `analyzeContext()` examines a context snippet around the payload to determine if it's in an executable position. The function checks for HTML comments (`<!--`) before the payload. DVWA pages contain HTML comments in the page structure (e.g., `<!-- You used a wrong captcha -->`, source code comments). If any `<!--` appears before the payload position in the extracted snippet, and the corresponding `-->` appears after the payload, the function classifies the payload as inside a comment and skips it — even though the payload is actually in the HTML body, not inside that comment. The comment detection uses `strings.Index()` on the full body rather than checking the specific DOM context around the injection point.

**Files:** `pkg/scanner/xss.go` — `analyzeContext()` comment detection logic

---

## ✅ RESOLVED: CMDi — not detecting command injection on live DVWA (PR #260)

**Root cause (fixed):** Two issues, both resolved:

1. **Empty baseline value:** The discovery pipeline extracts the form with `ip=""` (empty default value). Separator-based payloads like `; id` were sent without a leading valid IP, so DVWA's `shell_exec("ping -c 4 " . $target)` received `ping -c 4 ;id` with an empty target and no command was injected. **Fix:** Added `preparePayload()` helper in `cmdi.go` that prepends `127.0.0.1` to separator-based payloads (`;`, `|`, `&`) when the original parameter value is empty, producing `127.0.0.1; id` etc.

2. **Submit button injection waste:** Resolved in a prior PR — `isSubmitButton()` excludes submit-type params from injection testing.

**Files changed:** `pkg/scanner/cmdi.go` — added `preparePayload()`, updated all six test functions (`testErrorBased`, `testOutputBased`, `testTimeBased` and their POST variants). `pkg/scanner/cmdi_test.go` — added unit tests. Integration test assertions hardened to `t.Errorf`.

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

**Done (PR #260):** CMDi warnings converted to `t.Errorf(...)` hard failures in `TestDVWA_CommandInjection` and `TestDVWA_FullDiscoveryScanAssertions` — CMDi P0 scanner bug resolved.

**Pending (blocked by remaining P0 bugs):** XSS and Path Traversal remain as `t.Logf("Warning: ...")` in both individual tests and `TestDVWA_FullDiscoveryScanAssertions` until their P0 scanner detection bugs are resolved. Live DVWA retesting on 2026-03-28 confirmed 0 findings for both.

**What still needs to change once P0 bugs are fixed:** Convert remaining warnings to `t.Errorf(...)` for XSS and Path Traversal in `TestDVWA_XSS`, `TestDVWA_PathTraversal`, and `TestDVWA_FullDiscoveryScanAssertions`.
