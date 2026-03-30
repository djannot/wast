# WAST - TODO

## Goal: Pass all benchmarks with zero false positives

The CI runs full discovery scans against DVWA, Juice Shop, and WebGoat. Every scanner must hit its target score **and** produce no false positives. All assertions use hard failures (`t.Errorf`) so regressions break the build.

### DVWA target scores (latest live scan 2026-03-30)

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| XSS | >= 1 finding on `/xss_r/` `name` param | 26 (reflected + DOM + stored) | **PASS** |
| CMDi | >= 1 finding on `/exec/` `ip` param (POST) | 17 (time-based + output-based) | **PASS** |
| Path Traversal | >= 1 finding on `/fi/` `page` param | 3 | **PASS** |
| SQLi | >= 1 finding on `/sqli/` `id` param | 5 (sqli + sqli_blind) | **PASS** |
| CSRF | >= 7 forms with missing tokens | >= 7 (unenforced + missing) | **PASS** |
| SSTI | 0 findings | 0 | **PASS** |
| SSRF | 0 false positives | 0 FPs (reflection stripping) | **PASS** |
| NoSQLi | 0 false positives | 0 | **PASS** |
| XXE | 0 false positives | 0 | **PASS** |
| Headers | >= 5 missing | 7 | **PASS** |

### False positive targets

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| SQLi | 0 findings on non-injectable params | 0 FPs (content-routing pre-check) | **PASS** |
| SSRF | 0 false positives on non-SSRF params | 0 FPs | **PASS** |
| CMDi | 0 findings on non-injectable params | 0 FPs (reflection stripping) | **PASS** |
| All others | 0 false positives | 0 | **PASS** |

---

## Remaining work

### ~~SSRF: 25 false positives on params that reflect input~~ ✅ RESOLVED

Fixed by stripping the SSRF payload (and its URL-encoded/decoded variants) from the response body before running signature checks in `analyzeSSRFResponse()`. When a parameter merely reflects the payload URL (e.g., `http://127.0.0.1`) back into the page, the stripped body no longer contains localhost/private-IP signatures, so no finding is produced. Genuine SSRF (where the server fetches internal content containing those signatures independently of the payload) is still detected because the signatures remain after stripping.

### ~~SQLi: 8 false positives on `doc` param~~ ✅ RESOLVED

Fixed by adding a content-routing pre-check to both `testBooleanBased()` and `testBooleanBasedPOST()`. Before running differential analysis, the scanner sends a request with a random non-SQL string (e.g., `randomstring_12345`) and compares the response against the baseline. If the random value also produces a significantly different response (using the same size-difference thresholds), the parameter is classified as content-routing and skipped. This eliminates all 8 false positives on DVWA's `doc` parameter (`instructions.php`) while preserving true positive detection on injectable parameters like `id`.

### ~~CMDi: 4 false positives on non-command params~~ ✅ RESOLVED

Fixed by stripping the CMDi payload (and its HTML-encoded/URL-encoded variants) from the response body before running `cmdOutputPatterns` matching in `testOutputBased()` and `testOutputBasedPOST()`. When a parameter merely reflects the payload string (e.g., `localhost; cat /etc/passwd`) back into the page, the stripped body no longer contains patterns like `root:x:0` or `/etc/passwd`, so no finding is produced. Genuine command injection (where the server executes the command and the output appears independently of the reflected payload) is still detected because the patterns remain after stripping. This follows the same approach used successfully for the SSRF scanner's reflection-stripping fix.

### ~~CSRF: regression from 9 to 4~~ ✅ RESOLVED

Fixed by two changes:

1. **Removed POST-only filter in `scanTargetForCSRF()`** — the discovery phase was skipping GET targets, missing DVWA pages with GET-based forms (e.g., the password change page). Now both GET and POST targets are scanned for CSRF.

2. **Added server-side token enforcement verification** — when active mode is enabled (`--active`), the scanner now submits forms *without* the CSRF token field and checks whether the server still accepts the submission. If the server responds with 2xx and no rejection keywords, the token is flagged as `unenforced_token`. This catches DVWA's `user_token` field which is present but not validated on most forms. In passive/safe mode, the scanner continues with presence-only checks (no server-side requests).

Also added `user_token` to `csrfTokenFieldNames` so DVWA's token field is correctly recognized.
