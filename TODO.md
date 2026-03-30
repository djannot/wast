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
| CSRF | >= 7 forms with missing tokens | 4 | **REGRESSED** — was 9, now 4 |
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
| CMDi | 0 findings on non-injectable params | 4 FPs (`name`, `include`, `txtName`, `mtxMessage`) | **FAIL** |
| All others | 0 false positives | 0 | **PASS** |

---

## Remaining work

### ~~SSRF: 25 false positives on params that reflect input~~ ✅ RESOLVED

Fixed by stripping the SSRF payload (and its URL-encoded/decoded variants) from the response body before running signature checks in `analyzeSSRFResponse()`. When a parameter merely reflects the payload URL (e.g., `http://127.0.0.1`) back into the page, the stripped body no longer contains localhost/private-IP signatures, so no finding is produced. Genuine SSRF (where the server fetches internal content containing those signatures independently of the payload) is still detected because the signatures remain after stripping.

### ~~SQLi: 8 false positives on `doc` param~~ ✅ RESOLVED

Fixed by adding a content-routing pre-check to both `testBooleanBased()` and `testBooleanBasedPOST()`. Before running differential analysis, the scanner sends a request with a random non-SQL string (e.g., `randomstring_12345`) and compares the response against the baseline. If the random value also produces a significantly different response (using the same size-difference thresholds), the parameter is classified as content-routing and skipped. This eliminates all 8 false positives on DVWA's `doc` parameter (`instructions.php`) while preserving true positive detection on injectable parameters like `id`.

### CMDi: 4 false positives on non-command params

`name` on `/xss_r/`, `include` on `/csp/`, `txtName`/`mtxMessage` on `/xss_s/` are flagged as output-based CMDi. These params reflect input into the response — when the scanner sends `localhost; cat /etc/passwd` and the response contains `root:`, it flags CMDi. But the `root:` match is from the param reflection or stored XSS, not from actual command execution.

**What to do:** Output-based CMDi detection should verify the output is from command execution, not reflection. Options:
1. Check if the command output appears in a different location than the injected param (reflection puts it where the param value goes; command execution appends it elsewhere)
2. Use a unique canary in the command (e.g., `echo WAST_CANARY_12345`) and check for the canary — if reflected, both the command and canary appear; if executed, only the canary output appears
3. Cross-reference with XSS findings — if a param is already flagged as reflected XSS, discount CMDi findings on the same param

### CSRF: regression from 9 to 4

Previously found 9 forms without CSRF tokens, now only 4. The hidden field filter (`field.Type == "hidden"`) may now be too aggressive — DVWA forms have `user_token` hidden fields that look like CSRF tokens to the scanner. But DVWA intentionally doesn't validate them on most forms, so they should still be flagged.

**What to do:** Check if the CSRF scanner is now treating `user_token` as a valid CSRF token and skipping those forms. The scanner should verify that the token is actually validated server-side (e.g., submit the form without the token and check if it still succeeds) rather than just checking for the presence of a hidden field with a token-like name.
