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
| SSRF | 0 false positives | 25 FPs | **FAIL** |
| NoSQLi | 0 false positives | 0 | **PASS** |
| XXE | 0 false positives | 0 | **PASS** |
| Headers | >= 5 missing | 7 | **PASS** |

### False positive targets

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| SQLi | 0 findings on non-injectable params | 8 FPs on `doc` param | **FAIL** |
| SSRF | 0 false positives on non-SSRF params | 25 FPs | **FAIL** |
| CMDi | 0 findings on non-injectable params | 4 FPs (`name`, `include`, `txtName`, `mtxMessage`) | **FAIL** |
| All others | 0 false positives | 0 | **PASS** |

---

## Remaining work

### SSRF: 25 false positives on params that reflect input

All 25 findings are on `name` (XSS reflected), `txtName`/`mtxMessage` (XSS stored), and `page` (LFI). These params accept user input and return 200, but they don't fetch remote URLs. The scanner sends `http://127.0.0.1` as a value, gets a 200 back, and flags it as blind SSRF — but any param that ignores unknown values or reflects input will do this.

**What to do:** Blind SSRF detection needs a stronger signal than "200 response with SSRF payload." Options:
1. Require a callback-based confirmation (out-of-band detection) for blind SSRF — only flag if the server actually makes an outbound request
2. Compare response content: if the response body is identical whether the param is `test` or `http://127.0.0.1`, it's not SSRF
3. Skip SSRF testing on params already flagged as XSS or LFI to avoid duplicate noise

### SQLi: 8 false positives on `doc` param

The `doc` param on `instructions.php` switches between documentation pages (readme, PDF, changelog, copying). Different values produce different response sizes — this is normal content routing, not injection. The boolean-based differential analysis sees different content and flags it.

**What to do:** The differential analysis needs to distinguish between "response changes because input is injectable" vs "response changes because the app serves different content for different values." One approach: if the baseline value and a non-SQL value (e.g., `randomstring123`) also produce different responses, the param is content-routing, not injectable.

### CMDi: 4 false positives on non-command params

`name` on `/xss_r/`, `include` on `/csp/`, `txtName`/`mtxMessage` on `/xss_s/` are flagged as output-based CMDi. These params reflect input into the response — when the scanner sends `localhost; cat /etc/passwd` and the response contains `root:`, it flags CMDi. But the `root:` match is from the param reflection or stored XSS, not from actual command execution.

**What to do:** Output-based CMDi detection should verify the output is from command execution, not reflection. Options:
1. Check if the command output appears in a different location than the injected param (reflection puts it where the param value goes; command execution appends it elsewhere)
2. Use a unique canary in the command (e.g., `echo WAST_CANARY_12345`) and check for the canary — if reflected, both the command and canary appear; if executed, only the canary output appears
3. Cross-reference with XSS findings — if a param is already flagged as reflected XSS, discount CMDi findings on the same param

### CSRF: regression from 9 to 4

Previously found 9 forms without CSRF tokens, now only 4. The hidden field filter (`field.Type == "hidden"`) may now be too aggressive — DVWA forms have `user_token` hidden fields that look like CSRF tokens to the scanner. But DVWA intentionally doesn't validate them on most forms, so they should still be flagged.

**What to do:** Check if the CSRF scanner is now treating `user_token` as a valid CSRF token and skipping those forms. The scanner should verify that the token is actually validated server-side (e.g., submit the form without the token and check if it still succeeds) rather than just checking for the presence of a hidden field with a token-like name.
