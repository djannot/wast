# WAST - TODO

## Live DVWA Retest Results (2026-03-28)

Tested against DVWA (security=low) with `wast_scan active=true, discover=true, depth=3`.

| Scanner | Tests | Findings | Expected | Verdict |
|---------|-------|----------|----------|---------|
| SQLi | 395 | 12 | SQLi on `/sqli/`, `/brute/` | Mixed — real positives on `/brute/`, `/fi/`, `/exec/` but also FPs on `/csrf/`, `doc`, `captcha` |
| CSRF | — | 9 | 9 missing tokens | **PASS** — all real |
| SSTI | 370 | 0 | 0 (PHP app, no template engines) | **PASS** — FPs eliminated |
| SSRF | 629 | 0 | 0 (no SSRF vuln in DVWA) | **PASS** — no FPs |
| XSS | 259 | 0 | Reflected XSS on `/xss_r/?name=` | **FIXED** — issue #252 resolved; analyzeContext now uses full body for comment detection |
| CMDi | 1,184 | 0 | CMDi on POST `/exec/` `ip` param | **FAIL** — not detected |
| Path Traversal | 666 | 0 | LFI on `/fi/?page=` | **FAIL** — not detected |
| Headers | — | 7 | 7 missing | **PASS** — expected |

Unit tests for XSS, CMDi, and Path Traversal pass with simulated DVWA responses. The detection logic works in isolation but fails against the live DVWA instance. Root causes are documented below.

---

## ~~P0: XSS scanner doesn't detect reflected XSS on live DVWA~~ FIXED in #252

**Confirmed:** `curl "http://dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E"` returns the payload `<script>alert(1)</script>` verbatim in the HTML (1 match). The vulnerability is trivially exploitable.

**Root cause:** The `testParameter()` function in `xss.go` builds the test URL using `q.Encode()`, which URL-encodes `<` to `%3C`, `>` to `%3E`, etc. The payload is sent URL-encoded in the query string. DVWA decodes it and reflects `<script>alert(1)</script>` in the HTML body.

The detection at line ~609 does:
```go
payloadFound := strings.Contains(bodyStr, payload.Payload)  // looks for <script>alert(1)</script>
```

This should match since DVWA reflects the decoded payload. However, `analyzeContext()` then analyzes the surrounding HTML context. The likely failure is in context analysis — the function may be misclassifying the context (e.g., thinking the payload is inside an HTML comment, attribute, or non-executable context) and returning `isExecutable=false`.

**Fix approach:** Add debug logging to `analyzeContext()` to trace exactly what context it detects. The early detection at line ~438 (`if strings.Contains(payload, "<script") { return ContextHTMLBody, true, "high" }`) should catch this case — if it's not firing, something before it is returning early.

**Files:** `pkg/scanner/xss.go` — `testParameter()`, `analyzeContext()`

---

## P0: CMDi scanner doesn't detect command injection on live DVWA

**Confirmed:** `curl -X POST http://dvwa/vulnerabilities/exec/ -d "ip=127.0.0.1;id&Submit=Submit"` returns `uid=33(www-data)`. Without `Submit=Submit`, DVWA returns nothing — the form is not processed.

**Root cause:** The discovery pipeline extracts form fields including `Submit=Submit` (the crawler does capture `<input type="submit">`). The `ScanPOST()` method receives the parameters and sends them. However, the detection fails due to **baseline comparison logic**:

1. The scanner sends a baseline request with the original `ip` value
2. The scanner sends payloads like `127.0.0.1; id`
3. It checks for patterns like `uid=[0-9]+` in the response
4. BUT — the baseline comparison in `testOutputBasedPOST()` checks if the pattern ALSO appears in baseline
5. DVWA's page HTML contains `www-data` in the page header/footer (logged-in user), so the line-anchored `^www-data$` pattern may match in baseline
6. The `uid=` pattern should NOT appear in baseline, but if the baseline request fails (e.g., `ip=""` causes no output), the differential may not work correctly

**Additional issue:** The scanner tests each parameter independently. When testing the `ip` parameter, it keeps `Submit=Submit` as-is. But when testing the `Submit` parameter, it injects payloads into `Submit` while keeping `ip` as-is — this is wasted effort and the SQLi scanner is also doing this (explaining the false SQLi on `/exec/` `ip` param).

**Fix approach:**
1. Add debug logging to `testOutputBasedPOST()` to trace baseline vs injected responses
2. Verify that baseline is using a valid value for `ip` (e.g., `127.0.0.1`) not empty string
3. Consider marking `submit`-type parameters as non-testable for injection scanners (CMDi, SQLi, XSS) — only the data parameters should be injected

**Files:** `pkg/scanner/cmdi.go` — `ScanPOST()`, `testOutputBasedPOST()`, `getBaselineWithTimingPOST()`

---

## P0: Path Traversal scanner doesn't detect LFI on live DVWA

**Confirmed:** `curl "http://dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd"` returns `root:x:0:0:root:/root:/bin/bash` and other passwd entries. The vulnerability works with direct path replacement.

**Root cause:** The `testPayloadVariant()` function manually constructs `RawQuery` to avoid URL-encoding slashes. However, there are two failure modes:

1. **Wrapper payload mismatch:** When the parameter has an existing value (`page=include.php`), the scanner tries `page=include.php/../../../etc/passwd`. This assumes `include.php` exists as a real directory entry — it doesn't. The correct payload is direct replacement: `page=../../../../../../etc/passwd`. The wrapper logic should be secondary, not primary.

2. **Depth mismatch:** The hardcoded payloads use 3-6 `../` sequences. DVWA's file inclusion operates from a specific directory depth. If none of the preset depths match the DVWA container's filesystem layout, all payloads fail. The scanner should try more depth variations or auto-detect the correct depth.

3. **Signature detection:** `containsPasswdSignature()` checks for patterns like `root:x:0:0:`. Verify this actually matches the Docker container's `/etc/passwd` format (Alpine vs Debian base images may differ).

**Fix approach:**
1. Test direct replacement FIRST (without wrapper), trying multiple depths
2. Only try wrapper payloads as a fallback
3. Add the DVWA-specific depth (`../../../../../../etc/passwd` = 6 levels) if not already present
4. Log payload and response for debugging

**Files:** `pkg/scanner/pathtraversal.go` — `testParameter()`, `testPayloadVariant()`

---

## P1: SQLi boolean-based detection produces false positives

**Root cause:** The `analyzeResponse()` function computes `ContentHash` from `extractBodyContent()` which does NOT normalize CSRF tokens. Every DVWA page has a `user_token` hidden field that changes on every request. This means:

1. Baseline request: `user_token=ABC` → ContentHash X
2. True payload request: `user_token=DEF` → ContentHash Y
3. False payload request: `user_token=GHI` → ContentHash Z

`contentHashDiffers` is **always true** because the CSRF token changes. Combined with a word count difference of ~4 words (from the different token values), this exceeds the `minWordCountDifference=2` threshold, triggering a false positive.

**The asymmetry:** `extractDataContent()` calls `normalizeResponseContent()` (which strips tokens), but `extractBodyContent()` (used for ContentHash) does NOT. The normalization exists but isn't applied to the right function.

**Affected findings:** SQLi reported on `Change` button (`/csrf/`), `doc` param, `captcha` Change button — all non-injectable params where the only response difference is the CSRF token.

**Fix:** Apply `normalizeResponseContent()` to the input of `extractBodyContent()` before computing ContentHash, or compute ContentHash from the already-normalized `extractDataContent()` output.

**Files:** `pkg/scanner/sqli.go` — `analyzeResponse()`, `extractBodyContent()` vs `extractDataContent()`

---

## P2: CI integration tests should do full discovery scan assertions

The current CI DVWA integration tests (`make test-dvwa`) run individual scanner tests with manually-constructed parameters. This validates scanner logic but does NOT test the full discovery pipeline that real users exercise.

**What's needed:** A CI test that does exactly what the manual retest does:

1. Start DVWA container (`docker-compose.test.yml`)
2. Wait for DVWA to be ready
3. Initialize database (POST to `setup.php` with CSRF token)
4. Login (POST to `login.php` with `admin/password` + CSRF token)
5. Set security=low (POST to `security.php`)
6. Run `wast_scan` with `active=true, discover=true, depth=3` and session cookies
7. Assert expected findings:
   - SQLi: >= 1 finding on `/brute/` or `/fi/` or `/sqli/` `id` param
   - XSS: >= 1 finding on `/xss_r/` `name` param
   - CMDi: >= 1 finding on `/exec/` `ip` param
   - CSRF: >= 7 forms with missing tokens
   - SSTI: 0 findings (no false positives)
   - Path Traversal: >= 1 finding on `/fi/` `page` param
8. Assert no false positives on submit buttons

This test should be the **gate for merging** — if any scanner regresses on DVWA, the PR is blocked.

**Implementation:** Add a `TestDVWA_FullDiscoveryScan` test in `test/integration/dvwa_test.go` that:
- Uses the Go scanner API directly (not CLI) to run the full discovery scan
- Passes cookies programmatically
- Parses the result and asserts on each scanner's findings
- Runs as part of `make test-dvwa` in CI

**Files:** `test/integration/dvwa_test.go`, `.github/workflows/ci.yml`
