# WAST - TODO

## Goal: Pass DVWA benchmark with zero false positives

The CI runs a full discovery scan against DVWA (security=low) via `TestDVWA_FullDiscoveryScanAssertions`. Every scanner must hit its target score **and** produce no false positives. Once all targets are met, convert the soft warnings (`t.Logf`) to hard failures (`t.Errorf`) so regressions break the build.

### Target scores

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| XSS | >= 1 finding on `/xss_r/` `name` param | 0 (259 tests) | **FAIL** |
| CMDi | >= 1 finding on `/exec/` `ip` param (POST) | 0 (1,120 tests) | **FAIL** |
| Path Traversal | >= 1 finding on `/fi/` `page` param | 0 (666 tests) | **FAIL** |
| SQLi | >= 1 finding on `/sqli/` or `/brute/` `id`/`username` param | 1 on `username` | **PASS** |
| CSRF | >= 7 forms with missing tokens | 9 | **PASS** |
| SSTI | 0 findings (no template engines in DVWA) | 0 | **PASS** |
| SSRF | 0 findings | 0 | **PASS** |
| NoSQLi | 0 false positives on non-MongoDB app | 0 | **PASS** |
| XXE | 0 false positives (no XXE in DVWA) | 0 | **PASS** |
| Headers | >= 5 missing security headers | 7 | **PASS** |

### False positive targets

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| SQLi | 0 findings on non-injectable params | 2 FPs (`Change` on `/csrf/`, `ip` on `/exec/`) | **FAIL** |
| All others | 0 false positives | 0 | **PASS** |

---

## Remaining work

### XSS: `analyzeContext()` rejects a valid reflected payload

The payload `<script>alert(1)</script>` is reflected verbatim in `/xss_r/` (confirmed via curl). The scanner finds it in the response (`payloadFound=true`) but `analyzeContext()` returns `isExecutable=false`.

**What to do:** The early detection path (`if strings.Contains(payload, "<script")`) should return `ContextHTMLBody, true, "high"` before any comment/attribute checks. Either that path isn't reached, or a check before it returns early. Add a debug test that calls `analyzeContext()` with the real DVWA `/xss_r/` response body and the `<script>alert(1)</script>` payload, and trace which branch rejects it. Fix that branch.

**Files:** `pkg/scanner/xss.go` — `analyzeContext()`

### CMDi: detection logic doesn't match on live DVWA output

The `ip` param on `/exec/` is confirmed injectable via curl (`127.0.0.1;id` → `uid=33`). The scanner runs 1,120 tests but finds nothing.

**What to do:** The scanner has prepended payload support (`buildPrependedPayloads`), but something in the request/response flow still prevents detection. Write a debug test that:
1. Sends `POST /vulnerabilities/exec/` with `ip=127.0.0.1;id&Submit=Submit` using a real DVWA session
2. Prints the response body
3. Runs the CMDi output detection patterns against it
4. Identifies which step fails: is the payload not sent correctly? Is the response not containing the pattern? Or is the baseline comparison suppressing the finding?

The most likely cause is that `ip` starts with empty value `""` from form discovery, and prepended payloads may still not produce the right format. Check what `buildPrependedPayloads("", "; id")` actually generates.

**Files:** `pkg/scanner/cmdi.go` — `ScanPOST()`, `buildPrependedPayloads()`, `testOutputBasedPOST()`

### Path Traversal: payloads not reaching PHP's `include()` correctly

The `page` param on `/fi/` is confirmed injectable via curl (`page=../../../../../../etc/passwd` → `root:x:0:0:`). The scanner runs 666 tests but finds nothing.

**What to do:** Write a debug test that:
1. Sends `GET /vulnerabilities/fi/?page=../../../../../../etc/passwd` using a real DVWA session (raw slashes, no encoding)
2. Prints the response body and checks for `root:x:0:0:`
3. Then does the same request using the scanner's `testPayloadVariant()` URL construction
4. Compares the two — if the scanner's URL has encoded slashes (`%2F`) that's the bug

The `RawQuery` construction was fixed (sorted keys, manual encoding), but Go's `http.Client` may still re-encode the URL when sending the request. If so, the fix is to use `req.URL.Opaque` or `req.URL.RawPath` to prevent re-encoding.

**Files:** `pkg/scanner/pathtraversal.go` — `testPayloadVariant()`

### SQLi: 2 remaining false positives from CSRF token noise

`Change` on `/csrf/` and `ip` on `/exec/` are flagged as boolean-based SQLi. Both are caused by CSRF token changes between requests making `contentHashDiffers=true` + word count diff of 4 words.

**What to do:** `normalizeResponseContent()` should strip `user_token` hidden fields. Either it's not being called before `extractBodyContent()` in all code paths, or the regex doesn't match DVWA's token format. Check that the normalization regex matches `<input type='hidden' name='user_token' value='...' />` (note: single quotes, not double quotes — DVWA uses single quotes in its HTML).

**Files:** `pkg/scanner/sqli.go` — `normalizeResponseContent()`, `analyzeResponse()`
