# WAST - TODO

## Goal: Pass all benchmarks with zero false positives

The CI runs full discovery scans against DVWA, Juice Shop, and WebGoat. Every scanner must hit its target score **and** produce no false positives. All assertions use hard failures (`t.Errorf`) so regressions break the build.

### DVWA target scores (latest live scan 2026-04-01)

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| XSS | >= 1 finding on `/xss_r/` `name` param | 26 (reflected + DOM + stored) | **PASS** |
| CMDi | >= 1 finding on `/exec/` `ip` param (POST) | 14 (0 FPs) | **PASS** |
| Path Traversal | >= 1 finding on `/fi/` `page` param | 3 | **PASS** |
| SQLi | >= 1 finding on `/sqli/` `id` param | 3 on `id` | **PASS** |
| CSRF | >= 7 forms with missing tokens | 10 | **PASS** |
| SSTI | 0 findings | 0 | **PASS** |
| SSRF | 0 false positives | 1 (deduplicated) | **PASS** |
| NoSQLi | 0 false positives | 0 | **PASS** |
| XXE | 0 false positives | 0 | **PASS** |
| Headers | >= 5 missing | 7 | **PASS** |

### False positive targets

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| SQLi | 0 findings on non-injectable params | 6 FPs (`doc` x5, `mtxMessage` x1) | **FAIL** |
| All others | 0 false positives | 0 | **PASS** |

---

## Remaining work

### SQLi: 6 phantom false positives (4-word noise on static pages)

All 6 FPs share the same signature: `content hash differs; word count differs (true: 564/568, false: 568/564, diff: 4 words)` on pages where the parameter is completely ignored. Confirmed via curl: the raw HTTP responses are byte-identical regardless of the parameter value.

**Affected params:** `doc` on `http://localhost:8080?doc=*` (5 FPs), `mtxMessage` on `/xss_s/` (1 FP).

**Root cause:** The scanner's own HTTP requests produce slightly different responses between the true and false payload requests, even though the parameter is ignored. The 4-word / content-hash difference is not in the application response — it's noise from:
- DVWA generating a new CSRF token on pages that DO have `user_token` (but the root page doesn't have one — so this may be a Set-Cookie or session rotation issue)
- Or concurrent scan requests altering shared session state between the baseline and payload requests

**Why existing checks don't catch it:**
- `isContentRouting`: returns `false` because a random string produces an identical response to baseline (correct — the param IS ignored)
- `isMutualContentRouting`: returns `false` because it requires both payloads to deviate from baseline by >5% of body length — but here the body lengths are identical (6721 bytes), so neither deviates

**Fix:** Add a minimum absolute threshold to the differential analysis. If the true-vs-false body length difference is 0 bytes AND the word count difference is <= 4 (CSRF token noise floor), skip the finding regardless of content hash. A content hash difference with zero body length difference and <= 4 word count difference is always noise, never real injection.

Alternatively, increase the `minWordCountDifference` from 2 to 5 — but that risks missing real injection on small pages. The body-length-zero check is safer and more targeted.
