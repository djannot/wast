# WAST - TODO

## Goal: Pass all benchmarks with zero false positives

The CI runs full discovery scans against DVWA, Juice Shop, and WebGoat. Every scanner must hit its target score **and** produce no false positives. All assertions use hard failures (`t.Errorf`) so regressions break the build.

### DVWA target scores (latest live scan 2026-04-01)

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| XSS | >= 1 finding on `/xss_r/` `name` param | 26 (reflected + DOM + stored) | **PASS** |
| CMDi | >= 1 finding on `/exec/` `ip` param (POST) | 13 (time-based + output-based, 0 FPs) | **PASS** |
| Path Traversal | >= 1 finding on `/fi/` `page` param | 3 | **PASS** |
| SQLi | >= 1 finding on `/sqli/` `id` param | 3 on `id` (sqli + sqli_blind) | **PASS** |
| CSRF | >= 7 forms with missing tokens | 10 (8 missing + 2 unenforced) | **PASS** |
| SSTI | 0 findings | 0 | **PASS** |
| SSRF | 0 false positives | 1 (deduplicated via Correlation 7) | **PASS** |
| NoSQLi | 0 false positives | 0 | **PASS** |
| XXE | 0 false positives | 0 | **PASS** |
| Headers | >= 5 missing | 7 | **PASS** |

### False positive targets

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| SQLi | 0 findings on non-injectable params | 0 | **PASS** |
| CMDi | 0 findings on non-injectable params | 0 | **PASS** |
| SSRF | 0 false positives on non-SSRF params | 0 (deduplicated via Correlation 7) | **PASS** |
| All others | 0 false positives | 0 | **PASS** |

---

## Remaining work

### SQLi: 5 false positives on `doc` param (root URL)

The `doc` param on `http://localhost:8080?doc=*` (root URL, NOT `instructions.php`) is completely ignored by DVWA — every response is byte-identical at 6721 bytes regardless of the `doc` value. Confirmed via curl: `doc=readme`, `doc=randomstring`, `doc=' OR '1'='1`, `doc=' OR '1'='2` all return identical responses.

Despite this, the scanner reports a 4-word difference (568 vs 564) and differing content hashes between the true and false payloads. Since the raw HTTP responses are byte-identical, the difference must originate from non-determinism in the scanner's processing pipeline:

1. **Session state drift:** The scanner's HTTP client cookie jar may cause subtle session changes between the baseline and payload requests (e.g., DVWA rotating session internally, causing a Set-Cookie that alters subsequent responses)
2. **Race condition in normalization:** The `normalizeResponseContent()` regex patterns may not be idempotent or may interact with extracted content differently depending on timing
3. **Concurrent request interference:** Discovery mode scans multiple targets concurrently — another concurrent request to a different DVWA page might alter shared session state (e.g., security level, stored XSS entries) between the baseline and payload requests for the `doc` param

**What to do:** The mutual-diff check (`isMutualContentRouting`) should catch this case since both true and false payloads should produce identical responses. Debug why it doesn't fire:
- Check if `trueDelta` and `falseDelta` are both 0 (identical to baseline) — if so, the check at line 2381 (`trueDelta <= baseline.BodyLength/20`) returns `false` and skips the mutual check, because the responses DON'T differ from baseline by >5%. The function requires BOTH payloads to deviate from baseline — but in this case neither deviates, so it falls through.
- The fix: if both true and false responses are nearly identical to the baseline AND to each other (within CSRF token noise), the param is not injectable. Add an early return in `testBooleanBased()`: if the true-vs-false body length difference is 0 and the word count difference is <= the CSRF token noise threshold (4 words), skip the finding.
