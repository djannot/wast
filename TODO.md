# WAST - TODO

## Goal: Pass all benchmarks with zero false positives

The CI runs full discovery scans against DVWA, Juice Shop, and WebGoat. Every scanner must hit its target score **and** produce no false positives. All assertions use hard failures (`t.Errorf`) so regressions break the build.

### DVWA target scores (latest live scan 2026-03-30)

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| XSS | >= 1 finding on `/xss_r/` `name` param | 26 (reflected + DOM + stored) | **PASS** |
| CMDi | >= 1 finding on `/exec/` `ip` param (POST) | 13 (time-based + output-based, 0 FPs) | **PASS** |
| Path Traversal | >= 1 finding on `/fi/` `page` param | 3 | **PASS** |
| SQLi | >= 1 finding on `/sqli/` `id` param | 3 on `id` (sqli + sqli_blind) | **PASS** |
| CSRF | >= 7 forms with missing tokens | 10 (8 missing + 2 unenforced) | **PASS** |
| SSTI | 0 findings | 0 | **PASS** |
| SSRF | 0 false positives | 1 (`page` + `file:///etc/passwd` — see note below) | **REVIEW** |
| NoSQLi | 0 false positives | 0 | **PASS** |
| XXE | 0 false positives | 0 | **PASS** |
| Headers | >= 5 missing | 7 | **PASS** |

### False positive targets

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| SQLi | 0 findings on non-injectable params | 4 FPs on `doc` param | **FAIL** |
| CMDi | 0 findings on non-injectable params | 0 | **PASS** |
| SSRF | 0 false positives on non-SSRF params | 0 (1 arguable — see note) | **REVIEW** |
| All others | 0 false positives | 0 | **PASS** |

---

## Remaining work

### SQLi: 4 false positives on `doc` param

The content-routing pre-check eliminated some `doc` FPs but 4 remain (`doc=PDF`, `doc=copying`, `doc=PHPIDS-license`). The pre-check sends a random string and compares against baseline — but these `doc` values also produce different responses from each other, so the differential analysis still triggers.

**What to do:** The pre-check may need to be stricter. If `randomstring` produces a different response from baseline AND the true/false SQL payloads ALSO produce different responses, the param is likely content-routing. An alternative: if the true payload (`' OR '1'='1`) and false payload (`' OR '1'='2`) both produce responses that differ from baseline by a similar amount, it's content-routing (both are just "unknown doc values"), not injection (where true and false should differ from each other).

### SSRF: 1 finding on `page` param with `file:///etc/passwd`

This is a borderline case. The `page` param on `/fi/` IS vulnerable to file inclusion, and `file:///etc/passwd` IS a valid protocol for LFI. The SSRF scanner found it independently from the Path Traversal scanner. This could reasonably be classified as a true positive (protocol-based file access via SSRF) rather than a false positive. Consider whether `file://` protocol findings on params already flagged by Path Traversal should be deduplicated or kept as a separate finding class.
