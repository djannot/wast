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
| SQLi | 0 findings on non-injectable params | 0 (secondary mutual-diff check added) | **PASS** |
| CMDi | 0 findings on non-injectable params | 0 | **PASS** |
| SSRF | 0 false positives on non-SSRF params | 0 (1 arguable — see note) | **REVIEW** |
| All others | 0 false positives | 0 | **PASS** |

---

## Remaining work

### ~~SQLi: 4 false positives on `doc` param~~ FIXED (issue #326)

A secondary mutual-difference check was added after the existing content-routing pre-check.
After fetching both true and false SQL payloads, if both differ from the baseline by >5% AND
are mutually similar (body-length diff ≤5% of baseline AND data-word diff ≤1), the parameter
is classified as content-routing and skipped. This eliminates the remaining `doc=PDF`,
`doc=copying`, and `doc=PHPIDS-license` false positives without affecting real SQLi detection.

### SSRF: 1 finding on `page` param with `file:///etc/passwd`

This is a borderline case. The `page` param on `/fi/` IS vulnerable to file inclusion, and `file:///etc/passwd` IS a valid protocol for LFI. The SSRF scanner found it independently from the Path Traversal scanner. This could reasonably be classified as a true positive (protocol-based file access via SSRF) rather than a false positive. Consider whether `file://` protocol findings on params already flagged by Path Traversal should be deduplicated or kept as a separate finding class.
