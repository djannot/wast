# WAST - TODO

## Goal: Pass DVWA benchmark with zero false positives

The CI runs a full discovery scan against DVWA (security=low) via `TestDVWA_FullDiscoveryScanAssertions`. Every scanner must hit its target score **and** produce no false positives. Once all targets are met, convert the soft warnings (`t.Logf`) to hard failures (`t.Errorf`) so regressions break the build.

### Target scores

| Scanner | Target | Current | Gap |
|---------|--------|---------|-----|
| XSS | >= 1 finding on `/xss_r/` `name` param | 0 | Payload reflected verbatim but `analyzeContext()` still rejects it |
| CMDi | >= 1 finding on `/exec/` `ip` param (POST) | 0 | 1,120 tests run, prepended payloads added, still no detection |
| Path Traversal | >= 1 finding on `/fi/` `page` param | 0 | 666 tests run, raw slashes preserved, still no detection |
| SQLi | >= 1 finding on `/sqli/` or `/brute/` `id`/`username` param | 4 (but 0 on `id`) | Detects on `username`/`page` but misses the primary `/sqli/?id=` endpoint |
| CSRF | >= 7 forms with missing tokens | 9 | **PASS** |
| SSTI | 0 findings (no template engines in DVWA) | 0 | **PASS** |
| SSRF | 0 findings | 0 | **PASS** |
| NoSQLi | 0 false positives on non-MongoDB app | 14 FPs | All on `doc` param — DVWA uses MySQL, not MongoDB |
| Headers | >= 5 missing security headers | 7 | **PASS** |

### False positive targets

| Scanner | Target | Current | Gap |
|---------|--------|---------|-----|
| SQLi | 0 findings on `Change`, `doc`, `Login`, submit buttons | 4 FPs | CSRF token normalization not fully effective |
| NoSQLi | 0 findings on DVWA (MySQL app) | 14 FPs | `doc` param loads different pages — response size change is not injection |
| SSTI | 0 findings | 0 | **PASS** |
| SSRF | 0 findings | 0 | **PASS** |

### When all targets are met

Harden `TestDVWA_FullDiscoveryScanAssertions` — convert every `t.Logf("Warning: ...")` to `t.Errorf(...)` so CI fails on regression.
