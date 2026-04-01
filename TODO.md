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
| SQLi | 0 findings on non-injectable params | 0 | **PASS** |
| All others | 0 false positives | 0 | **PASS** |
