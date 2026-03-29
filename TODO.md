# WAST - TODO

## Goal: Pass DVWA benchmark with zero false positives

The CI runs a full discovery scan against DVWA (security=low) via `TestDVWA_FullDiscoveryScanAssertions`. All targets are met and assertions use hard failures (`t.Errorf`) so regressions break the build.

### Target scores

| Scanner | Target | Current | Gap |
|---------|--------|---------|-----|
| XSS | >= 1 finding on `/xss_r/` `name` param | >= 1 | **PASS** (PR #280) |
| CMDi | >= 1 finding on `/exec/` `ip` param (POST) | >= 1 | **PASS** (PR #280) |
| Path Traversal | >= 1 finding on `/fi/` `page` param | >= 1 | **PASS** (PR #280) |
| SQLi | >= 1 finding on `/sqli/` or `/brute/` `id`/`username` param | 5 (including `id`) | **PASS** (PR #276) |
| CSRF | >= 7 forms with missing tokens | 9 | **PASS** |
| SSTI | 0 findings (no template engines in DVWA) | 0 | **PASS** |
| SSRF | 0 findings | 0 | **PASS** |
| NoSQLi | 0 false positives on non-MongoDB app | 0 | **PASS** |
| XXE | 0 false positives (no XXE in DVWA) | 0 | **PASS** |
| Headers | >= 5 missing security headers | 7 | **PASS** |

### False positive targets

| Scanner | Target | Current | Status |
|---------|--------|---------|--------|
| SQLi | 0 findings on non-injectable params | 0 FPs | **PASS** (PR #282) — `Change` on `/csrf/` fixed by adding `"change"` to `submitPatterns`; `ip` on `/exec/` fixed by `normalizeResponseContent()` correctly stripping `user_token` single-quoted hidden fields (the `['"]` delimiters in the named-token patterns already covered single quotes — the CSRF token noise was making `contentHashDiffers=true`, causing the FP) |
| All others | 0 false positives | 0 | **PASS** |

---

## Completed

All original DVWA benchmark targets have been achieved:

- **XSS** — `analyzeContext()` correctly identifies reflected payloads (PR #280)
- **CMDi** — Detection logic matches live DVWA output (PR #280)
- **Path Traversal** — Payloads reach PHP's `include()` correctly (PR #280)
- **SQLi** — Zero false positives; CSRF token noise resolved via `normalizeResponseContent()` (PR #282)
- All assertions in `test/integration/dvwa_test.go` use hard failures (`t.Errorf`) so regressions break the build.
- **Open Redirect & XXE** — Zero-false-positive assertions added to `TestDVWA_FullDiscoveryScanAssertions` (PR #286)

---

## Next steps

- Expand the benchmark beyond DVWA to other test targets (e.g., WebGoat, Juice Shop)
- Increase coverage thresholds as new scanner capabilities are added
- Explore authenticated scanning improvements for other session management patterns
