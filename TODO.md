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

## Juice Shop benchmark (PR #290)

Added OWASP Juice Shop as a second integration test target alongside DVWA.
Juice Shop (Node.js/Angular + MongoDB + JWT) exercises scanner capabilities that
DVWA (legacy PHP/MySQL) does not cover.

| Scanner | Target | Notes |
|---------|--------|-------|
| NoSQLi | >= 1 finding on `/rest/products/search?q=` | MongoDB backend — validates true positive detection |
| Headers | >= 3 missing security headers | Juice Shop ships without HSTS, CSP, X-Frame-Options |
| XSS | >= 1 finding on search endpoint | Hard assertion (t.Errorf); JSON reflection detection added (PR #292) |
| SQLi | 0 findings (no SQL database) | Validates zero false positives on MongoDB app |

See `test/integration/juiceshop/juiceshop_test.go` and `docker-compose.juiceshop.yml`.

---

## Next steps

- ~~Convert the Juice Shop XSS assertion from soft (t.Logf) to hard (t.Errorf) once
  the XSS scanner's JSON-response reflection detection is validated against live Juice Shop~~
  **DONE** — JSON reflection detection (verbatim + Unicode-escaped) added in PR #292;
  assertion converted to t.Errorf.
- ~~Expand Juice Shop coverage: path traversal, CSRF, SSRF, XXE assertions~~
  **DONE** — `TestJuiceShop_PathTraversal`, `TestJuiceShop_CSRF`, `TestJuiceShop_SSRF_NoFalsePositives`, and `TestJuiceShop_XXE_NoFalsePositives` added in PR #294; all four scanners also wired into `TestJuiceShop_FullScanSummary`.
- ~~Add WebGoat as a third benchmark target (Java/Spring, different session patterns)~~
  **DONE** — `docker-compose.webgoat.yml`, `test/integration/webgoat/webgoat_test.go`, `make test-webgoat`, and optional CI job added in PR #297; covers SQLi, XSS, PathTraversal, Headers assertions plus NoSQLi/XXE zero-false-positive checks.
- ~~Increase coverage thresholds as new scanner capabilities are added~~
  **DONE** — Minimum coverage threshold (MIN_COVERAGE=74%) enforced in CI via `make coverage-check`; initial threshold set ~5 pp below current total coverage of 78.8% (PR #300).
- ~~Explore authenticated scanning improvements for other session management patterns~~
  **DONE** — JWT-in-response-body authentication added to `PerformLogin` in PR #298; `LoginConfig.TokenField` allows custom dot-separated JSON paths; `LooksLikeJWT` exported from `pkg/api/jwt.go`; unit tests and `docs/authentication.md` updated.
