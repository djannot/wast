# WAST - TODO

## Retest results (2026-03-27)

Tested against DVWA (security=low) with `active=true, discover=true, depth=3`.

| Scanner | Findings | Tests | Status |
|---------|----------|-------|--------|
| SQLi | 9 | 511 | Detecting, but some FPs on non-injectable params (`Upload`, `seclev_submit`) |
| CSRF | 9 | — | Real missing CSRF tokens |
| SSRF | 0 | 629 | Clean — no false positives |
| XSS | 0 | 259 | Not detecting reflected XSS on `/xss_r/` |
| CMDi | 0 | 1,184 | Not detecting POST injection on `/exec/` |
| Path Traversal | 0 | 666 | Not detecting LFI on `/fi/?page=` |
| SSTI | 29 | 370 | All false positives — massive FP problem |
| Headers | 7 missing | — | Expected for DVWA |

## ✅ P0: SSTI scanner produces massive false positives - RESOLVED

**Impact:** 29 SSTI findings reported across 6+ template engines (Jinja2, Freemarker, Thymeleaf, Velocity, ERB, Smarty) on a plain PHP app that uses none of them. Every parameter that reflects input is flagged.

**Root cause:** The detection logic checks if the payload string appears in the response, but does not verify that the template expression was actually **evaluated**. For example, sending `{{7*7}}` and finding `{{7*7}}` in the response is reflection, not injection. The scanner should check for `49` (the computed result) in the response instead.

**Fix implemented:** Updated `detectTemplateInjection()` to require:
1. Expected result (e.g., `49`) appears in response AND payload literal (e.g., `{{7*7}}`) does NOT appear (pure evaluation)
2. If both appear, expected result count must exceed payload count (evaluation occurred)
3. Baseline comparison prevents flagging numbers naturally present in pages
4. Added comprehensive unit tests for false positive and true positive scenarios

**Files:** `pkg/scanner/ssti.go`, `pkg/scanner/ssti_test.go`

## P0: XSS scanner doesn't detect reflected XSS

**Impact:** DVWA `/vulnerabilities/xss_r/?name=<script>alert(1)</script>` reflects the payload verbatim in the response HTML. 259 tests run, 0 findings.

**Root cause:** The `testParameter()` detection logic is not checking whether injected payloads appear unescaped in the response body. Detection should:
1. Send a payload containing HTML/JS (e.g., `<script>alert(1)</script>`)
2. Check if the exact payload appears unescaped in the response HTML
3. If found, it's reflected XSS

**Files:** `pkg/scanner/xss.go` — `testParameter()`

## P0: CMDi scanner doesn't detect command injection via POST

**Impact:** DVWA `/vulnerabilities/exec/` accepts POST param `ip` and passes it to `shell_exec()`. 1,184 tests run, 0 findings.

**Root cause:** Despite POST scanning support being added, the CMDi detection heuristics aren't matching. The scanner needs to:
1. Send a baseline request (e.g., `ip=127.0.0.1`)
2. Send a payload like `127.0.0.1; whoami` or `127.0.0.1 && id`
3. Detect extra output (username, uid) in the response compared to baseline

**Debug:** `curl -X POST http://localhost:8080/vulnerabilities/exec/ -d "ip=127.0.0.1;id&Submit=Submit" -b "PHPSESSID=...; security=low"` confirms the injection works. Trace why the scanner doesn't flag it.

**Files:** `pkg/scanner/cmdi.go` — `ScanPOST()`, `testParameter()`, detection heuristics

## P1: Path traversal scanner misses LFI

**Impact:** DVWA `/vulnerabilities/fi/?page=../../etc/passwd` returns file contents. 666 tests run, 0 findings.

**Root cause:** Either the payloads don't match what DVWA expects, or the `containsPasswdSignature()` response check is too strict. Verify the scanner is actually sending the right traversal depth and checking the response correctly.

**Files:** `pkg/scanner/pathtraversal.go`

## P1: SQLi false positives on non-injectable parameters

**Impact:** SQLi scanner reports boolean-based injection on `Upload` button, `seclev_submit`, and `security` dropdown — these are not actually injectable. The differential analysis is being fooled by DVWA's dynamic content (e.g., CSRF tokens changing between requests cause content hash differences).

**Fix approach:** Filter out parameters that are submit buttons or known non-data fields. Also tighten differential analysis to ignore known-dynamic content (CSRF tokens, nonces, timestamps) when comparing responses.

**Files:** `pkg/scanner/sqli.go` — `testBooleanBased()`, differential analysis logic

## P2: Add DVWA integration tests to CI

**Impact:** All scanner improvements are currently validated manually against a local DVWA instance. Regressions can slip in undetected.

**Approach:**
1. Add a Docker Compose file that spins up DVWA (e.g., `vulnerables/web-dvwa`) in CI
2. Create an integration test suite that:
   - Starts DVWA container, waits for it to be ready, initializes the database
   - Logs in and sets security=low
   - Runs discovery scan against `http://localhost:8080`
   - Asserts expected findings: SQLi on `/sqli/`, XSS on `/xss_r/`, CMDi on `/exec/`, LFI on `/fi/`, CSRF on all forms
   - Asserts no false positives on known-clean parameters
3. Run as a separate CI job (e.g., `make test-integration`) since it requires Docker
4. Gate on: each scanner must detect at least its primary DVWA vulnerability (acts as a regression test for detection logic)

**Files:** new `docker-compose.test.yml`, new `pkg/scanner/dvwa_integration_test.go` or `test/integration/`
