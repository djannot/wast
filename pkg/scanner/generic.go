// Package scanner provides security scanning functionality for web applications.
package scanner

import "context"

// newActiveScanEntry constructs an activeScanEntry using Go generics, eliminating
// repetitive closures for the verify-all/filter-verified/get-errors/total-findings
// pattern that would otherwise be duplicated once per scanner type in executor.go.
//
// F is the concrete finding type for a scanner (e.g. XSSFinding, SQLiFinding).
//
// Parameters:
//   - name:            scanner name used for filtering and stats (e.g. "XSS")
//   - scan:            runs the scanner and captures the typed result
//   - getFindings:     returns the current findings slice from the captured result
//   - setFindings:     replaces the findings slice in the captured result
//   - verifyOne:       calls the scanner's VerifyFinding for a single finding
//   - applyVR:         applies a VerificationResult to a finding; differs per scanner
//     because some findings lack a Confidence or VerificationAttempts field
//   - isVerified:      reports whether a finding passed verification (always f.Verified)
//   - setSummaryCount: sets the post-filter count in the summary; differs per scanner
//     because CSRF uses VulnerableForms while others use VulnerabilitiesFound
//   - getErrors:       returns scan-time errors from the captured result
func newActiveScanEntry[F any](
	name string,
	scan func(ctx context.Context, target string),
	getFindings func() []F,
	setFindings func([]F),
	verifyOne func(ctx context.Context, f *F, cfg VerificationConfig) (*VerificationResult, error),
	applyVR func(*F, *VerificationResult),
	isVerified func(F) bool,
	setSummaryCount func(int),
	getErrors func() []string,
) activeScanEntry {
	return activeScanEntry{
		name: name,
		scan: scan,
		verifyAll: func(ctx context.Context, cfg VerificationConfig) {
			findings := getFindings()
			for i := range findings {
				vr, err := verifyOne(ctx, &findings[i], cfg)
				if err == nil && vr != nil {
					applyVR(&findings[i], vr)
				}
			}
		},
		filterVerified: func() {
			findings := getFindings()
			verified := make([]F, 0, len(findings))
			for _, f := range findings {
				if isVerified(f) {
					verified = append(verified, f)
				}
			}
			setFindings(verified)
			setSummaryCount(len(verified))
		},
		getErrors:     getErrors,
		totalFindings: func() int { return len(getFindings()) },
	}
}
