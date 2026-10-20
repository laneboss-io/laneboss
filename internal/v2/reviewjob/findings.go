package reviewjob

import (
	"path"
	"regexp"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// Each rule is bounded by a path component or a full filename. Keeping the
// complete table here prevents broad directory guesses such as "internal/".
var testOnlyPathPatterns = [...]*regexp.Regexp{
	regexp.MustCompile(`(^|/)[^/]*_test\.go$`),
	regexp.MustCompile(`(^|/)testdata(/|$)`),
	regexp.MustCompile(`(^|/)fixtures(/|$)`),
	regexp.MustCompile(`(^|/)fakes(/|$)`),
	regexp.MustCompile(`(^|/)fake_[^/]*\.go$`),
	regexp.MustCompile(`(^|/)[^/]*_fake\.go$`),
	regexp.MustCompile(`(^|/)mocks(/|$)`),
	regexp.MustCompile(`(^|/)mock_[^/]*\.go$`),
	regexp.MustCompile(`(^|/)tests(/|$)`),
	regexp.MustCompile(`(^|/)[^/]*_test\.py$`),
	regexp.MustCompile(`(^|/)test_[^/]*\.py$`),
	regexp.MustCompile(`(^|/)[^/]*\.spec\.[^/]*$`),
	regexp.MustCompile(`(^|/)[^/]*\.test\.[^/]*$`),
	regexp.MustCompile(`(^|/)e2e(/|$)`),
	regexp.MustCompile(`(^|/)e2e-rows(/|$)`),
	regexp.MustCompile(`(^|/)testfixture(/|$)`),
	regexp.MustCompile(`(^|/)testenv(/|$)`),
}

// IsTestOnlyPath classifies a canonical repository-relative path without I/O.
// Neither a matching ancestor's spelling nor an invalid path grants coverage.
func IsTestOnlyPath(name string) bool {
	if name == "" || name == "." || path.IsAbs(name) || path.Clean(name) != name ||
		name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") {
		return false
	}
	for _, pattern := range testOnlyPathPatterns {
		if pattern.MatchString(name) {
			return true
		}
	}
	return false
}

// DiffFindings uses authenticated check facts as V2's structured pass claim;
// report.submit transports opaque prose and has no success field. A failed or
// absent check set is not a pass, even if the verifier process itself exits zero.
// Call only after the candidate diff has matched the actual frozen trees.
func DiffFindings(diff Diff, checks []api.ReviewCheckFact) []api.ReviewFinding {
	findings := []api.ReviewFinding{}
	if len(checks) == 0 {
		return findings
	}
	for _, check := range checks {
		if check.ExitCode != 0 {
			return findings
		}
	}
	changedFiles := 0
	for _, change := range diff.Changes {
		// Frozen manifests include directory scaffolding (including the base
		// root "."), while a Git diff records files and links. Keep that
		// scaffolding in the integrity diff without letting it hide test-only
		// edits. A file/directory type change still counts as a file edit.
		if (change.Before != nil || change.After != nil) &&
			(change.Before == nil || change.Before.Kind == "directory") &&
			(change.After == nil || change.After.Kind == "directory") {
			continue
		}
		changedFiles++
		if !IsTestOnlyPath(change.Path) {
			return findings
		}
	}
	if changedFiles == 0 {
		return append(findings, api.ReviewFinding{Kind: api.ReviewFindingEmptyDiff,
			Message: "Checks claim success with an empty file diff; independent human or judge review is required before trusting the result."})
	}
	return append(findings, api.ReviewFinding{Kind: api.ReviewFindingFakeOnlyDiff,
		Message: "Checks claim success after changes only to tests, fakes, mocks or fixtures; independent human or judge review is required before trusting the result."})
}
