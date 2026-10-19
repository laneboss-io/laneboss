package reviewjob

import "laneboss.io/laneboss/internal/v2/api"

// CompletedGeneration permits only native consumption followed by result
// retention, or an exact already-completed read-back. Immutable lease fields
// and the actual completed effect/observation are checked separately by callers.
func CompletedGeneration(before, after api.WorkerLease) bool {
	const ceiling = api.Generation(1<<53 - 1)
	if before.Generation == 0 || after.Generation == 0 || before.Generation > ceiling || after.Generation > ceiling || after.ConsumedBy == "" {
		return false
	}
	if before.ConsumedBy == "" {
		return before.Generation <= ceiling-2 && after.Generation == before.Generation+2
	}
	return before.ConsumedBy == after.ConsumedBy && (after.Generation == before.Generation ||
		before.Generation < ceiling && after.Generation == before.Generation+1)
}
