package boxcore

const (
	// ExitOK means the operation succeeded.
	ExitOK = 0
	// ExitFailed means all launches failed or the suite exited non-zero.
	ExitFailed = 1 // launch: every candidate failed, no box exists. run: the suite exited non-zero
	// ExitUsage means the invocation was invalid.
	ExitUsage = 2
	// ExitNoCandidate means no candidate exists or end polling expired.
	ExitNoCandidate = 3 // launch/run: no candidate at all. end: the poll bound passed, END_PENDING written
	// ExitNotRecorded means a running box has no ledger line; never relaunch.
	ExitNotRecorded = 4 // the box is UP and has no ledger line: never relaunch
	// ExitNotRegistered means a running recorded box is absent from the registry.
	ExitNotRegistered = 5 // the box is UP, in the ledger, not in the legacy registry
	// ExitDryDenied means the provider denied the dry run.
	ExitDryDenied = 6
	// ExitDryUnexpected means the dry run returned an unexpected answer.
	ExitDryUnexpected = 7
	// ExitAccess means the box never became reachable.
	ExitAccess = 10 // the box never became reachable
	// ExitHarvest means results are incomplete or could not be fetched.
	ExitHarvest = 11 // harvest failed or is incomplete
	// ExitPreempted means the provider took the box before the suite finished.
	ExitPreempted = 12 // the provider took the box before the suite finished
	// ExitTimeout means the suite passed its timeout.
	ExitTimeout = 13 // the suite passed its timeout
	// ExitCostCap means the cost cap refused or stopped the run.
	ExitCostCap = 14 // refused or stopped by the cost cap
	// ExitEndPending means a run's box was not confirmed gone within the bound.
	ExitEndPending = 15 // run: the box was not confirmed gone within the bound
	// ExitInternal means an internal failure prevented completion.
	ExitInternal = 70
)

// ExitName returns the stable name for an exit code.
func ExitName(code int) string {
	switch code {
	case ExitOK:
		return "ok"
	case ExitFailed:
		return "failed"
	case ExitUsage:
		return "usage"
	case ExitNoCandidate:
		return "no-candidate"
	case ExitNotRecorded:
		return "not-recorded"
	case ExitNotRegistered:
		return "not-registered"
	case ExitDryDenied:
		return "dry-denied"
	case ExitDryUnexpected:
		return "dry-unexpected"
	case ExitAccess:
		return "access"
	case ExitHarvest:
		return "harvest"
	case ExitPreempted:
		return "preempted"
	case ExitTimeout:
		return "timeout"
	case ExitCostCap:
		return "cost-cap"
	case ExitEndPending:
		return "end-pending"
	case ExitInternal:
		return "internal"
	default:
		return "unknown"
	}
}
