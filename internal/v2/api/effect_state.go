package api

// Effect state is separate from Operation.Status and ContinuationIntent.Status.
type EffectState string

const (
	EffectPending   EffectState = "pending"
	EffectClaimed   EffectState = "claimed"
	EffectCompleted EffectState = "completed"
	EffectFailed    EffectState = "failed"
)

func ValidEffectState(state EffectState) bool {
	switch state {
	case EffectPending, EffectClaimed, EffectCompleted, EffectFailed:
		return true
	}
	return false
}

func EffectLeaseClaimed(lease EffectLease) bool {
	return lease.Record.State == EffectClaimed
}
