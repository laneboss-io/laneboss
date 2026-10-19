package secrets

// CredentialStop is the bounded cause class used by the credential
// withdrawal policy. It is deliberately separate from the wire reason strings
// used by a particular projection so a caller cannot make an unknown cause
// look like a releasable stop.
type CredentialStop string

const (
	CredentialStopNormal CredentialStop = "normal"
	CredentialStopCancel CredentialStop = "cancel"
	CredentialStopRevoke CredentialStop = "revoke"
)

// CredentialRotationPolicyInput contains only the facts needed by ruling B.
// LeakHit represents the LB-301 observation that credential bytes escaped the
// expected private boundary; it always wins over the stop cause.
type CredentialRotationPolicyInput struct {
	Cause   CredentialStop
	LeakHit bool
}

// CredentialRotationPolicyDecision tells projection withdrawal whether its
// lane-owned copy may be retired. RotationRequired remains true for every
// exposed credential, including a normal stop; BlockSeat is the quarantine
// decision for the canonical credential owner.
type CredentialRotationPolicyDecision struct {
	RetireLaneCopy   bool
	RotationRequired bool
	BlockSeat        bool
}

func credentialStopForWithdrawalReason(reason string) CredentialStop {
	switch reason {
	case "release":
		return CredentialStopNormal
	case "cancelled":
		return CredentialStopCancel
	case "revoked":
		return CredentialStopRevoke
	default:
		return CredentialStop(reason)
	}
}

// EvaluateCredentialRotationPolicy is the pure ruling-B policy. A normal stop
// retires only the stopped lane copy and leaves the canonical seat available
// while recording that the credential must be rotated. Cancellation, revoke,
// leak, and unknown causes retain the quarantine. Unknown values fail closed.
func EvaluateCredentialRotationPolicy(input CredentialRotationPolicyInput) CredentialRotationPolicyDecision {
	decision := CredentialRotationPolicyDecision{RotationRequired: true, BlockSeat: true}
	if input.LeakHit {
		return decision
	}
	if input.Cause == CredentialStopNormal {
		decision.RetireLaneCopy = true
		decision.BlockSeat = false
	}
	return decision
}
