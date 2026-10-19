package api

// These checks establish shape and correlation only. The helper attests real
// pipe/process ownership; AppendCapture checks the authenticated worker lease,
// retained binding, immutable bytes, current offset and CAS under the store lock.
func ValidateCaptureBinding(binding CaptureBinding) error {
	b := binding
	if !launchID(b.ID) || !bindingConfigName.MatchString(b.Config) || !launchID(b.ReservationID) ||
		!launchID(b.Target.LifeID) || b.Target.Run == 0 || b.Target.Run > launchMaxInteger ||
		!launchID(b.LaunchID) || !launchID(b.HelperLeaseID) || !launchID(b.OperationID) ||
		!launchID(b.RequestID) || !launchID(b.RequestedBy.ID) || !launchGeneration(b.Generation) {
		return launchInvalid("invalid capture binding shape")
	}
	switch b.Status {
	case "refused":
		if b.RefusalPolicy == nil || !b.RefusalPolicy.Allowed || !launchGeneration(b.RefusalPolicy.PolicyGeneration) || !launchID(b.RefusalPolicy.ApprovalID) {
			return launchInvalid("capture refusal requires explicit approved policy")
		}
		if b.Refusal == nil || b.Refusal.Owner == "" || b.Refusal.Message == "" || b.Refusal.Instead == "" ||
			b.Refusal.OperationID != b.OperationID ||
			b.Refusal.Code != CodeNotImplemented && b.Refusal.Code != CodeUnavailable && b.Refusal.Code != CodeUnsupported ||
			len(b.Streams) != 0 || b.WorkerLeaseID != "" || b.EffectID != "" || b.ProducerID != "" ||
			b.ProducerGeneration != "" || b.BootID != "" || b.Supervisor != nil {
			return launchInvalid("capture refusal lacks an explicit unavailable result")
		}
		return nil
	case "registered":
		if b.Refusal != nil || b.RefusalPolicy != nil || !launchID(b.WorkerLeaseID) || !launchID(b.EffectID) || !launchID(b.ProducerID) ||
			b.ProducerGeneration == "" || b.BootID == "" || b.Supervisor == nil || !launchExecutable(*b.Supervisor) {
			return launchInvalid("capture registration lacks its producer attestation")
		}
	default:
		return launchInvalid("capture binding has no explicit disposition")
	}
	streams, ids, pipes := map[string]bool{}, map[ID]bool{}, map[ID]bool{}
	for _, stream := range b.Streams {
		if stream.Stream != "stdout" && stream.Stream != "stderr" && stream.Stream != "vendor" ||
			streams[stream.Stream] || !launchID(stream.ID) || ids[stream.ID] || !launchID(stream.PipeID) || pipes[stream.PipeID] {
			return launchInvalid("capture registration has ambiguous stream ownership")
		}
		streams[stream.Stream], ids[stream.ID], pipes[stream.PipeID] = true, true, true
	}
	if !streams["stdout"] || !streams["stderr"] {
		return launchInvalid("capture registration lacks stdout or stderr")
	}
	return nil
}

// The policy must be read from the protected current store, whose publisher
// verifies the referenced consumed D6 approval. Metadata supplied by a binding
// is only a comparison claim; it cannot enable the default-false exception.
func ValidateCapturePolicy(binding CaptureBinding, policy EffectivePolicy) error {
	if err := ValidateCaptureBinding(binding); err != nil {
		return err
	}
	if binding.Status != "refused" {
		return nil
	}
	if !policy.AllowCaptureRefusal || !launchID(policy.CaptureRefusalApprovalID) ||
		policy.Generation != binding.RefusalPolicy.PolicyGeneration || policy.CaptureRefusalApprovalID != binding.RefusalPolicy.ApprovalID {
		return launchInvalid("capture refusal is not enabled by current D6 policy")
	}
	return nil
}

func validCaptureProducer(binding CaptureBinding, request CaptureAppendRequest) bool {
	b, cause := binding, request.Intent
	return b.Status == "registered" && cause.Kind == InternalCaptureAppend && cause.Config == b.Config &&
		cause.Actor.Kind == "worker" && cause.Actor.ID == b.ProducerID && cause.RequestedBy == b.RequestedBy &&
		cause.Target == b.Target && cause.CauseOperationID == b.OperationID && cause.CauseRequestID == b.RequestID && cause.EffectID == b.EffectID
}

func ValidateCaptureAppend(binding CaptureBinding, request CaptureAppendRequest) error {
	if err := ValidateCaptureBinding(binding); err != nil {
		return err
	}
	b, r, cause := binding, request, request.Intent
	if !validCaptureProducer(b, r) || r.BindingID != b.ID || !launchGeneration(r.ExpectedGeneration) ||
		!launchID(cause.ID) || r.Offset < 0 || r.Offset > launchMaxInteger {
		return launchInvalid("capture append differs from its registered producer or cause")
	}
	found := false
	for _, stream := range b.Streams {
		found = found || stream.ID == r.StreamID
	}
	if !found || r.EOF == (r.Data != nil) ||
		r.Data != nil && (!launchBlob(*r.Data, "capture") || r.Data.Bytes > MaxChunkBytes || r.Offset > launchMaxInteger-r.Data.Bytes) {
		return launchInvalid("invalid capture stream range or EOF")
	}
	return nil
}
