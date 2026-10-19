package api

import "slices"

func ValidateChannelJob(job ChannelJob) error {
	j, lease := job, job.Lease
	if !launchID(j.ChannelID) || !launchGeneration(j.ChannelGeneration) || !launchID(j.DestinationID) || !launchID(j.MailID) ||
		!launchID(j.ProviderIdempotencyKey) || !launchID(lease.ID) || lease.Kind != "channel" || !launchGeneration(lease.Generation) ||
		!launchID(lease.Target.LifeID) || lease.Target.Run == 0 || !launchID(lease.OperationID) || !launchID(lease.EffectID) ||
		!launchID(lease.GrantSetID) || lease.ExpiresAt == "" || !launchBlob(lease.Input, "channel_input") || lease.Input.Bytes > MaxFrameBytes ||
		!launchBlob(j.Payload, "channel_payload") || j.Payload.Bytes > MaxFrameBytes || j.Runtime == nil || !launchExecutable(j.Runtime.Executable) ||
		!launchBlob(j.Runtime.Manifest, "manifest") || j.Runtime.Manifest != lease.RuntimeManifest ||
		j.Runtime.Reconcile != "provider_key" && j.Runtime.Reconcile != "receipt_id" && j.Runtime.Reconcile != "unsupported" {
		return launchInvalid("channel job lacks its fixed enrolled worker handoff")
	}
	return nil
}

func ValidateChannelInput(job ChannelJob, input ChannelSendInput) error {
	if err := ValidateChannelJob(job); err != nil {
		return err
	}
	if input.Schema != "laneboss.channel-input.v2" || input.LeaseID != job.Lease.ID || input.MailID != job.MailID ||
		input.ChannelID != job.ChannelID || input.ChannelGeneration != job.ChannelGeneration || input.DestinationID != job.DestinationID ||
		input.ProviderIdempotencyKey != job.ProviderIdempotencyKey || input.Payload != job.Payload || input.Content != job.Content || !slices.Equal(input.Artifacts, job.Artifacts) {
		return launchInvalid("channel input differs from its sealed job")
	}
	return nil
}

func ValidateChannelExecution(execution ChannelExecution) error {
	e, j := execution, execution.Job
	if err := ValidateChannelJob(j); err != nil {
		return err
	}
	s, b := e.Handoff.Spec, e.Binding
	canonical, digest, err := launchCanonical(s)
	_, recordDigest, recordErr := launchCanonical(b.Record)
	argv := []string{"laneboss", "internal", "channel", "--binding", "/runtime/laneboss-worker.json", "--lease", string(j.Lease.ID)}
	if err != nil || recordErr != nil || s.Kind != "worker" || s.Runner != nil || s.Worker == nil || s.Worker.Kind != "channel" ||
		s.Worker.Schema != "laneboss.worker-plan.v2" || !launchID(s.ID) || !launchID(s.LaunchID) || !launchID(s.UIDLeaseID) || s.PlanID != "" || s.Capture != nil ||
		s.Worker.Executable != j.Runtime.Executable || !slices.Equal(s.Worker.Argv, argv) || s.Worker.Input != j.Lease.Input ||
		s.Worker.GrantSetID != j.Lease.GrantSetID ||
		s.RuntimeManifest != j.Runtime.Manifest || s.Target != j.Lease.Target || s.Grants.ID != j.Lease.GrantSetID ||
		e.Handoff.OperationID != j.Lease.OperationID || !bindingConfigName.MatchString(e.Handoff.Config) ||
		e.Handoff.Cause.Kind != InternalHelperRegister || e.Handoff.Cause.Config != e.Handoff.Config || e.Handoff.Cause.Target != j.Lease.Target ||
		e.Handoff.Cause.CauseOperationID != j.Lease.OperationID || !launchBlob(e.Handoff.Original, "launch_spec") ||
		e.Handoff.SpecSHA256 != digest || e.Handoff.Original.SHA256 != digest || e.Handoff.Original.Bytes != int64(len(canonical)) ||
		b.Record.Kind != "worker" || b.Record.Actor.Kind != "worker" || !launchID(b.Record.Actor.ID) || b.Record.Config != e.Handoff.Config ||
		b.Record.ID != s.LaunchID || b.Record.Target != s.Target || b.Record.GrantsSHA256 != s.Grants.SHA256 || b.Record.PolicyGeneration != s.PolicyGeneration ||
		b.Record.UIDLeaseID != s.UIDLeaseID || b.Record.GrantSetID != j.Lease.GrantSetID || b.Prepared.Target != s.Target ||
		!launchID(b.Prepared.ID) || !launchID(b.Prepared.GateID) || b.Prepared.ContainmentID != b.Record.ContainmentID ||
		b.Prepared.ProcessGeneration == "" || b.Prepared.ProcessGeneration != b.Record.ProcessGeneration || b.Record.Revoked ||
		b.Prepared.EndpointGeneration != s.EndpointGeneration || b.Record.EndpointGeneration != s.EndpointGeneration ||
		b.Prepared.SpecSHA256 != e.Handoff.SpecSHA256 || b.Identity.LaunchID != s.LaunchID || b.Identity.CommittedSeq == 0 || !launchID(b.Identity.EventID) || b.Identity.RecordSHA256 != recordDigest {
		return launchInvalid("channel execution differs from its committed fixed worker")
	}
	return nil
}

func ValidateChannelSendEvidence(job ChannelJob, evidence ChannelSendEvidence) error {
	if err := ValidateChannelJob(job); err != nil {
		return err
	}
	e, j := evidence, job
	if e.Schema != "laneboss.channel-result.v2" || e.LeaseID != j.Lease.ID || e.OperationID != j.Lease.OperationID || e.EffectID != j.Lease.EffectID ||
		e.MailID != j.MailID || e.ChannelID != j.ChannelID || e.ChannelGeneration != j.ChannelGeneration || e.DestinationID != j.DestinationID ||
		e.ProviderIdempotencyKey != j.ProviderIdempotencyKey || e.PayloadSHA256 != j.Payload.SHA256 {
		return launchInvalid("channel result differs from its original job")
	}
	switch e.Outcome {
	case "confirmed":
		if e.Error != nil || e.RemoteReceiptID == "" || e.Response == nil || !launchBlob(*e.Response, "channel_receipt") ||
			e.ReadBack == nil || e.ReadBack.RemoteReceiptID != e.RemoteReceiptID || e.ReadBack.PayloadSHA256 != j.Payload.SHA256 ||
			!launchBlob(e.ReadBack.Response, "channel_receipt") || e.ReadBack.ObservedAt == "" {
			return launchInvalid("channel confirmation lacks measured acknowledgement and read-back")
		}
	case "uncertain", "failed", "unsupported":
		if e.Error == nil || e.Error.Owner == "" || e.Error.Code == "" || e.ReadBack != nil {
			return launchInvalid("channel failure lacks its actual owning result")
		}
	default:
		return launchInvalid("unknown channel delivery outcome")
	}
	return nil
}

func ValidateChannelDelivery(job ChannelJob, delivery Delivery) error {
	if delivery.Evidence == nil {
		return launchInvalid("channel delivery lacks measured worker evidence")
	}
	if err := ValidateChannelSendEvidence(job, *delivery.Evidence); err != nil {
		return err
	}
	if !launchID(delivery.ID) || delivery.MailID != job.MailID || delivery.ChannelID != job.ChannelID ||
		delivery.Status != "delivered" || delivery.Evidence.Outcome != "confirmed" || delivery.RemoteReceiptID != delivery.Evidence.RemoteReceiptID || delivery.Error != nil {
		return launchInvalid("channel delivery is not a measured confirmed result")
	}
	return nil
}
