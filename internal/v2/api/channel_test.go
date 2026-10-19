package api

import "testing"

func channelFixture(t *testing.T) (ChannelExecution, ChannelSendEvidence) {
	t.Helper()
	p := launchFixture(t)
	runtime := &ChannelRuntime{Executable: Executable{ID: "channel-worker", Version: "fixture-v1", SHA256: launchFixtureBlob("channel-binary", "manifest").SHA256},
		Manifest: p.Inputs.Sources.Runtime.Manifest, Reconcile: "provider_key"}
	job := ChannelJob{Runtime: runtime, Payload: launchFixtureBlob("payload", "channel_payload"), ChannelID: "channel-one", ChannelGeneration: 1,
		DestinationID: "destination-one", MailID: "mail-one", Content: launchFixtureBlob("message", "message"), Artifacts: []BlobRef{}, ProviderIdempotencyKey: "provider-key",
		Lease: WorkerLease{ID: "channel-lease", Kind: "channel", Target: p.Reservation.Target, OperationID: p.Reservation.OperationID, EffectID: "channel-effect",
			Input: launchFixtureBlob("channel-input", "channel_input"), RuntimeManifest: runtime.Manifest, GrantSetID: p.Inputs.Grants.ID, Generation: 1, ExpiresAt: "2100-01-01T00:00:00Z"}}
	binding := launchFixtureBinding(t, p)
	handoff := binding.Recovery.Handoff
	handoff.Spec.Kind, handoff.Spec.PlanID, handoff.Spec.Runner, handoff.Spec.Capture = "worker", "", nil, nil
	handoff.Spec.Worker = &WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "channel", Executable: runtime.Executable,
		Argv:  []string{"laneboss", "internal", "channel", "--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Lease.ID)},
		Input: job.Lease.Input, GrantSetID: job.Lease.GrantSetID, Budget: p.Budget}
	encoded, digest := launchFixtureHash(t, handoff.Spec)
	handoff.SpecSHA256, handoff.Original.SHA256, handoff.Original.Bytes = digest, digest, int64(len(encoded))
	binding.Recovery = nil
	binding.Record.Kind, binding.Record.Actor.Kind, binding.Record.Actor.Level, binding.Record.Actor.Role = "worker", "worker", 0, ""
	binding.Prepared.SpecSHA256 = digest
	_, binding.Identity.RecordSHA256 = launchFixtureHash(t, binding.Record)
	response := launchFixtureBlob("provider-response", "channel_receipt")
	evidence := ChannelSendEvidence{Schema: "laneboss.channel-result.v2", LeaseID: job.Lease.ID, OperationID: job.Lease.OperationID, EffectID: job.Lease.EffectID,
		MailID: job.MailID, ChannelID: job.ChannelID, ChannelGeneration: job.ChannelGeneration, DestinationID: job.DestinationID,
		ProviderIdempotencyKey: job.ProviderIdempotencyKey, PayloadSHA256: job.Payload.SHA256, Outcome: "confirmed", RemoteReceiptID: "remote-one", Response: &response,
		ReadBack: &ChannelReadBack{RemoteReceiptID: "remote-one", PayloadSHA256: job.Payload.SHA256, Response: launchFixtureBlob("read-back", "channel_receipt"), ObservedAt: "2026-01-01T00:00:00Z"}}
	return ChannelExecution{Job: job, Handoff: handoff, Binding: binding}, evidence
}

func TestChannelWorkerHandoff(t *testing.T) {
	execution, _ := channelFixture(t)
	if err := ValidateChannelExecution(execution); err != nil {
		t.Fatal(err)
	}
	input := ChannelSendInput{Schema: "laneboss.channel-input.v2", LeaseID: execution.Job.Lease.ID, MailID: execution.Job.MailID, ChannelID: execution.Job.ChannelID,
		ChannelGeneration: execution.Job.ChannelGeneration, DestinationID: execution.Job.DestinationID, ProviderIdempotencyKey: execution.Job.ProviderIdempotencyKey,
		Payload: execution.Job.Payload, Content: execution.Job.Content, Artifacts: execution.Job.Artifacts}
	if err := ValidateChannelInput(execution.Job, input); err != nil {
		t.Fatal(err)
	}
	input.DestinationID = "foreign-destination"
	requireLaunchInvalid(t, ValidateChannelInput(execution.Job, input), "channel sealed input was changed")
	for _, fault := range []string{"runtime", "argv", "input", "binding"} {
		t.Run(fault, func(t *testing.T) {
			e, _ := channelFixture(t)
			switch fault {
			case "runtime":
				e.Handoff.Spec.Worker.Executable.ID = "foreign-worker"
			case "argv":
				e.Handoff.Spec.Worker.Argv = []string{"caller-command"}
			case "input":
				e.Handoff.Spec.Worker.Input.ID = "foreign-input"
			case "binding":
				e.Binding.Record.Kind = "agent"
			}
			// Keep both byte hashes valid so the nominated input pin decides.
			encoded, digest := launchFixtureHash(t, e.Handoff.Spec)
			e.Handoff.SpecSHA256, e.Handoff.Original.SHA256, e.Handoff.Original.Bytes = digest, digest, int64(len(encoded))
			e.Binding.Prepared.SpecSHA256 = digest
			_, e.Binding.Identity.RecordSHA256 = launchFixtureHash(t, e.Binding.Record)
			requireLaunchInvalid(t, ValidateChannelExecution(e), "channel fixed worker handoff was bypassed")
		})
	}
}

func TestChannelMeasuredResult(t *testing.T) {
	e, result := channelFixture(t)
	if err := ValidateChannelSendEvidence(e.Job, result); err != nil {
		t.Fatal(err)
	}
	delivery := Delivery{ID: "delivery-one", MailID: e.Job.MailID, ChannelID: e.Job.ChannelID, Status: "delivered", RemoteReceiptID: result.RemoteReceiptID, Evidence: &result}
	if err := ValidateChannelDelivery(e.Job, delivery); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"readback", "payload", "operation", "exit_only", "uncertain"} {
		t.Run(fault, func(t *testing.T) {
			execution, evidence := channelFixture(t)
			switch fault {
			case "readback":
				evidence.ReadBack = nil
			case "payload":
				evidence.ReadBack.PayloadSHA256 = launchFixtureBlob("other-payload", "channel_payload").SHA256
			case "operation":
				evidence.OperationID = "foreign-operation"
			case "exit_only":
				evidence.Response, evidence.ReadBack, evidence.RemoteReceiptID = nil, nil, ""
			case "uncertain":
				evidence.Outcome = "uncertain"
				evidence.ReadBack = nil
				evidence.Error = NotImplemented("lb-v2-messaging", "read-back")
			}
			if fault == "uncertain" {
				if err := ValidateChannelSendEvidence(execution.Job, evidence); err != nil {
					t.Fatal(err)
				}
				d := Delivery{ID: "delivery-one", MailID: execution.Job.MailID, ChannelID: execution.Job.ChannelID, Status: "delivered", Evidence: &evidence}
				requireLaunchInvalid(t, ValidateChannelDelivery(execution.Job, d), "uncertain send became delivered")
			} else {
				requireLaunchInvalid(t, ValidateChannelSendEvidence(execution.Job, evidence), "unmeasured channel confirmation accepted")
			}
		})
	}
}
