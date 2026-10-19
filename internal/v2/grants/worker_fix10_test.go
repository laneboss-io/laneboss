package grants_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type launchJobs struct {
	*launchGraph
	leases   map[api.ID]api.WorkerLease
	effects  map[api.ID]api.EffectRecord
	channels map[api.ID]api.EnrolledChannel
}

func (j *launchJobs) WorkerLease(_ context.Context, scope api.Scope, id api.ID) (api.WorkerLease, error) {
	j.check(scope)
	value, ok := j.leases[id]
	if !ok {
		return api.WorkerLease{}, &api.Error{Code: api.CodeNotFound}
	}
	return launchCopy(j.t, value), nil
}

func (j *launchJobs) Effect(_ context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	j.check(scope)
	value, ok := j.effects[id]
	if !ok {
		return api.EffectRecord{}, &api.Error{Code: api.CodeNotFound}
	}
	return launchCopy(j.t, value), nil
}

func (j *launchJobs) Channel(_ context.Context, scope api.Scope, id api.ID) (api.EnrolledChannel, error) {
	j.check(scope)
	value, ok := j.channels[id]
	if !ok {
		return api.EnrolledChannel{}, &api.Error{Code: api.CodeNotFound}
	}
	return launchCopy(j.t, value), nil
}

func launchJobFixture(t *testing.T) *launchJobs {
	t.Helper()
	g := newLaunchGraph(t)
	j := &launchJobs{launchGraph: g, leases: map[api.ID]api.WorkerLease{}, effects: map[api.ID]api.EffectRecord{}, channels: map[api.ID]api.EnrolledChannel{}}
	var err error
	g.worker, err = dataworker.New(dataworker.Dependencies{Config: "case-grants", Store: j, Helper: g.helper, Launcher: &launchProbe{}, Clock: launchClock{}})
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func (j *launchJobs) channelJob() api.ChannelJob {
	j.t.Helper()
	lease := api.WorkerLease{ID: "channel-lease", Kind: "channel", Target: api.LifeRef{LifeID: "child-one", Run: 1}, OperationID: "channel-operation",
		EffectID: "channel-effect", RuntimeManifest: j.runtime, GrantSetID: "reserved-grants", Generation: 1, ExpiresAt: "2030-01-01T04:00:00Z"}
	job := api.ChannelJob{Lease: lease, ChannelID: "channel-one", ChannelGeneration: 1, DestinationID: "destination-one", MailID: "mail-one",
		Content: j.object("message-one", "message", []byte("hello"), lease.OperationID), Artifacts: []api.BlobRef{}, ProviderIdempotencyKey: "provider-key",
		Payload: j.privateChannelObject("payload-one", "channel_payload", []byte("serialized provider payload"), lease),
		Runtime: &api.ChannelRuntime{Executable: api.Executable{ID: "laneboss-artifact", SHA256: j.metadata["artifact-bytes"].Ref.SHA256, Version: "fixture-version"},
			Manifest: j.runtime, Reconcile: "provider_key"}}
	input := api.ChannelSendInput{Schema: "laneboss.channel-input.v2", LeaseID: lease.ID, MailID: job.MailID, ChannelID: job.ChannelID,
		ChannelGeneration: job.ChannelGeneration, DestinationID: job.DestinationID, ProviderIdempotencyKey: job.ProviderIdempotencyKey,
		Payload: job.Payload, Content: job.Content, Artifacts: job.Artifacts}
	job.Lease.Input = j.privateChannelInput("channel-input", input, lease)
	if err := api.ValidateChannelJob(job); err != nil {
		j.t.Fatal(err)
	}
	if err := api.ValidateChannelInput(job, input); err != nil {
		j.t.Fatal(err)
	}
	j.channels[job.ChannelID] = api.EnrolledChannel{ID: job.ChannelID, Config: j.scope.Config, Generation: job.ChannelGeneration,
		Runtime: job.Runtime, ExpiresAt: lease.ExpiresAt, Destinations: []api.ChannelDestination{{ID: job.DestinationID,
			Transport: "fixture", EndpointID: "channel-endpoint", CredentialHandle: "credential-handle", DeliverySemantics: "fixture"}}}
	j.saveChannel(job)
	return job
}

// Fixed channel preflight consumes sealed private job inputs. Generic source
// objects remain owner-visible; the model writer derives the job's exact
// operation/life provenance from its retained lease.
func (j *launchJobs) privateChannelObject(id api.ID, class string, raw []byte, lease api.WorkerLease) api.BlobRef {
	ref := j.object(id, class, raw, lease.OperationID)
	metadata := j.metadata[ref.ID]
	metadata.ACL.Audience, metadata.ACL.LifeID = "private", lease.Target.LifeID
	j.metadata[ref.ID] = metadata
	return ref
}

func (j *launchJobs) privateChannelInput(id api.ID, input api.ChannelSendInput, lease api.WorkerLease) api.BlobRef {
	raw, err := json.Marshal(input)
	if err != nil {
		j.t.Fatal(err)
	}
	return j.privateChannelObject(id, "channel_input", raw, lease)
}

func (j *launchJobs) saveChannel(job api.ChannelJob) {
	j.leases[job.Lease.ID] = launchCopy(j.t, job.Lease)
	j.effects[job.Lease.EffectID] = api.EffectRecord{Effect: api.Effect{ID: job.Lease.EffectID, OperationID: job.Lease.OperationID, Channel: &job},
		Generation: 1, State: "claimed", ClaimID: "channel-claim", ClaimantID: j.scope.Actor.ID, ClaimExpiresAt: job.Lease.ExpiresAt}
}

func (j *launchJobs) channelExecution() api.ChannelExecution {
	j.t.Helper()
	r := j.retained("resume")
	binding := j.bindings[r.Reservation.PreviousLaunchID]
	handoff := binding.Recovery.Handoff
	job := j.channelJob()
	// The worker has distinct spec, helper, gate and launch identities. A prior
	// agent binding is only a DTO template; it is never relabelled in the store.
	binding.Record.ID, binding.Record.UIDLeaseID, binding.Record.ContainmentID = "channel-launch", "channel-helper-lease", "channel-containment"
	binding.Record.Actor.ID, binding.Record.HostUID, binding.Record.ProcessGeneration = "channel-principal", 41002, "channel-generation"
	binding.Prepared.ID, binding.Prepared.GateID, binding.Prepared.ContainmentID = "channel-prepared", "channel-gate", binding.Record.ContainmentID
	binding.Prepared.ProcessGeneration = binding.Record.ProcessGeneration
	binding.Identity.LaunchID, binding.Identity.EventID, binding.Identity.CommittedSeq = binding.Record.ID, "channel-identity-event", 11
	job.Lease.ConsumedBy = binding.Record.ID
	j.saveChannel(job)
	handoff.OperationID, handoff.Cause.CauseOperationID = job.Lease.OperationID, job.Lease.OperationID
	handoff.Spec.ID, handoff.Spec.LaunchID, handoff.Spec.UIDLeaseID = "channel-worker-spec", binding.Record.ID, binding.Record.UIDLeaseID
	handoff.Spec.Kind, handoff.Spec.PlanID, handoff.Spec.Runner, handoff.Spec.Capture = "worker", "", nil, nil
	handoff.Spec.Worker = &api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "channel", Executable: job.Runtime.Executable,
		Argv:  []string{"laneboss", "internal", "channel", "--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Lease.ID)},
		Input: job.Lease.Input, GrantSetID: job.Lease.GrantSetID, Budget: j.selection.Budget}
	ref := j.canonicalSpec(handoff.Spec, job.Lease.OperationID)
	handoff.Original, handoff.SpecSHA256 = ref, ref.SHA256
	binding.Recovery = nil
	binding.Record.Kind, binding.Record.Actor.Kind, binding.Record.Actor.Level, binding.Record.Actor.Role = "worker", "worker", 0, ""
	binding.Prepared.SpecSHA256 = ref.SHA256
	var err error
	binding.Identity.RecordSHA256, err = manifest.HashValue(binding.Record)
	if err != nil {
		j.t.Fatal(err)
	}
	j.bindings[binding.Record.ID] = binding
	execution := api.ChannelExecution{Job: job, Handoff: handoff, Binding: binding}
	if err := api.ValidateChannelExecution(execution); err != nil {
		j.t.Fatal("channel fixture rejected by production validator", err)
	}
	return execution
}

func (j *launchJobs) canonicalSpec(spec api.LaunchSpec, operation api.ID) api.BlobRef {
	j.t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		j.t.Fatal(err)
	}
	canonical, err := api.CanonicalJSON(raw)
	if err != nil {
		j.t.Fatal(err)
	}
	return j.object("channel-spec", "launch_spec", canonical, operation)
}

func TestChannelJobPreflight(t *testing.T) {
	for _, fault := range []string{"valid-closed", "lease", "effect", "claim", "runtime", "destination", "input", "origin", "audience", "payload"} {
		t.Run(fault, func(t *testing.T) {
			j := launchJobFixture(t)
			job := j.channelJob()
			code := api.CodeForbidden
			switch fault {
			case "valid-closed":
				code = api.CodeNotImplemented
			case "lease":
				lease := j.leases[job.Lease.ID]
				lease.Generation++
				j.leases[lease.ID] = lease
			case "effect":
				effect := j.effects[job.Lease.EffectID]
				foreign := launchCopy(t, job)
				foreign.MailID = "foreign-mail"
				effect.Effect.Channel = &foreign
				j.effects[job.Lease.EffectID] = effect
			case "claim":
				effect := j.effects[job.Lease.EffectID]
				effect.ClaimantID = "foreign-executor"
				j.effects[job.Lease.EffectID], code = effect, api.CodeConflict
			case "runtime":
				channel := launchCopy(t, j.channels[job.ChannelID])
				channel.Runtime.Executable.ID = "foreign-worker"
				j.channels[job.ChannelID] = channel
			case "destination":
				channel := j.channels[job.ChannelID]
				channel.Destinations = nil
				j.channels[job.ChannelID] = channel
			case "input":
				var input api.ChannelSendInput
				if err := api.DecodeObject(j.blobs[job.Lease.Input.ID], &input); err != nil {
					t.Fatal(err)
				}
				input.DestinationID = "foreign-destination"
				job.Lease.Input = j.privateChannelInput(job.Lease.Input.ID, input, job.Lease)
				j.saveChannel(job)
				code = api.CodeInvalid
			case "origin":
				meta := j.metadata[job.Lease.Input.ID]
				meta.Origin = "upload"
				j.metadata[meta.Ref.ID], code = meta, api.CodeIntegrity
			case "audience":
				meta := j.metadata[job.Lease.Input.ID]
				meta.ACL.Audience = "owner"
				j.metadata[meta.Ref.ID], code = meta, api.CodeIntegrity
			case "payload":
				j.blobs[job.Payload.ID], code = []byte("changed provider payload"), api.CodeIntegrity
			}
			result, err := j.worker.PrepareChannel(context.Background(), j.scope, job)
			launchError(t, err, code)
			if result.Handoff.Spec.ID != "" || result.Binding.Record.ID != "" {
				t.Fatal("channel preflight manufactured a prepared worker")
			}
		})
	}
}

func TestChannelExecutionPreflight(t *testing.T) {
	for _, mode := range []string{"send", "readback"} {
		for _, fault := range []string{"valid-closed", "argv", "binding"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				j := launchJobFixture(t)
				execution := j.channelExecution()
				code := api.CodeNotImplemented
				if fault == "argv" {
					execution.Handoff.Spec.Worker.Argv = []string{"caller-command"}
					ref := j.canonicalSpec(execution.Handoff.Spec, execution.Job.Lease.OperationID)
					execution.Handoff.Original, execution.Handoff.SpecSHA256 = ref, ref.SHA256
					execution.Binding.Prepared.SpecSHA256, code = ref.SHA256, api.CodeInvalid
					j.bindings[execution.Binding.Record.ID] = execution.Binding
				} else if fault == "binding" {
					stored := j.bindings[execution.Binding.Record.ID]
					stored.Identity.EventID = "foreign-event"
					j.bindings[stored.Record.ID], code = stored, api.CodeIntegrity
				}
				var result api.ChannelSendEvidence
				var err error
				if mode == "send" {
					result, err = j.worker.SendChannel(context.Background(), j.scope, execution)
				} else {
					result, err = j.worker.ReadBackChannel(context.Background(), j.scope, execution)
				}
				launchError(t, err, code)
				if result.Outcome != "" || result.Response != nil || result.ReadBack != nil {
					t.Fatal("channel preflight manufactured provider evidence")
				}
			})
		}
	}
}

func TestReviewJobPreflight(t *testing.T) {
	// Retained plan/lease checks now run after the native result handoff.
	// TestReviewMeasuredResult/{plan,lease} exercises those checks with an
	// actual verifier result; this fixture intentionally has no coordinator.
	for _, fault := range []string{"valid-closed", "run", "end", "diff", "check"} {
		t.Run(fault, func(t *testing.T) {
			j := launchJobFixture(t)
			channel := j.channelJob()
			lease := channel.Lease
			lease.Kind = "test"
			// No verifier input schema is invented by this preflight fixture.
			// The opaque retained bytes cannot produce an evidence result.
			lease.Input = j.object("review-job-input", "manifest", []byte("opaque retained verifier input"), lease.OperationID)
			j.leases[lease.ID] = lease
			j.effects[lease.EffectID] = api.EffectRecord{Effect: api.Effect{ID: lease.EffectID, OperationID: lease.OperationID,
				Worker: &api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: lease.Kind, Input: lease.Input, GrantSetID: lease.GrantSetID,
					Executable: channel.Runtime.Executable, Budget: j.selection.Budget}},
				Generation: 1, State: "claimed", ClaimID: "review-claim", ClaimantID: j.scope.Actor.ID, ClaimExpiresAt: lease.ExpiresAt}
			request := api.ReviewVerifyRequest{Lease: lease, ExpectedGeneration: 2, EndEventID: "ended-one", EndSeq: 10,
				Request: api.ReviewRequest{Target: lease.Target, Diff: j.object("diff", "diff", []byte("measured diff candidate"), lease.OperationID),
					Checks:          []api.BlobRef{j.object("check", "check", []byte("candidate check"), lease.OperationID)},
					RecordInventory: j.encoded("inventory", "manifest", map[string]bool{"candidate": true}, lease.OperationID)}}
			code := api.CodeInvalid
			switch fault {
			case "valid-closed":
				code = api.CodePrerequisite
			case "run":
				request.Request.Target.Run++
			case "end":
				request.EndEventID = ""
			case "diff":
				request.Request.Diff.Class = "artifact"
			case "check":
				request.Request.Checks[0].Class = "artifact"
			}
			result, err := j.worker.VerifyReview(context.Background(), j.scope, request)
			launchError(t, err, code)
			if result.Coverage != "" || result.Subject.LaunchID != "" || result.VerifierLeaseID != "" {
				t.Fatal("review candidates manufactured measured coverage")
			}
		})
	}
}

func TestFixedWorkerOwnerFailure(t *testing.T) {
	j := launchJobFixture(t)
	job := j.channelJob()
	refusal := api.NotImplemented("lb-v2-store", "fixed worker lease lookup")
	// Inject the store owner's typed failure. No helper, launcher, credential
	// broker or provider success is installed in this propagation test.
	worker, err := dataworker.New(dataworker.Dependencies{Config: "case-grants", Store: &unportedJobStore{launchJobs: j, err: refusal}, Helper: j.helper,
		Launcher: &launchProbe{}, Clock: launchClock{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = worker.PrepareChannel(context.Background(), j.scope, job)
	if !errors.Is(err, refusal) {
		t.Fatal("fixed worker replaced its store owner refusal", err)
	}
}

type unportedJobStore struct {
	*launchJobs
	err error
}

func (s *unportedJobStore) WorkerLease(context.Context, api.Scope, api.ID) (api.WorkerLease, error) {
	return api.WorkerLease{}, s.err
}
