//go:build linux

package store_test

import (
	"context"
	"os"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/assembly/credn"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type inventoryLauncher struct{ api.Launcher }

func workerCredentialRequest(t *testing.T, kind string) (*fx.Fixture, api.CredentialProjectionRequest) {
	t.Helper()
	f := fx.Ready(t, true)
	ctx := context.Background()
	cause := f.Intent(t, api.InternalOrgBootstrap)
	cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
	retain := func(class string, value any) api.BlobRef {
		raw, err := api.CanonicalJSON(fx.JSON(t, value))
		if err != nil {
			t.Fatal(err)
		}
		ref, err := f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: class,
			Bytes: raw, SHA256: fx.Digest(raw), Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, LifeID: f.Reservation.Target.LifeID, Audience: "owner", Generation: 1}}})
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	grant := api.SecretGrant{ID: fx.ID(t), Name: "worker-key", SourceHandle: fx.ID(t), Version: "one", Delivery: "env", Target: "WORKER_ACCESS", ExpiresAt: fx.Expiry()}
	grants := f.Plan.Inputs.Grants
	grants.ID, grants.Generation, grants.SHA256 = fx.ID(t), 1, ""
	grants.Data, grants.Profiles, grants.Secrets = []api.DataGrant{}, []api.ProfileGrant{}, []api.SecretGrant{grant}
	var err error
	grants.SHA256, err = manifest.HashValue(grants)
	if err != nil {
		t.Fatal(err)
	}
	executable := api.Executable{ID: fx.ID(t), SHA256: fx.Digest([]byte("component-worker")), Version: "component"}
	runtime := retain("manifest", api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: executable, Bootstrap: executable, Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}})
	lease := api.WorkerLease{ID: fx.ID(t), Kind: kind, Target: f.Reservation.Target, OperationID: cause.CauseOperationID, EffectID: cause.EffectID,
		RuntimeManifest: runtime, GrantSetID: grants.ID, Generation: 1, ExpiresAt: fx.Expiry(), ConsumedBy: fx.ID(t)}
	channels := []api.EnrolledChannel{}
	if kind == "usage" {
		lease.Input = retain("worker_input", api.UsageCredentialInput{Schema: "laneboss.usage-input.v1", Request: api.UsageWindowRequest{Target: lease.Target,
			OperationID: lease.OperationID, Executable: executable, RuntimeManifest: runtime}, VendorProfile: "component", ProfileGeneration: 1, Source: grant})
	} else {
		channel := api.EnrolledChannel{ID: fx.ID(t), Config: f.Deps.Config, Generation: 1, ExpiresAt: fx.Expiry(),
			Runtime:      &api.ChannelRuntime{Executable: executable, Manifest: runtime, Reconcile: "idempotency_key"},
			Source:       api.SourceRef{ID: fx.ID(t), Path: "channel.toml", SHA256: fx.Digest([]byte("component-channel")), Generation: 1},
			Destinations: []api.ChannelDestination{{ID: fx.ID(t), Transport: "component", EndpointID: fx.ID(t), CredentialHandle: grant.SourceHandle, DeliverySemantics: "idempotency_key"}}}
		channels = append(channels, channel)
		payload := retain("manifest", api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}})
		lease.Input = retain("channel_input", api.ChannelSendInput{Schema: "laneboss.channel-input.v2", LeaseID: lease.ID, MailID: fx.ID(t), ChannelID: channel.ID, ChannelGeneration: channel.Generation,
			DestinationID: channel.Destinations[0].ID, ProviderIdempotencyKey: fx.ID(t), Payload: payload, Content: f.Lane.Task, Artifacts: []api.BlobRef{}})
	}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: kind, Executable: executable, Argv: []string{string(executable.ID), "fixed-job"}, Input: lease.Input, GrantSetID: grants.ID, Budget: f.Plan.Budget}
	jobCause := cause
	jobCause.Kind = api.InternalLifecycleEffect
	job := api.Effect{ID: lease.EffectID, OperationID: lease.OperationID, Context: &jobCause, Worker: &plan}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Grants: []api.GrantSet{grants}, WorkerLeases: []api.WorkerLease{lease}, Channels: channels}, Effects: []api.Effect{job}}); err != nil {
		t.Fatal("cannot retain actual credential job", err)
	}
	jobClaim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: job.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	helper := api.HelperLease{ID: fx.ID(t), UID: uint32(os.Geteuid()) + 1000, GID: uint32(os.Getegid()) + 1000, ContainmentID: fx.ID(t), EndpointGeneration: 1}
	home := f.Plan.Data.Home
	home.RootID, home.Home.ID = fx.ID(t), fx.ID(t)
	spec := api.LaunchSpec{Kind: "worker", ID: fx.ID(t), LaunchID: lease.ConsumedBy, Target: lease.Target, Worker: &plan, RuntimeManifest: runtime, UIDLeaseID: helper.ID,
		Workspace: f.Plan.Data.Workspace, Materialization: f.Plan.Data.Materialization, Grants: grants, Budget: plan.Budget, Backend: "linux-bwrap-landlock", EndpointGeneration: 1, PolicyGeneration: grants.PolicyGeneration,
		Injection: api.Injection{Target: lease.Target, SlotIDs: []api.ID{fx.ID(t)}, TaskSecretNames: []string{grant.Name}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{grant.ID}, SourceVersions: []string{grant.Version}, Outcome: "prepared"}}
	spec.Materialization.GrantSetID = grants.ID
	original := retain("launch_spec", spec)
	register := cause
	register.Kind = api.InternalHelperRegister
	handoff := api.PreparedSpecHandoff{Config: f.Deps.Config, Cause: register, OperationID: lease.OperationID, RequestID: cause.CauseRequestID, Original: original, Spec: spec, SpecSHA256: original.SHA256}
	if err := f.State.RegisterCredentialWorker(api.WithEffectLease(ctx, jobClaim), f.Execution, handoff); err != nil {
		t.Fatal("cannot register actual sealed worker", err)
	}
	prepare := cause
	prepare.ID, prepare.EffectID, prepare.Kind = fx.ID(t), fx.ID(t), api.InternalHelperPrepare
	prepareRequest := api.HelperLaunchRequest{Cause: prepare, LeaseID: helper.ID, PreparedSpecID: spec.ID, SpecSHA256: handoff.SpecSHA256}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &prepare, Effects: []api.Effect{{ID: prepare.EffectID, OperationID: lease.OperationID, Context: &prepare, HelperPrepare: &prepareRequest}}}); err != nil {
		t.Fatal(err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: prepare.EffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal("cannot claim worker prepare", err)
	}
	request := api.CredentialProjectionRequest{Cause: prepare, Claim: claim, Handoff: handoff, Lease: helper, Home: home, Worker: &lease,
		Prepared:          api.PreparedLaunch{ID: fx.ID(t), GateID: fx.ID(t), Target: lease.Target, SpecSHA256: handoff.SpecSHA256, ContainmentID: helper.ContainmentID, ProcessGeneration: "component-worker", EndpointGeneration: 1},
		WorkerCredentials: []api.WorkerCredential{{Name: grant.Name, SourceHandle: grant.SourceHandle, Version: grant.Version, Delivery: grant.Delivery, Target: grant.Target}}}
	return f, request
}

func TestCredentialWorkerInventory(t *testing.T) {
	for _, kind := range []string{"usage", "channel"} {
		t.Run(kind, func(t *testing.T) {
			f, request := workerCredentialRequest(t, kind)
			n := installCredentialRequest(t, f, request)
			source := credn.New()
			if err := source.BindNative(n); err != nil {
				t.Fatal(err)
			}
			if err := f.State.Close(); err != nil {
				t.Fatal(err)
			}
			f.Deps.CredentialProjection = source
			var err error
			f.State, err = store.New(f.Deps)
			if err != nil {
				t.Fatal(err)
			}
			worker, err := dataworker.New(dataworker.Dependencies{Config: f.Deps.Config, Store: f.State, Clock: f.Deps.Clock, Helper: &admin.Service{}, Launcher: &inventoryLauncher{}})
			if err != nil {
				t.Fatal(err)
			}
			if err := source.BindWorkers(worker); err != nil {
				t.Fatal(err)
			}
			actual, err := worker.CredentialWorkerSelection(context.Background(), f.Execution, request.Handoff)
			if err != nil || actual.Lease != *request.Worker || !reflect.DeepEqual(actual.Credentials, request.WorkerCredentials) {
				t.Fatal("protected worker inventory differs from sealed job", err)
			}
			reserved, err := f.State.ReserveCredentialProjection(context.Background(), f.Execution, request)
			if err != nil {
				t.Fatal("worker projection did not reach reservation", err)
			}
			if reserved.State != "reserved" {
				t.Fatal("worker reservation state differs")
			}
			bad := request
			bad.WorkerCredentials = append([]api.WorkerCredential{}, request.WorkerCredentials...)
			bad.WorkerCredentials[0].Target = "FOREIGN_ACCESS"
			if _, err := f.State.ReserveCredentialProjection(context.Background(), f.Execution, bad); err == nil {
				t.Fatal("caller-selected worker credential target was accepted")
			}
			held := credentialHeld(t, n, reserved)
			committed, err := f.State.CommitCredentialProjection(context.Background(), f.Execution, held)
			if err != nil || committed.State != "held" {
				t.Fatal("protected worker did not reach actual held state", err)
			}
			if err := f.State.CheckCredentialProjection(context.Background(), f.Deps.Config, request.Prepared.ID, committed.Generation); err != nil {
				t.Fatal("live protected worker holding was refused", err)
			}
			if verified, err := f.State.Verify(context.Background(), api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
				t.Fatal("worker credential state did not verify", err)
			}
		})
	}
}
