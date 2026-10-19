//go:build linux

package store_test

import (
	"context"
	"os"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func usageReady(t *testing.T) (*fx.Fixture, api.UsageCredentialInput) {
	t.Helper()
	f := fx.New(t)
	f.Start.Driver, f.Ceiling.Profiles[0].Driver = api.DriverClaudock, api.DriverClaudock
	f.Ceiling.SHA256 = ""
	var err error
	f.Ceiling.SHA256, err = manifest.HashValue(f.Ceiling)
	if err != nil {
		t.Fatal(err)
	}
	f.Replace(t, "grants", f.Ceiling.ID, f.Ceiling.Generation, f.Ceiling)
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	selected := f.Plan.Inputs.Grants.Profiles[0]
	return f, api.UsageCredentialInput{Schema: "laneboss.usage-input.v1", ProfileGeneration: 1, VendorProfile: string(selected.ProfileID),
		Source: api.SecretGrant{ID: fx.ID(t), Name: "usage-login", SourceHandle: fx.ID(t), Version: "v1", Delivery: "file", Target: "login.json", ExpiresAt: fx.Expiry()},
		Request: api.UsageWindowRequest{Target: f.Reservation.Target, LaunchID: f.Reservation.LaunchID, OperationID: f.Reservation.OperationID,
			ProfileGrantID: selected.ID, ProfileID: selected.ProfileID, Provider: selected.Provider, Executable: f.Plan.Runner.Executable,
			RuntimeManifest: f.Plan.Inputs.Sources.Runtime.Manifest, AdapterVersion: f.Plan.Runner.AdapterVersion}}
}

func TestUsageReplay(t *testing.T) {
	f, input := usageReady(t)
	first, err := f.State.PrepareUsageJob(context.Background(), f.Execution, input)
	if err != nil {
		t.Fatal("usage preparation failed", err)
	}
	again, err := f.State.PrepareUsageJob(context.Background(), f.Execution, input)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("usage retry replaced its durable job", err)
	}
}

func TestUsageNativeStage(t *testing.T) {
	f, input := usageReady(t)
	ctx := context.Background()
	job, err := f.State.PrepareUsageJob(ctx, f.Execution, input)
	if err != nil {
		t.Fatal("usage preparation failed", err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: job.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	allocation := api.HelperLease{ID: fx.ID(t), UID: uint32(os.Geteuid()) + 1, GID: uint32(os.Getegid()) + 1, ContainmentID: fx.ID(t), EndpointGeneration: 1}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision,
		Config: f.Deps.Config, Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()),
		Socket: "/runtime/laneboss-worker.sock", Backend: "linux-bwrap-landlock", ArtifactSHA256: job.Runtime.Executable.SHA256, ServiceVersion: job.Runtime.Executable.Version,
		LaunchID: job.LaunchID, Target: &job.Lease.Target, WorkerLeaseID: job.Lease.ID}
	injection := api.Injection{Target: job.Lease.Target, Outcome: "prepared", SlotIDs: []api.ID{}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}}
	handoff, err := f.State.UsageHandoff(ctx, f.Execution, claim, allocation, endpoint, injection)
	if err != nil {
		t.Fatal("usage narrow native handoff failed", err)
	}
	if handoff.Spec.Grants.ID == f.Plan.Inputs.Grants.ID || !reflect.DeepEqual(handoff.Spec.Grants, job.Grants) {
		t.Fatal("usage borrowed the lane grant set")
	}
	if err := f.State.RegisterCredentialWorker(api.WithEffectLease(ctx, claim), f.Execution, handoff); err != nil {
		t.Fatal("usage bootstrap and vendor executable were conflated", err)
	}
	again, err := f.State.UsageHandoff(ctx, f.Execution, claim, allocation, endpoint, injection)
	if err != nil || !reflect.DeepEqual(handoff, again) {
		t.Fatal("usage handoff replay changed bytes", err)
	}
	prepared := api.PreparedLaunch{ID: fx.ID(t), GateID: fx.ID(t), Target: job.Lease.Target, ContainmentID: allocation.ContainmentID,
		EndpointGeneration: 1, SpecSHA256: handoff.SpecSHA256, ProcessGeneration: "component:usage"}
	binding, err := f.State.BindUsageWorker(ctx, f.Execution, claim, prepared)
	if err != nil {
		t.Fatal("usage actual identity commit failed", err)
	}
	lease, err := f.State.WorkerLease(ctx, f.Execution, job.Lease.ID)
	if err != nil || lease.ConsumedBy != binding.Record.ID || binding.Record.HostUID != allocation.UID {
		t.Fatal("usage lease lost its actual native allocation", err)
	}
	found, err := f.State.UsageGrant(ctx, f.Execution, job.Grants)
	if err != nil || !found {
		t.Fatal("private usage grants cannot be revalidated", err)
	}
	changed := job.Grants
	changed.Resources = append(changed.Resources, api.ResourceGrant{ID: fx.ID(t)})
	if found, err := f.State.UsageGrant(ctx, f.Execution, changed); !found || err == nil {
		t.Fatal("private usage grants accepted a widened capability")
	}
}
