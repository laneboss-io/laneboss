package identity_test

import (
	"context"
	"os"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/identity"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Actual single-writer preparation/claim/spec/binding and actual sealed memfd
// bytes. The peer and containment registry remain explicit consumer fixtures.
func TestUsageStoreSealedHandoff(t *testing.T) {
	for _, fault := range []string{"current", "sealed-input"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
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
			source := api.SecretGrant{ID: fx.ID(t), Name: "usage-login", SourceHandle: fx.ID(t), Version: "v1", Delivery: "file", Target: "login.json", ExpiresAt: fx.Expiry()}
			input := api.UsageCredentialInput{Schema: "laneboss.usage-input.v1", ProfileGeneration: 1, VendorProfile: string(selected.ProfileID), Source: source,
				Request: api.UsageWindowRequest{Target: f.Reservation.Target, LaunchID: f.Reservation.LaunchID, OperationID: f.Reservation.OperationID, ProfileGrantID: selected.ID, ProfileID: selected.ProfileID, Provider: selected.Provider,
					Executable: f.Plan.Runner.Executable, RuntimeManifest: f.Plan.Inputs.Sources.Runtime.Manifest, AdapterVersion: f.Plan.Runner.AdapterVersion}}
			job, err := f.State.PrepareUsageJob(ctx, f.Execution, input)
			if err != nil {
				t.Fatal(err)
			}
			claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: job.Lease.ExpiresAt})
			if err != nil {
				t.Fatal(err)
			}
			allocation := api.HelperLease{ID: fx.ID(t), UID: uint32(os.Geteuid()) + 1, GID: uint32(os.Getegid()) + 1, ContainmentID: fx.ID(t), EndpointGeneration: 1}
			endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision, Config: f.Deps.Config, Class: api.EndpointWorker,
				InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: "/runtime/laneboss-worker.sock", Backend: "linux-bwrap-landlock",
				ArtifactSHA256: job.Runtime.Executable.SHA256, ServiceVersion: job.Runtime.Executable.Version, LaunchID: job.LaunchID, Target: &job.Lease.Target, WorkerLeaseID: job.Lease.ID}
			injection := api.Injection{Target: job.Lease.Target, Outcome: "prepared", SlotIDs: []api.ID{fx.ID(t)}, GrantIDs: []api.ID{source.ID}, SourceVersions: []string{source.Version}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}}
			handoff, err := f.State.UsageHandoff(ctx, f.Execution, claim, allocation, endpoint, injection)
			if err != nil {
				t.Fatal(err)
			}
			prepared := api.PreparedLaunch{ID: fx.ID(t), GateID: fx.ID(t), Target: job.Lease.Target, ContainmentID: allocation.ContainmentID, EndpointGeneration: 1, SpecSHA256: handoff.SpecSHA256, ProcessGeneration: "component-boot:" + string(fx.ID(t))}
			binding, err := f.State.BindUsageWorker(ctx, f.Execution, claim, prepared)
			if err != nil {
				t.Fatal(err)
			}
			facts := api.PeerFacts{HostUID: allocation.UID, HostGID: allocation.GID, HostPID: os.Getpid(), ProcessGeneration: prepared.ProcessGeneration, ContainmentID: allocation.ContainmentID}
			principal, err := f.State.WorkerBinding(ctx, endpoint, facts)
			if err != nil {
				t.Fatal(err)
			}
			chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: job.Lease.Input.ID, Limit: api.MaxChunkBytes})
			if err != nil {
				t.Fatal(err)
			}
			raw := chunk.Data
			if fault == "sealed-input" {
				raw = append(append([]byte{}, raw...), '\n')
			}
			guard := &reservationGuard{a: identity.WorkerLaunchAuthority{Binding: binding, Handoff: handoff, Principal: principal}, input: reservationMemfd(t, raw), endpoint: reservationMemfd(t, fx.JSON(t, endpoint)), peer: &fx.Peer{FactsValue: facts}}
			t.Cleanup(func() {
				if guard.closes == 0 {
					if err := guard.Close(); err != nil {
						t.Error(err)
					}
				}
			})
			directory, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			registry := &reservationRegistry{binding: api.ContainmentBinding{Config: endpoint.Config, Target: job.Lease.Target, Backend: endpoint.Backend, BootID: principal.BootID, Generation: principal.AllocationGeneration, Lease: allocation, Directory: directory}}
			service, err := identity.New(identity.Dependencies{Store: f.State, Clock: f.Deps.Clock, Peers: reservationPeers{}, Registry: registry,
				Workers: reservationSource(func(_ context.Context, config string, id api.ID) (identity.WorkerLaunchGuard, error) {
					if config != f.Deps.Config || id != prepared.ID {
						t.Fatal("usage source received foreign selection")
					}
					return guard, nil
				})})
			if err != nil {
				t.Fatal(err)
			}
			permit, err := service.BindLaunch(ctx, binding)
			if fault == "current" {
				if err != nil || permit.LaunchID != binding.Record.ID || permit.RecordSHA256 != binding.Identity.RecordSHA256 || guard.closes != 1 {
					t.Fatal("writer-issued usage job did not bind its sealed query", err)
				}
			} else {
				if err == nil || permit != (api.LaunchPermit{}) || guard.closes != 1 {
					t.Fatal("changed sealed query acquired a launch permit", err)
				}
			}
		})
	}
}
