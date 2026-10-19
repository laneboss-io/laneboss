package identity

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func archiveHandoffMetadata(t *testing.T) (*Service, WorkerLaunchAuthority, api.LaunchBindingRequest) {
	t.Helper()
	target := api.LifeRef{LifeID: "archive-life", Run: 1}
	endpoint := fixtureHumanBinding()
	endpoint.Class, endpoint.Socket = api.EndpointWorker, "/runtime/laneboss-worker.sock"
	endpoint.LaunchID, endpoint.Target, endpoint.WorkerLeaseID = "archive-launch", &target, "archive-lease"
	runtime := launchBlob(t, "archive-runtime", "manifest", "retained runtime")
	grants := api.GrantSet{ID: "archive-grants", LifeID: target.LifeID, PolicyGeneration: 1, SHA256: digestBytes([]byte("archive grants"))}
	lease := api.WorkerLease{ID: endpoint.WorkerLeaseID, Kind: "archive", Target: target, OperationID: "archive-operation", EffectID: "archive-effect", GrantSetID: grants.ID, RuntimeManifest: runtime, ConsumedBy: endpoint.LaunchID, Input: launchBlob(t, "archive-input", "archive_input", "sealed archive input")}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: lease.Kind, Input: lease.Input, GrantSetID: grants.ID, Executable: api.Executable{ID: "archive-executable", SHA256: endpoint.ArtifactSHA256, Version: endpoint.ServiceVersion}, Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(lease.ID)}}
	record := api.LaunchRecord{ID: endpoint.LaunchID, Config: endpoint.Config, Kind: "worker", Actor: api.Actor{Kind: "worker", ID: "archive-principal"}, Target: target, ProcessGeneration: "archive-boot:1", EndpointGeneration: endpoint.EndpointGeneration, PolicyGeneration: 1, GrantSetID: grants.ID, GrantsSHA256: grants.SHA256}
	cause := api.InternalIntent{ID: "archive-cause", Kind: api.InternalLifecycleEffect, Config: record.Config, Actor: api.Actor{Kind: "service", ID: "archive-store"}, RequestedBy: api.Actor{Kind: "human", ID: "archive-requester"}, CauseOperationID: lease.OperationID, CauseRequestID: "archive-request", EffectID: lease.EffectID, Target: target, CancellationEpoch: 1}
	p := api.WorkerPrincipal{StageID: "archive-stage", Lease: lease, Record: record, Endpoint: endpoint, CancellationEpoch: cause.CancellationEpoch, Claim: api.EffectLease{Record: api.EffectRecord{ClaimantID: "archive-reconciler", Effect: api.Effect{ID: lease.EffectID, OperationID: lease.OperationID, Context: &cause, Worker: &plan}}}}
	spec := api.LaunchSpec{ID: "archive-spec", Kind: "worker", PlanID: p.StageID, LaunchID: record.ID, Target: target, Backend: endpoint.Backend, UIDLeaseID: record.UIDLeaseID, EndpointGeneration: record.EndpointGeneration, PolicyGeneration: record.PolicyGeneration, RuntimeManifest: runtime, Worker: &plan, Grants: grants, Materialization: api.Materialization{GrantSetID: grants.ID, Manifest: launchBlob(t, "archive-freeze", "manifest", "retained freeze"), Objects: []api.MaterializedObject{}}, Injection: api.Injection{Target: target, Outcome: "prepared"}}
	ref := launchBlob(t, "archive-spec-object", "launch_spec", spec)
	binding := api.LaunchBindingRequest{Record: record, Prepared: api.PreparedLaunch{ID: "archive-prepared", ProcessGeneration: record.ProcessGeneration, SpecSHA256: ref.SHA256}, Identity: api.IdentityCommit{RecordSHA256: launchBlob(t, "archive-record", "manifest", record).SHA256}}
	handoffCause := cause
	handoffCause.Kind, handoffCause.Actor = api.InternalHelperRegister, api.Actor{Kind: "service", ID: p.Claim.Record.ClaimantID}
	handoff := api.PreparedSpecHandoff{Cause: handoffCause, Config: record.Config, Spec: spec, Original: ref, SpecSHA256: ref.SHA256, OperationID: lease.OperationID, RequestID: cause.CauseRequestID}
	return &Service{}, WorkerLaunchAuthority{Binding: binding, Handoff: handoff, Principal: p}, binding
}

// These are hostile metadata controls. The service and native canaries exercise
// the real store and helper; this fixture isolates the closed archive grammar.
func TestArchiveWorkerHandoff(t *testing.T) {
	for _, mode := range []string{"current", "input-class", "stage", "freeze", "write", "delegate", "network", "credential", "argv", "actor", "runtime"} {
		t.Run(mode, func(t *testing.T) {
			s, a, binding := archiveHandoffMetadata(t)
			p, spec := &a.Principal, &a.Handoff.Spec
			p.Lease.Kind, p.Lease.Input.Class = "archive", "archive_input"
			plan := *spec.Worker
			plan.Kind, plan.Input = "archive", p.Lease.Input
			spec.Worker = &plan
			spec.PlanID = p.StageID
			spec.Materialization = api.Materialization{GrantSetID: spec.Grants.ID, Manifest: launchBlob(t, "archive-freeze", "manifest", "retained freeze"), Objects: []api.MaterializedObject{}}
			// Archive effects are authored by the store, then claimed by a
			// different reconciler. The retained requester must stay unchanged.
			p.Claim.Record.ClaimantID = "archive-reconciler"
			a.Handoff.Cause.Actor = api.Actor{Kind: "service", ID: p.Claim.Record.ClaimantID}
			switch mode {
			case "input-class":
				p.Lease.Input.Class, plan.Input.Class = "materialize_input", "materialize_input"
			case "stage":
				spec.PlanID = "foreign-archive-job"
			case "freeze":
				spec.Materialization.Manifest = api.BlobRef{}
			case "write", "delegate":
				spec.Grants.Data = []api.DataGrant{{ID: "archive-source", Access: "ro"}}
				if mode == "write" {
					spec.Grants.Data[0].Access = "rw"
				} else {
					spec.Grants.Data[0].Delegate = true
				}
			case "network":
				spec.Grants.Network = []api.NetworkGrant{{}}
			case "credential":
				spec.Injection.SlotIDs = []api.ID{"foreign-slot"}
			case "argv":
				plan.Argv = append([]string{}, plan.Argv...)
				plan.Argv[2] = "shell"
			case "actor":
				a.Handoff.Cause.Actor.ID = "foreign-reconciler"
			case "runtime":
				spec.RuntimeManifest.SHA256 = digestBytes([]byte("foreign runtime"))
			}
			p.Claim.Record.Effect.Worker = &plan
			ref := launchBlob(t, "archive-spec", "launch_spec", *spec)
			a.Handoff.Original, a.Handoff.SpecSHA256 = ref, ref.SHA256
			binding.Prepared.SpecSHA256 = ref.SHA256
			a.Binding = binding
			err := s.checkWorkerHandoff(binding, a)
			if mode == "current" {
				if err != nil {
					t.Fatal("archive fixed handoff did not reach live-state validation", err)
				}
			} else {
				fixtureCode(t, err, api.CodeIntegrity)
			}
		})
	}
}
