package identity

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// Only the descriptors and their seals are native here. The independent store,
// claim and peer projections are hostile controls, not installed-run evidence.
type reviewWorkerStoreFixture struct {
	*fixtureStore
	job       archivejob.Job
	reads     int
	planReads int
}

func (s *reviewWorkerStoreFixture) ReviewJob(ctx context.Context, scope api.Scope, operation api.ID) (archivejob.Job, error) {
	s.reads++
	if err := ctx.Err(); err != nil {
		return archivejob.Job{}, err
	}
	if operation != s.job.Intent.OperationID || scope.Config != s.record.Config || scope.Actor.Kind != "service" || scope.Actor.ID != s.worker.Claim.Record.ClaimantID {
		return archivejob.Job{}, refusal(api.CodeForbidden, "fixture review job read lost its actual claimant")
	}
	return s.job, nil
}

func (s *reviewWorkerStoreFixture) LaunchPlan(context.Context, api.Scope, api.ID) (api.LaunchPlanRecord, error) {
	s.planReads++
	return api.LaunchPlanRecord{}, refusal(api.CodeIntegrity, "review job is not a materialization reservation")
}

func refreshReviewWorkerFixture(t *testing.T, store *reviewWorkerStoreFixture, guard *workerGuardFixture, binding *api.LaunchBindingRequest) {
	t.Helper()
	a := &guard.a
	binding.Record = a.Principal.Record
	ref := launchBlob(t, "review-original-spec", "launch_spec", a.Handoff.Spec)
	a.Handoff.Original, a.Handoff.SpecSHA256 = ref, ref.SHA256
	binding.Prepared.SpecSHA256 = ref.SHA256
	binding.Identity.RecordSHA256 = launchBlob(t, "review-original-record", "manifest", binding.Record).SHA256
	a.Binding = *binding
	worker := cloneLaunchValue(t, a.Principal)
	committed := cloneLaunchValue(t, *binding)
	store.worker, store.binding, store.record = &worker, &committed, worker.Record
	effect := cloneLaunchValue(t, worker.Claim.Record)
	store.projectionEffect = &effect
}

func reviewWorkerBindFixture(t *testing.T) (*Service, *reviewWorkerStoreFixture, *workerGuardFixture, api.LaunchBindingRequest) {
	t.Helper()
	s, original, guard, binding := workerBindFixture(t, "current")
	p, spec := &guard.a.Principal, &guard.a.Handoff.Spec
	p.StageID, p.Lease.Kind, p.Lease.Generation = "review-original-job", "export", 2
	original.lane.Generation, original.lane.State, original.lane.Containment = 7, "verifying", "quiescent"
	original.lane.LaunchID, original.lane.Session.ID = "review-ended-agent", "review-ended-session"
	subject := api.ReviewSubject{Target: p.Lease.Target, LaunchID: original.lane.LaunchID, Generation: original.lane.Generation, SessionID: original.lane.Session.ID,
		EndEventID: "review-ended-event", EndSeq: 5, Snapshot: launchBlob(t, "review-snapshot", "manifest", "measured snapshot"), Streams: []api.CaptureStreamBinding{}, RefusalIDs: []api.ID{}}
	input := reviewjob.Input{Schema: "laneboss.review-input.v2", Subject: subject,
		Request:  api.ReviewRequest{Target: subject.Target, Checks: []api.BlobRef{}, RefusalResolution: []api.ID{}},
		Required: []string{"unit"}, Checks: []api.ReviewCheckFact{{Name: "unit"}}, Inventory: api.ReviewInventory{Streams: []api.ReviewStreamFact{}}, Resolutions: []api.ReviewResolution{}}
	raw := launchJSON(t, input)
	var decoded reviewjob.Input
	if err := api.DecodeObject(raw, &decoded); err != nil {
		t.Fatal("review input fixture must obey the real sealed-input grammar", err)
	}
	p.Lease.Input = api.BlobRef{ID: "review-sealed-input", Class: "manifest", SHA256: digestBytes(raw), Bytes: int64(len(raw))}
	if err := guard.input.Close(); err != nil {
		t.Fatal(err)
	}
	guard.input = workerMemfd(t, raw, true, true)
	plan := *spec.Worker
	plan.Kind, plan.Input = p.Lease.Kind, p.Lease.Input
	spec.Worker, p.Claim.Record.Effect.Worker = &plan, &plan
	spec.PlanID = p.StageID
	spec.Materialization = api.Materialization{GrantSetID: p.Lease.GrantSetID, Manifest: launchBlob(t, "review-freeze", "manifest", "original measured freeze"), Objects: []api.MaterializedObject{}}
	p.Claim.Record.Effect.Context.Kind = api.InternalLifecycleEffect
	p.Claim.Record.Effect.Context.Actor = api.Actor{Kind: "service", ID: "review-original-store"}
	p.Claim.Record.ClaimantID = "review-first-claimant"
	guard.a.Handoff.Cause = *p.Claim.Record.Effect.Context
	guard.a.Handoff.Cause.Kind = api.InternalHelperRegister
	guard.a.Handoff.Cause.Actor = api.Actor{Kind: "service", ID: p.Claim.Record.ClaimantID}
	original.events.Events[0].Actor = guard.a.Handoff.Cause.Actor
	lease := p.Lease
	lease.ConsumedBy, lease.Generation = "", 1
	store := &reviewWorkerStoreFixture{fixtureStore: original, job: archivejob.Job{ID: p.StageID, Lease: lease, Plan: cloneLaunchValue(t, plan), Freeze: spec.Materialization.Manifest,
		Intent: archivejob.Intent{Request: api.ArchiveRequest{Target: subject.Target, ExpectedGeneration: subject.Generation}, OperationID: lease.OperationID,
			EndEventID: subject.EndEventID, EndSeq: subject.EndSeq, CancellationEpoch: p.CancellationEpoch}}}
	refreshReviewWorkerFixture(t, store, guard, &binding)
	s.deps.Store = store
	return s, store, guard, binding
}

func TestReviewWorkerHandoff(t *testing.T) {
	for _, mode := range []string{"current", "class", "stage", "freeze", "write", "delegate", "network", "secret", "objects", "argv", "actor", "cause", "runtime"} {
		t.Run(mode, func(t *testing.T) {
			s, store, guard, binding := reviewWorkerBindFixture(t)
			p, spec := &guard.a.Principal, &guard.a.Handoff.Spec
			switch mode {
			case "class":
				p.Lease.Input.Class, spec.Worker.Input.Class = "archive_input", "archive_input"
			case "stage":
				spec.PlanID = "another-review-job"
			case "freeze":
				spec.Materialization.Manifest = api.BlobRef{}
			case "write", "delegate":
				spec.Grants.Data = []api.DataGrant{{ID: "review-source", Access: "ro"}}
				if mode == "write" {
					spec.Grants.Data[0].Access = "rw"
				} else {
					spec.Grants.Data[0].Delegate = true
				}
			case "network":
				spec.Grants.Network = []api.NetworkGrant{{}}
			case "secret":
				spec.Grants.Secrets = []api.SecretGrant{{}}
			case "objects":
				spec.Materialization.Objects = []api.MaterializedObject{{}}
			case "argv":
				spec.Worker.Argv = []string{"sh", "-c", "untrusted"}
			case "actor":
				guard.a.Handoff.Cause.Actor.ID = "another-claimant"
			case "cause":
				guard.a.Handoff.Cause.ID = "another-cause"
			case "runtime":
				spec.RuntimeManifest.SHA256 = digestBytes([]byte("another runtime"))
			}
			refreshReviewWorkerFixture(t, store, guard, &binding)
			err := s.checkWorkerHandoff(binding, guard.a)
			if mode == "current" {
				if err != nil {
					t.Fatal("original review handoff did not reach native-state validation", err)
				}
			} else {
				fixtureCode(t, err, api.CodeIntegrity)
			}
		})
	}
}

func TestReviewWorkerBind(t *testing.T) {
	for _, mode := range []string{"current", "reclaimed", "job", "freeze", "generation", "lease-generation", "input", "event", "claim", "late-job", "late-native"} {
		t.Run(mode, func(t *testing.T) {
			s, store, guard, binding := reviewWorkerBindFixture(t)
			want := api.CodeIntegrity
			switch mode {
			case "reclaimed":
				guard.a.Principal.Claim.Record.ClaimantID = "review-next-claimant"
				guard.a.Handoff.Cause.Actor.ID = "review-next-claimant"
				refreshReviewWorkerFixture(t, store, guard, &binding)
			case "job":
				store.job.ID = "another-job"
			case "freeze":
				store.job.Freeze.SHA256 = digestBytes([]byte("another freeze"))
			case "generation":
				store.lane.Generation++
				want = api.CodeConflict
			case "lease-generation":
				store.job.Lease.Generation++
			case "input":
				if err := guard.input.Close(); err != nil {
					t.Fatal(err)
				}
				guard.input = workerMemfd(t, []byte("another sealed input"), true, true)
			case "event":
				store.events.Events[0].RequestID = "another-request"
			case "claim":
				store.projectionEffect.Generation++
				want = api.CodeConflict
			case "late-job":
				guard.after = func(n int) {
					if n == 2 {
						store.job.Freeze.SHA256 = digestBytes([]byte("changed after native validation"))
					}
				}
			case "late-native":
				want = api.CodeUnauthenticated
				guard.after = func(n int) {
					if n == 2 {
						guard.peer.(*fixturePeer).facts.ProcessGeneration = "boot:replacement"
					}
				}
			}
			permit, err := s.BindLaunch(context.Background(), binding)
			if mode == "current" || mode == "reclaimed" {
				if err != nil || permit.LaunchID != binding.Record.ID || permit.PreparedID != binding.Prepared.ID || permit.RecordSHA256 != binding.Identity.RecordSHA256 ||
					permit.CommittedSeq != binding.Identity.CommittedSeq || store.reads != 2 || guard.checks != 2 || store.planReads != 0 {
					t.Fatalf("original review did not retain its two-pass native job permit: reads=%d plans=%d err=%v", store.reads, store.planReads, err)
				}
			} else {
				fixtureCode(t, err, want)
				if !reflect.DeepEqual(permit, api.LaunchPermit{}) {
					t.Fatal("refused review acquired a permit")
				}
			}
			if guard.closes != 1 || store.transaction != nil {
				t.Fatal("review guard leaked or identity executed the job in process")
			}
		})
	}
}

func TestReviewWorkerReservationFence(t *testing.T) {
	s, store, guard, _ := reviewWorkerBindFixture(t)
	if err := s.checkWorkerLaunchState(context.Background(), guard.a, guard.a.Principal.Peer); err != nil || store.planReads != 0 {
		t.Fatal("review's original job was treated as a materialization reservation", err)
	}
	store.lane.CancellationEpoch++
	fixtureCode(t, s.checkWorkerLaunchState(context.Background(), guard.a, guard.a.Principal.Peer), api.CodeConflict)
}

func TestReviewWorkerEventAuthor(t *testing.T) {
	s, store, guard, binding := reviewWorkerBindFixture(t)
	guard.a.Principal.Claim.Record.ClaimantID = "review-next-claimant"
	guard.a.Handoff.Cause.Actor.ID = "review-next-claimant"
	refreshReviewWorkerFixture(t, store, guard, &binding)
	scope := api.Scope{Config: binding.Record.Config, Actor: guard.a.Handoff.Cause.Actor, PolicyGeneration: binding.Record.PolicyGeneration}
	if err := s.checkWorkerBoundEvent(context.Background(), scope, binding, guard.a); err != nil {
		t.Fatal("reclaimed review lost its original committed event author", err)
	}
	store.events.Events[0].Payload = launchJSON(t, api.LaunchRecord{})
	fixtureCode(t, s.checkWorkerBoundEvent(context.Background(), scope, binding, guard.a), api.CodeIntegrity)
}
