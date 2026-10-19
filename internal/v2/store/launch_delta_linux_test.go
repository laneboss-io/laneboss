//go:build linux

package store_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestIssuedLaunchGrants(t *testing.T) {
	for _, fault := range []string{"foreign_source", "source_digest", "request_access", "request_path", "request_destination", "request_expiry", "request_delegate", "extra_entry"} {
		t.Run(fault, func(t *testing.T) {
			f := fx.New(t)
			if fault != "foreign_source" && fault != "source_digest" {
				f.Start.Grants.Data[0].Access = "ro"
				f.Start.Grants.Data[0].RelativePath = "allowed"
				f.Start.Grants.Data[0].Delegate = false
				f.Admit(t, "lane.start", f.Start)
			}
			f.Reserve(t)
			input := f.SourceTransaction(t)
			grant := input.Writes.Grants[0]
			want := api.CodeForbidden
			switch fault {
			case "foreign_source":
				foreign := f.Retain(t, "manifest", []byte("starter never held "+string(fx.ID(t))), f.Execution.Actor, "")
				grant.Data[0].SourceObjectID, grant.Data[0].SourceSHA256 = foreign.ID, foreign.SHA256
				grant.Data[0].Access, grant.Data[0].Destination = "rw", "/work/main"
				input.Writes.LaunchPlans[0].Inputs.Sources.Project.Object = foreign
			case "source_digest":
				grant.Data[0].SourceSHA256 = fx.Digest([]byte("different source"))
				input.Writes.LaunchPlans[0].Inputs.Sources.Project.Object.SHA256 = grant.Data[0].SourceSHA256
			case "request_access":
				grant.Data[0].Access = "rw"
			case "request_path":
				grant.Data[0].RelativePath = "."
			case "request_destination":
				grant.Data[0].Destination = "/work/other"
				want = api.CodeInvalid // The shared main-workspace shape refuses first.
			case "request_expiry":
				grant.Data[0].ExpiresAt = api.Timestamp(time.Now().Add(45 * time.Minute).UTC().Format(time.RFC3339Nano))
			case "request_delegate":
				grant.Data[0].Delegate = true
			case "extra_entry":
				extra := grant.Data[0]
				extra.ID = fx.ID(t)
				grant.Data = append(grant.Data, extra)
			}
			grant.SHA256 = fx.Digest(fx.JSON(t, grant))
			input.Writes.Grants[0] = grant
			input.Writes.LaunchPlans[0].Inputs.Grants = grant
			input.Events[0].Payload = fx.JSON(t, api.GrantEvent{GrantSet: grant})
			if _, err := f.State.Transact(context.Background(), input); err == nil {
				t.Fatal("planner issued launch grants outside " + fault)
			} else {
				launchCode(t, err, want)
			}
			current, err := f.State.LaunchPlan(context.Background(), f.Execution, f.Reservation.ID)
			if err != nil || current.Phase != "reserved" || current.Inputs != nil || current.Generation != 1 {
				t.Fatal("refused grant issuance partially committed its plan", err)
			}
			// The same reservation can still commit its real, requested grant
			// set. No fixture inserts a child grant or a plan projection.
			f.Source(t)
			if _, err := f.State.Grants(context.Background(), f.Reservation.GrantSetID); err != nil {
				t.Fatal("valid issuance did not retain child grants", err)
			}
		})
	}
}

func TestIssuedGrantCannotBeStaged(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t)
	input := f.SourceTransaction(t)
	foreign := f.Retain(t, "manifest", []byte("unheld staged source "+string(fx.ID(t))), f.Execution.Actor, "")
	grant := input.Writes.Grants[0]
	grant.Data[0].SourceObjectID, grant.Data[0].SourceSHA256 = foreign.ID, foreign.SHA256
	input.Writes.LaunchPlans = nil
	input.Writes.Grants[0] = grant
	input.Events[0].Payload = fx.JSON(t, api.GrantEvent{GrantSet: grant})
	if _, err := f.State.Transact(context.Background(), input); err == nil {
		t.Fatal("planner staged unheld child grants without a plan")
	} else {
		launchCode(t, err, api.CodeForbidden)
	}
	if _, err := f.State.Grants(context.Background(), f.Reservation.GrantSetID); err == nil {
		t.Fatal("refused staged grants remained visible")
	} else {
		launchCode(t, err, api.CodeNotFound)
	}
	f.Source(t)
}

func freshRootTicket(t *testing.T, f *fx.Fixture) {
	t.Helper()
	ticket, err := f.State.Ticket(context.Background(), f.Human, f.Start.RootTicketID)
	if err != nil {
		t.Fatal(err)
	}
	ticket.ID, ticket.Redeemed = fx.ID(t), false
	f.Replace(t, "ticket", ticket.ID, 1, struct {
		RedeemedBy         api.ID
		PrincipalID        api.ID
		Config             string
		EndpointGeneration api.Generation
		Ticket             api.Ticket
	}{PrincipalID: f.Human.Actor.ID, Config: f.Deps.Config, EndpointGeneration: f.Human.EndpointGeneration, Ticket: ticket})
	f.Start.RootTicketID = ticket.ID
	f.Admit(t, "lane.start", f.Start)
}

func TestFailedLaunchNameReuse(t *testing.T) {
	f, input, jobs := failedPlanFixture(t, false)
	old := f.Reservation
	failed := input.Writes.LaunchPlans[0]
	if _, err := f.State.FailPlan(context.Background(), input, jobs); err != nil {
		t.Fatal("unbound failure did not retain its atomic cleanup", err)
	}
	if _, err := f.State.CompleteEffect(context.Background(), f.Execution, api.EffectOutcome{EffectID: f.Claim.Record.Effect.ID, ClaimID: f.Claim.ClaimID, ExpectedGeneration: f.Claim.Record.Generation, Status: "failed", Error: failed.Error}); err != nil {
		t.Fatal("failed reservation did not finish its measured refusal", err)
	}
	if _, err := f.State.Lane(context.Background(), f.Execution, old.Target); err == nil {
		t.Fatal("pre-binding failed launch unexpectedly created a lane")
	} else {
		launchCode(t, err, api.CodeNotFound)
	}
	freshRootTicket(t, f)
	next, err := f.State.ReserveLaunch(context.Background(), f.Human, f.ReservationRequest(t))
	if err != nil {
		t.Fatal("failed unbound launch kept its lane name reserved", err)
	}
	if next.ID == old.ID || next.Target.LifeID == old.Target.LifeID || next.LaunchID == old.LaunchID {
		t.Fatal("name reuse revived a failed reservation")
	}
	saved, err := f.State.LaunchPlan(context.Background(), f.Execution, old.ID)
	if err != nil || !reflect.DeepEqual(saved, failed) {
		t.Fatal("name reuse discarded the failed plan history", err)
	}
	for _, job := range jobs {
		actual, err := f.State.PlanCleanup(context.Background(), f.Execution, job.ID)
		if err != nil || !reflect.DeepEqual(actual, job) {
			t.Fatal("name reuse discarded pending original cleanup", err)
		}
	}
}

func TestLaunchClaimantFence(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t) // Authentic claimant is the positive control.
	f.ExpireClaim(t)
	request := api.EffectClaimRequest{EffectID: f.Claim.Record.Effect.ID, ExpectedGeneration: f.Claim.Record.Generation, ClaimantID: fx.ID(t), Deadline: fx.Expiry()}
	if _, err := f.State.ClaimEffect(context.Background(), f.Execution, request); err == nil {
		t.Fatal("foreign claimant acquired a launch effect")
	} else {
		launchCode(t, err, api.CodeForbidden)
	}
	request.ClaimantID = f.Execution.Actor.ID
	if _, err := f.State.ClaimEffect(context.Background(), f.Execution, request); err != nil {
		t.Fatal("authentic claimant could not recover its expired effect", err)
	}
}

func TestLaunchCompletionClaimant(t *testing.T) {
	f := fx.Ready(t, true)
	f.Opened(t)
	ctx := context.Background()
	completed, err := f.State.Effect(ctx, f.Execution, f.Claim.Record.Effect.ID)
	if err != nil || completed.Outcome == nil {
		t.Fatal("measured outcome control is absent", err)
	}
	if replay, err := f.State.CompleteEffect(ctx, f.Execution, *completed.Outcome); err != nil || !replay.Replayed {
		t.Fatal("authentic measured outcome did not replay", err)
	}
	foreign := f.Execution
	foreign.Actor.ID = fx.ID(t)
	if _, err := f.State.CompleteEffect(ctx, foreign, *completed.Outcome); err == nil {
		t.Fatal("foreign claimant replayed measured launch outcome")
	} else {
		launchCode(t, err, api.CodeForbidden)
	}
}

func TestLaunchEffectCause(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t)
	f.Source(t)
	ctx := context.Background()
	for _, foreign := range []bool{false, true} {
		cause := f.Intent(t, api.InternalHelperAllocate)
		cause.EffectID = fx.ID(t)
		if foreign {
			cause.CauseRequestID = fx.ID(t)
		}
		effect := api.Effect{ID: cause.EffectID, OperationID: f.Reservation.OperationID, Context: &cause,
			HelperAllocate: &api.HelperLeaseRequest{ReservationID: f.Reservation.ID, Cause: cause, Config: f.Deps.Config, LifeID: f.Reservation.Target.LifeID, Backend: f.Record.Inputs.Sources.Runtime.Backend, Budget: f.Start.Budget, RuntimeManifestID: f.Record.Inputs.Sources.Runtime.Manifest.ID}}
		parent := f.Intent(t, api.InternalLaunchPlan)
		if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &parent, Effects: []api.Effect{effect}}); err != nil {
			t.Fatal("effect cause control did not retain its actual intent", err)
		}
		_, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
		if foreign {
			if err == nil {
				t.Fatal("foreign request cause acquired launch effect")
			}
			launchCode(t, err, api.CodeForbidden)
		} else if err != nil {
			t.Fatal("original effect cause was refused", err)
		}
	}
}

func TestCaptureProducerGeneration(t *testing.T) {
	for _, source := range []string{"peer_generation", "launch_generation"} {
		t.Run(source, func(t *testing.T) {
			f := fx.Ready(t, true)
			ctx := context.Background()
			data := f.CaptureData(t, []byte("producer lifetime "+string(fx.ID(t))))
			request := f.AppendRequest(t, &data, false)
			if _, err := f.State.AppendCapture(ctx, f.Worker, request); err != nil {
				t.Fatal("producer lifetime control failed", err)
			}
			connection := f.Worker.Connection.(*fx.Connection)
			if source == "peer_generation" {
				connection.Verified.(*fx.Peer).FactsValue.ProcessGeneration = "different-producer-process"
			} else {
				launch, err := f.State.Launch(ctx, f.Worker.LaunchID)
				if err != nil {
					t.Fatal(err)
				}
				launch.ID = fx.ID(t)
				launch.ProcessGeneration = "different-retained-process"
				cause := f.Intent(t, api.InternalLifecycleEffect)
				if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Events: []api.Event{f.Event(t, "identity.bound", launch)}}); err != nil {
					t.Fatal("second worker identity control failed", err)
				}
				// A different retained worker launch may share this component
				// principal/lease, but cannot inherit the registered producer's
				// generation. Both records were committed through the writer.
				f.Worker.LaunchID = launch.ID
				connection.Endpoint.LaunchID = launch.ID
			}
			if _, err := f.State.AppendCapture(ctx, f.Worker, request); err == nil {
				t.Fatal("capture replay accepted changed " + source)
			} else {
				launchCode(t, err, api.CodeUnauthenticated)
			}
		})
	}
}

// These two older authorization controls now obtain their lane identity from
// the real reservation/plan/ready path, rather than projecting identity.bound
// without a reservation. The peer remains an explicit component fixture.
func laneObservation(t *testing.T, f *fx.Fixture) api.Transaction {
	t.Helper()
	r := f.Binding.Record
	content := f.Retain(t, "record", []byte("lane observation "+string(fx.ID(t))), r.Actor, r.Target.LifeID)
	connection := &fx.Connection{Identity: fx.ID(t), Endpoint: api.InstalledBinding{Config: r.Config, Class: api.EndpointLane, LaunchID: r.ID, Target: &r.Target, EndpointGeneration: r.EndpointGeneration}, Verified: &fx.Peer{FactsValue: api.PeerFacts{HostUID: r.HostUID, ContainmentID: r.ContainmentID, ProcessGeneration: "component-lane-connector"}}}
	scope := api.Scope{Config: r.Config, Actor: r.Actor, LaunchID: r.ID, EndpointGeneration: r.EndpointGeneration, PolicyGeneration: r.PolicyGeneration, Connection: connection, Source: "cli"}
	record := api.Record{ID: fx.ID(t), Collection: "observations", LifeID: r.Target.LifeID, Run: r.Target.Run, Content: content, Actor: r.Actor, Origin: "observation", Generation: 1, RecordedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: r.Config, Method: "records.append", RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, api.RecordAppendRequest{Collection: "observations", Content: content, RelatedIDs: []api.ID{}})}
	var err error
	request.RequestSHA256, err = wire.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request, scope.Frame = request, &fx.Frame{Raw: fx.JSON(t, request)}
	event := api.Event{Schema: api.SchemaVersion, ID: fx.ID(t), Config: r.Config, Kind: "record.appended", Actor: r.Actor, RequestedBy: r.Actor, LifeID: r.Target.LifeID, Run: r.Target.Run, Origin: "observation", StarterChain: []api.ID{}, Payload: fx.JSON(t, record)}
	return api.Transaction{Scope: scope, RawRequest: fx.JSON(t, request), Events: []api.Event{event}, Reply: &api.RPCReply{Result: event.Payload}}
}

func TestBoundLaneCannotEmitForeignLife(t *testing.T) {
	f := fx.Ready(t, true)
	input := laneObservation(t, f)
	if _, err := f.State.Transact(context.Background(), input); err != nil {
		t.Fatal("own-life lane observation control failed", err)
	}
	var record api.Record
	if err := json.Unmarshal(input.Events[0].Payload, &record); err != nil {
		t.Fatal(err)
	}
	input.Scope.Request.RequestID, input.Scope.Request.IdempotencyKey = fx.ID(t), fx.ID(t)
	input.Scope.Frame = &fx.Frame{Raw: fx.JSON(t, input.Scope.Request)}
	input.RawRequest = fx.JSON(t, input.Scope.Request)
	input.Events[0].ID, record.ID = fx.ID(t), fx.ID(t)
	input.Events[0].LifeID = fx.ID(t)
	record.LifeID = input.Events[0].LifeID
	input.Events[0].Payload = fx.JSON(t, record)
	input.Reply.Result = input.Events[0].Payload
	if _, err := f.State.Transact(context.Background(), input); err == nil {
		t.Fatal("bound lane emitted foreign-life event")
	} else {
		launchCode(t, err, api.CodeForbidden)
	}
}

func TestReplayRechecksRevocation(t *testing.T) {
	f := fx.Ready(t, true)
	input := laneObservation(t, f)
	ctx := context.Background()
	commit, err := f.State.Transact(ctx, input)
	if err != nil {
		t.Fatal("bound lane control failed", err)
	}
	record := f.Binding.Record
	record.Revoked = true
	cause := f.Intent(t, api.InternalHelperStop)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Events: []api.Event{f.Event(t, "identity.revoked", record)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.Transact(ctx, input); err == nil {
		t.Fatal("wanted unauthenticated, got <nil>")
	} else {
		launchCode(t, err, api.CodeUnauthenticated)
	}
	if _, err := f.State.Operation(ctx, input.Scope, commit.Operation.ID); err == nil {
		t.Fatal("revoked lane read an operation")
	} else {
		launchCode(t, err, api.CodeUnauthenticated)
	}
}
