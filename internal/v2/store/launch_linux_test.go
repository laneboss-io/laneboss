//go:build linux

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func launchCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}

func TestLaunchReserveReplay(t *testing.T) {
	f := fx.New(t)
	ctx := context.Background()
	type result struct {
		Reservation api.LaunchReservation
		Err         error
	}
	results := make(chan result, 8)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			r, err := f.State.ReserveLaunch(ctx, f.Human, f.ReservationRequest(t))
			results <- result{r, err}
		}()
	}
	workers.Wait()
	close(results)
	var original api.LaunchReservation
	for result := range results {
		if result.Err != nil {
			t.Fatal("duplicate reservation did not reconcile", result.Err)
		}
		if original.ID == "" {
			original = result.Reservation
		} else if !reflect.DeepEqual(original, result.Reservation) {
			t.Fatal("duplicate start issued another child or launch")
		}
	}
	if original.Target.Run != 1 || original.Generation != 1 || original.Target.LifeID == original.LaunchID || original.RequestedBy != f.Human.Actor {
		t.Fatal("store did not issue a fresh correlated child")
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil || len(effects) != 1 || effects[0].PlanLaunch == nil || effects[0].PlanLaunch.ReservationID != original.ID || effects[0].Launch != nil {
		t.Fatal("reservation did not retain exactly one planning intent", err)
	}
	receipt, err := f.State.LookupReceipt(ctx, f.Human, api.RequestKey{Method: f.Human.Request.Method, IdempotencyKey: f.Human.Request.IdempotencyKey, RequestSHA256: f.Human.Request.RequestSHA256})
	if err != nil || receipt.Reply == nil || receipt.Operation.Status != "pending" || !bytes.Equal(receipt.RawRequest, f.Raw) {
		t.Fatal("launch handoff changed the exact pending reply/input", err)
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal("reserved launch did not survive restart", err)
	}
	retry, err := f.State.ReserveLaunch(ctx, f.Human, f.ReservationRequest(t))
	if err != nil || !reflect.DeepEqual(original, retry) {
		t.Fatal("restart reissued a launch reservation", err)
	}
	read, err := f.State.LaunchPlan(ctx, f.Execution, original.ID)
	if err != nil || read.Phase != "reserved" || read.Generation != 1 || read.Plan != nil || read.Reservation.OriginalRequest.SHA256 != fx.Digest(f.Raw) {
		t.Fatal("reserved phase manufactured a ready lane or lost bytes", err)
	}
	if _, err := f.State.Lane(ctx, f.Execution, original.Target); err == nil {
		t.Fatal("reservation manufactured a ready Lane")
	} else {
		launchCode(t, err, api.CodeNotFound)
	}
}

func TestLaunchReserveGuards(t *testing.T) {
	for _, fault := range []string{"foreign_operation", "foreign_actor", "stale_policy", "used_ticket", "expired_ticket", "foreign_ticket", "ticket_endpoint", "ticket_role", "budget", "path", "grant_ceiling", "name_claim", "changed_digest"} {
		t.Run(fault, func(t *testing.T) {
			f := fx.New(t)
			ctx := context.Background()
			scope, request := f.Human, f.ReservationRequest(t)
			switch fault {
			case "foreign_operation":
				request.OperationID = fx.ID(t)
			case "foreign_actor":
				scope.Actor.ID = fx.ID(t)
			case "stale_policy":
				scope.PolicyGeneration++
			case "used_ticket", "expired_ticket", "foreign_ticket", "ticket_endpoint", "ticket_role":
				ticket, err := f.State.Ticket(ctx, f.Human, f.Start.RootTicketID)
				if err != nil {
					t.Fatal(err)
				}
				principal, endpoint := f.Human.Actor.ID, f.Human.EndpointGeneration
				if fault == "used_ticket" {
					ticket.Redeemed = true
				}
				if fault == "expired_ticket" {
					ticket.ExpiresAt = api.Timestamp(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
				}
				if fault == "foreign_ticket" {
					principal = fx.ID(t)
					ticket.PrincipalID = principal
				}
				if fault == "ticket_endpoint" {
					endpoint++
					ticket.EndpointGeneration = endpoint
				}
				if fault == "ticket_role" {
					ticket.Role = "different-role"
				}
				f.Replace(t, "ticket", ticket.ID, 1, struct {
					RedeemedBy         api.ID
					PrincipalID        api.ID
					Config             string
					EndpointGeneration api.Generation
					Ticket             api.Ticket
				}{PrincipalID: principal, Config: f.Deps.Config, EndpointGeneration: endpoint, Ticket: ticket})
			case "budget":
				f.Start.Budget.WallMS = 0
				f.Admit(t, "lane.start", f.Start)
				scope, request = f.Human, f.ReservationRequest(t)
			case "path":
				f.Start.Lane = "../caller"
				f.Admit(t, "lane.start", f.Start)
				scope, request = f.Human, f.ReservationRequest(t)
			case "grant_ceiling":
				f.Start.Grants.Data[0].ParentGrantID = fx.ID(t)
				f.Admit(t, "lane.start", f.Start)
				scope, request = f.Human, f.ReservationRequest(t)
			case "name_claim":
				f.Reserve(t)
				ticket, err := f.State.Ticket(ctx, f.Human, f.Start.RootTicketID)
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
				scope, request = f.Human, f.ReservationRequest(t)
			case "changed_digest":
				changed := f.Start
				changed.Budget.CPUSeconds++
				scope.Request.Params = fx.JSON(t, changed)
				scope.Request.RequestSHA256, _ = wire.RequestDigest(scope.Request)
			}
			if _, err := f.State.ReserveLaunch(ctx, scope, request); err == nil {
				t.Fatal("launch reservation accepted " + fault)
			}
		})
	}
}

func TestLaunchSelectorsStayClosed(t *testing.T) {
	f := fx.New(t)
	for _, field := range []string{"child_id", "workspace_path", "home", "executable"} {
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(f.Human.Request.Params, &fields); err != nil {
			t.Fatal(err)
		}
		fields[field] = json.RawMessage(`"/caller/choice"`)
		request := f.Human.Request
		request.Params = fx.JSON(t, fields)
		request.RequestSHA256, _ = wire.RequestDigest(request)
		if err := wire.ValidateRequest(request); err == nil {
			t.Fatal("launch request admitted caller authority field", field)
		}
	}
}

func sourcedWrite(t *testing.T, f *fx.Fixture) api.Transaction {
	t.Helper()
	// Exercise ordinary launch authority with the real reserved-to-sourced
	// issuance. Failed planner revisions belong to FailPlan plus its batch.
	input := f.SourceTransaction(t)
	if err := api.ValidateTransactionShape(input); err != nil {
		t.Fatal("launch authority fixture lost its valid source transition", err)
	}
	return input
}

func TestLaunchPlanAuthority(t *testing.T) {
	for _, fault := range []string{"foreign_reservation", "stale_policy", "stale_grants", "expired_claim", "changed_claimant", "missing_cas", "missing_epoch", "new_reservation"} {
		t.Run(fault, func(t *testing.T) {
			f := fx.New(t)
			f.Reserve(t)
			input := sourcedWrite(t, f)
			ctx := context.Background()
			switch fault {
			case "foreign_reservation":
				input.Writes.LaunchPlans[0].Reservation.SpecID = fx.ID(t)
			case "stale_policy":
				policy, err := f.State.Policy(ctx, f.Execution)
				if err != nil {
					t.Fatal(err)
				}
				policy.Generation++
				f.Replace(t, "policy", api.ID(f.Deps.Config), policy.Generation, policy)
			case "stale_grants":
				ceiling := f.Ceiling
				ceiling.Generation++
				ceiling.Revoked = true
				f.Replace(t, "grants", ceiling.ID, ceiling.Generation, ceiling)
			case "changed_claimant":
				input.Scope.Actor.ID = fx.ID(t)
				input.Internal.Actor = input.Scope.Actor
			case "expired_claim":
				f.ExpireClaim(t)
			case "missing_cas":
				comparisons := input.Compare[:0]
				for _, compare := range input.Compare {
					if compare.Kind != api.CompareLaunchPlan {
						comparisons = append(comparisons, compare)
					}
				}
				input.Compare = comparisons
			case "missing_epoch":
				input.Guards = nil
			case "new_reservation":
				input.Writes.LaunchPlans[0].Phase = "reserved"
				input.Writes.LaunchPlans[0].Inputs = nil
				input.Writes.Grants, input.Events = nil, nil
			}
			if _, err := f.State.Transact(ctx, input); err == nil {
				t.Fatal("launch plan accepted " + fault)
			}
			actual, err := f.State.LaunchPlan(ctx, f.Execution, f.Reservation.ID)
			if err != nil || !reflect.DeepEqual(actual, f.Record) {
				t.Fatal("refused plan partially changed the reserved record", err)
			}
		})
	}
	control := fx.New(t)
	control.Reserve(t)
	input := sourcedWrite(t, control)
	if _, err := control.State.Transact(context.Background(), input); err != nil {
		t.Fatal("current launch plan source transition failed", err)
	}
	actual, err := control.State.LaunchPlan(context.Background(), control.Execution, control.Reservation.ID)
	if err != nil || !reflect.DeepEqual(actual, input.Writes.LaunchPlans[0]) {
		t.Fatal("source transition changed its committed plan", err)
	}
	replay, err := control.State.Transact(context.Background(), input)
	if err != nil || !replay.Replayed {
		t.Fatal("identical plan transaction did not replay", err)
	}
	input.Compare = append(input.Compare, api.Compare{Kind: api.CompareRecord, ID: fx.ID(t)})
	if _, err := control.State.Transact(context.Background(), input); err == nil {
		t.Fatal("plan replay accepted changed comparison inputs")
	} else {
		launchCode(t, err, api.CodeIdempotencyConflict)
	}
}

func TestLaunchBindingRestart(t *testing.T) {
	f := fx.Ready(t, true)
	ctx := context.Background()
	original := f.Binding
	if original.Recovery == nil || original.Identity.CommittedSeq == 0 {
		t.Fatal("binding did not retain the complete recovery tuple")
	}
	canonical, err := api.CanonicalJSON(fx.JSON(t, original.Record))
	if err != nil {
		t.Fatal(err)
	}
	if original.Identity.RecordSHA256 != fx.Digest(canonical) {
		t.Fatal("binding digest did not use the actual canonical record")
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal("bound launch did not reopen", err)
	}
	read, err := f.State.LaunchBinding(ctx, f.Reservation.LaunchID)
	if err != nil || !reflect.DeepEqual(read, original) {
		t.Fatal("restart changed the retained launch binding", err)
	}
	if _, err := f.State.LaunchPlan(ctx, f.Human, f.Reservation.ID); err == nil {
		t.Fatal("public human scope read private launch planning objects")
	} else {
		launchCode(t, err, api.CodeForbidden)
	}
	if _, err := f.State.LaunchBinding(ctx, fx.ID(t)); err == nil {
		t.Fatal("unknown launch produced a binding")
	} else {
		launchCode(t, err, api.CodeNotFound)
	}
}

func TestCaptureReplayRestart(t *testing.T) {
	f := fx.Ready(t, true)
	ctx := context.Background()
	data := []byte("stdout exact bytes " + string(fx.ID(t)))
	ref := f.CaptureData(t, data)
	request := f.AppendRequest(t, &ref, false)
	first, err := f.State.AppendCapture(ctx, f.Worker, request)
	if err != nil || first.Replayed || first.NextOffset != int64(len(data)) || first.Generation != 2 {
		t.Fatal("registered capture append failed", err)
	}
	retry, err := f.State.AppendCapture(ctx, f.Worker, request)
	if err != nil || !retry.Replayed || retry.RecordID != first.RecordID || retry.LastSeq != first.LastSeq {
		t.Fatal("stale-revision exact range replay changed its acknowledgement", err)
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal("capture state did not reopen", err)
	}
	state, err := f.State.CaptureState(ctx, f.Worker, f.Plan.Capture.ID)
	if err != nil || state.Generation != 2 || state.Positions[0].NextOffset != first.NextOffset || state.Positions[0].EOF {
		t.Fatal("restart lost capture offsets", err)
	}
	retry, err = f.State.AppendCapture(ctx, f.Worker, request)
	if err != nil || !retry.Replayed || retry.RecordID != first.RecordID {
		t.Fatal("restart recaptured an acknowledged range", err)
	}
	eof := f.AppendRequest(t, nil, true)
	eof.ExpectedGeneration, eof.Offset = state.Generation, first.NextOffset
	closed, err := f.State.AppendCapture(ctx, f.Worker, eof)
	if err != nil || !closed.EOF || closed.NextOffset != first.NextOffset {
		t.Fatal("actual producer EOF acknowledgement failed", err)
	}
	state, err = f.State.CaptureState(ctx, f.Worker, f.Plan.Capture.ID)
	if err != nil || !state.Positions[0].EOF || state.Generation != 3 {
		t.Fatal("capture EOF state was not retained", err)
	}
	verification, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("capture journal/acknowledgements did not verify", err)
	}
}

func TestCaptureRangeGuards(t *testing.T) {
	for _, fault := range []string{"changed_bytes", "offset_hole", "stale_revision", "foreign_producer", "foreign_binding", "foreign_operation", "foreign_requester", "foreign_stream", "eof_with_data", "after_eof", "old_epoch", "missing_bytes", "wrong_hash", "wrong_class"} {
		t.Run(fault, func(t *testing.T) {
			f := fx.Ready(t, true)
			ctx := context.Background()
			ref := f.CaptureData(t, []byte("first "+string(fx.ID(t))))
			request := f.AppendRequest(t, &ref, false)
			first, err := f.State.AppendCapture(ctx, f.Worker, request)
			if err != nil {
				t.Fatal("capture guard positive control failed", err)
			}
			next := f.CaptureData(t, []byte("second "+string(fx.ID(t))))
			bad := f.AppendRequest(t, &next, false)
			bad.Offset, bad.ExpectedGeneration = first.NextOffset, first.Generation
			scope := f.Worker
			switch fault {
			case "changed_bytes":
				bad.Offset, bad.ExpectedGeneration = 0, 1
			case "offset_hole":
				bad.Offset++
			case "stale_revision":
				bad.ExpectedGeneration = 1
			case "foreign_producer":
				scope.Actor.ID = fx.ID(t)
				bad.Intent.Actor = scope.Actor
			case "foreign_binding":
				bad.BindingID = fx.ID(t)
			case "foreign_operation":
				bad.Intent.CauseOperationID = fx.ID(t)
			case "foreign_requester":
				bad.Intent.RequestedBy.ID = fx.ID(t)
			case "foreign_stream":
				bad.StreamID = fx.ID(t)
			case "eof_with_data":
				bad.EOF = true
			case "after_eof":
				eof := f.AppendRequest(t, nil, true)
				eof.ExpectedGeneration, eof.Offset = first.Generation, first.NextOffset
				closed, err := f.State.AppendCapture(ctx, f.Worker, eof)
				if err != nil {
					t.Fatal(err)
				}
				bad.ExpectedGeneration = closed.Generation
			case "old_epoch":
				bad.Intent.CancellationEpoch++
			case "missing_bytes":
				copy := next
				copy.ID = fx.ID(t)
				bad.Data = &copy
			case "wrong_hash":
				copy := next
				copy.SHA256 = fx.Digest([]byte("unrelated"))
				bad.Data = &copy
			case "wrong_class":
				copy := next
				copy.Class = "report"
				bad.Data = &copy
			}
			if _, err := f.State.AppendCapture(ctx, scope, bad); err == nil {
				t.Fatal("capture range accepted " + fault)
			}
		})
	}
}

func TestCaptureIngressCannotBeGeneric(t *testing.T) {
	f := fx.Ready(t, true)
	ref := f.CaptureData(t, []byte("captured "+string(fx.ID(t))))
	request := f.AppendRequest(t, &ref, false)
	record := api.CaptureRecord{ID: fx.ID(t), BindingID: f.Plan.Capture.ID, Target: f.Reservation.Target, Stream: "stdout", Data: ref, Primary: true, Coverage: "partial", ObservedAt: fx.Expiry()}
	event := f.Event(t, "capture.appended", record)
	event.Actor = f.Worker.Actor
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Worker, Internal: &request.Intent, Events: []api.Event{event}}); err == nil {
		t.Fatal("generic transaction forged primary capture provenance")
	} else {
		launchCode(t, err, api.CodeForbidden)
	}
}

func TestLaunchMissingRecovery(t *testing.T) {
	f := fx.Ready(t, true)
	broken := f.Binding
	broken.Recovery = nil
	f.Corrupt(t, "launch_binding", broken.Record.ID, 1, broken)
	reopened, err := store.New(f.Deps)
	if err == nil {
		if closeErr := reopened.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("restart accepted missing retained recovery")
	}
	launchCode(t, err, api.CodeIntegrity)
}

func TestLaunchEffectCompletion(t *testing.T) {
	f := fx.Ready(t, true)
	ctx := context.Background()
	invalid := api.EffectOutcome{EffectID: f.Claim.Record.Effect.ID, ClaimID: f.Claim.ClaimID, ExpectedGeneration: f.Claim.Record.Generation, Status: "succeeded", LaunchPlan: &f.Plan}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, invalid); err == nil {
		t.Fatal("planning success accepted an unopened gate")
	}
	f.Opened(t)
	operation, err := f.State.Operation(ctx, f.Execution, f.Reservation.OperationID)
	if err != nil || operation.Status != "succeeded" {
		t.Fatal("observed plan completion did not finish its actual operation", err)
	}
	key := api.RequestKey{Method: f.Human.Request.Method, IdempotencyKey: f.Human.Request.IdempotencyKey, RequestSHA256: f.Human.Request.RequestSHA256}
	receipt, err := f.State.LookupReceipt(ctx, f.Human, key)
	var original api.Operation
	if err != nil || receipt.Reply == nil || json.Unmarshal(receipt.Reply.Result, &original) != nil || original.Status != "pending" {
		t.Fatal("measured completion rewrote the original public reply", err)
	}
	complete := api.EffectOutcome{EffectID: f.Claim.Record.Effect.ID, ClaimID: f.Claim.ClaimID, ExpectedGeneration: f.Claim.Record.Generation, Status: "succeeded", LaunchPlan: &f.Plan, Process: &f.Process}
	replayed, err := f.State.CompleteEffect(ctx, f.Execution, complete)
	if err != nil || !replayed.Replayed {
		t.Fatal("exact measured completion did not replay", err)
	}
	foreign := f.Execution
	foreign.Actor.ID = fx.ID(t)
	if _, err := f.State.CompleteEffect(ctx, foreign, complete); err == nil {
		t.Fatal("another claimant replayed a launch completion")
	} else {
		launchCode(t, err, api.CodeForbidden)
	}
	changed := complete
	different := f.Process
	different.ID = fx.ID(t)
	changed.Process = &different
	if _, err := f.State.CompleteEffect(ctx, f.Execution, changed); err == nil {
		t.Fatal("completed launch accepted changed measured process")
	} else {
		launchCode(t, err, api.CodeConflict)
	}
}

func TestLaunchRetainedReservation(t *testing.T) {
	for _, mode := range []string{"resume", "turn"} {
		t.Run(mode, func(t *testing.T) {
			f := fx.ControlledChild(t)
			f.Opened(t)
			f.Ended(t)
			old := f.Reservation
			if mode == "resume" {
				f.Admit(t, "lane.resume", api.ResumeRequest{Target: old.Target, ExpectedGeneration: f.Lane.Generation, Message: f.Start.Task, Budget: f.Lane.BudgetRemaining})
			} else {
				message := f.Start.Task
				f.Admit(t, "lane.turn", api.TurnRequest{Target: old.Target, ExpectedGeneration: f.Lane.Generation, MailIDs: []api.ID{}, IdleMessage: &message, Budget: f.Lane.BudgetRemaining})
			}
			next, err := f.State.ReserveLaunch(context.Background(), f.Human, f.ReservationRequest(t))
			if err != nil || next.Target.LifeID != old.Target.LifeID || next.Target.Run != old.Target.Run+1 || next.LaunchID == old.LaunchID || next.PreviousLaunchID != old.LaunchID || next.GrantSetID != old.GrantSetID || next.RequestedBy != f.Human.Actor || next.BaseGeneration != f.Lane.Generation {
				t.Fatal("retained reservation replaced a life, grant set, requester or run fence", err)
			}
		})
	}
}

func TestLaunchRetainedGuards(t *testing.T) {
	for _, fault := range []string{"stale_base", "budget_reset", "foreign_home", "foreign_workspace", "running", "cleaned"} {
		t.Run(fault, func(t *testing.T) {
			f := fx.ControlledChild(t)
			f.Opened(t)
			f.Ended(t)
			target := f.Reservation.Target
			generation, budget := f.Lane.Generation, f.Lane.BudgetRemaining
			switch fault {
			case "stale_base":
				generation--
			case "budget_reset":
				budget.WallMS++
			case "foreign_home":
				f.Lane.Session.HomeID = fx.ID(t)
				f.Replace(t, "lane", f.Lane.LifeID, f.Lane.Generation, f.Lane)
			case "foreign_workspace":
				f.Lane.Workspace.LogicalCWD = "/caller/work"
				f.Replace(t, "lane", f.Lane.LifeID, f.Lane.Generation, f.Lane)
			case "running":
				f.Lane.State = "running"
				f.Replace(t, "lane", f.Lane.LifeID, f.Lane.Generation, f.Lane)
			case "cleaned":
				f.Lane.Cleaned = true
				f.Replace(t, "lane", f.Lane.LifeID, f.Lane.Generation, f.Lane)
			}
			f.Admit(t, "lane.resume", api.ResumeRequest{Target: target, ExpectedGeneration: generation, Message: f.Start.Task, Budget: budget})
			if _, err := f.State.ReserveLaunch(context.Background(), f.Human, f.ReservationRequest(t)); err == nil {
				t.Fatal("retained launch accepted changed private state, budget or base", fault)
			}
		})
	}
}

func TestLaunchParentReservation(t *testing.T) {
	f := fx.Ready(t, true)
	f.Opened(t)
	ctx := context.Background()
	parent := f.Binding.Record
	data := []byte("parent-owned child task " + string(fx.ID(t)))
	cause := f.Intent(t, api.InternalObjectRetain)
	task, err := f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: "task", Bytes: data, SHA256: fx.Digest(data), Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: parent.Actor, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	connection := &fx.Connection{Identity: fx.ID(t), Endpoint: api.InstalledBinding{Config: f.Deps.Config, Class: api.EndpointLane, EndpointGeneration: parent.EndpointGeneration, LaunchID: parent.ID, Target: &parent.Target}, Verified: &fx.Peer{FactsValue: api.PeerFacts{HostUID: parent.HostUID, HostPID: 1, ProcessGeneration: "component-child-connector", ContainmentID: parent.ContainmentID}}}
	f.Human = api.Scope{Config: f.Deps.Config, Actor: parent.Actor, LaunchID: parent.ID, EndpointGeneration: parent.EndpointGeneration, PolicyGeneration: parent.PolicyGeneration, Connection: connection, Source: "cli"}
	start := f.Start
	start.Lane = string(fx.ID(t))
	start.Level, start.Role, start.RootTicketID, start.Task = 3, "executor", "", task
	start.ProfileGrantID = f.Plan.Inputs.Grants.Profiles[0].ID
	start.Grants.Data = append([]api.DataGrantRequest{}, start.Grants.Data...)
	start.Grants.Profiles = append([]api.ProfileDelegation{}, start.Grants.Profiles...)
	start.Grants.Data[0].ParentGrantID = f.Plan.Inputs.Grants.Data[0].ID
	start.Grants.Profiles[0].ParentGrantID = f.Plan.Inputs.Grants.Profiles[0].ID
	start.Grants.Data[0].ExpiresAt, start.Grants.Profiles[0].ExpiresAt = api.Timestamp(time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339Nano)), api.Timestamp(time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339Nano))
	f.Admit(t, "lane.start", start)
	child, err := f.State.ReserveLaunch(ctx, f.Human, f.ReservationRequest(t))
	if err != nil || child.ParentLifeID != parent.Target.LifeID || child.RootLifeID != parent.RootLifeID || child.StarterEventSeq == 0 || len(child.StarterChain) != 1 || child.StarterChain[0] != parent.Target.LifeID || child.Target.LifeID == parent.Target.LifeID {
		t.Fatal("child reservation did not use its authentic starter event and chain", err)
	}
	start.Lane = string(fx.ID(t))
	start.Level = parent.Actor.Level
	f.Admit(t, "lane.start", start)
	if _, err := f.State.ReserveLaunch(ctx, f.Human, f.ReservationRequest(t)); err == nil {
		t.Fatal("child reservation bypassed D9")
	}
}

func TestCaptureLeaseFence(t *testing.T) {
	f := fx.Ready(t, true)
	ctx := context.Background()
	ref := f.CaptureData(t, []byte("lease-bound capture "+string(fx.ID(t))))
	request := f.AppendRequest(t, &ref, false)
	if _, err := f.State.AppendCapture(ctx, f.Worker, request); err != nil {
		t.Fatal("capture lease positive control failed", err)
	}
	foreign := f.WorkerLease
	foreign.ID = fx.ID(t)
	foreign.Kind = "archive"
	f.Replace(t, "worker_lease", foreign.ID, foreign.Generation, foreign)
	connection := f.Worker.Connection.(*fx.Connection)
	connection.Endpoint.WorkerLeaseID = foreign.ID
	if _, err := f.State.AppendCapture(ctx, f.Worker, request); err == nil {
		t.Fatal("foreign worker endpoint replayed another capture lease")
	}
}

func TestCapturePipeOwnership(t *testing.T) {
	f := fx.Ready(t, true)
	binding := f.Plan.Capture
	binding.ID = fx.ID(t)
	cause := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Events: []api.Event{f.Event(t, "capture.bound", binding)}}); err == nil {
		t.Fatal("capture registration reused another binding's one-use pipe")
	} else {
		launchCode(t, err, api.CodeConflict)
	}
}

func continuationSetup(t *testing.T) (*fx.Fixture, api.ContinuationClaimRequest) {
	t.Helper()
	f := fx.Ready(t, true)
	ctx := context.Background()
	data := f.CaptureData(t, []byte("component pinned limit input "+string(fx.ID(t))))
	captured, err := f.State.AppendCapture(ctx, f.Worker, f.AppendRequest(t, &data, false))
	if err != nil {
		t.Fatal(err)
	}
	evidence := f.Retain(t, "manifest", []byte("component eligibility evidence "+string(fx.ID(t))), f.Execution.Actor, f.Reservation.Target.LifeID)
	f.Opened(t)
	f.Ended(t)
	profile := f.Plan.Inputs.Grants.Profiles[0]
	eligible := api.ProfileEligibility{ID: fx.ID(t), Request: api.ProfileEligibilityRequest{Target: f.Reservation.Target, GrantSetID: f.Reservation.GrantSetID, FromGrantID: profile.ID, ToGrantID: profile.ID, Driver: f.Lane.Session.Driver, Model: f.Lane.Model, Session: f.Lane.Session, HistoryID: f.Lane.Session.HistoryID}, Compatible: true, Reason: "component retained eligibility", Evidence: evidence, CheckedAt: fx.Expiry(), ExpiresAt: fx.Expiry()}
	cause := f.Intent(t, api.InternalProfileContinue)
	cause.EffectID, cause.CauseOperationID, cause.CauseRequestID = fx.ID(t), fx.ID(t), fx.ID(t)
	cause.RequestedBy = api.Actor{Kind: "watchdog", ID: fx.ID(t)}
	cause.LogicalTurnID = f.Lane.LogicalTurnID
	swap := api.ProfileSwap{ProfileGrantID: profile.ID, EligibilityID: eligible.ID, ExpectedGeneration: f.Lane.Generation, CancellationEpoch: f.Lane.CancellationEpoch, FromProfileID: profile.ProfileID, ToProfileID: profile.ProfileID, CausingRun: f.Lane.Run, ContinuationRun: f.Lane.Run + 1, LogicalTurnID: f.Lane.LogicalTurnID,
		Limit: api.LimitSignal{Target: f.Reservation.Target, Kind: "quota", ProfileID: profile.ProfileID, Provider: "component-provider", CaptureID: captured.RecordID, CaptureSHA256: data.SHA256, AdapterVersion: "component-v1", ObservedAt: fx.Expiry()}, Room: api.Room{ProfileID: profile.ProfileID, Available: true, CheckedAt: fx.Expiry(), ExpiresAt: fx.Expiry(), Evidence: evidence, Reason: "component room observation"}, OperationID: cause.CauseOperationID}
	slot := f.Plan.Runner.Slot
	slot.ID, slot.LeaseID = fx.ID(t), fx.ID(t)
	intent := api.ContinuationIntent{ID: fx.ID(t), Target: f.Reservation.Target, LogicalTurnID: f.Lane.LogicalTurnID, ExpectedGeneration: f.Lane.Generation, CancellationEpoch: f.Lane.CancellationEpoch, Generation: 1, Status: "pending", Swap: swap, Eligibility: eligible, Slot: &slot, OperationID: cause.CauseOperationID}
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Swap: &swap}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Continuations: []api.ContinuationIntent{intent}}, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal("component continuation intent was not retained", err)
	}
	if _, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()}); err != nil {
		t.Fatal(err)
	}
	return f, api.ContinuationClaimRequest{Intent: cause, Request: api.ContinuationRequest{IntentID: intent.ID, Swap: swap}}
}

func TestContinuationLaunchReservation(t *testing.T) {
	f, request := continuationSetup(t)
	ctx := context.Background()
	claimed, err := f.State.ClaimContinuation(ctx, f.Execution, request)
	if err != nil || claimed.Status != "claimed" {
		t.Fatal("actual durable continuation claim failed", err)
	}
	reservation, err := f.State.ReserveLaunch(ctx, f.Execution, api.LaunchReservationRequest{OperationID: claimed.OperationID, ContinuationID: claimed.ID, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: f.Lane.LifeID, Epoch: f.Lane.CancellationEpoch}}}})
	if err != nil || reservation.Mode != "continue" || reservation.Target.LifeID != f.Lane.LifeID || reservation.Target.Run != f.Lane.Run+1 || reservation.RequestedBy != request.Intent.RequestedBy || reservation.PreviousLaunchID != f.Reservation.LaunchID || reservation.GrantSetID != f.Reservation.GrantSetID {
		t.Fatal("continuation reservation reset or relabelled its original life and requester", err)
	}
	read, err := f.State.LaunchPlan(ctx, f.Execution, reservation.ID)
	if err != nil || read.Reservation.RequestSHA256 != reservation.OriginalRequest.SHA256 {
		t.Fatal("internal continuation input bytes were not retained", err)
	}
	retry, err := f.State.ReserveLaunch(ctx, f.Execution, api.LaunchReservationRequest{OperationID: claimed.OperationID, ContinuationID: claimed.ID, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: f.Lane.LifeID, Epoch: f.Lane.CancellationEpoch}}}})
	if err != nil || !reflect.DeepEqual(retry, reservation) {
		t.Fatal("continuation replay reserved another run", err)
	}
}

func TestContinuationLaunchGuards(t *testing.T) {
	for _, fault := range []string{"foreign_actor", "changed_swap", "old_epoch", "changed_turn", "foreign_slot"} {
		t.Run(fault, func(t *testing.T) {
			f, request := continuationSetup(t)
			scope := f.Execution
			original := request
			claim, err := f.State.Effect(context.Background(), scope, request.Intent.EffectID)
			if err != nil || claim.State != api.EffectClaimed || claim.Outcome != nil || claim.ClaimantID != scope.Actor.ID {
				t.Fatal("continuation guard lacks its real claimed effect", err)
			}
			switch fault {
			case "foreign_actor":
				scope.Actor.ID = fx.ID(t)
				request.Intent.Actor = scope.Actor
			case "changed_swap":
				request.Request.Swap.ToProfileID = fx.ID(t)
			case "old_epoch":
				request.Intent.CancellationEpoch++
			case "changed_turn":
				request.Request.Swap.LogicalTurnID = fx.ID(t)
			case "foreign_slot":
				intent, err := f.State.ContinuationIntent(context.Background(), f.Execution, request.Request.IntentID)
				if err != nil {
					t.Fatal(err)
				}
				slot := *intent.Slot
				slot.ProfileID = fx.ID(t)
				intent.Slot = &slot
				f.Replace(t, "continuation", intent.ID, intent.Generation, intent)
			}
			if _, err := f.State.ClaimContinuation(context.Background(), scope, request); err == nil {
				t.Fatal("continuation claim accepted " + fault)
			} else {
				launchCode(t, err, api.CodeConflict)
			}
			if fault == "old_epoch" {
				pending, err := f.State.ContinuationIntent(context.Background(), f.Execution, original.Request.IntentID)
				if err != nil || pending.Status != "pending" || pending.Generation != 1 {
					t.Fatal("epoch refusal consumed the pending continuation", err)
				}
				claimed, err := f.State.ClaimContinuation(context.Background(), f.Execution, original)
				if err != nil || claimed.Status != "claimed" || claimed.Generation != pending.Generation+1 || claimed.ID != pending.ID || claimed.OperationID != pending.OperationID {
					t.Fatal("current epoch could not claim the original continuation", err)
				}
			}
		})
	}
}

// The existing launch fixture supplies component helper/capture receipts.
// Only the real SQLite writer reserves and claims the continuation here;
// no fixture reports a replacement process, login or successful launch.
func pendingCase(t *testing.T) (*fx.Fixture, api.Scope, api.LaunchReservationRequest) {
	t.Helper()
	f, prior := continuationSetup(t)
	ctx := context.Background()
	i, err := f.State.ContinuationIntent(ctx, f.Execution, prior.Request.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: f.Deps.Config, Source: "watchdog", Actor: prior.Intent.RequestedBy, PolicyGeneration: f.Lane.PolicyGeneration}
	i.ID, i.Generation, i.Status, i.Slot = fx.ID(t), 1, "pending", nil
	i.OperationID, i.Swap.OperationID = "", ""
	next := f.Lane
	next.Generation++
	next.State = "profile_wait"
	i.ExpectedGeneration, i.Swap.ExpectedGeneration = next.Generation, next.Generation
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalProfileContinue, Config: scope.Config,
		Actor: scope.Actor, RequestedBy: f.Reservation.RequestedBy, Target: i.Target,
		CauseOperationID: f.Reservation.OperationID, CauseRequestID: f.Reservation.RequestID,
		LogicalTurnID: i.LogicalTurnID, CancellationEpoch: i.CancellationEpoch}
	commit, err := f.State.Transact(ctx, api.Transaction{Scope: scope, Internal: &cause,
		Writes: api.StateWrites{Lanes: []api.Lane{next}, Continuations: []api.ContinuationIntent{i}},
		Compare: []api.Compare{{Kind: api.CompareLane, ID: next.LifeID, Generation: f.Lane.Generation},
			{Kind: api.CompareGrants, ID: f.Plan.Inputs.Grants.ID, Generation: f.Plan.Inputs.Grants.Generation},
			{Kind: api.CompareContinuation, ID: i.ID}},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: next.LifeID, Epoch: next.CancellationEpoch}}}})
	if err != nil {
		t.Fatal(err)
	}
	f.Lane = next
	return f, scope, api.LaunchReservationRequest{OperationID: commit.Operation.ID, ContinuationID: i.ID,
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: next.LifeID, Epoch: next.CancellationEpoch}}}}
}

func TestPendingReserve(t *testing.T) {
	f, scope, request := pendingCase(t)
	ctx := context.Background()
	before := f.Lane
	r, err := f.State.ReserveLaunch(ctx, scope, request)
	if err != nil {
		t.Fatal("slot-free continuation cannot reach its leased planner", err)
	}
	if r.Mode != "continue" || r.Target.LifeID != before.LifeID || r.Target.Run != before.Run+1 || r.BaseGeneration != before.Generation || r.PreviousLaunchID != before.LaunchID {
		t.Fatal("continuation reservation lost the retained run fence")
	}
	i, err := f.State.ContinuationIntent(ctx, scope, request.ContinuationID)
	if err != nil || i.Status != "claimed" || i.Slot != nil || i.OperationID != request.OperationID {
		t.Fatal("reservation invented a slot or completed a launch", err)
	}
	op, err := f.State.Operation(ctx, scope, request.OperationID)
	if err != nil || op.Status != "pending" || op.Run != r.Target.Run {
		t.Fatal("reservation reported a completed continuation", err)
	}
	replay, err := f.State.ReserveLaunch(ctx, scope, request)
	if err != nil || !reflect.DeepEqual(r, replay) {
		t.Fatal("replay minted another plan", err)
	}
	plan, err := f.State.LaunchPlan(ctx, scope, r.ID)
	if err != nil || plan.Phase != "reserved" || plan.Reservation.RequestedBy != scope.Actor {
		t.Fatal("continuation lost its exact requester or retained bytes", err)
	}
	data, err := f.State.Blob(ctx, scope, api.BlobReadRequest{ObjectID: r.OriginalRequest.ID, Limit: api.MaxChunkBytes})
	var input api.ContinuationRequest
	if err != nil || api.DecodeObject(data.Data, &input) != nil || input.IntentID != i.ID || input.Swap != i.Swap {
		t.Fatal("planner did not retain the actual continuation input", err)
	}
}

func TestPendingFences(t *testing.T) {
	for _, fault := range []string{"config", "epoch", "operation", "missing"} {
		t.Run(fault, func(t *testing.T) {
			f, scope, request := pendingCase(t)
			switch fault {
			case "config":
				scope.Config += "-other"
			case "epoch":
				request.Guards[0].Cancellation.Epoch++
			case "operation":
				request.OperationID = fx.ID(t)
			case "missing":
				request.ContinuationID = fx.ID(t)
			}
			if _, err := f.State.ReserveLaunch(context.Background(), scope, request); err == nil {
				t.Fatal("foreign or missing continuation authority passed", fault)
			}
		})
	}
}

func TestContSlot(t *testing.T) {
	f, scope, q := pendingCase(t)
	ctx := context.Background()
	r, err := f.State.ReserveLaunch(ctx, scope, q)
	if err != nil {
		t.Fatal(err)
	}
	execScope := api.Scope{Config: scope.Config, Actor: api.Actor{Kind: "service", ID: fx.ID(t)}, Source: "worker", PolicyGeneration: scope.PolicyGeneration}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var chosen api.Effect
	for _, effect := range effects {
		if effect.PlanLaunch != nil && effect.OperationID == q.OperationID {
			chosen = effect
		}
	}
	lease, err := f.State.ClaimEffect(ctx, execScope, api.EffectClaimRequest{EffectID: chosen.ID, ExpectedGeneration: 1, ClaimantID: execScope.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	ctx = api.WithEffectLease(ctx, lease)
	keeper, ok := any(f.State).(interface {
		KeepContinueSlot(context.Context, api.Scope, api.LaunchPlanRequest, api.CredentialSlot) (api.ContinuationIntent, error)
	})
	if !ok {
		t.Fatal("store has no live-claim slot handoff")
	}
	slot := f.Plan.Runner.Slot
	slot.ID, slot.LeaseID = fx.ID(t), fx.ID(t)
	request := api.LaunchPlanRequest{Lease: lease}
	if _, err := keeper.KeepContinueSlot(ctx, execScope, request, slot); err == nil {
		t.Fatal("slot without its actual retained stage passed")
	}
	profile := f.Plan.Inputs.Grants.Profiles[0]
	input, err := api.CanonicalJSON(fx.JSON(t, profile))
	if err != nil {
		t.Fatal(err)
	}
	result := fx.JSON(t, struct {
		Schema string             `json:"schema"`
		Input  api.Digest         `json:"input"`
		Value  api.CredentialSlot `json:"value"`
	}{"laneboss.launch-stage.v2", fx.Digest(input), slot})
	cause := *lease.Record.Effect.Context
	cause.ID, cause.Actor = fx.ID(t), execScope.Actor
	id := api.ID(fx.Digest([]byte("launch\x00" + string(r.ID) + "\x00result-credential-slot")))
	_, err = f.State.RetainObject(ctx, execScope, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{
		ObjectKey: id, Class: "manifest", Bytes: result, SHA256: fx.Digest(result), Origin: "service",
		ACL: api.ObjectACL{Config: scope.Config, Owner: execScope.Actor, LifeID: r.Target.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal("could not retain actual slot result", err)
	}
	kept, err := keeper.KeepContinueSlot(ctx, execScope, request, slot)
	if err != nil || kept.Status != "claimed" || kept.Slot == nil || *kept.Slot != slot {
		t.Fatal("actual slot was not retained under its live claim", err)
	}
	replay, err := keeper.KeepContinueSlot(ctx, execScope, request, slot)
	if err != nil || !reflect.DeepEqual(replay, kept) {
		t.Fatal("slot replay changed its durable handoff", err)
	}
	changed := slot
	changed.ID = fx.ID(t)
	if _, err := keeper.KeepContinueSlot(ctx, execScope, request, changed); err == nil {
		t.Fatal("second slot replaced the retained acquisition")
	}
	foreign := execScope
	foreign.Actor.ID = fx.ID(t)
	if _, err := keeper.KeepContinueSlot(ctx, foreign, request, slot); err == nil {
		t.Fatal("foreign claimant retained a slot")
	}
	request.Lease.ClaimID = fx.ID(t)
	if _, err := keeper.KeepContinueSlot(ctx, execScope, request, slot); err == nil {
		t.Fatal("stale claim retained a slot")
	}
}

func TestContOpen(t *testing.T) {
	f, scope, q := pendingCase(t)
	ctx := context.Background()
	prior, lane := f.Plan, f.Lane
	turn, err := f.State.Turn(ctx, f.Execution, api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, lane.LogicalTurnID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.State.ReserveLaunch(ctx, scope, q)
	if err != nil {
		t.Fatal(err)
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range effects {
		if effect.PlanLaunch != nil && effect.PlanLaunch.ReservationID == r.ID {
			f.Claim, err = f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	f.Reservation = r
	f.Record, err = f.State.LaunchPlan(ctx, f.Execution, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	inputs := prior.Inputs
	inputs.Sources.ReservationID = r.ID
	next := f.Record
	next.Generation++
	next.Phase, next.Inputs = "sourced", &inputs
	cause := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{next}},
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: f.Record.Generation}}, Guards: q.Guards}); err != nil {
		t.Fatal("continued sources", err)
	}
	f.Record = next
	f.PlanSetup = func(p *api.LaunchPlan) {
		p.Data.Home, p.Data.Workspace = prior.Data.Home, prior.Data.Workspace
		p.Data.Materialization.Objects[0].WorkspaceID = prior.Data.Workspace.ID
		p.Data.Materialization.Objects[0].SnapshotSHA256 = prior.Data.Workspace.Snapshot.SHA256
		p.Runner.Home, p.Runner.Session, p.Runner.Prompt = prior.Runner.Home, lane.Session, prior.Runner.Prompt
		p.Budget = lane.BudgetRemaining
		profile := inputs.Grants.Profiles[0]
		input, err := api.CanonicalJSON(fx.JSON(t, profile))
		if err != nil {
			t.Fatal(err)
		}
		raw := fx.JSON(t, struct {
			Schema string             `json:"schema"`
			Input  api.Digest         `json:"input"`
			Value  api.CredentialSlot `json:"value"`
		}{"laneboss.launch-stage.v2", fx.Digest(input), p.Runner.Slot})
		id := api.ID(fx.Digest([]byte("launch\x00" + string(r.ID) + "\x00result-credential-slot")))
		if _, err := f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{ObjectKey: id, Class: "manifest", Bytes: raw, SHA256: fx.Digest(raw), Origin: "service",
			ACL: api.ObjectACL{Config: scope.Config, Owner: f.Execution.Actor, LifeID: r.Target.LifeID, Audience: "owner", Generation: 1}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.State.KeepContinueSlot(api.WithEffectLease(ctx, f.Claim), f.Execution, api.LaunchPlanRequest{Lease: f.Claim}, p.Runner.Slot); err != nil {
			t.Fatal(err)
		}
	}
	f.BuildPlan(t, true)
	f.Spec(t)
	f.PreparedClaim = api.EffectLease{}
	turn.Target = r.Target
	f.Bind(t, turn)
	f.Opened(t)
	i, err := f.State.ContinuationIntent(ctx, scope, q.ContinuationID)
	if err != nil || i.Status != "completed" {
		t.Fatal("actual opened continuation did not complete", err)
	}
	op, err := f.State.Operation(ctx, scope, q.OperationID)
	if err != nil || op.Status != "succeeded" || op.Run != r.Target.Run {
		t.Fatal("opened continuation lost its one operation", err)
	}
	if f.Lane.Session != lane.Session || f.Lane.Workspace != lane.Workspace || f.Lane.BudgetRemaining != lane.BudgetRemaining || f.Lane.Counters != lane.Counters || f.Lane.LogicalTurnID != lane.LogicalTurnID {
		t.Fatal("continued run reset retained task state")
	}
	complete := api.EffectOutcome{EffectID: f.Claim.Record.Effect.ID, ClaimID: f.Claim.ClaimID, ExpectedGeneration: f.Claim.Record.Generation, Status: "succeeded", LaunchPlan: &f.Plan, Process: &f.Process}
	if replay, err := f.State.CompleteEffect(ctx, f.Execution, complete); err != nil || !replay.Replayed || replay.Operation.ID != q.OperationID {
		t.Fatal("opened continuation did not replay its one completion", err)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: r.Target.LifeID})
	if err != nil {
		t.Fatal(err)
	}
	swaps := 0
	for _, event := range page.Events {
		if event.Kind != "watchdog.swapped" {
			continue
		}
		var payload api.WatchdogEvent
		if api.DecodeObject(event.Payload, &payload) != nil || event.OperationID != q.OperationID || payload.Swap == nil || *payload.Swap != i.Swap {
			t.Fatal("opened swap event lost its original operation")
		}
		swaps++
	}
	if swaps != 1 {
		t.Fatal("completion repeated or omitted the opened swap event")
	}
	if verified, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
		t.Fatal("continued history failed verification", err)
	}
}

func frameCase(t *testing.T, closeAll bool) (*fx.Fixture, []byte) {
	t.Helper()
	f := fx.Ready(t, true)
	ctx := context.Background()
	data := []byte("{\"type\":\"system\",\"nonce\":\"" + string(fx.ID(t)) + "\"}\n{\"type\":\"result\",\"is_error\":true}\n")
	offset, generation := int64(0), api.Generation(1)
	for _, part := range [][]byte{data[:9], data[9 : len(data)-5], data[len(data)-5:]} {
		ref := f.CaptureData(t, part)
		q := f.AppendRequest(t, &ref, false)
		q.Offset, q.ExpectedGeneration = offset, generation
		receipt, err := f.State.AppendCapture(ctx, f.Worker, q)
		if err != nil {
			t.Fatal(err)
		}
		offset, generation = receipt.NextOffset, receipt.Generation
	}
	if closeAll {
		for n, stream := range f.Plan.Capture.Streams {
			q := f.AppendRequest(t, nil, true)
			q.StreamID, q.ExpectedGeneration = stream.ID, generation
			if n == 0 {
				q.Offset = offset
			}
			receipt, err := f.State.AppendCapture(ctx, f.Worker, q)
			if err != nil {
				t.Fatal(err)
			}
			generation = receipt.Generation
		}
	}
	f.Opened(t)
	f.Ended(t)
	return f, data
}

func TestFrames(t *testing.T) {
	f, raw := frameCase(t, true)
	ctx := context.Background()
	port, ok := any(f.State).(interface {
		FrameCapture(context.Context, api.Scope, api.ID) ([]api.CaptureRecord, error)
		CaptureFrame(context.Context, api.ID) (api.CaptureRecord, []byte, error)
	})
	if !ok {
		t.Fatal("native capture has no honest frame port")
	}
	records, err := port.FrameCapture(ctx, f.Execution, f.Plan.Capture.ID)
	if err != nil || len(records) != 2 {
		t.Fatal("split raw chunks were not framed", err)
	}
	var combined []byte
	for _, record := range records {
		if !record.Primary || record.Coverage != "complete" || record.Offset != int64(len(combined)) || record.BindingID != f.Plan.Capture.ID {
			t.Fatal("frame lost its byte range")
		}
		saved, data, err := port.CaptureFrame(ctx, record.ID)
		if err != nil || saved != record || fx.Digest(data) != record.Data.SHA256 || len(bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))) != 1 {
			t.Fatal("frame lost its exact source bytes", err)
		}
		combined = append(combined, data...)
	}
	if !bytes.Equal(combined, raw) {
		t.Fatal("framing changed original bytes")
	}
	replay, err := port.FrameCapture(ctx, f.Execution, f.Plan.Capture.ID)
	if err != nil || !reflect.DeepEqual(replay, records) {
		t.Fatal("framing replay minted new records", err)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: f.Reservation.Target.LifeID})
	if err != nil {
		t.Fatal(err)
	}
	rawCount, frameCount := 0, 0
	for _, event := range page.Events {
		if event.Kind != "capture.appended" && event.Kind != "capture.framed" {
			continue
		}
		var record api.CaptureRecord
		if err := api.DecodeObject(event.Payload, &record); err != nil {
			t.Fatal(err)
		}
		if event.Kind == "capture.appended" {
			rawCount++
			if record.Coverage != "partial" {
				t.Fatal("framing rewrote raw coverage")
			}
			for _, frame := range records {
				if record.ID == frame.ID || record.Data.ID == frame.Data.ID {
					t.Fatal("framing aliased raw primary evidence")
				}
			}
		} else {
			frameCount++
		}
	}
	if rawCount != 3 || frameCount != len(records) {
		t.Fatal("framing lost raw chunks or repeated an event")
	}
	foreign := f.Execution
	foreign.Config += "-other"
	if _, err := port.FrameCapture(ctx, foreign, f.Plan.Capture.ID); err == nil {
		t.Fatal("foreign config framed capture")
	}
	if _, err := port.FrameCapture(ctx, f.LaneScope(t), f.Plan.Capture.ID); err == nil {
		t.Fatal("lane framed its own evidence")
	}
	if _, _, err := port.CaptureFrame(ctx, fx.ID(t)); err == nil {
		t.Fatal("missing source became a frame")
	}
	if _, err := port.FrameCapture(ctx, f.Execution, fx.ID(t)); err == nil {
		t.Fatal("foreign binding became a frame")
	}
	if result, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !result.OK {
		t.Fatal("derived frames broke retained-state verification", err)
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := f.State.FrameCapture(ctx, f.Execution, f.Plan.Capture.ID)
	if err != nil || !reflect.DeepEqual(restarted, records) {
		t.Fatal("restart replaced the framed evidence", err)
	}
}

func TestFramesNeedEOF(t *testing.T) {
	f, _ := frameCase(t, false)
	port, ok := any(f.State).(interface {
		FrameCapture(context.Context, api.Scope, api.ID) ([]api.CaptureRecord, error)
	})
	if !ok {
		t.Fatal("native capture has no honest frame port")
	}
	if _, err := port.FrameCapture(context.Background(), f.Execution, f.Plan.Capture.ID); err == nil {
		t.Fatal("incomplete streams became complete evidence")
	}
	state, err := f.State.CaptureState(context.Background(), f.Execution, f.Plan.Capture.ID)
	if err != nil {
		t.Fatal(err)
	}
	for n := range state.Positions {
		state.Positions[n].EOF = true
		state.Generation++
	}
	f.Corrupt(t, "capture_state", state.Binding.ID, state.Generation, state)
	reopened, err := store.New(f.Deps)
	if err == nil {
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("an EOF projection without its journal acknowledgements reopened")
	}
	launchCode(t, err, api.CodeIntegrity)
}

func TestContAuthority(t *testing.T) {
	f, scope, q := pendingCase(t)
	ctx := context.Background()
	r, err := f.State.ReserveLaunch(ctx, scope, q)
	if err != nil {
		t.Fatal(err)
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var lease api.EffectLease
	for _, e := range effects {
		if e.PlanLaunch != nil && e.PlanLaunch.ReservationID == r.ID {
			lease, err = f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: e.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	claim := api.PlanningClaim(r.ID, lease)
	markerID := fx.ID(t)
	marker := api.InitialPublicationMarker{Schema: "laneboss.initial-marker.v2", Config: f.Deps.Config, ID: markerID, Manifest: f.Plan.Inputs.Sources.Runtime.Manifest}
	snapshot := api.OrgSnapshot{Ref: api.OrgSnapshotRef{OrgID: api.ID(f.Deps.Config), Generation: 1, ManifestSHA256: marker.Manifest.SHA256}, Config: f.Deps.Config,
		Sources: []api.ResourceFile{}, Derived: []api.ResourceFile{}, PublishedBy: markerID, PublishedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	bootstrap := api.InternalIntent{ID: api.ID("initial-" + string(markerID)), Kind: api.InternalOrgBootstrap, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Execution.Actor, CauseOperationID: api.ID("initial-op-" + string(markerID)), CauseRequestID: markerID}
	event := api.Event{Schema: api.SchemaVersion, ID: api.ID("initial-event-" + string(markerID)), Config: f.Deps.Config, Kind: "org.bootstrapped", Actor: f.Execution.Actor, RequestedBy: f.Execution.Actor, Origin: "service", StarterChain: []api.ID{}, Payload: fx.JSON(t, marker)}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &bootstrap, Writes: api.StateWrites{OrgSnapshots: []api.OrgSnapshot{snapshot}}, Events: []api.Event{event}, Compare: []api.Compare{{Kind: api.CompareOrg, ID: api.ID(f.Deps.Config)}}}); err != nil {
		t.Fatal("component publication prerequisite failed", err)
	}
	actual, err := admin.CheckLaunchPlanningAuthority(api.WithEffectLease(ctx, lease), f.State, f.Deps.Config, claim)
	if err != nil || !reflect.DeepEqual(actual.Reservation, r) {
		t.Fatal("native source authority rejected the actual internal continuation", err)
	}
	changed := claim
	changed.ClaimID = fx.ID(t)
	if _, err := admin.CheckLaunchPlanningAuthority(ctx, f.State, f.Deps.Config, changed); err == nil {
		t.Fatal("foreign continuation claim passed native source authority")
	}
	if _, err := admin.CheckLaunchPlanningAuthority(ctx, f.State, f.Deps.Config+"-other", claim); err == nil {
		t.Fatal("foreign configuration passed native continuation authority")
	}
	intent, err := f.State.ContinuationIntent(ctx, scope, q.ContinuationID)
	if err != nil || intent.Status != "claimed" || intent.Slot != nil {
		t.Fatal("authority read acquired a slot or completed continuation", err)
	}
	op, err := f.State.Operation(ctx, scope, q.OperationID)
	if err != nil || op.Status != "pending" {
		t.Fatal("source authority read completed the pending selection", err)
	}
}
