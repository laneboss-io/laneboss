//go:build linux

package service

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/guidance"
	"laneboss.io/laneboss/internal/v2/judge"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestRevPromptPinnedView(t *testing.T) {
	f, request := sourcedPromptFixture(t)
	ctx := context.Background()
	view, err := f.State.BeginRead(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := view.Close(); err != nil {
			t.Error(err)
		}
	}()
	scope := f.Execution
	scope.ReadView = view
	if _, err := f.State.LaunchBriefingInput(ctx, scope, request); err != nil {
		t.Fatal("live pinned control failed", err)
	}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: request.Lease.Record.Effect.ID,
		ClaimID: request.Lease.ClaimID, ExpectedGeneration: request.Lease.Record.Generation, Status: "failed", Error: api.NotImplemented("lb-v2-grants", "review control")}); err != nil {
		t.Fatal("could not invalidate actual durable claim", err)
	}
	if input, err := f.State.LaunchBriefingInput(ctx, scope, request); err == nil || input.Lane != nil {
		t.Fatal("pinned view restored authority after actual effect completion", err)
	}
}

func retainedReviewPrompt(t *testing.T, mode string, mail []api.ID) (*fx.Fixture, api.LaunchPromptRequest) {
	t.Helper()
	f := fx.ControlledChild(t)
	f.Opened(t)
	f.Ended(t)
	prior := *f.Record.Inputs
	if mode == "resume" {
		f.Admit(t, "lane.resume", api.ResumeRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation, Message: f.Start.Task, Budget: f.Lane.BudgetRemaining})
	} else {
		message := f.Start.Task
		f.Admit(t, "lane.turn", api.TurnRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation, MailIDs: mail, IdleMessage: &message, Budget: f.Lane.BudgetRemaining})
	}
	f.Reserve(t)
	prior.Sources.ReservationID = f.Reservation.ID
	next := f.Record
	next.Phase, next.Inputs, next.Generation = "sourced", &prior, next.Generation+1
	cause := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes:  api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{next}},
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: f.Reservation.ID, Generation: f.Record.Generation}, {Kind: api.CompareGrants, ID: prior.Grants.ID, Generation: prior.Grants.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: f.Reservation.Target.LifeID, Epoch: f.Reservation.CancellationEpoch}}}}); err != nil {
		t.Fatal("could not retain actual sourced resume/turn", err)
	}
	f.Record = next
	installPlanningOrg(t, f)
	return f, api.LaunchPromptRequest{ReservationID: f.Reservation.ID, Lease: f.Claim}
}

func TestReviewRetainedPromptTurnSchema(t *testing.T) {
	for _, mode := range []string{"resume", "idle", "mail"} {
		t.Run(mode, func(t *testing.T) {
			mail := []api.ID{}
			if mode == "mail" {
				mail = []api.ID{fx.ID(t), fx.ID(t)}
			}
			f, request := retainedReviewPrompt(t, mode, mail)
			selector, err := guidance.New(guidance.Dependencies{Store: f.State, Judge: &judge.Service{}, Clock: f.Deps.Clock})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := selector.LaunchGuidance(context.Background(), f.Execution, request); err != nil {
				t.Fatal("retained public launch could not complete real guidance", err)
			}
			turn, err := f.State.Turn(context.Background(), f.Execution, f.Reservation.Target, f.Claim.Record.Effect.Context.LogicalTurnID)
			want := mode
			if mode == "resume" {
				want = "manual"
			}
			if err != nil || turn.Trigger.Kind != want || len(turn.MailIDs) != len(mail) || len(turn.Trigger.MailIDs) != len(mail) || turn.Generation != 2 {
				t.Fatal("retained turn lost its valid trigger or ordered mail references", err)
			}
			for i := range mail {
				if turn.MailIDs[i] != mail[i] || turn.Trigger.MailIDs[i] != mail[i] {
					t.Fatal("turn changed its original mail ordering")
				}
			}
		})
	}
}
func TestReviewPromptOriginalPins(t *testing.T) {
	for _, mutation := range []string{"driver", "project"} {
		t.Run(mutation, func(t *testing.T) {
			f, request := sourcedPromptFixture(t)
			changed := f.Record
			if mutation == "driver" {
				changed.Reservation.Driver = api.DriverClaudock
			} else {
				inputs := *changed.Inputs
				inputs.Sources.Project.ProjectID = fx.ID(t)
				changed.Inputs = &inputs
			}
			f.Replace(t, "launch_plan", changed.Reservation.ID, changed.Generation, changed)
			if input, err := f.State.LaunchBriefingInput(context.Background(), f.Execution, request); err == nil || input.Lane != nil {
				t.Fatal("launch prompt accepted pins that disagree with the original public frame", err)
			}
		})
	}
}

func TestReviewPromptAdoptPins(t *testing.T) {
	f := fx.New(t)
	installPlanningOrg(t, f)
	raw := fx.JSON(t, map[string]string{"component": string(fx.ID(t))})
	manifest := api.BlobRef{ID: fx.ID(t), Class: "manifest", Bytes: int64(len(raw)), SHA256: fx.Digest(raw)}
	cause := f.Intent(t, api.InternalOrgBootstrap)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes: api.StateWrites{Objects: []api.ObjectWrite{{ObjectKey: manifest.ID, Class: manifest.Class, Bytes: raw, SHA256: manifest.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Human.Actor, Audience: "owner", Generation: 1}}}}}); err != nil {
		t.Fatal(err)
	}
	start := f.Start
	f.Admit(t, "lane.adopt", api.AdoptRequest{Lane: start.Lane, Level: start.Level, Role: start.Role, Task: start.Task, Grants: start.Grants,
		Driver: start.Driver, ProfileGrantID: start.ProfileGrantID, Model: start.Model, Effort: start.Effort, Budget: start.Budget,
		RootTicketID: start.RootTicketID, ExpectedPolicyGeneration: start.ExpectedPolicyGeneration, ImportManifest: manifest})
	f.Reserve(t)
	f.Source(t)
	request := api.LaunchPromptRequest{ReservationID: f.Reservation.ID, Lease: f.Claim}
	if _, err := f.State.LaunchBriefingInput(context.Background(), f.Execution, request); err != nil {
		t.Fatal("actual adoption prompt control failed", err)
	}
	changed := f.Record
	changed.Reservation.Driver = api.DriverClaudock
	f.Replace(t, "launch_plan", changed.Reservation.ID, changed.Generation, changed)
	if input, err := f.State.LaunchBriefingInput(context.Background(), f.Execution, request); err == nil || input.Lane != nil {
		t.Fatal("adoption prompt accepted a driver absent from its original frame", err)
	}
}

func TestReviewPromptRetainedBasePins(t *testing.T) {
	for _, mode := range []string{"resume", "turn"} {
		t.Run(mode, func(t *testing.T) {
			f, request := retainedReviewPrompt(t, mode, []api.ID{})
			// Both protected projections agree with each other but disagree
			// with the original admitted request's ExpectedGeneration.
			prior := f.Lane
			prior.Generation++
			f.Corrupt(t, "lane", prior.LifeID, prior.Generation, prior)
			changed := f.Record
			changed.Reservation.BaseGeneration = prior.Generation
			f.Corrupt(t, "launch_plan", changed.Reservation.ID, changed.Generation, changed)
			opened, err := store.New(f.Deps)
			if err != nil {
				// Restart verification can reject the combined corruption
				// before any prompt reader obtains the altered projections.
				codeIs(t, err, api.CodeIntegrity)
				return
			}
			f.State = opened
			if input, err := f.State.LaunchBriefingInput(context.Background(), f.Execution, request); err == nil || input.Lane != nil {
				t.Fatal("retained prompt accepted a base generation absent from its original request", err)
			}
		})
	}
}
