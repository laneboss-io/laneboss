//go:build linux

package service

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/guidance"
	"laneboss.io/laneboss/internal/v2/judge"
	"laneboss.io/laneboss/internal/v2/policy"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/templates"
)

func TestRootIssuanceRetainsBothCeilings(t *testing.T) {
	for _, mutation := range []string{"valid", "delegation_parent", "source", "profile", "delivery", "destination", "expiry", "extra_grant", "policy"} {
		t.Run(mutation, func(t *testing.T) {
			f, r, effect := scopePlanningFixture(t)
			ctx := context.Background()
			lease, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
			if err != nil {
				t.Fatal(err)
			}
			f.Reservation, f.Claim = r, lease
			resolver, err := grants.New(grants.Dependencies{Config: f.Deps.Config, Store: f.State, Worker: &dataworker.Service{}, Clock: fx.Clock{}})
			if err != nil {
				t.Fatal(err)
			}
			issued, err := resolver.Resolve(ctx, f.Execution, api.GrantResolveRequest{ReservationID: r.ID})
			if err != nil {
				t.Fatal("real root resolution failed before issuance control", err)
			}
			switch mutation {
			case "delegation_parent":
				issued.Data[0].ParentGrantID = f.Ceiling.Data[0].ID
			case "source":
				issued.Data[0].SourceObjectID = fx.ID(t)
			case "profile":
				issued.Profiles[0].ProfileID = fx.ID(t)
			case "delivery":
				issued.Data[0].Delivery = "mount"
			case "destination":
				issued.Data[0].Destination = "/work/another"
			case "expiry":
				issued.Data[0].ExpiresAt = api.Timestamp(time.Now().Add(45 * time.Minute).UTC().Format(time.RFC3339Nano))
				issued.ExpiresAt = issued.Data[0].ExpiresAt
			case "extra_grant":
				next := issued.Profiles[0]
				next.ID, next.ProfileID = fx.ID(t), fx.ID(t)
				issued.Profiles = append(issued.Profiles, next)
			case "policy":
				issued.PolicyGeneration++
			}
			issued.SHA256 = ""
			issued.SHA256, err = manifest.HashValue(issued)
			if err != nil {
				t.Fatal(err)
			}
			cause := f.Intent(t, api.InternalLaunchPlan)
			_, err = f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
				Writes: api.StateWrites{Grants: []api.GrantSet{issued}}, Events: []api.Event{f.Event(t, "grants.issued", api.GrantEvent{GrantSet: issued})},
				Compare: []api.Compare{{Kind: api.CompareGrants, ID: r.GrantSetID}},
				Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}})
			if mutation == "valid" {
				if err != nil {
					t.Fatal("root issuance rejected parentless grants selected by the actual ticket", err)
				}
				stored, readErr := f.State.Grants(ctx, r.GrantSetID)
				if readErr != nil || !reflect.DeepEqual(stored, issued) {
					t.Fatal("root issuance lost its exact derived bytes", readErr)
				}
			} else {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeForbidden {
					t.Fatal("root issuance accepted a grant beyond its template or original request", err)
				}
				_, readErr := f.State.Grants(ctx, r.GrantSetID)
				codeIs(t, readErr, api.CodeNotFound)
			}
		})
	}
}

func sourcedPromptFixture(t *testing.T) (*fx.Fixture, api.LaunchPromptRequest) {
	t.Helper()
	f := fx.New(t)
	installPlanningOrg(t, f)
	f.Reserve(t)
	f.Source(t)
	return f, api.LaunchPromptRequest{ReservationID: f.Reservation.ID, Lease: f.Claim}
}

func TestLaunchPromptRetainedClaim(t *testing.T) {
	f, request := sourcedPromptFixture(t)
	ctx := context.Background()
	view, err := f.State.BeginRead(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	scope := f.Execution
	scope.ReadView = view
	input, err := f.State.LaunchBriefingInput(ctx, scope, request)
	if err != nil || input.Lane == nil || input.Lane.LifeID != f.Reservation.Target.LifeID || input.Task == nil || *input.Task != f.Start.Task || input.GrantSet == nil || input.GrantSet.ID != f.Reservation.GrantSetID {
		t.Fatal("protected launch briefing did not derive the actual reservation inputs", err)
	}
	for _, mutation := range []string{"claimant", "borrowed_view", "reservation", "generation", "requester", "public_request", "config", "policy"} {
		t.Run(mutation, func(t *testing.T) {
			foreign, selected := scope, request
			want := api.CodeConflict
			switch mutation {
			case "claimant":
				foreign.ReadView = nil
				foreign.Actor.ID = fx.ID(t)
			case "borrowed_view":
				foreign.Actor.ID = fx.ID(t)
				want = api.CodeUnauthenticated
			case "reservation":
				selected.ReservationID = fx.ID(t)
			case "generation":
				selected.Lease.Record.Generation++
			case "requester":
				cause := *selected.Lease.Record.Effect.Context
				cause.RequestedBy.ID = fx.ID(t)
				selected.Lease.Record.Effect.Context = &cause
			case "public_request":
				foreign.Request = f.Human.Request
				want = api.CodeForbidden
			case "config":
				foreign.Config = "other-config"
				want = api.CodeUnauthenticated
			case "policy":
				foreign.PolicyGeneration++
			}
			input, refusal := f.State.LaunchBriefingInput(ctx, foreign, selected)
			codeIs(t, refusal, want)
			if input.Lane != nil || input.Task != nil {
				t.Fatal("foreign launch claim returned selected prompt inputs")
			}
		})
	}
	if err := view.Close(); err != nil {
		t.Fatal(err)
	}
	renderer, err := templates.New(templates.Dependencies{Store: f.State, Policy: &policy.Service{}, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	briefing, err := renderer.LaunchBriefing(ctx, f.Execution, request)
	if err != nil || briefing.Markdown.ID == "" {
		t.Fatal("actual template renderer refused the protected root reservation", err)
	}
	_, err = renderer.BriefRender(ctx, f.Execution, api.TemplateRequest{Context: api.RoleContext{Level: f.Start.Level, Role: f.Start.Role}, Task: f.Start.Task, GrantSetID: f.Reservation.GrantSetID})
	codeIs(t, err, api.CodeForbidden)
}

func TestPromptPinnedViewLive(t *testing.T) {
	f, request := sourcedPromptFixture(t)
	ctx := context.Background()
	view, err := f.State.BeginRead(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	scope := f.Execution
	scope.ReadView = view
	changed := request.Lease.Record
	changed.ClaimID = fx.ID(t)
	raw := fx.JSON(t, changed)
	db, err := sql.Open("sqlite", filepath.Join(f.Deps.Directory, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "UPDATE effect_states SET data=? WHERE id=?", raw, string(changed.Effect.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.LaunchBriefingInput(ctx, scope, request); err == nil {
		t.Fatal("pinned launch view accepted a claim changed in the live store")
	} else {
		codeIs(t, err, api.CodeConflict)
	}
}

func TestPromptForeignProject(t *testing.T) {
	f, request := sourcedPromptFixture(t)
	ctx := context.Background()
	plan, err := f.State.LaunchPlan(ctx, f.Execution, f.Reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	plan.Inputs.Sources.Project.ProjectID = fx.ID(t)
	f.Replace(t, "launch_plan", f.Reservation.ID, plan.Generation, plan)
	if _, err := f.State.LaunchBriefingInput(ctx, f.Execution, request); err == nil {
		t.Fatal("launch prompt accepted a project source outside the original start pin")
	} else {
		codeIs(t, err, api.CodeForbidden)
	}
}

func TestLaunchGuidanceOneSelection(t *testing.T) {
	f, request := sourcedPromptFixture(t)
	ctx := context.Background()
	selector, err := guidance.New(guidance.Dependencies{Store: f.State, Judge: &judge.Service{}, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := selector.LaunchGuidance(ctx, f.Execution, request)
	if err != nil || first.Status != "empty" || first.WeightedScore == nil || *first.WeightedScore != 0 || len(first.JudgmentIDs) != 0 || first.Task != f.Start.Task {
		t.Fatal("launch guidance did not retain its actually empty snapshot", err)
	}
	replay, err := selector.LaunchGuidance(ctx, f.Execution, request)
	if err != nil || !reflect.DeepEqual(replay, first) {
		t.Fatal("launch guidance repeated or changed the original logical-turn selection", err)
	}
	turn, err := f.State.Turn(ctx, f.Execution, f.Reservation.Target, request.Lease.Record.Effect.Context.LogicalTurnID)
	if err != nil || turn.Generation != 2 || turn.GuidanceID != first.ID {
		t.Fatal("launch guidance did not commit one turn CAS", err)
	}
	_, err = selector.GuidanceSelect(ctx, f.Execution, api.GuidanceRequest{Target: f.Reservation.Target, LogicalTurnID: turn.LogicalTurnID, Task: f.Start.Task})
	codeIs(t, err, api.CodeForbidden)
	foreign := request
	foreign.Lease.ClaimID = fx.ID(t)
	_, err = selector.LaunchGuidance(ctx, f.Execution, foreign)
	codeIs(t, err, api.CodeConflict)
}

func TestLaunchPromptPolicyCannotRelabel(t *testing.T) {
	f, request := sourcedPromptFixture(t)
	ctx := context.Background()
	current, err := f.State.Policy(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	current.Context.Level--
	current.SHA256 = ""
	raw, err := api.CanonicalJSON(fx.JSON(t, current))
	if err != nil {
		t.Fatal(err)
	}
	current.SHA256 = fx.Digest(raw)
	f.Replace(t, "policy", api.ID(f.Deps.Config), current.Generation, current)
	input, err := f.State.LaunchBriefingInput(ctx, f.Execution, request)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeConflict || typed.Message != "launch prompt approved policy belongs to another role" || input.Lane != nil {
		t.Fatal("launch briefing relabelled an approved policy context", err)
	}
}

func TestLaunchGuidanceCannotInventEmpty(t *testing.T) {
	f, request := sourcedPromptFixture(t)
	ctx := context.Background()
	input, err := f.State.ReserveLaunchGuidance(ctx, f.Execution, api.LaunchGuidanceRequest{Prompt: request, AttemptID: fx.ID(t), Deadline: api.Timestamp(time.Now().Add(4 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil || !input.Claim.Acquired {
		t.Fatal("could not acquire actual launch guidance control", err)
	}
	r := input.Claim
	// An explicit retained-snapshot corruption control, not a stubbed read.
	f.Replace(t, "decision_snapshot", r.CandidateSnapshotID, 1, struct {
		ID         api.ID
		Target     api.LifeRef
		Policy     api.Generation
		AsOf       api.Timestamp
		Candidates []api.DecisionCandidate
	}{ID: r.CandidateSnapshotID, Target: r.Target, Policy: r.PolicyGeneration, AsOf: r.ReservedAt,
		Candidates: []api.DecisionCandidate{{ID: fx.ID(t), Source: api.SourceRef{ID: fx.ID(t), Path: "decisions/component", SHA256: f.Start.Task.SHA256, Generation: 1}, EffectiveAt: r.ReservedAt}}})
	zero := float64(0)
	result := api.Guidance{ID: fx.ID(t), Target: r.Target, Task: r.Task, LogicalTurnID: r.LogicalTurnID, PolicyGeneration: r.PolicyGeneration,
		CandidateSnapshotID: r.CandidateSnapshotID, ReservationID: r.ID, AsOf: r.ReservedAt, Items: []api.GuidanceItem{}, JudgmentIDs: []api.ID{}, Status: "empty", WeightedScore: &zero}
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalGuidanceComplete, Config: f.Deps.Config, Actor: f.Execution.Actor,
		RequestedBy: r.RequestedBy, CauseOperationID: r.OwnerOperationID, CauseRequestID: r.OwnerRequestID, EffectID: r.LaunchEffectID,
		Target: r.Target, LogicalTurnID: r.LogicalTurnID, CancellationEpoch: r.CancellationEpoch}
	event := f.Event(t, "guidance.selected", result)
	_, err = f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes: api.StateWrites{Guidance: []api.GuidanceSelection{{ReservationID: r.ID, ClaimID: r.ClaimID, AttemptID: r.OwnerAttemptID, ExpectedGeneration: 1, Result: result}}},
		Events: []api.Event{event}, Compare: []api.Compare{{Kind: api.CompareGuidance, ID: r.ID, Generation: 1}},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Message != "empty guidance requires an actually empty reminder snapshot" {
		t.Fatal("guidance fabricated empty success for a retained reminder", err)
	}
}
