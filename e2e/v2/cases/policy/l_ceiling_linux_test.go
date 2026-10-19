//go:build linux && !laneboss_root_canary

package policycase

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// This follows actual boot/assembly/binding through real reservation, grant
// resolution, committed source selection, and materialization planning.
// Primitive ceiling IDs, publication metadata, the already-enrolled human
// ticket, and helper allocation are explicit component fixtures. No native
// worker, installed root issuance, or authenticated model execution is claimed.
func TestPolicyBootLaunchCeiling(t *testing.T) {
	t.Run("actual", func(t *testing.T) { policyBootLaunchCeiling(t, false) })
	t.Run("extra-copy-source", func(t *testing.T) { policyBootLaunchCeiling(t, true) })
}

func policyBootLaunchCeiling(t *testing.T, extraCopy bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "launch-inputs.json")
	args := []string{"-I", "l_probe.py", "--output", path}
	if extraCopy {
		args = append(args, "--extra-copy-source")
	}
	probe := exec.CommandContext(ctx, "python3", args...)
	if output, err := probe.CombinedOutput(); err != nil {
		t.Fatalf("actual policy boot/assembler/binder: %v\n%s", err, output)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Approved    api.RootGrantManifest `json:"approved"`
		RootRequest api.RootGrantRequest  `json:"root_request"`
		Ceiling     api.GrantSet          `json:"ceiling"`
		Launches    []api.StartRequest    `json:"launches"`
		Documents   []struct {
			Ref  api.BlobRef `json:"ref"`
			Data []byte      `json:"data"`
		} `json:"documents"`
		Project        api.BlobRef `json:"project"`
		ProjectGrantID api.ID      `json:"project_grant_id"`
		Enrollment     api.BlobRef `json:"enrollment"`
		Runtime        api.BlobRef `json:"runtime"`

		OrgSnapshot api.OrgSnapshot     `json:"org_snapshot"`
		Policy      api.EffectivePolicy `json:"policy"`
	}
	if err := api.DecodeObject(raw, &input); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Root(input.Approved, time.Now()); err != nil {
		t.Fatal("actual approved root manifest", err)
	}
	if err := manifest.RootInput(input.RootRequest); err != nil {
		t.Fatal("actual root issuance request", err)
	}
	// Confirm the component identities did not replace any approved scope.
	approved := api.RootGrantManifest{Schema: input.Approved.Schema,
		Resources: input.Ceiling.Resources, Data: append([]api.DataGrant{}, input.Ceiling.Data...),
		Secrets: input.Ceiling.Secrets, Profiles: append([]api.ProfileGrant{}, input.Ceiling.Profiles...),
		Network: input.Ceiling.Network, Channels: input.Ceiling.Channels}
	if len(approved.Resources)+len(approved.Secrets)+len(approved.Network)+len(approved.Channels) != 0 {
		t.Fatal("policy case gained an unexamined capability family")
	}
	for i := range approved.Data {
		approved.Data[i].ID = ""
	}
	for i := range approved.Profiles {
		approved.Profiles[i].ID = ""
	}
	if !reflect.DeepEqual(approved, input.Approved) {
		t.Fatal("component ceiling differs from the actual case's approved root grants")
	}
	input.Ceiling.SHA256, err = manifest.HashValue(input.Ceiling)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Set(input.Ceiling, time.Now()); err != nil {
		t.Fatal("component ceiling lost the actual approved fields", err)
	}
	if len(input.Launches) != 2 {
		t.Fatal("assembler did not supply both baseline driver launches")
	}
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		t.Run(string(driver), func(t *testing.T) {
			f := fx.New(t, "policy-case")
			f.Replace(t, "policy", api.ID(f.Deps.Config), input.Policy.Generation, input.Policy)
			var start api.StartRequest
			matches := 0
			for _, candidate := range input.Launches {
				if candidate.Driver == driver {
					start = candidate
					matches++
				}
			}
			if matches != 1 || start.RootTicketID != "" || !reflect.DeepEqual(start.Budget, input.RootRequest.Budget) {
				t.Fatal("actual launch driver, root ticket or budget differs from the assembler's root request")
			}
			// Retain the actual task, source, and approved-manifest bytes. The
			// only replaced setup data are the fixture's primitive ceiling and
			// ticket. ReserveLaunch and its private launchCeiling run unchanged.
			var objects []api.ObjectWrite
			rootFound := false
			for _, document := range input.Documents {
				if document.Ref.Bytes != int64(len(document.Data)) || document.Ref.SHA256 != fx.Digest(document.Data) {
					t.Fatal("actual assembler document lost its pinned bytes")
				}
				if document.Ref == input.RootRequest.Manifest {
					var pinned api.RootGrantManifest
					if err := api.DecodeObject(document.Data, &pinned); err != nil || !reflect.DeepEqual(pinned, input.Approved) {
						t.Fatal("root request does not select the actual approved manifest", err)
					}
					rootFound = true
				}
				owner := f.Execution.Actor
				if document.Ref == start.Task {
					owner = f.Human.Actor
				}
				objects = append(objects, api.ObjectWrite{ObjectKey: document.Ref.ID, Class: document.Ref.Class,
					Bytes: document.Data, SHA256: document.Ref.SHA256, Origin: "service",
					ACL: api.ObjectACL{Config: f.Deps.Config, Owner: owner, Audience: "owner", Generation: 1}})
			}
			if !rootFound {
				t.Fatal("root manifest bytes were not retained")
			}
			cause := f.Intent(t, api.InternalOrgBootstrap)
			snapshot := input.OrgSnapshot
			snapshot.PublishedBy, snapshot.PublishedAt = fx.ID(t), api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
			if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
				Writes: api.StateWrites{Grants: []api.GrantSet{input.Ceiling}, Objects: objects, OrgSnapshots: []api.OrgSnapshot{snapshot}}}); err != nil {
				t.Fatal("retain actual policy root ceiling and inputs", err)
			}
			ticket, err := f.State.Ticket(ctx, f.Human, f.Start.RootTicketID)
			if err != nil {
				t.Fatal(err)
			}
			ticket.GrantSetID = input.Ceiling.ID
			f.Replace(t, "ticket", ticket.ID, 1, struct {
				RedeemedBy         api.ID
				PrincipalID        api.ID
				Config             string
				EndpointGeneration api.Generation
				Ticket             api.Ticket
			}{PrincipalID: ticket.PrincipalID, Config: ticket.Config, EndpointGeneration: ticket.EndpointGeneration, Ticket: ticket})
			f.Ceiling = input.Ceiling
			start.RootTicketID = ticket.ID
			policyData := -1
			for i, request := range start.Grants.Data {
				for _, grant := range input.Ceiling.Data {
					if request.ParentGrantID == input.ProjectGrantID && request.ParentGrantID == grant.ID && grant.SourceObjectID == input.Project.ID && grant.SourceSHA256 == input.Project.SHA256 {
						if policyData != -1 {
							t.Fatal("policy project selection is ambiguous")
						}
						policyData = i
					}
				}
			}
			if policyData == -1 || len(start.Grants.Data) != len(input.Ceiling.Data) {
				t.Fatal("actual binder omitted an approved project grant")
			}
			// Restore only the original offending request field. A successful
			// reservation here would mean the service ceiling was bypassed.
			bad := start
			bad.Grants.Data = append([]api.DataGrantRequest{}, start.Grants.Data...)
			bad.Grants.Data[policyData].Destination = "/data/policy"
			f.Start = bad
			f.Admit(t, "lane.start", bad)
			_, err = f.State.ReserveLaunch(ctx, f.Human, f.ReservationRequest(t))
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Owner != "lb-v2-service" || typed.Message != "launch request exceeds its current grant ceiling" {
				t.Fatalf("original destination did not reach the unchanged service ceiling: %v", err)
			}
			t.Logf("CONTROL: grants.data[%d].destination=/data/policy reached the real ceiling refusal", policyData)
			f.Start = start
			f.Admit(t, "lane.start", start)
			reservation, err := f.State.ReserveLaunch(ctx, f.Human, f.ReservationRequest(t))
			if err != nil {
				t.Fatalf("actual case launch grants.data[%d].destination=%q: %v", policyData, start.Grants.Data[policyData].Destination, err)
			}
			if reservation.ID == "" || reservation.Target.LifeID == "" || reservation.Driver != driver || reservation.Mode != "start" {
				t.Fatal("actual policy case did not produce a durable launch reservation")
			}
			stored, err := f.State.LaunchPlan(ctx, f.Execution, reservation.ID)
			if err != nil || !reflect.DeepEqual(stored.Reservation, reservation) {
				t.Fatal("store lost the actual case launch reservation", err)
			}
			f.Reservation, f.Record = reservation, stored
			for _, effect := range mustPolicyEffects(t, f) {
				if effect.PlanLaunch != nil && effect.PlanLaunch.ReservationID == reservation.ID {
					f.Claim, err = f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID,
						ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if f.Claim.ClaimID == "" {
				t.Fatal("actual launch lost its planning effect")
			}
			resolver, err := grants.New(grants.Dependencies{Config: f.Deps.Config, Store: f.State, Worker: &dataworker.Service{}, Clock: fx.Clock{}})
			if err != nil {
				t.Fatal(err)
			}
			issued, err := resolver.Resolve(ctx, f.Execution, api.GrantResolveRequest{ReservationID: reservation.ID})
			if err != nil {
				t.Fatal("real case grant resolution", err)
			}
			cause = f.Intent(t, api.InternalLaunchPlan)
			if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
				Writes:  api.StateWrites{Grants: []api.GrantSet{issued}},
				Events:  []api.Event{f.Event(t, "grants.issued", api.GrantEvent{GrantSet: issued})},
				Compare: []api.Compare{{Kind: api.CompareGrants, ID: reservation.GrantSetID}},
				Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: reservation.Target.LifeID, Epoch: reservation.CancellationEpoch}}}}); err != nil {
				t.Fatal("retain real case grant resolution", err)
			}
			claim := api.PlanningClaim(reservation.ID, f.Claim)
			sources, err := admin.ResolveCommittedLaunchSources(ctx, f.State, f.Deps.Config,
				api.LaunchSourceRequest{ReservationID: reservation.ID, GrantSetID: issued.ID, Claim: claim}, input.Enrollment, input.Runtime)
			if err != nil {
				t.Fatal("actual case enrollment source selection", err)
			}
			record := f.Record
			record.Generation++
			record.Phase, record.Inputs = "sourced", &api.LaunchInputs{Grants: issued, Sources: sources}
			cause = f.Intent(t, api.InternalLaunchPlan)
			if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
				Writes:  api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{record}},
				Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: reservation.ID, Generation: f.Record.Generation}},
				Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: reservation.Target.LifeID, Epoch: reservation.CancellationEpoch}}}}); err != nil {
				t.Fatal("retain actual case materialization sources", err)
			}
			f.Record = record
			// The helper lease is an explicit component allocation, retained by
			// the real outbox. No native worker or model process is executed.
			allocate := f.Intent(t, api.InternalHelperAllocate)
			allocate.Actor = f.Claim.Record.Effect.Context.Actor
			allocate.EffectID = fx.ID(t)
			effect := api.Effect{ID: allocate.EffectID, OperationID: reservation.OperationID, Context: &allocate,
				HelperAllocate: &api.HelperLeaseRequest{ReservationID: reservation.ID, Cause: allocate, Config: f.Deps.Config,
					LifeID: reservation.Target.LifeID, Backend: sources.Runtime.Backend, Budget: start.Budget, RuntimeManifestID: input.Runtime.ID}}
			cause = f.Intent(t, api.InternalLaunchPlan)
			if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
				t.Fatal(err)
			}
			allocationClaim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID,
				ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
			if err != nil {
				t.Fatal(err)
			}
			lease := api.HelperLease{ID: fx.ID(t), UID: uint32(os.Geteuid()) + 1000, GID: uint32(os.Getegid()) + 1000,
				ContainmentID: fx.ID(t), EndpointGeneration: 1}
			if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: effect.ID, ClaimID: allocationClaim.ClaimID,
				ExpectedGeneration: allocationClaim.Record.Generation, Status: "succeeded", HelperLease: &lease}); err != nil {
				t.Fatal(err)
			}
			for _, source := range issued.Data {
				if source.Delivery != "copy" || source.RelativePath != "." {
					t.Fatal("materialization control did not preserve complete copy-source grants")
				}
			}
			if extraCopy && len(issued.Data) < 2 {
				t.Fatal("additional copy-source control lost its extra grant")
			}
			request := api.LaunchDataRequest{ReservationID: reservation.ID, GrantSetID: issued.ID, LeaseID: lease.ID, Claim: claim}
			stage, err := f.State.LaunchDataStage(ctx, f.Execution, request)
			if extraCopy {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeUnsupported || typed.Owner != "lb-v2-service" || typed.Message != "materialization requires its single granted copy source" {
					t.Fatalf("additional granted copy source did not reach the unchanged materializer: %v", err)
				}
				t.Logf("CONTROL: %s %d granted copy sources reached the real materializer refusal", driver, len(issued.Data))
				return
			}
			if err != nil {
				t.Fatalf("actual %s materialization with %d granted data sources: %v", driver, len(issued.Data), err)
			}
			if len(issued.Data) != 1 || len(stage.Grants.Data) != 1 || stage.Grants.Data[0].ParentGrantID != sources.Project.GrantID ||
				stage.Grants.Data[0].SourceObjectID != sources.Project.Object.ID || stage.Grants.Data[0].SourceSHA256 != sources.Project.Object.SHA256 ||
				stage.Grants.Data[0].Delivery != "bind_ro" || stage.Grants.Data[0].Destination != "/job/source" || !reflect.DeepEqual(stage.Inputs.Grants, issued) {
				t.Fatal("materialization planning did not retain the sole actual granted copy source")
			}
			t.Logf("GREEN: actual %s boot/assembler/binder/resolver passed ceiling and materialization planning with one copy source", driver)
		})
	}
}

func mustPolicyEffects(t *testing.T, f *fx.Fixture) []api.Effect {
	t.Helper()
	effects, err := f.State.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	return effects
}
