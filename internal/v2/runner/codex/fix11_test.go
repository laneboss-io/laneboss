package codex

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCapturePolicyAdvance(t *testing.T) {
	f := newFixture(t)
	f.quotaProof()
	prefix := threadLine()
	f.capture(prefix, 0)
	sealed := f.currentPlan()
	f.store.policy.Generation++
	f.service.deps.ReadScope.PolicyGeneration = f.store.policy.Generation
	record := f.capture([]byte("{\"type\":\"turn.failed\",\"error\":{\"code\":\"synthetic_quota\"}}\n"), int64(len(prefix)))
	exit := observation(record.Target, 1)
	f.store.event(record.Target, "credential.leased", api.CredentialEvent{Slot: f.request.Slot, Outcome: "leased"})
	f.store.event(record.Target, "run.observed", exit)
	f.closeCapture(record)
	f.seedUsage(exit)
	ctx := context.Background()
	session, err := f.service.SessionFromCapture(ctx, record)
	if err != nil || session.VendorID != testVendorID {
		t.Fatal("policy advance blocked the opened launch session", err)
	}
	signal, err := f.service.LimitFromCapture(ctx, record, exit)
	if err != nil || signal == nil || signal.UsageEvidence == nil {
		t.Fatal("policy advance blocked the opened launch limit", err)
	}
	if !reflect.DeepEqual(f.currentPlan(), sealed) || f.store.grants.PolicyGeneration != sealed.Reservation.PolicyGeneration {
		t.Fatal("historical policy pins were rewritten after policy advance")
	}
	f.store.grants.Revoked = true
	_, err = f.service.SessionFromCapture(ctx, record)
	wantCode(t, err, api.CodeForbidden)
	_, err = f.service.LimitFromCapture(ctx, record, exit)
	wantCode(t, err, api.CodeForbidden)
}

func TestCapturePolicyUnknown(t *testing.T) {
	f := newFixture(t)
	record, _ := f.endCapture(threadLine(), 0)
	f.store.policy.Generation = 0
	_, err := f.service.SessionFromCapture(context.Background(), record)
	wantCode(t, err, api.CodeInvalid)
}

func TestHistoricalGrants(t *testing.T) {
	for _, fault := range []string{"revoked", "expired", "generation", "snapshot"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			r := f.currentPlan().Reservation
			retained := fixtureCopy(f.store.grants)
			ctx := context.Background()
			f.store.policy.Generation++
			if err := f.service.retainedGrants(ctx, r, retained); err != nil {
				t.Fatal("historical grants required current issuance", err)
			}
			switch fault {
			case "revoked":
				f.store.grants.Revoked = true
				retained = fixtureCopy(f.store.grants)
			case "expired":
				f.clock.now = f.clock.Now().Add(2 * time.Hour)
				f.service.deps.Clock = f.clock
			case "generation":
				f.store.grants.PolicyGeneration++
				retained = fixtureCopy(f.store.grants)
			case "snapshot":
				f.store.grants.Generation++
			}
			wantCode(t, f.service.retainedGrants(ctx, r, retained), api.CodeForbidden)
		})
	}
}

func TestDataStageGate(t *testing.T) {
	for _, fault := range []string{"missing", "foreign", "parent", "running", "outcome", "result", "output", "observation", "bytes", "provenance", "unavailable"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			if _, err := f.service.Start(ctx, f.request); err != nil {
				t.Fatal("completed materialization control failed", err)
			}
			record := f.currentPlan()
			r := record.Reservation
			stage, err := f.store.LaunchDataStage(ctx, f.service.deps.ReadScope, api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID,
				LeaseID: f.store.effects[f.service.deps.AllocationEffectID].Outcome.HelperLease.ID})
			if err != nil {
				t.Fatal(err)
			}
			child := fixtureCopy(f.store.effects[stage.Worker.EffectID])
			result, err := f.store.AwaitMaterialization(ctx, stage.ID)
			if err != nil {
				t.Fatal(err)
			}
			code := api.CodeIntegrity
			switch fault {
			case "missing":
				record.DataStageID = ""
				code = api.CodePrerequisite
			case "foreign":
				record.DataStageID = "foreign_data_stage"
			case "parent":
				stage.ParentEffectID = "foreign_parent_effect"
			case "running":
				child.State = api.EffectClaimed
				code = api.CodeConflict
			case "outcome":
				child.Outcome.Status = "failed"
				code = api.CodeConflict
			case "result":
				result.ReadBackSHA256 = hashBytes([]byte("foreign readback"))
				code = api.CodeInvalid
			case "output":
				child.Outcome.Output = nil
			case "observation":
				child.Outcome.Observation.Handle.Generation = "foreign_process"
			case "bytes":
				f.store.blobs[result.ResultReceipt.Result.ID][0] = '['
			case "provenance":
				metadata := f.store.metadata[result.ResultReceipt.Result.ID]
				metadata.SourceOperationID = "foreign_operation"
				f.store.metadata[result.ResultReceipt.Result.ID] = metadata
			case "unavailable":
				f.service.deps.Materialization = nil
				code = api.CodeNotImplemented
			}
			f.store.plans[r.ID] = record
			f.store.effects[stage.Worker.EffectID] = child
			f.store.dataStages[r.ID], f.store.dataResults[stage.ID] = f.keepJSON(stage, "record"), f.keepJSON(result, "record")
			plan, err := f.service.Start(ctx, f.request)
			wantCode(t, err, code)
			if !reflect.DeepEqual(plan, api.RunnerPlan{}) {
				t.Fatal("incomplete materialization returned argv")
			}
		})
	}
}
