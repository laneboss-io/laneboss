package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPlanFailOutbox(t *testing.T) {
	for _, mode := range []string{"runner", "inject", "bound", "acquire"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			if mode == "bound" {
				plan, err := f.service.PlanLaunch(context.Background(), scope, request)
				if err != nil {
					t.Fatal(err)
				}
				f.bindPrepared(t, scope, request, plan)
				f.ports.failStage = "reconcile-capture"
			} else if mode == "inject" {
				f.ports.failStage = "inject"
			} else if mode == "acquire" {
				f.ports.failStage = "acquire"
			} else {
				f.ports.failStage = "runner-start"
			}
			primary := api.NotImplemented("stage-owner", "original stage failure")
			f.ports.failure = primary
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			retained := f.store.plans[record.Reservation.ID]
			if !reflect.DeepEqual(err, primary) || retained.Phase != "failed" || !reflect.DeepEqual(retained.Error, primary) || len(f.store.failedWrites) != 1 {
				t.Fatalf("failed plan lost its atomic cleanup request: %v", err)
			}
			write := f.store.failedWrites[0]
			if write.Transaction.Internal == nil || write.Transaction.Internal.Kind != api.InternalLaunchPlan ||
				write.Transaction.Internal.EffectID != request.Lease.Record.Effect.ID ||
				!reflect.DeepEqual(write.Transaction.Writes.LaunchPlans, []api.LaunchPlanRecord{retained}) {
				t.Fatal("failed plan cleanup escaped its planning transaction")
			}
			want := []string{"release", "revoke_injection"}
			if mode == "bound" {
				want = []string{"withdraw"}
			}
			if len(write.Cleanup) != len(want) || len(f.store.cleanups) != len(want) {
				t.Fatal("failed plan omitted a required cleanup effect")
			}
			for i, job := range write.Cleanup {
				if job.Kind != want[i] || job.Slot != f.ports.slots[record.Reservation.Target] ||
					job.Cause.CauseOperationID != record.Reservation.OperationID || job.Cause.CauseRequestID != record.Reservation.RequestID ||
					job.Cause.RequestedBy != record.Reservation.RequestedBy || job.Cause.Actor != scope.Actor ||
					job.SlotResult.ID != launchObjectID(record.Reservation.ID, "result-credential-slot") ||
					job.SlotKnown != (mode != "acquire") || mode != "acquire" && (job.InjectionIn == nil || job.InjectionOut == nil) {
					t.Fatal("failed plan cleanup changed its original credential selectors")
				}
				if mode == "bound" && (job.Prepared == nil || job.Withdrawal == nil || job.Withdrawal.Cause != job.Cause || job.Withdrawal.Reason != "refused") {
					t.Fatal("failed bound plan omitted its original projection withdrawal")
				}
				if (mode == "inject" || mode == "acquire") && job.Injection != nil || mode != "inject" && mode != "acquire" && job.Injection == nil {
					t.Fatal("failed plan invented or lost its injection outcome")
				}
			}
			slotID := launchObjectID(record.Reservation.ID, "result-credential-slot")
			before := append([]byte{}, f.store.blobs[slotID]...)
			calls := launchClone(t, f.ports.calls)
			_, replay := f.service.PlanLaunch(context.Background(), scope, request)
			if !reflect.DeepEqual(replay, primary) || len(f.store.failedWrites) != 1 || !bytes.Equal(f.store.blobs[slotID], before) ||
				f.ports.calls["acquire"] != calls["acquire"] || f.ports.calls["inject"] != calls["inject"] || f.ports.calls["runner-start"] != calls["runner-start"] {
				t.Fatalf("failed plan replay reacquired or replaced its retained stages: %v", replay)
			}
		})
	}
}

func TestPlanFailAtomic(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	primary := api.NotImplemented("stage-owner", "original runner refusal")
	storage := api.NotImplemented("store-owner", "atomic failure commit")
	f.ports.failStage, f.ports.failure, f.store.failPlanErr = "runner-start", primary, storage
	_, err := f.service.PlanLaunch(context.Background(), scope, request)
	if !errors.Is(err, primary) || !errors.Is(err, storage) || f.store.plans[record.Reservation.ID].Phase == "failed" ||
		len(f.store.cleanups) != 0 || len(f.store.failedWrites) != 0 {
		t.Fatalf("failed cleanup transaction committed only half its state: %v", err)
	}
	before := f.ports.calls["acquire"]
	f.store.failPlanErr = nil
	_, err = f.service.PlanLaunch(context.Background(), scope, request)
	if !reflect.DeepEqual(err, primary) || f.store.plans[record.Reservation.ID].Phase != "failed" || len(f.store.cleanups) != 2 || f.ports.calls["acquire"] != before {
		t.Fatalf("failed cleanup transaction did not retry its retained slot: %v", err)
	}
	write := f.store.failedWrites[0]
	// A standalone failed-plan transaction cannot bypass the writer's paired
	// outbox contract, even when its generation comparison is current.
	tx := write.Transaction
	tx.Writes = launchClone(t, tx.Writes)
	tx.Compare = append([]api.Compare{}, tx.Compare...)
	tx.Writes.LaunchPlans[0].Generation++
	tx.Compare[0].Generation++
	beforeWrites := len(f.store.transactions)
	// Exercise the fixture's paired-jobs boundary directly as well. The
	// shared ordinary-transaction refusal must not mask its own regression.
	if err := f.store.checkFailedPlan(tx, nil); err == nil {
		t.Fatal("failed plan accepted a separately queued cleanup")
	}
	if _, err := f.store.Transact(context.Background(), tx); err == nil || len(f.store.transactions) != beforeWrites || len(f.store.cleanups) != 2 {
		t.Fatalf("failed plan accepted a separately queued cleanup: %v", err)
	}
}

func TestPlanFailUncertain(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	if _, err := f.service.PlanLaunch(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	// Corrupt only the retained injection result after it was consumed. The
	// broker still owns that original selection; an unreadable reply cannot
	// discard the cleanup trigger or authorize a second injection.
	f.store.blobs[launchObjectID(record.Reservation.ID, "result-injection")][0] ^= 1
	_, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err == nil || f.store.plans[record.Reservation.ID].Phase != "failed" || len(f.store.failedWrites) != 1 || len(f.store.cleanups) != 2 {
		t.Fatalf("uncertain injection lost its durable cleanup trigger: %v", err)
	}
	for _, job := range f.store.cleanups {
		if job.Injection != nil || job.InjectionOut == nil || len(job.Issues) == 0 || !job.SlotKnown {
			t.Fatal("uncertain injection invented an empty cleanup receipt")
		}
	}
	_, err = f.service.PlanLaunch(context.Background(), scope, request)
	if err == nil || f.ports.calls["acquire"] != 1 || f.ports.calls["inject"] != 1 || len(f.store.failedWrites) != 1 {
		t.Fatalf("uncertain cleanup retry replaced its original credentials: %v", err)
	}
}

type noFailureWriter struct{ api.StateStore }

func TestPlanFailPort(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	f.service.deps.Store = noFailureWriter{f.store}
	primary := api.NotImplemented("stage-owner", "original runner refusal")
	f.ports.failStage, f.ports.failure = "runner-start", primary
	_, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err == nil || !errors.Is(err, primary) || !strings.Contains(err.Error(), "atomic failed-plan credential cleanup outbox") ||
		f.store.plans[record.Reservation.ID].Phase == "failed" || len(f.store.cleanups) != 0 || f.ports.calls["acquire"] != 1 {
		t.Fatalf("missing cleanup writer was reported as a durable request: %v", err)
	}
}
