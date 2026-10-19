package lifecycle

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestProjectionKey(t *testing.T) {
	f, scope, request, plan := preparedFixture(t)
	binding := f.store.bindings[plan.Reservation.LaunchID]
	record, err := f.store.CredentialProjection(context.Background(), scope.Config, binding.Prepared.ID)
	if err != nil || record.Authority.ID == binding.Prepared.ID {
		t.Fatalf("projection fixture did not distinguish prepared and authority keys: %v", err)
	}
	if _, err := f.store.CredentialProjection(context.Background(), scope.Config, record.Authority.ID); !notFound(err) {
		t.Fatalf("projection fixture accepted an authority key alias: %v", err)
	}
	got, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(got, plan) || f.ports.calls["acquire"] != 1 {
		t.Fatalf("bound recovery used a projection authority key: %v", err)
	}
}

func TestPrepareFields(t *testing.T) {
	for _, mode := range []string{"workspace", "turn", "policy"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _, _ := preparedFixture(t)
			tx := f.store.transactions[len(f.store.transactions)-1]
			if api.ValidateTransactionShape(tx) != nil || f.store.preparePins(tx) != nil {
				t.Fatal("prepare pin fixture lost its valid fenced transaction")
			}
			tx.Writes = launchClone(t, tx.Writes)
			switch mode {
			case "workspace":
				tx.Writes.Lanes[0].Workspace = api.Workspace{}
			case "turn":
				tx.Writes.Lanes[0].LogicalTurnID = ""
			case "policy":
				tx.Writes.Lanes[0].PolicyGeneration = 0
			}
			if err := f.store.preparePins(tx); err == nil {
				t.Fatal("prepare writer omitted a required recovery pin")
			}
			before := f.store.intentReads
			if _, err := f.store.Transact(context.Background(), tx); err == nil || f.store.intentReads != before {
				t.Fatalf("prepare writer reached intent checks without recovery pins: %v", err)
			}
		})
	}
}

func TestOpenedReceipt(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "home", "prepared", "lease", "generation", "targets", "sources", "source-key", "held-fence", "no-fence", "bad-fence"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, request, plan := preparedFixture(t)
			if _, err := f.store.Transact(context.Background(), openFixtureTransaction(t, f)); err != nil {
				t.Fatal(err)
			}
			key := f.store.bindings[plan.Reservation.LaunchID].Prepared.ID
			record := launchClone(t, f.store.projections[key])
			record.Receipt.GateClosed = false
			switch mode {
			case "missing":
				record.Receipt = nil
			case "home":
				record.Receipt.Home.RootID = "foreign-home"
			case "prepared":
				record.Receipt.Prepared.ID = "foreign-prepared"
			case "lease":
				record.Receipt.HelperLeaseID = "foreign-lease"
			case "generation":
				record.Authority.Generation = 0
			case "targets":
				record.Authority.Targets = nil
			case "sources":
				record.Authority.Sources = nil
			case "source-key":
				record.Authority.Sources[0].Key = "foreign-source"
			case "held-fence":
				record.Fence = &api.CredentialWithdrawalRequest{ProjectionID: record.Authority.ID}
			case "no-fence":
				record.State, record.Generation = "withdrawing", record.Generation+1
			case "bad-fence":
				record.State, record.Generation = "withdrawing", record.Generation+1
				record.Fence = &api.CredentialWithdrawalRequest{ProjectionID: "foreign-projection", ExpectedGeneration: record.Receipt.Generation}
			}
			f.store.projections[key] = record
			got, err := f.service.PlanLaunch(context.Background(), scope, request)
			if mode == "valid" {
				if err != nil || !reflect.DeepEqual(got, plan) {
					t.Fatalf("opened history required fresh opening authority: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("opened recovery trusted corrupt projection history: %v", err)
			}
			if f.ports.calls["credential-check"] != 0 || f.ports.calls["acquire"] != 1 {
				t.Fatal("opened history rechecked or reacquired opening authority")
			}
		})
	}
}

func TestClaimEntry(t *testing.T) {
	t.Run("planner", func(t *testing.T) {
		f := newLaunchFixture(t)
		_, record := f.reserve(t)
		scope, request := f.claim(t, record)
		request.Lease.Record.Generation = 1
		f.store.effects[request.Lease.Record.Effect.ID] = request.Lease.Record
		before := f.ports.calls["grants"]
		_, err := f.service.PlanLaunch(context.Background(), scope, request)
		if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || f.ports.calls["grants"] != before {
			t.Fatalf("planner accepted a generation one claimed effect: %v", err)
		}
	})
	t.Run("lifecycle", func(t *testing.T) {
		control, scope, lease := readyInput(t)
		lease.Record.Generation = 1
		control.f.store.effects[lease.Record.Effect.ID] = lease.Record
		_, err := control.f.service.lifecycleClaim(context.Background(), scope, lease)
		if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict {
			t.Fatalf("lifecycle accepted a generation one claimed effect: %v", err)
		}
		if _, err := control.f.service.ApplyInput(context.Background(), scope, lease); err == nil || control.calls != 0 {
			t.Fatalf("input crossed a generation one claim: %v", err)
		}
	})
	t.Run("clean", func(t *testing.T) {
		f, scope, lease, _, _ := cleanReplayFixture(t)
		lease.Record.Generation = 1
		f.store.effects[lease.Record.Effect.ID] = lease.Record
		if _, err := f.service.CollectClean(context.Background(), scope, lease); err == nil {
			t.Fatal("collector accepted a generation one claimed effect")
		}
	})
	t.Run("revoke", func(t *testing.T) {
		f, store, identity, scope, lease := newRevocationFixture(t)
		lease.Record.Generation = 1
		store.effects[lease.Record.Effect.ID] = lease.Record
		before := store.intentReads
		err := f.service.RevokeLaunch(context.Background(), scope, lease)
		if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || store.intentReads != before || store.commits != 0 || identity.calls != 0 {
			t.Fatalf("revocation crossed a generation one claimed effect: %v", err)
		}
	})
}
