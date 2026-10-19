package messaging

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestItem3LogicalDeliveryCoordinator(t *testing.T) {
	for _, cell := range []string{"complete", "limit", "missing-end", "foreign-claim", "stale-claim"} {
		t.Run(cell, func(t *testing.T) {
			f, scope, request := completedDelivery(t)
			record := f.store.effectRows[request.Intent.EffectID]
			lease := api.EffectLease{Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt}
			switch cell {
			case "limit":
				var end api.RunEndEvent
				if err := json.Unmarshal(f.store.events[len(f.store.events)-1].Payload, &end); err != nil {
					t.Fatal(err)
				}
				end.Reason, end.ProfileContinuation = "limit", true
				f.store.events[len(f.store.events)-1].Payload = mustJSON(t, end)
			case "missing-end":
				f.store.events = f.store.events[:len(f.store.events)-1]
			case "foreign-claim":
				scope.Actor.ID = randomID(t)
			case "stale-claim":
				lease.ClaimID = randomID(t)
			}
			before := len(f.store.events)
			observation, err := f.service.ReconcileDelivery(context.Background(), scope, lease)
			if cell == "complete" {
				if err != nil || observation.Handle.Target != request.Receipt.Target || observation.State != "exited" || f.store.mail[request.MailID].Status != "delivered" || len(f.store.events) != before+1 {
					t.Fatal("real completion observations did not produce exactly one logical receipt", err)
				}
				return
			}
			if err == nil || f.store.mail[request.MailID].Status != "delivering" || len(f.store.events) != before {
				t.Fatal("limit, absent end or changed claim acknowledged logical mail", err)
			}
		})
	}
}

func TestItem3LogicalDeliveryRecovery(t *testing.T) {
	f, scope, request := completedDelivery(t)
	record := f.store.effectRows[request.Intent.EffectID]
	lease := api.EffectLease{Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt}
	first, err := f.service.ReconcileDelivery(context.Background(), scope, lease)
	if err != nil {
		t.Fatal("actual original logical receipt did not commit", err)
	}
	before, generation := len(f.store.events), f.store.mail[request.MailID].Generation
	lane := f.store.lanes[request.Receipt.Target.LifeID]
	lane.Run++
	lane.Generation++
	lane.LogicalTurnID = randomID(t)
	f.store.lanes[lane.LifeID] = lane
	replay, err := f.service.ReconcileDelivery(context.Background(), scope, lease)
	if err != nil || !reflect.DeepEqual(first, replay) || len(f.store.events) != before || f.store.mail[request.MailID].Generation != generation {
		t.Fatal("lost reply after a later turn did not recover the original receipt once", err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
